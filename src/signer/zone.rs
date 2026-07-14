//! Zone-specific signing state.

use std::{
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use tracing::{debug, info, trace};

use crate::{
    center::Center,
    signer::{
        ResigningTrigger, SigningTrigger,
        queue::{SigningPending, SigningPermit, SigningQueueLock},
        status::{SigningStatusPerZone, ZoneSigningStatus},
    },
    util::BackgroundTasks,
    zone::{Zone, ZoneByPtr, ZoneHandle, ZoneState},
    zonedata::SignedZoneBuilder,
};

//----------- SignerZoneHandle -------------------------------------------------

/// A handle for signer-related operations on a [`Zone`].
pub struct SignerZoneHandle<'a> {
    /// The zone being operated on.
    pub zone: &'a Arc<Zone>,

    /// The locked zone state.
    pub state: &'a mut ZoneState,

    /// Cascade's global state.
    pub center: &'a Arc<Center>,
}

impl SignerZoneHandle<'_> {
    /// Access the generic [`ZoneHandle`].
    pub const fn zone(&mut self) -> ZoneHandle<'_> {
        ZoneHandle {
            zone: self.zone,
            state: self.state,
            center: self.center,
        }
    }
}

/// # Reacting to changes
impl SignerZoneHandle<'_> {
    /// React to a change in the zone's policy.
    pub fn after_policy_change(&mut self) {
        // TODO: Try to reschedule re-signing in fewer cases.
        self.reschedule_resigning();
    }

    /// React to the zone being restored from disk.
    ///
    /// This is called upon startup when a loaded+signed instance of the zone is
    /// successfully restored from disk. It schedules the zone for re-signing.
    pub fn on_restoration(&mut self) {
        assert!(
            self.state.signer.scheduled_resign_time.is_none(),
            "A zone cannot be scheduled for re-signing until restoration completes"
        );

        self.reschedule_resigning();
    }

    /// React to the upcoming (signed) instance of the zone being published.
    ///
    /// This schedules the zone for re-signing as needed.
    pub fn on_publication(&mut self) {
        self.reschedule_resigning();
    }

    /// React to a signed instance of the zone being abandoned.
    pub fn before_signed_abandonment(&mut self) {
        // TODO: Make the caller pass in the right `SigningTrigger`.
        // TODO: Only enqueue a re-sign if a re-sign was abandoned.
        //
        // TODO: Decide what the semantically correct thing to do is. For now,
        // we just try to re-sign again, in an infinite loop.
        self.enqueue_resign(ResigningTrigger::SIGS_NEED_REFRESH);
    }

    /// (Re-)schedule a zone for re-signing.
    ///
    /// This will recompute when the zone should be scheduled (if at all) and
    /// update its schedule in the global state.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(%zone = self.zone.name),
    )]
    fn reschedule_resigning(&mut self) {
        // TODO: Make `Scheduler` work with `SystemTime` directly.
        fn to_instant(time: SystemTime) -> std::time::Instant {
            // We are computing a timeout value. If the timeout is in the
            // past then we can just as well use zero.
            let since_now = time
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO);

            std::time::Instant::now() + since_now
        }

        let new_time = resign_time(self.state);
        let old_time = self.state.signer.scheduled_resign_time;

        trace!(?new_time, ?old_time, "Rescheduling re-signing");

        let zone = ZoneByPtr(self.zone.clone());
        self.center.signer.resign_scheduler.update(
            &zone,
            old_time.map(to_instant),
            new_time.map(to_instant),
        );

        self.state.signer.scheduled_resign_time = new_time;
    }
}

/// # Initiating signing
impl SignerZoneHandle<'_> {
    /// Enqueue a new-signing operation.
    ///
    /// When a new instance of the zone is loaded, reviewed, and approved, this
    /// method should be called to initiate signing for it. `builder` should
    /// originate from the zone storage after the loaded instance is approved.
    ///
    /// ## Panics
    ///
    /// Panics if `builder.have_next_loaded()` is false.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name)
    )]
    pub fn enqueue_new_sign(&mut self, builder: SignedZoneBuilder) {
        info!("Enqueuing a sign operation");

        assert!(
            builder.have_next_loaded(),
            "a new loaded instance of the zone was not provided"
        );

        // A zone can have at most one 'SignedZoneBuilder' at a time. Because
        // we have 'builder', we are guaranteed that no other signing operations
        // are ongoing right now. A re-signing operation may be enqueued, but it
        // has lower priority than this (TODO: for now).

        assert!(self.state.signer.enqueued_new_sign.is_none());

        // Try to get a spot in the signing queue.
        match self
            .center
            .signer
            .queue
            .enqueue(self.zone.clone(), &builder)
        {
            Ok(permit) => {
                self.start_op(builder, SigningTrigger::Load, permit);
            }

            Err(pending) => {
                // Save the operation for later.
                self.state.signer.enqueued_new_sign = Some(EnqueuedSign { builder, pending })
            }
        }
    }

    /// Enqueue a re-signing operation for the zone.
    ///
    /// When the zone needs re-signing (for one or more reasons, enumerated by
    /// `trigger`), this method should be called to enqueue the operation. The
    /// zone will be re-signed as soon as possible.
    ///
    /// Unlike [`Self::enqueue_new_sign()`], a [`SignedZoneBuilder`] does not
    /// have to be passed here. It does not need to be available when this
    /// method is called; it will be obtained automatically (possibly after some
    /// time, if the underlying zone storage is currently busy).
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name, ?trigger)
    )]
    pub fn enqueue_resign(&mut self, trigger: ResigningTrigger) {
        // TODO: The key manager can call 'enqueue_resign()' even when the zone
        // has not been signed. So we need to ignore some (but not all) calls
        // to 'enqueue_resign()'. Ideally, the key manager would check the
        // current signed instance of the zone itself, and check that it really
        // needs re-signing (i.e. that the signing keys used for building that
        // instance are different from the latest ones).
        //
        // If a published instance of the zone exists, we definitely want to
        // re-sign it. If a published instance of the zone does not exist, but
        // an upcoming signed instance does (or if the zone is being restored
        // from disk), we should try re-signing it too. Before re-signing is
        // actually initiated, we will verify that the upcoming instance was
        // accepted and published (and ignore the re-signing request otherwise).
        if self.state.instances.current.is_none()
            && self.state.instances.upcoming.is_none()
            && !self.state.storage.is_restoring()
        {
            debug!(
                "Ignoring re-signing request; \
                there is no published or upcoming signed instance to re-sign"
            );
            return;
        }

        info!("Enqueuing a re-sign operation");

        // If a re-signing operation has already been enqueued, add to it.
        if let Some(resign) = &mut self.state.signer.enqueued_resign {
            resign.trigger |= trigger;
            return;
        }

        // Make sure a published instance exists.
        // Then, try to obtain a `SignedZoneBuilder` so building can begin.
        if self.state.instances.current.is_some()
            && let Some(builder) = self.zone().try_start_resign()
        {
            // A zone can have at most one 'SignedZoneBuilder' at a time.
            // Because we have 'builder', we are guaranteed that no other
            // signing operations are ongoing right now.

            assert!(self.state.signer.enqueued_new_sign.is_none());

            // Try to get a spot in the signing queue.
            match self
                .center
                .signer
                .queue
                .enqueue(self.zone.clone(), &builder)
            {
                Ok(permit) => {
                    // Start signing immediately.
                    self.start_op(builder, SigningTrigger::Resign(trigger), permit);
                }

                Err(pending) => {
                    // Give up and save the operation for later.
                    self.state.signer.enqueued_resign = Some(EnqueuedResign {
                        builder: Some(builder),
                        pending: Some(pending),
                        trigger,
                    });
                }
            }
        } else {
            // Give up and save the operation for later.
            self.state.signer.enqueued_resign = Some(EnqueuedResign {
                builder: None,
                pending: None,
                trigger,
            });
        }
    }

    /// Start a pending enqueued re-sign.
    ///
    /// This should be called when the zone state machine is in the waiting
    /// state and the zone is not in maintenance mode. If a re-sign has been
    /// enqueued, it will be initiated (making the data storage busy), and
    /// `true` will be returned.
    ///
    /// This method cannot initiate enqueued new-signing operations (see
    /// [`Self::enqueue_new_sign()`]); when a new-signing operation is enqueued,
    /// it includes a [`SignedZoneBuilder`], which prevents the zone state
    /// from being waiting.
    ///
    /// ## Panics
    ///
    /// Panics if the zone is not in the waiting state.
    pub fn start_pending(&mut self) -> bool {
        // An enqueued or ongoing signing operation holds a 'SignedZoneBuilder',
        // which prevents the zone data storage from being passive. This method
        // is only called if the zone data storage is in the passive state.
        assert!(self.state.signer.enqueued_new_sign.is_none());

        // Load the one enqueued re-sign operation, if it exists.
        let Some(EnqueuedResign {
            builder,
            pending,
            trigger,
        }) = self.state.signer.enqueued_resign.take()
        else {
            // A re-sign is not enqueued, nothing to do.
            return false;
        };

        // As mentioned above, 'SignedZoneBuilder' cannot exist when the zone
        // data storage is in the passive state.
        assert!(builder.is_none());
        assert!(
            pending.is_none(),
            "`pending` can only exist when `builder` exists"
        );

        // Since the zone data storage is passive, there is no upcoming instance
        // of the zone. If a published signed instance does not exist either,
        // there is nothing to re-sign, and we should just abandon the existing
        // re-signing operation.
        if self.state.instances.current.is_none() {
            debug!(
                ?trigger,
                "Dropping previously enqueued re-signing request; \
                there is no published or upcoming signed instance of the zone"
            );

            return false;
        }

        let builder = self
            .zone()
            .try_start_resign()
            .expect("the zone data storage is passive");

        // Add the zone to the signing queue.
        match self
            .center
            .signer
            .queue
            .enqueue(self.zone.clone(), &builder)
        {
            Ok(permit) => {
                // Start signing immediately.
                self.start_op(builder, SigningTrigger::Resign(trigger), permit);
            }
            Err(pending) => {
                // Save the pending operation back in state.
                self.state.signer.enqueued_resign = Some(EnqueuedResign {
                    builder: Some(builder),
                    pending: Some(pending),
                    trigger,
                });
            }
        }

        true
    }

    /// Accept a signing queue permit.
    ///
    /// ## Panics
    ///
    /// Panics if the zone does not have an enqueued signing operation.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn accept_queue_permit(&mut self, lock: &mut SigningQueueLock<'_>) {
        if let Some(op) = self.state.signer.enqueued_new_sign.take() {
            let EnqueuedSign { builder, pending } = op;
            let permit = self.center.signer.queue.accept(pending, lock);

            self.start_op(builder, SigningTrigger::Load, permit);
        } else if let Some(op) = self.state.signer.enqueued_resign.take() {
            let EnqueuedResign {
                builder,
                pending,
                trigger,
            } = op;

            let Some(pending) = pending else {
                panic!("The zone did not have an enqueued signing operation");
            };
            let Some(builder) = builder else {
                unreachable!("`pending` must only exist when `builder` exists");
            };
            let permit = self.center.signer.queue.accept(pending, lock);

            self.start_op(builder, SigningTrigger::Resign(trigger), permit);
        }
    }

    /// Cancel enqueued signing operations.
    pub fn cancel_enqueued_signing_operations(&mut self) {
        // NOTE: This method is called while a `{Loaded,Signed}ZoneRestorer` is
        // held, so `SignedZoneBuilder`s cannot exist.

        // An enqueued new-sign would have a `SignedZoneBuilder`, which cannot
        // exist at this stage.
        assert!(self.state.signer.enqueued_new_sign.is_none());

        if let Some(op) = self.state.signer.enqueued_resign.take() {
            // NOTE: Even if `op` exists, it should not contain a builder at
            // this stage, and `op.pending` only exists iff `op.builder` exists.
            assert!(op.builder.is_none());
            assert!(op.pending.is_none());
        }
    }

    /// Start a signing operation immediately.
    fn start_op(
        &mut self,
        builder: SignedZoneBuilder,
        trigger: SigningTrigger,
        permit: SigningPermit,
    ) {
        let status = Arc::new(RwLock::new(SigningStatusPerZone {
            current_action: "Initiating signing".into(),
            status: ZoneSigningStatus::new(),
        }));

        // The current logging span is nested fairly deep within the logic for
        // initiating signing operations, and does not really matter for the
        // actual signing function. Start with an empty logging context.
        let span = tracing::Span::none();
        self.state.signer.ongoing.spawn_blocking(span, {
            let center = self.center.clone();
            let zone = self.zone.clone();
            let status = status.clone();
            move || super::sign(center, zone, builder, trigger, permit, status)
        });
        self.state.signer.active_signing_status = Some(status);
    }
}

//----------- SignerState ------------------------------------------------------

/// State for signing a zone.
#[derive(Debug, Default)]
pub struct SignerState {
    /// Ongoing (re-)signing operations.
    pub ongoing: BackgroundTasks,

    /// An enqueued signing operation, if any.
    pub enqueued_new_sign: Option<EnqueuedSign>,

    /// An enqueued re-signing operation, if any.
    pub enqueued_resign: Option<EnqueuedResign>,

    /// When a zone is scheduled to be re-signed.
    ///
    /// If this is [`Some`], the zone is currently scheduled for re-signing, at
    /// the specified time.
    pub scheduled_resign_time: Option<SystemTime>,

    /// Status for an active signing operation, if any.
    //
    // TODO: Embed in a state machine.
    pub active_signing_status: Option<Arc<RwLock<SigningStatusPerZone>>>,
}

//----------- EnqueuedSign -----------------------------------------------------

/// An enqueued sign of a zone.
#[derive(Debug)]
pub struct EnqueuedSign {
    /// The zone builder.
    pub builder: SignedZoneBuilder,

    /// The zone's position in the signing queue.
    ///
    /// If the zone can be signed immediately (i.e. a [`SigningPermit`] is
    /// received instead of a [`SigningPending`]), it should be.
    pub pending: SigningPending,
}

//----------- EnqueuedResign ---------------------------------------------------

/// An enqueued re-sign of a zone.
#[derive(Debug)]
pub struct EnqueuedResign {
    /// The zone builder, if obtained.
    ///
    /// The builder is necessary to begin re-signing. It is optional because
    /// it might not be available when the re-sign operation is enqueued.
    /// Even if the builder is obtained, the operation might not be ready
    /// to start.
    pub builder: Option<SignedZoneBuilder>,

    /// The zone's position in the signing queue.
    ///
    /// This must be [`Some`] exactly when [`Self::builder`] is [`Some`]; that
    /// is, re-signing cannot be enqueued until a builder is available. If the
    /// zone can be re-signed immediately (i.e. a [`SigningPermit`] is received
    /// instead of a [`SigningPending`]), it should be.
    pub pending: Option<SigningPending>,

    /// The trigger causing this operation.
    pub trigger: ResigningTrigger,
    //
    // TODO:
    // - The ID of the signed instance to re-sign.
    //   Panic if the actual obtained instance does not match this.
}

//------------------------------------------------------------------------------

/// Compute when a zone should be re-signed.
///
/// Returns [`None`] if the zone does not need re-signing.
fn resign_time(state: &ZoneState) -> Option<SystemTime> {
    let policy = state.policy.as_ref()?;

    let last_refresh_time =
        SystemTime::UNIX_EPOCH + Duration::from(state.last_signature_refresh.clone());
    let refresh_interval = Duration::from_secs(policy.signer.signature_refresh_interval as u64);

    Some(last_refresh_time + refresh_interval)
}
