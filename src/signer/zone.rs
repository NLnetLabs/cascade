//! Zone-specific signing state.

use std::{sync::Arc, time::SystemTime};

use cascade_zonedata::SignedZoneBuilder;
use tracing::{debug, info};

use crate::{
    center::Center,
    signer::{ResigningTrigger, SigningTrigger},
    util::BackgroundTasks,
    zone::{Zone, ZoneHandle, ZoneState},
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
        // has lower priority than this (for now).

        assert!(self.state.signer.enqueued_new_sign.is_none());

        // TODO: Keep state for a queue of pending (re-)signing operations, so
        // that the number of simultaneous operations can be limited. At the
        // moment, this queue is opaque and is handled within the asynchronous
        // task.

        let span = tracing::Span::none();
        self.state.signer.ongoing.spawn(
            span,
            super::sign(
                self.center.clone(),
                self.zone.clone(),
                builder,
                SigningTrigger::Load,
            ),
        );
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
        // has not been signed. The re-signing request is ignored if no previous
        // signed instance of the zone seems to exist. Ideally, the key manager
        // would check the current signed instance of the zone itself, and check
        // that it really needs re-signing (i.e. that the signing keys used for
        // building that instance are different from the latest ones).
        //
        // TODO: Explicitly track whether a signed instance exists. Maybe the
        // zone data storage can report it via a method on 'PassiveStorage'? Or
        // track instances of zones more explicitly in 'ZoneState' (the latter
        // will happen / has happened when integrating the zone server with the
        // zone data storage).
        if self
            .state
            .next_min_expiration
            .or(self.state.min_expiration)
            .is_none()
            && trigger == ResigningTrigger::KEYS_CHANGED
        {
            debug!("Ignoring re-signing request; the zone has not been signed yet");
            return;
        }

        info!("Enqueuing a re-sign operation");

        // If a re-signing operation has already been enqueued, add to it.
        if let Some(resign) = &mut self.state.signer.enqueued_resign {
            resign.trigger |= trigger;
            return;
        }

        // Try to obtain a 'SignedZoneBuilder' so building can begin.
        let builder = self.zone().storage().start_resign();

        // TODO: Keep state for a queue of pending (re-)signing operations, so
        // that the number of simultaneous operations can be limited. At the
        // moment, this queue is opaque and is handled within the asynchronous
        // task.

        // Try to initiate the re-sign immediately.
        if let Some(builder) = builder {
            // A zone can have at most one 'SignedZoneBuilder' at a time.
            // Because we have 'builder', we are guaranteed that no other
            // signing operations are ongoing right now.

            assert!(self.state.signer.enqueued_new_sign.is_none());

            let span = tracing::Span::none();
            self.state.signer.ongoing.spawn(
                span,
                super::sign(
                    self.center.clone(),
                    self.zone.clone(),
                    builder,
                    SigningTrigger::Resign(trigger),
                ),
            );
        } else {
            // TODO: Track expiration time in 'SignerState'.
            let expiration_time = self
                .state
                .next_min_expiration
                .or(self.state.min_expiration)
                .unwrap_or_else(|| panic!("re-sign enqueued but the zone has not been signed"))
                .to_system_time(SystemTime::now());

            self.state.signer.enqueued_resign = Some(EnqueuedResign {
                builder: None,
                trigger,
                expiration_time,
            });
        }
    }

    /// Start a pending enqueued re-sign.
    ///
    /// This should be called when the zone data storage is in the passive
    /// state. If a re-sign has been enqueued, it will be initiated (making the
    /// data storage busy), and `true` will be returned.
    ///
    /// This method cannot initiate enqueued new-signing operations (see
    /// [`Self::enqueue_new_sign()`]); when a new-signing operation is enqueued,
    /// it includes a [`SignedZoneBuilder`], which prevents the data storage
    /// from being passive.
    ///
    /// ## Panics
    ///
    /// Panics if the data storage is not in the passive state.
    pub fn start_pending(&mut self) -> bool {
        // An enqueued or ongoing signing operation holds a 'SignedZoneBuilder',
        // which prevents the zone data storage from being passive. This method
        // is only called if the zone data storage is in the passive state.
        assert!(self.state.signer.enqueued_new_sign.is_none());

        // Load the one enqueued re-sign operation, if it exists.
        let Some(EnqueuedResign {
            builder,
            trigger,
            expiration_time: _, // TODO
        }) = self.state.signer.enqueued_resign.take()
        else {
            // A re-sign is not enqueued, nothing to do.
            return false;
        };

        // As mentioned above, 'SignedZoneBuilder' cannot exist when the zone
        // data storage is in the passive state.
        assert!(builder.is_none());

        let builder = self
            .zone()
            .storage()
            .start_resign()
            .expect("the zone data storage is passive");

        // TODO: Once an explicit queue of signing operations has been
        // implemented (for limiting the number of simultaneous operations),
        // add the operation to the queue before starting the re-sign. If the
        // queue is too full to start the operation yet, leave it enqueued.

        let span = tracing::Span::none();
        self.state.signer.ongoing.spawn(
            span,
            super::sign(
                self.center.clone(),
                self.zone.clone(),
                builder,
                SigningTrigger::Resign(trigger),
            ),
        );

        true
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
}

//----------- EnqueuedSign -----------------------------------------------------

/// An enqueued sign of a zone.
#[derive(Debug)]
pub struct EnqueuedSign {
    /// The zone builder.
    pub builder: SignedZoneBuilder,
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

    /// The trigger causing this operation.
    pub trigger: ResigningTrigger,

    /// When signatures in the zone will expire.
    ///
    /// `self` represents an enqueued re-sign, which means that a current signed
    /// instance of the zone exists. This field tracks the expiration time (not
    /// the time to enqueue re-signing) for that instance, to ensure it will be
    /// re-signed in time.
    //
    // TODO: Force loading to cancel if this gets too close?
    pub expiration_time: SystemTime,
    //
    // TODO:
    // - The ID of the signed instance to re-sign.
    //   Panic if the actual obtained instance does not match this.
}
