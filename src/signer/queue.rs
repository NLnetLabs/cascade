//! Enqueueing zones for (re-)signing.
//
// TODO: Is there some way to unit-test this code? This is difficult because it
// interacts with `ZoneState` directly.

use core::fmt;
use std::{
    collections::VecDeque,
    mem::ManuallyDrop,
    num::NonZeroUsize,
    sync::{Arc, Mutex, PoisonError},
};

use cascade_zonedata::SignedZoneBuilder;
use tracing::{debug, trace};

use crate::{center::Center, util::FmtBy, zone::Zone};

//----------- SigningQueue -----------------------------------------------------

/// A queue of zones pending signing.
///
/// This is a thread-safe queue of zones which need to be (re-)signed but are
/// waiting due to a limit on the number of concurrent signing operations. This
/// queue enforces that limit and initiates signing for zones once capacity is
/// available.
pub struct SigningQueue {
    /// The maximum number of concurrent operations to allow.
    concurrency_limit: NonZeroUsize,

    /// The underlying queue of zones.
    ///
    /// The first `concurrency_limit` elements of this queue are undergoing
    /// signing (or signing will be initiated for them shortly). The remainder
    /// wait for the earlier ones to finish.
    ///
    /// Duplicates of the same zone must not be present.
    zones: Mutex<VecDeque<Arc<Zone>>>,
}

/// A lock on the [`SigningQueue`].
///
/// This is sometimes passed around explicitly to prevent deadlocks.
pub struct SigningQueueLock<'a> {
    /// The underlying queue.
    zones: &'a mut VecDeque<Arc<Zone>>,
}

impl SigningQueue {
    /// Construct a new [`SigningQueue`].
    #[must_use]
    pub fn new(concurrency_limit: NonZeroUsize) -> Self {
        Self {
            concurrency_limit,
            zones: Mutex::new(VecDeque::new()),
        }
    }

    /// Enqueue signing for a zone.
    ///
    /// If the queue has capacity, a [`SigningPermit`] is returned immediately.
    /// Otherwise, the zone is enqueued and it must wait until capacity is
    /// available; once capacity is available, the returned [`SigningPending`]
    /// can be traded for a [`SigningPermit`]. A [`SignedZoneBuilder`] is taken
    /// as proof that the caller intends to perform signing.
    ///
    /// ## Panics
    ///
    /// May cause panics (indirectly) if the same zone is enqueued twice. Make
    /// sure to return the [`SigningPermit`] for a zone from any previous
    /// signing operation before enqueueing the same zone again.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %zone.name),
    )]
    pub fn enqueue(
        &self,
        zone: Arc<Zone>,
        _builder: &SignedZoneBuilder,
    ) -> Result<SigningPermit, SigningPending> {
        trace!("Enqueueing for signing");
        let mut zones = self.zones.lock().unwrap_or_else(handle_poison);

        zones.push_back(zone.clone());

        if zones.len() <= self.concurrency_limit.get() {
            // The inserted zone fits within the concurrency limit.

            trace!("Within concurrency limit, offering permit now");

            Ok(SigningPermit {
                zone,
                _assertion: (),
            })
        } else {
            debug!(
                "Zone '{}' is ready to be signed, but is waiting for other zones to finish first.",
                zone.name
            );

            Err(SigningPending {
                zone,
                _assertion: (),
            })
        }
    }

    /// Abandon a [`SigningPending`].
    ///
    /// A pending permit may need to be abandoned if a re-signing operation is
    /// canceled. If this is called when the zone would have received a permit,
    /// the permit will be passed on to the next zone in the queue.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %pending.zone.name),
    )]
    pub fn abandon(&self, pending: SigningPending, center: &Arc<Center>) {
        trace!("Abandoning the position in the signing queue");
        let mut zones = self.zones.lock().unwrap_or_else(handle_poison);

        // Consume the token.
        let zone = pending.consume();

        // Locate this zone in the queue and remove it.
        let Some(pos) = zones.iter().position(|z| Arc::ptr_eq(z, &zone)) else {
            unreachable!(
                "Zone '{}' has a permit but is not present in the signing queue",
                zone.name
            )
        };
        let _ = zones.remove(pos);
        let finished_zone = zone;

        // If the zone was within signing capacity, try activating a new zone.
        if pos >= self.concurrency_limit.get() {
            return;
        }

        trace!("The zone was within signing capacity");
        let mut lock = SigningQueueLock { zones: &mut zones };
        self.initiate_resigning(&finished_zone, &mut lock, center);
    }

    /// Accept a signing permit.
    ///
    /// A [`SigningPending`] is exchanged for a [`SigningPermit`] following a
    /// check that the zone is now within signing capacity.
    ///
    /// ## Panics
    ///
    /// Panics if the zone is not within signing capacity.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %pending.zone.name),
    )]
    pub fn accept(
        &self,
        pending: SigningPending,
        lock: &mut SigningQueueLock<'_>,
    ) -> SigningPermit {
        trace!("Exchanging a pending token for a permit");
        let zones = &mut *lock.zones;

        // Consume the token.
        let zone = pending.consume();

        // Ensure the zone is within the signing capacity.
        let pos = zones.iter().position(|z| Arc::ptr_eq(z, &zone));
        let pos = pos.unwrap_or_else(|| {
            panic!(
                "Zone '{}' has a `SigningPending` but could not be found in the signing queue",
                zone.name
            )
        });
        assert!(
            pos < self.concurrency_limit.get(),
            "Zone '{}' is not within the signing capacity (position {pos}, limit {})",
            zone.name,
            self.concurrency_limit.get()
        );

        // We have validated the zone is now within signing capacity.
        SigningPermit {
            zone,
            _assertion: (),
        }
    }

    /// Finish using a signing permit.
    ///
    /// This must be called for every [`SigningPermit`] provided once the
    /// associated signing operation is complete. It initiates re-signing for
    /// the next zone in the queue.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %permit.zone.name),
    )]
    pub fn finish(&self, permit: SigningPermit, center: &Arc<Center>) {
        trace!("Finishing using a permit");
        let mut zones = self.zones.lock().unwrap_or_else(handle_poison);

        // Consume the permit.
        let zone = permit.consume();

        // Locate this zone in the queue and remove it.
        let Some(pos) = zones.iter().position(|z| Arc::ptr_eq(z, &zone)) else {
            unreachable!(
                "Zone '{}' has a permit but is not present in the signing queue",
                zone.name
            )
        };
        let _ = zones.remove(pos);
        let finished_zone = zone;

        // Initiate re-signing for a zone that now fits within capacity.
        let mut lock = SigningQueueLock { zones: &mut zones };
        self.initiate_resigning(&finished_zone, &mut lock, center);
    }

    /// Initiate re-signing due to the freeing up of signing capacity.
    fn initiate_resigning(
        &self,
        finished_zone: &Arc<Zone>,
        lock: &mut SigningQueueLock<'_>,
        center: &Arc<Center>,
    ) {
        // Look for a zone that now fits within capacity.
        if let Some(zone) = lock.zones.get(self.concurrency_limit.get() - 1) {
            // Make sure 'finished_zone' doesn't appear again, otherwise we
            // might cause a deadlock!
            assert!(
                !Arc::ptr_eq(zone, finished_zone),
                "Zone '{}' appeared twice in the signing queue",
                finished_zone.name
            );

            // Try initiating the zone's signing operation.

            trace!("Passing on the queue permit to '{}'", zone.name);

            // NOTE: We lock `zone` and then tell it to obtain a permit. It
            // will call `SigningQueue::accept()` to do so. This could easily
            // lead to a deadlock --- this is why we explicitly pass `lock` and
            // make `accept()` consume `lock`.
            zone.clone()
                .write_handle(center)
                .signer()
                .accept_queue_permit(lock);
        }
    }
}

impl fmt::Debug for SigningQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let concurrency_limit = self.concurrency_limit.get();
        let zones = self.zones.lock().unwrap_or_else(handle_poison);
        let zones = &*zones;
        let active = zones.iter().take(concurrency_limit);
        let pending = zones.iter().skip(concurrency_limit);
        f.debug_struct("SigningQueue")
            .field("concurrency_limit", &concurrency_limit)
            .field(
                "active",
                &FmtBy(|f| f.debug_list().entries(active.clone()).finish()),
            )
            .field(
                "pending",
                &FmtBy(|f| f.debug_list().entries(pending.clone()).finish()),
            )
            .finish()
    }
}

//----------- SigningPermit ----------------------------------------------------

/// A permit from the signing queue.
///
/// This token asserts that the caller is allowed to initiate signing. It is
/// provided by the [`SigningQueue`] and must be returned to it when signing
/// completes.
#[must_use = "Return this permit to `SigningQueue::finish()`"]
pub struct SigningPermit {
    /// The zone associated with this permit.
    ///
    /// This is used to find the zone's entry in the signing queue.
    zone: Arc<Zone>,

    /// The underlying assertion, local to this module.
    _assertion: (),
}

impl SigningPermit {
    /// Consume a [`SigningPermit`], returning the underlying zone.
    ///
    /// This is a module-local function, asserting that the permit is finished.
    fn consume(self) -> Arc<Zone> {
        // NOTE: Rust (currently?) disallows moving out of `self` because of the
        // `Drop` impl. Clone `zone` out while preventing the drop hook (which
        // tries to panic) from running.
        ManuallyDrop::new(self).zone.clone()
    }
}

impl Drop for SigningPermit {
    /// Panic because [`SigningPermit`] should not be dropped.
    fn drop(&mut self) {
        panic!("Dropped {self:?}")
    }
}

impl fmt::Debug for SigningPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Write a single line for brevity, even for `{#?}`.
        write!(f, "SigningPermit {{ zone: \"{}\" }}", self.zone.name)
    }
}

//----------- SigningPending ---------------------------------------------------

/// Proof a zone is waiting in the [`SigningQueue`].
///
/// This token asserts that the caller is in the [`SigningQueue`] and is waiting
/// for signing capacity. It is provided by the [`SigningQueue`] and must be
/// returned to it in exchange for a [`SigningPermit`].
#[must_use = "Call `SigningQueue::abandon()` instead of dropping"]
pub struct SigningPending {
    /// The zone associated with this permit.
    ///
    /// This is used to find the zone's entry in the signing queue.
    zone: Arc<Zone>,

    /// The underlying assertion, local to this module.
    _assertion: (),
}

impl SigningPending {
    /// Consume a [`SigningPending`], returning the underlying zone.
    ///
    /// This is a module-local function, asserting that the permit is finished.
    fn consume(self) -> Arc<Zone> {
        // NOTE: Rust (currently?) disallows moving out of `self` because of the
        // `Drop` impl. Clone `zone` out while preventing the drop hook (which
        // tries to panic) from running.
        ManuallyDrop::new(self).zone.clone()
    }
}

impl Drop for SigningPending {
    /// Panic because [`SigningPending`] should not be dropped.
    fn drop(&mut self) {
        panic!("Dropped {self:?}")
    }
}

impl fmt::Debug for SigningPending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Write a single line for brevity, even for `{#?}`.
        write!(f, "SigningPending {{ zone: \"{}\" }}", self.zone.name)
    }
}

//------------------------------------------------------------------------------

/// Handle a lock poisoning failure.
//
// TODO: Return '!'.
#[track_caller]
fn handle_poison<T, R>(_: PoisonError<T>) -> R {
    panic!("The zone signing queue is poisoned because a panic occurred elsewhere")
}
