use tracing::{info, trace};

use crate::{
    api::ZoneReviewStatus,
    server::PublicationServer,
    units::zone_signer::SignerError,
    zone::{HistoricalEvent, ZoneHandle},
    zonedata::{
        LoadedZoneBuilder, LoadedZoneBuilt, LoadedZonePersisted, SignedZoneBuilder,
        SignedZoneBuilt, SignedZonePersisted,
    },
};

/// State machine for a particular zone
///
/// It contains 5 consecutive "happy path" states:
///
/// 1. `Waiting`
/// 2. `Loading`
/// 3. `LoaderReview`
/// 4. `Signing`
/// 5. `SignerReview`
///
/// We can go from `Waiting` to `Loading` when we start a load and from `Waiting`
/// to `Signing` when starting a resign.
///
/// Then there are 3 halting states:
///
/// 1. `RejectLoaded`
/// 2. `SigningFailure`
/// 3. `RejectSigned`
///
/// If the pipeline is ever in one of these states, it can be `reset` to the
/// `Waiting` state. The `Reject` states are reached on a hard reject of a
/// loaded or a signed zone. The rejection can then be overridden to continue
/// the pipeline anyway. `SigningFailure` cannot be overridden but only `reset`.
///
/// Here is the diagram for it:
//
// TODO: There is an additional transition from 'Signing' to 'Waiting', in case
// signing is abandoned (e.g. incremental signing turns out to be a no-op).
///
/// ```text
/// ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
/// │                                                       Waiting                                                        │
/// └─▲────────╥────────▲─────────────────▲──────────────────────────╥──────────────────────────▲────────────────────────▲─┘
///   │        ║        │                 │                          ║                          │                        ║  
///   │        ║ load   │ fail            │ soft reject              ║ resign                   │ soft reject            ║  
///   │        ║        │ abandon         │                          ║                          │                        ║  
///   │     ╔══▼════════╧════╗ review  ╔══╧═════════════╗ approve ╔══▼═════════════╗ review  ╔══╧═════════════╗ approve  ║  
///   │     ║    Loading     ╠═════════▶  LoaderReview  ╠═════════▶    Signing     ╠═════════▶  SignerReview  ╠══════════▲  
///   │     ╚════════════════╝         ╚══╤═════════════╝         ╚▲═╤═════════▲═══╝         ╚══╤═════════════╝          │  
///   │                                   │                        │ │         │                │                        │  
///   │                                   │ hard reject   override │ │ fail    │ retry          │     hard reject        │  
///   │                                   │            ┌───────────┘ │         │                │                        │  
///   │                                ┌──▼────────────┴┐         ┌──▼─────────┴───┐         ┌──▼─────────────┐ override │  
///   │                                │  RejectLoaded  │         │ SigningFailure │         │  RejectSigned  ├──────────┘  
///   │                                └──┬─────────────┘         └──┬─────────────┘         └──┬─────────────┘             
///   │                                   │                          │                          │                           
///   │                                   │ reset                    │ reset                    │ reset                     
///   │                                   │                          │                          │                           
///   └───────────────────────────────────▼──────────────────────────▼──────────────────────────▼                           
/// ```
#[derive(Debug)]
pub enum ZoneStateMachine {
    Waiting(Waiting),
    Loading(Loading),
    LoadedReview(LoadedReview),
    HaltLoaded(HaltLoaded),
    PersistingLoaded(PersistingLoaded),
    Signing(Signing),
    SigningFailed(SigningFailed),
    SignedReview(SignedReview),
    HaltSigned(HaltSigned),
    PersistingSigned(PersistingSigned),

    /// A value to leave the state in when we take it by value.
    ///
    /// To do transitions, we take ownership of the data in this enum. We do
    /// this by replacing it with a `Poisoned` value. We then do the transition
    /// and replace the `Poisoned` value with the new state. Therefore, if we
    /// ever find the state machine in a poisoned state when we want to do a
    /// transition, we should just panic because something has gone wrong.
    Poisoned,
}

impl ZoneStateMachine {
    pub fn is_halted(&self) -> bool {
        matches!(
            self,
            Self::HaltLoaded(_) | Self::HaltSigned(_) | Self::SigningFailed(_)
        )
    }

    pub fn display_halted_reason(&self) -> Option<String> {
        let s = match self {
            Self::HaltLoaded(_) => "loaded zone was rejected".into(),
            Self::HaltSigned(_) => "signed zone was rejected".into(),
            Self::SigningFailed(SigningFailed { err }) => format!("signing the zone failed: {err}"),
            _ => return None,
        };
        Some(s)
    }
}

/// # Initiating operations
impl<'a> ZoneHandle<'a> {
    pub(crate) fn try_start_load(&mut self) -> Option<LoadedZoneBuilder> {
        // If we're in maintenance mode, then we don't start this operation.
        // TODO: distinguish between a manual load and an automatic one.
        if self.state.maintenance_mode {
            return None;
        }

        let ZoneStateMachine::Waiting(_) = &self.state.machine else {
            info!("Could not start load since an operation is in progress on the zone.");
            return None;
        };

        // The zone state machine may be in the waiting state, but the storage
        // might still be persisting or cleaning the zone, and we shouldn't
        // start a new operation if that's the case.
        let Some(builder) = self.storage().start_load() else {
            info!("Could not start load since an operation is in progress on the zone.");
            return None;
        };

        let (transition, state) = self.state.machine.transition();
        let ZoneStateMachine::Waiting(waiting) = state else {
            unreachable!("already checked that the state machine is `Waiting`")
        };

        transition.move_to(ZoneStateMachine::Loading(waiting.start_load()));

        self.state.instances.start_load();

        self.state.record_event(HistoricalEvent::StartedLoad, None);

        Some(builder)
    }

    pub(crate) fn try_start_resign(&mut self) -> Option<SignedZoneBuilder> {
        // If we're in maintenance mode, then we don't start this operation.
        // TODO: distinguish between a manual resign and an automatic one.
        if self.state.maintenance_mode {
            return None;
        }

        let ZoneStateMachine::Waiting(_) = &self.state.machine else {
            info!("Could not start load since an operation is in progress on the zone.");
            return None;
        };

        // The zone state machine may be in the waiting state, but the storage
        // might still be persisting or cleaning the zone, and we shouldn't
        // start a new operation if that's the case.
        let Some(builder) = self.storage().start_resign() else {
            info!("Could not start resign since an operation is in progress on the zone.");
            return None;
        };

        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::Waiting(waiting) = state else {
            panic!(
                "The storage was in the passive state but the state machine wasn't in the waiting state"
            );
        };

        transition.move_to(ZoneStateMachine::Signing(waiting.start_resign()));

        self.state.instances.start_resign();

        self.state
            .record_event(HistoricalEvent::StartedResign, None);

        Some(builder)
    }
}

/// # Loading operations
impl<'a> ZoneHandle<'a> {
    pub(crate) fn abandon_load(&mut self, builder: LoadedZoneBuilder) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::Loading(loaded) = state else {
            panic!("cannot abandon load in this state");
        };

        transition.move_to(ZoneStateMachine::Waiting(loaded.abandon_load()));

        self.storage().abandon_load(builder);

        // Abandon the entire upcoming instance.
        self.state.instances.abandon();
    }

    pub(crate) fn finish_load(&mut self, built: LoadedZoneBuilt) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::Loading(loaded) = state else {
            panic!("cannot start loader review in this state");
        };

        transition.move_to(ZoneStateMachine::LoadedReview(loaded.finish_load()));

        let soa = built.next().unwrap().soa();
        let serial = soa.rdata.serial;

        self.state.instances.finish_load(&built);

        let loaded_reviewer = self.storage().finish_load(built);

        // TODO: Use the instance ID here.
        self.state.record_event(
            HistoricalEvent::NewVersionReceived,
            Some(domain::base::Serial(serial.into())),
        );

        self.storage().start_loaded_review(loaded_reviewer);
    }
}

/// # Loaded Review operations
impl<'a> ZoneHandle<'a> {
    /// Approve the loaded instance currently under review.
    pub(crate) fn approve_loaded(&mut self) {
        info!("The loaded instance has been approved");

        self.state.record_event(
            HistoricalEvent::UnsignedZoneReview {
                status: ZoneReviewStatus::Approved,
            },
            None, // TODO
        );

        let (transition, state) = self.state.machine.transition();
        let ZoneStateMachine::LoadedReview(loaded) = state else {
            panic!("cannot approve loaded in this state");
        };
        transition.move_to(ZoneStateMachine::PersistingLoaded(loaded.approve()));

        // We move to the signing state and start persisting. The actual signing
        // will be triggered by the zone storage when persisting is done.
        let persister = self.storage().accept_loaded();
        self.persistence().start_loaded_persistence(persister);
    }

    pub(crate) fn soft_reject_loaded(&mut self) {
        self.state.record_event(
            HistoricalEvent::UnsignedZoneReview {
                status: ZoneReviewStatus::Rejected,
            },
            None, // TODO
        );

        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::LoadedReview(loaded) = state else {
            panic!("cannot soft reject loaded in this state");
        };

        transition.move_to(ZoneStateMachine::Waiting(loaded.soft_reject()));
        let loaded_reviewer = self.storage().abandon_loaded_review();
        // Abandon the entire upcoming instance.
        self.state.instances.abandon();
        // Stop serving the abandoned instance.
        self.storage()
            .start_rewinding_loaded_review(loaded_reviewer);
    }

    pub(crate) fn hard_reject_loaded(&mut self) {
        self.state.record_event(
            HistoricalEvent::UnsignedZoneReview {
                status: ZoneReviewStatus::Rejected,
            },
            None, // TODO
        );

        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::LoadedReview(loaded) = state else {
            panic!("cannot hard reject loaded in this state");
        };

        transition.move_to(ZoneStateMachine::HaltLoaded(loaded.hard_reject()));
    }
}

/// # Signing operations
impl<'a> ZoneHandle<'a> {
    /// Begin signing a new approved and persisted loaded instance.
    pub(crate) fn start_new_sign(&mut self, persisted: LoadedZonePersisted) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::PersistingLoaded(persisting) = state else {
            panic!("cannot start signing in this state");
        };

        transition.move_to(ZoneStateMachine::Signing(persisting.done()));

        let builder = self.storage().start_new_sign(persisted);
        self.signer().enqueue_new_sign(builder);
    }

    pub(crate) fn finish_signing(&mut self, built: SignedZoneBuilt) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::Signing(signing) = state else {
            panic!("cannot start signed review in this state");
        };

        transition.move_to(ZoneStateMachine::SignedReview(signing.finish_signing()));

        self.state.instances.finish_sign(&built);

        let signed_reviewer = self.storage().finish_sign(built);
        // Begin reviewing the prepared instance.
        self.storage().start_signed_review(signed_reviewer);
    }

    /// Abandon the ongoing signing operation (but not due to failure).
    pub(crate) fn abandon_signing(&mut self, builder: SignedZoneBuilder) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::Signing(signing) = state else {
            unreachable!(
                "'ZoneStateMachine::Signing' is the only state where a 'SignedZoneBuilder' is available"
            );
        };

        transition.move_to(ZoneStateMachine::Waiting(signing.abandon()));

        let loaded_reviewer = self.storage().abandon_sign(builder);
        // Abandon the entire upcoming instance.
        self.state.instances.abandon();
        // Stop serving the abandoned instance.
        self.storage()
            .start_rewinding_loaded_review(loaded_reviewer);
    }

    pub(crate) fn signing_failed(&mut self, builder: SignedZoneBuilder, err: SignerError) {
        self.signer().before_signed_abandonment();

        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::Signing(signing) = state else {
            panic!("cannot fail signing in this state");
        };

        transition.move_to(ZoneStateMachine::SigningFailed(signing.signing_failed(err)));

        let loaded_reviewer = self.storage().abandon_sign(builder);
        // Abandon the entire upcoming instance.
        self.state.instances.abandon();
        // Stop serving the abandoned instance.
        self.storage()
            .start_rewinding_loaded_review(loaded_reviewer);
    }
}

/// # Signed Review operations
impl<'a> ZoneHandle<'a> {
    pub(crate) fn approve_signed(&mut self) {
        info!("The signed instance has been approved; publishing");

        self.state.record_event(
            HistoricalEvent::SignedZoneReview {
                status: ZoneReviewStatus::Approved,
            },
            None, // TODO
        );

        // Move to the 'Waiting' state.
        let (transition, state) = self.state.machine.transition();
        let ZoneStateMachine::SignedReview(signed) = state else {
            panic!("The zone must be in signer review")
        };
        transition.move_to(ZoneStateMachine::PersistingSigned(signed.approve()));

        // Persist the signed instance while we are already in the Waiting state.
        // The state machine will only start a new operation when the zone storage
        // is ready, so this is safe to do.
        let persister = self.storage().accept_signed();
        self.persistence().start_signed_persistence(persister);
    }

    pub(crate) fn soft_reject_signed(&mut self) {
        self.state.record_event(
            HistoricalEvent::SignedZoneReview {
                status: ZoneReviewStatus::Rejected,
            },
            None, // TODO
        );

        self.signer().before_signed_abandonment();

        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::SignedReview(signed) = state else {
            panic!("cannot soft reject signed in this state");
        };

        transition.move_to(ZoneStateMachine::Waiting(signed.soft_reject()));

        let (loaded_reviewer, signed_reviewer) = self.storage().abandon_signed_review();

        // Abandon the entire upcoming instance.
        self.state.instances.abandon();
        // TODO: This should be handled by 'Instances'.
        self.state.next_min_expiration = None;

        self.storage()
            .start_rewinding_review(loaded_reviewer, signed_reviewer);
    }

    pub(crate) fn hard_reject_signed(&mut self) {
        self.state.record_event(
            HistoricalEvent::SignedZoneReview {
                status: ZoneReviewStatus::Rejected,
            },
            None, // TODO
        );

        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::SignedReview(review) = state else {
            panic!("cannot hard reject signed in this state");
        };

        transition.move_to(ZoneStateMachine::HaltSigned(review.hard_reject()));

        // Abandon the entire upcoming instance.
        self.state.instances.abandon();
    }
}

/// # Switching operations
impl<'a> ZoneHandle<'a> {
    /// Finish persisting an approved signed instance.
    pub(crate) fn finish_signed_persistence(&mut self, persisted: SignedZonePersisted) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::PersistingSigned(persisting) = state else {
            panic!("cannot start publishing in this state");
        };

        transition.move_to(ZoneStateMachine::Waiting(persisting.done()));

        let viewer = self.storage().finish_signed_persistence(persisted);

        self.state.instances.switch();
        // TODO: Handle this with `Instances`.
        self.state.min_expiration = self.state.next_min_expiration;
        self.state.next_min_expiration = None;

        let serial = self
            .state
            .instances
            .current
            .as_ref()
            .unwrap()
            .signed
            .serial();

        info!(
            "Published a signed instance of '{}' with SOA serial {}",
            self.zone.name,
            serial.get()
        );

        self.signer().on_publication();

        self.storage().start_publishing(viewer);

        PublicationServer::after_publication(self);
    }
}

/// # Halted operations
impl<'a> ZoneHandle<'a> {
    pub(crate) fn try_reset(&mut self) -> Result<(), ()> {
        let (transition, state) = self.state.machine.transition();

        match state {
            ZoneStateMachine::HaltLoaded(halt_loaded) => {
                let waiting = halt_loaded.reset();
                transition.move_to(ZoneStateMachine::Waiting(waiting));
                let loaded_reviewer = self.storage().abandon_loaded_review();
                self.state.instances.abandon();
                self.storage()
                    .start_rewinding_loaded_review(loaded_reviewer);
            }
            ZoneStateMachine::HaltSigned(halt_signed) => {
                let waiting = halt_signed.reset();
                transition.move_to(ZoneStateMachine::Waiting(waiting));

                self.signer().before_signed_abandonment();
                self.state.instances.abandon();
                // TODO: This should be handled by 'Instances'.
                self.state.next_min_expiration = None;

                let (loaded_reviewer, signed_reviewer) = self.storage().abandon_signed_review();
                self.storage()
                    .start_rewinding_review(loaded_reviewer, signed_reviewer);
            }
            ZoneStateMachine::SigningFailed(signing_failed) => {
                let waiting = signing_failed.reset();
                transition.move_to(ZoneStateMachine::Waiting(waiting));

                // TODO: This should be handled by 'Instances'.
                self.state.next_min_expiration = None;

                self.state.instances.abandon();

                // The signing operation has already been abandoned, so the zone
                // data storage is already passive. Its call to `on_passive()`
                // was ignored because the zone state machine was busy at the
                // time. Call it again now.
                self.storage().on_passive();
            }
            _ => {
                transition.move_to(state);
                return Err(());
            }
        }

        Ok(())
    }
}

/// # Halt Loaded operations
impl<'a> ZoneHandle<'a> {
    pub(crate) fn try_override_loaded_reject(&mut self) -> Result<(), ()> {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::HaltLoaded(halt) = state else {
            transition.move_to(state);
            return Err(());
        };

        transition.move_to(ZoneStateMachine::PersistingLoaded(
            halt.override_rejection(),
        ));

        // We move to the signing state and start persisting. The actual signing
        // will be triggered by the zone storage when persisting is done.
        let persister = self.storage().accept_loaded();
        self.persistence().start_loaded_persistence(persister);

        Ok(())
    }
}

/// # Halt Signed operations
impl<'a> ZoneHandle<'a> {
    pub(crate) fn try_override_signed_reject(&mut self) -> Result<(), ()> {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::HaltSigned(halt_signed) = state else {
            transition.move_to(state);
            return Err(());
        };

        transition.move_to(ZoneStateMachine::PersistingSigned(
            halt_signed.override_rejection(),
        ));

        // Persist the signed instance while we are already in the Waiting state.
        // The state machine will only start a new operation when the zone storage
        // is ready, so this is safe to do.
        let persister = self.storage().accept_signed();
        self.persistence().start_signed_persistence(persister);

        Ok(())
    }
}

impl ZoneStateMachine {
    fn transition(&mut self) -> (Transition<'_>, Self) {
        let state = self.take();
        (
            Transition {
                machine: self,
                previous: state.as_str(),
            },
            state,
        )
    }

    fn take(&mut self) -> Self {
        core::mem::replace(self, Self::Poisoned)
    }

    fn as_str(&self) -> &'static str {
        match self {
            ZoneStateMachine::Waiting(_) => "waiting",
            ZoneStateMachine::Loading(_) => "loading",
            ZoneStateMachine::LoadedReview(_) => "loaded review",
            ZoneStateMachine::HaltLoaded(_) => "halt loaded",
            ZoneStateMachine::PersistingLoaded(_) => "persisting loaded",
            ZoneStateMachine::Signing(_) => "signing",
            ZoneStateMachine::SigningFailed(_) => "signing failed",
            ZoneStateMachine::SignedReview(_) => "signed review",
            ZoneStateMachine::HaltSigned(_) => "halt signed",
            ZoneStateMachine::PersistingSigned(_) => "persisting signed",
            ZoneStateMachine::Poisoned => "poisoned",
        }
    }
}

impl Default for ZoneStateMachine {
    fn default() -> Self {
        Self::Waiting(Waiting::default())
    }
}

struct Transition<'a> {
    /// The zone state machine
    machine: &'a mut ZoneStateMachine,

    /// The previous state
    previous: &'static str,
}

impl Transition<'_> {
    /// Complete the transition, moving to the specified state.
    fn move_to(self, state: ZoneStateMachine) {
        trace!(old = %self.previous, new = %state.as_str(), "Transitioning");
        *self.machine = state;
        std::mem::forget(self);
    }
}

impl Drop for Transition<'_> {
    fn drop(&mut self) {
        panic!("a 'ZoneStateMachine' transition failed");
    }
}

#[derive(Debug, Default)]
pub struct Waiting {}

impl Waiting {
    fn start_load(self) -> Loading {
        Loading {}
    }

    // fn start_sign_after_restore(self) -> Signing {
    //     Signing {}
    // }

    fn start_resign(self) -> Signing {
        Signing {}
    }
}

#[derive(Debug)]
pub struct Loading {}

impl Loading {
    fn finish_load(self) -> LoadedReview {
        LoadedReview {}
    }

    fn abandon_load(self) -> Waiting {
        Waiting {}
    }
}

#[derive(Debug)]
pub struct LoadedReview {}

impl LoadedReview {
    fn approve(self) -> PersistingLoaded {
        PersistingLoaded {}
    }

    fn soft_reject(self) -> Waiting {
        Waiting {}
    }

    fn hard_reject(self) -> HaltLoaded {
        HaltLoaded {}
    }
}

#[derive(Debug)]
pub struct HaltLoaded {}

impl HaltLoaded {
    fn override_rejection(self) -> PersistingLoaded {
        PersistingLoaded {}
    }

    fn reset(self) -> Waiting {
        Waiting {}
    }
}

#[derive(Debug)]
pub struct PersistingLoaded {}

impl PersistingLoaded {
    fn done(self) -> Signing {
        Signing {}
    }
}

#[derive(Debug)]
pub struct Signing {}

impl Signing {
    fn finish_signing(self) -> SignedReview {
        SignedReview {}
    }

    /// Abandon the signing operation (but not due to failure).
    fn abandon(self) -> Waiting {
        Waiting {}
    }

    fn signing_failed(self, err: SignerError) -> SigningFailed {
        SigningFailed { err }
    }
}

#[derive(Debug)]
pub struct SigningFailed {
    err: SignerError,
}

impl SigningFailed {
    fn reset(self) -> Waiting {
        Waiting {}
    }
}

#[derive(Debug)]
pub struct SignedReview {}

impl SignedReview {
    fn approve(self) -> PersistingSigned {
        PersistingSigned {}
    }

    fn hard_reject(self) -> HaltSigned {
        HaltSigned {}
    }

    fn soft_reject(self) -> Waiting {
        Waiting {}
    }
}

#[derive(Debug)]
pub struct HaltSigned {}

impl HaltSigned {
    fn override_rejection(self) -> PersistingSigned {
        PersistingSigned {}
    }

    fn reset(self) -> Waiting {
        Waiting {}
    }
}

#[derive(Debug)]
pub struct PersistingSigned {}

impl PersistingSigned {
    fn done(self) -> Waiting {
        Waiting {}
    }
}
