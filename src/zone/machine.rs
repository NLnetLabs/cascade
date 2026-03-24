use cascade_api::ZoneReviewStatus;
use cascade_zonedata::{LoadedZoneBuilder, LoadedZoneBuilt, SignedZoneBuilder};
use tracing::{info, trace};

use crate::{
    signer::SigningTrigger,
    units::zone_signer::SignerError,
    zone::{HistoricalEvent, ZoneHandle},
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
    Signing(Signing),
    SigningFailed(SigningFailed),
    SignedReview(SignedReview),
    HaltSigned(HaltSigned),

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
        // It's important that we first check the storage here instead of the
        // zone state machine. The reason is that while the zone state machine
        // is in the waiting state, the storage might still be persisting or
        // cleaning the zone and we shouldn't start a new operation if that's
        // the case.
        let Some(builder) = self.storage().start_load() else {
            info!("Could not start load since an operation is in progress on the zone.");
            return None;
        };

        let (transition, state) = self.state.machine.transition();
        let ZoneStateMachine::Waiting(waiting) = state else {
            panic!(
                "The storage was in the passive state but the state machine wasn't in the waiting state"
            );
        };

        transition.move_to(ZoneStateMachine::Loading(waiting.start_load()));

        Some(builder)
    }

    pub(crate) fn try_start_resign(&mut self) -> Option<SignedZoneBuilder> {
        // It's important that we first check the storage here instead of the
        // zone state machine. The reason is that while the zone state machine
        // is in the waiting state, the storage might still be persisting or
        // cleaning the zone and we shouldn't start a new operation if that's
        // the case.
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
    }

    pub(crate) fn finish_load(&mut self, built: LoadedZoneBuilt) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::Loading(loaded) = state else {
            panic!("cannot start loader review in this state");
        };

        transition.move_to(ZoneStateMachine::LoadedReview(loaded.finish_load()));

        self.storage().finish_load(built);
    }
}

/// # Loaded Review operations
impl<'a> ZoneHandle<'a> {
    pub(crate) fn approve_loaded(&mut self) {
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

        transition.move_to(ZoneStateMachine::Signing(loaded.approve()));

        self.storage().approve_loaded();
    }

    #[expect(dead_code)]
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
    pub(crate) fn finish_signing(&mut self, built: cascade_zonedata::SignedZoneBuilt) {
        self.state.record_event(
            // TODO: Get the right trigger.
            HistoricalEvent::SigningSucceeded {
                trigger: SigningTrigger::Load.into(),
            },
            // TODO: Get the serial in here.
            None,
        );

        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::Signing(signing) = state else {
            panic!("cannot start signed review in this state");
        };

        transition.move_to(ZoneStateMachine::SignedReview(signing.finish_signing()));

        self.storage().finish_sign(built);
    }

    pub(crate) fn signing_failed(&mut self, builder: SignedZoneBuilder, err: SignerError) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::Signing(signing) = state else {
            panic!("cannot fail signing in this state");
        };

        transition.move_to(ZoneStateMachine::SigningFailed(signing.signing_failed(err)));

        self.storage().abandon_sign(builder);
    }
}

/// # Signed Review operations
impl<'a> ZoneHandle<'a> {
    pub(crate) fn approve_signed(&mut self) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::SignedReview(signed) = state else {
            panic!("cannot approve signed in this state: {}", state.as_str());
        };

        transition.move_to(ZoneStateMachine::Waiting(signed.approve()));
    }

    #[expect(dead_code)]
    pub(crate) fn soft_reject_signed(&mut self) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::SignedReview(signed) = state else {
            panic!("cannot soft reject signed in this state");
        };

        transition.move_to(ZoneStateMachine::Waiting(signed.soft_reject()));
    }

    pub(crate) fn hard_reject_signed(&mut self) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::SignedReview(review) = state else {
            panic!("cannot hard reject signed in this state");
        };

        transition.move_to(ZoneStateMachine::HaltSigned(review.hard_reject()));
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
                self.storage().reject_loaded();
            }
            ZoneStateMachine::HaltSigned(halt_signed) => {
                let waiting = halt_signed.reset();
                transition.move_to(ZoneStateMachine::Waiting(waiting));
            }
            ZoneStateMachine::SigningFailed(signing_failed) => {
                let waiting = signing_failed.reset();
                transition.move_to(ZoneStateMachine::Waiting(waiting));
            }
            _ => {
                transition.move_to(state);
                return Err(());
            }
        };

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

        transition.move_to(ZoneStateMachine::Signing(halt.override_rejection()));

        self.storage().approve_loaded();

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

        transition.move_to(ZoneStateMachine::Waiting(halt_signed.override_rejection()));

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
            ZoneStateMachine::Signing(_) => "signing",
            ZoneStateMachine::SigningFailed(_) => "signing failed",
            ZoneStateMachine::SignedReview(_) => "signed review",
            ZoneStateMachine::HaltSigned(_) => "halt signed",
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
    fn approve(self) -> Signing {
        Signing {}
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
    fn override_rejection(self) -> Signing {
        Signing {}
    }

    fn reset(self) -> Waiting {
        Waiting {}
    }
}

#[derive(Debug)]
pub struct Signing {}

impl Signing {
    fn finish_signing(self) -> SignedReview {
        SignedReview {}
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
    fn approve(self) -> Waiting {
        Waiting {}
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
    fn override_rejection(self) -> Waiting {
        Waiting {}
    }

    fn reset(self) -> Waiting {
        Waiting {}
    }
}
