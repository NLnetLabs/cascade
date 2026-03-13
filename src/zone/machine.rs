use cascade_zonedata::{LoadedZoneBuilder, LoadedZoneBuilt};
use tracing::trace;

use crate::zone::ZoneHandle;

/// State machine for a particular zone
///
/// Here is the diagram for it:
/// ```text
/// ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
/// │                                                       Waiting                                                        │
/// └─▲────────╥────────▲─────────────────▲──────────────────────────╥──────────────────────────▲────────────────────────▲─┘
///   │        ║        │                 │                          ║                          │                        ║  
///   │        ║ load   │ fail            │ soft reject              ║ resign                   │ soft reject            ║  
///   │        ║        │                 │                          ║                          │                        ║  
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
    Poisoned,
}

/// # Waiting operations
impl<'a> ZoneHandle<'a> {
    pub fn try_start_load(&mut self) -> Option<LoadedZoneBuilder> {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::Waiting(waiting) = state else {
            transition.move_to(state);
            return None;
        };

        transition.move_to(ZoneStateMachine::Loading(waiting.start_load()));

        let builder = self
            .storage()
            .start_load()
            .expect("storage is in sync with state");

        Some(builder)
    }

    pub fn start_resign(&mut self) {
        todo!()
    }
}

/// # Loading operations
impl<'a> ZoneHandle<'a> {
    pub fn abandon_load(&mut self, builder: LoadedZoneBuilder) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::Loading(loaded) = state else {
            panic!("cannot start review in this state");
        };

        transition.move_to(ZoneStateMachine::Waiting(loaded.abandon_load()));

        self.storage().abandon_load(builder);
    }

    pub fn finish_load(&mut self, built: LoadedZoneBuilt) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::Loading(loaded) = state else {
            panic!("cannot start review in this state");
        };

        transition.move_to(ZoneStateMachine::LoadedReview(loaded.finish_load()));

        self.storage().finish_load(built);
    }
}

/// # Loaded Review operations
impl<'a> ZoneHandle<'a> {
    pub fn approve_loaded(&mut self) {
        let (transition, state) = self.state.machine.transition();

        let ZoneStateMachine::LoadedReview(loaded) = state else {
            panic!("cannot start review in this state");
        };

        transition.move_to(ZoneStateMachine::Signing(loaded.approve()));

        self.storage().approve_loaded();
    }

    pub fn soft_reject_loaded(&mut self) {
        todo!()
    }

    pub fn hard_reject_loaded(&mut self) {
        todo!()
    }
}

impl<'a> ZoneHandle<'a> {}
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
    fn reset(self) -> Waiting {
        Waiting {}
    }
}

#[derive(Debug)]
pub struct Signing {}

impl Signing {
    fn signing_succeeded(self) -> SignedReview {
        SignedReview {}
    }

    fn signing_failed(self) -> SignedReview {
        SignedReview {}
    }
}

#[derive(Debug)]
pub struct SigningFailed {}

#[derive(Debug)]
pub struct SignedReview {}

impl SignedReview {
    fn approved(self) -> Waiting {
        Waiting {}
    }

    fn rejected(self) -> HaltSigned {
        HaltSigned {}
    }
}

#[derive(Debug)]
pub struct HaltSigned {}

impl HaltSigned {
    fn retry(self) -> Signing {
        Signing {}
    }

    fn reset(self) -> Waiting {
        Waiting {}
    }
}
