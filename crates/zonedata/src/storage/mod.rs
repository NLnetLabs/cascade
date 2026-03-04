//! The top-level control of zone data.
//!
//! This module provides [`ZoneDataStorage`], which defines a state machine
//! around the data of a zone and its progression as new instances are built.
//! Each state (i.e. variant of the [`ZoneDataStorage`] enum) is defined by a
//! dedicated type.

use std::sync::Arc;

use crate::{LoadedZoneReviewer, SignedZoneReviewer, ZoneViewer, data::Data};

mod states;
pub use states::{
    CleanLoadedPendingStorage, CleanSignedPendingStorage, CleanWholePendingStorage,
    CleaningSignedStorage, CleaningStorage, LoadingStorage, PassiveStorage,
    PersistingLoadedStorage, PersistingSignedStorage, ReviewLoadedPendingStorage,
    ReviewSignedPendingStorage, ReviewingLoadedStorage, ReviewingSignedStorage, SigningStorage,
    SwitchingStorage,
};

mod transitions;

//----------- ZoneDataStorage --------------------------------------------------

/// Storage for the data of a zone.
///
/// [`ZoneDataStorage`] is the top-level type defining the storage of zone data.
/// It is a state machine, describing how new instances of the zone are built,
/// reviewed, and switched to. While it requires `&mut` access to be modified,
/// it is designed to live in a (synchronous) mutex -- expensive operations on
/// the zone are always achievable without `&mut` access.
pub enum ZoneDataStorage {
    /// The zone is passive.
    Passive(PassiveStorage),

    /// A new instance is being loaded.
    Loading(LoadingStorage),

    /// A new instance is being signed.
    Signing(SigningStorage),

    /// A loaded instance is pending review.
    ReviewLoadedPending(ReviewLoadedPendingStorage),

    /// A signed instance is pending review.
    ReviewSignedPending(ReviewSignedPendingStorage),

    /// A loaded instance is being reviewed.
    ReviewingLoaded(ReviewingLoadedStorage),

    /// A signed instance is being reviewed.
    ReviewingSigned(ReviewingSignedStorage),

    /// A loaded instance is being persisted.
    PersistingLoaded(PersistingLoadedStorage),

    /// A signed instance is being persisted.
    PersistingSigned(PersistingSignedStorage),

    /// A loaded instance is waiting to be cleaned.
    CleanLoadedPending(CleanLoadedPendingStorage),

    /// A signed instance is waiting to be cleaned.
    CleanSignedPending(CleanSignedPendingStorage),

    /// A loaded and signed instance are waiting to be cleaned.
    CleanWholePending(CleanWholePendingStorage),

    /// An instance is being cleaned.
    Cleaning(CleaningStorage),

    /// A signed instance is being cleaned.
    CleaningSigned(CleaningSignedStorage),

    /// A new instance is being switched to.
    Switching(SwitchingStorage),

    /// The state is poisoned.
    ///
    /// This is a utility state. It allows moving out of the enum from an `&mut`
    /// reference, so that state transitions can be computed by value. If this
    /// state is unexpectedly observed, an implementation error has occurred.
    Poisoned,
}

impl ZoneDataStorage {
    /// Construct a new [`ZoneDataStorage`].
    pub fn new() -> (Self, LoadedZoneReviewer, SignedZoneReviewer, ZoneViewer) {
        // TODO: When Cascade starts up, it should check for existing instances
        // on disk. This might require a separate initialization function.

        let data = Arc::new(Data::new());
        let curr_unsigned_index = false;
        let curr_signed_index = false;

        let ureviewer = unsafe { LoadedZoneReviewer::new(data.clone(), curr_unsigned_index, None) };

        let reviewer = unsafe {
            SignedZoneReviewer::new(
                data.clone(),
                curr_unsigned_index,
                curr_signed_index,
                None,
                None,
            )
        };

        let viewer =
            unsafe { ZoneViewer::new(data.clone(), curr_unsigned_index, curr_signed_index) };

        let storage = Self::Passive(PassiveStorage {
            data,
            curr_loaded_index: false,
            curr_signed_index: false,
        });

        (storage, ureviewer, reviewer, viewer)
    }

    /// Extract the current state of the [`ZoneDataStorage`].
    ///
    /// `self` is replaced with [`Self::Poisoned`]. After a state transition,
    /// the new state should be written back. If the intermediate poisoned state
    /// can be observed, it is an implementation error.
    pub fn take(&mut self) -> Self {
        core::mem::replace(self, Self::Poisoned)
    }
}
