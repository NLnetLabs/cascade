//! The top-level control of zone data.
//!
//! This module provides [`ZoneDataStorage`], which defines a state machine
//! around the data of a zone and its progression as new instances are built.
//! Each state (i.e. variant of the [`ZoneDataStorage`] enum) is defined by a
//! dedicated type.

use std::sync::Arc;

use crate::{UnsignedZoneReviewer, ZoneReviewer, ZoneViewer, data::Data};

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
    Passive,

    /// A new instance is being built.
    Building,

    /// A new signed instance is being built.
    BuildingSigned,

    /// A re-signed instance is being built.
    BuildingResigned,

    /// An upcoming unsigned instance is pending review.
    PendingUnsignedReview,

    /// An upcoming signed instance is pending review.
    PendingSignedReview,

    /// An upcoming resigned instance is pending review.
    PendingResignedReview,

    /// An upcoming instance is pending review as a whole.
    PendingWholeReview,

    /// An upcoming instance is pending signed review.
    PendingWholeSignedReview,

    /// An upcoming unsigned instance is being reviewed.
    ReviewingUnsigned,

    /// An upcoming signed instance is being reviewed.
    ReviewingSigned,

    /// An upcoming resigned instance is being reviewed.
    ReviewingResigned,

    /// An upcoming instance is being reviewed as a whole.
    ReviewingWhole,

    /// An upcoming unsigned instance is being persisted.
    PersistingUnsigned,

    /// An upcoming instance is being persisted.
    Persisting,

    /// An old unsigned instance is waiting to be cleaned.
    PendingUnsignedClean,

    /// The signed component of an upcoming instance is waiting to be cleaned.
    PendingSignedClean,

    /// An old resigned instance is waiting to be cleaned.
    PendingResignedClean,

    /// An old instance is waiting to be cleaned as a whole.
    PendingWholeClean,

    /// An instance is being cleaned.
    Cleaning,

    /// A signed instance is being cleaned.
    CleaningSigned,

    /// A new instance is being switched to.
    Switching,

    /// The state is poisoned.
    ///
    /// This is a utility state. It allows moving out of the enum from an `&mut`
    /// reference, so that state transitions can be computed by value. If this
    /// state is unexpectedly observed, an implementation error has occurred.
    Poisoned,
}

impl ZoneDataStorage {
    /// Construct a new [`ZoneDataStorage`].
    pub fn new() -> (Self, UnsignedZoneReviewer, ZoneReviewer, ZoneViewer) {
        // TODO: When Cascade starts up, it should check for existing instances
        // on disk. This might require a separate initialization function.

        let data = Arc::new(Data::new());
        let curr_unsigned_index = false;
        let curr_signed_index = false;

        let ureviewer =
            unsafe { UnsignedZoneReviewer::new(data.clone(), curr_unsigned_index, None) };

        let reviewer = unsafe {
            ZoneReviewer::new(
                data.clone(),
                curr_unsigned_index,
                curr_signed_index,
                None,
                None,
            )
        };

        let viewer =
            unsafe { ZoneViewer::new(data.clone(), curr_unsigned_index, curr_signed_index) };

        (Self::Passive, ureviewer, reviewer, viewer)
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
