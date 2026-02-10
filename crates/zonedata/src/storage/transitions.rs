//! Transitions between states.

use std::sync::Arc;

use crate::{
    SignedZoneBuilder, SignedZoneBuilt, SignedZoneCleaned, SignedZoneCleaner, UnsignedZoneBuilt,
    UnsignedZonePersisted, UnsignedZonePersister, UnsignedZoneReviewer, ZoneBuilder, ZoneBuilt,
    ZoneCleaned, ZoneCleaner, ZonePersisted, ZonePersister, ZoneReviewer, ZoneViewer,
};

use super::{
    BuildingResignedStorage, BuildingSignedStorage, BuildingStorage, CleaningSignedStorage,
    CleaningStorage, PassiveStorage, PendingResignedCleanStorage, PendingResignedReviewStorage,
    PendingSignedCleanStorage, PendingSignedReviewStorage, PendingUnsignedCleanStorage,
    PendingUnsignedReviewStorage, PendingWholeCleanStorage, PendingWholeReviewStorage,
    PendingWholeSignedReviewStorage, PersistingStorage, PersistingUnsignedStorage,
    ReviewingResignedStorage, ReviewingSignedStorage, ReviewingUnsignedStorage,
    ReviewingWholeStorage, SwitchingStorage,
};

//----------- PassiveStorage ---------------------------------------------------

impl PassiveStorage {
    /// Build a new instance.
    pub fn build(self) -> (BuildingStorage, ZoneBuilder) {
        let builder = unsafe {
            ZoneBuilder::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                !self.curr_signed_index,
            )
        };

        let storage = BuildingStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, builder)
    }

    /// Resign the current unsigned instance.
    ///
    /// ## Errors
    ///
    /// Fails if the current authoritative instance of the zone does not have
    /// an unsigned or signed component.
    pub fn resign(self) -> Result<(BuildingResignedStorage, SignedZoneBuilder), Self> {
        // Ensure that a current unsigned and signed component is available.
        {
            let unsigned = unsafe { &*self.data.unsigned[self.curr_unsigned_index as usize].get() };
            let signed = unsafe { &*self.data.signed[self.curr_signed_index as usize].get() };

            if unsigned.soa.is_none() || signed.soa.is_none() {
                return Err(self);
            }
        }

        let builder = unsafe {
            SignedZoneBuilder::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                !self.curr_signed_index,
                None,
            )
        };

        let storage = BuildingResignedStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        };

        Ok((storage, builder))
    }
}

//----------- BuildingStorage --------------------------------------------------

impl BuildingStorage {
    /// Finish building the unsigned component.
    pub fn finish_unsigned(
        self,
        built: UnsignedZoneBuilt,
    ) -> (PendingUnsignedReviewStorage, UnsignedZoneReviewer) {
        assert!(
            Arc::ptr_eq(&built.data, &self.data),
            "'built' is for a different zone"
        );

        let unsigned_diff = Arc::new(built.unsigned_diff);

        let reviewer = unsafe {
            UnsignedZoneReviewer::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                Some(unsigned_diff.clone()),
            )
        };

        let storage = PendingUnsignedReviewStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff,
        };

        (storage, reviewer)
    }

    /// Finish building the whole instance.
    pub fn finish_whole(
        self,
        built: ZoneBuilt,
    ) -> (
        PendingWholeReviewStorage,
        UnsignedZoneReviewer,
        ZoneReviewer,
    ) {
        assert!(
            Arc::ptr_eq(&built.data, &self.data),
            "'built' is for a different zone"
        );

        let unsigned_diff = Arc::new(built.unsigned_diff);
        let signed_diff = Arc::new(built.signed_diff);

        let ureviewer = unsafe {
            UnsignedZoneReviewer::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                Some(unsigned_diff.clone()),
            )
        };

        let reviewer = unsafe {
            ZoneReviewer::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                !self.curr_signed_index,
                Some(unsigned_diff.clone()),
                Some(signed_diff.clone()),
            )
        };

        let storage = PendingWholeReviewStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff,
            signed_diff,
        };

        (storage, ureviewer, reviewer)
    }

    /// Give up.
    ///
    /// The ongoing attempt to build a new instance of the zone will be
    /// abandoned, and any intermediate artifacts will be cleaned up.
    pub fn give_up(self, builder: ZoneBuilder) -> (CleaningStorage, ZoneCleaner) {
        assert!(
            Arc::ptr_eq(builder.data(), &self.data),
            "'builder' is for a different zone"
        );

        let cleaner = unsafe {
            ZoneCleaner::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                !self.curr_signed_index,
            )
        };

        let storage = CleaningStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, cleaner)
    }
}

//----------- BuildingSignedStorage --------------------------------------------

impl BuildingSignedStorage {
    /// Finish building.
    pub fn finish(self, built: SignedZoneBuilt) -> (PendingSignedReviewStorage, ZoneReviewer) {
        assert!(
            Arc::ptr_eq(&built.data, &self.data),
            "'built' is for a different zone"
        );

        let signed_diff = Arc::new(built.signed_diff);

        let reviewer = unsafe {
            ZoneReviewer::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                !self.curr_signed_index,
                Some(self.unsigned_diff.clone()),
                Some(signed_diff.clone()),
            )
        };

        let storage = PendingSignedReviewStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff: self.unsigned_diff,
            signed_diff,
        };

        (storage, reviewer)
    }

    /// Give up.
    ///
    /// The ongoing attempt to build a signed component for the upcoming
    /// instance of the zone will be abandoned, and any intermediate artifacts
    /// will be cleaned up. The unsigned component will be preserved, so that
    /// signing can be retried.
    pub fn give_up(self, builder: SignedZoneBuilder) -> (CleaningSignedStorage, SignedZoneCleaner) {
        assert!(
            Arc::ptr_eq(builder.data(), &self.data),
            "'builder' is for a different zone"
        );

        let cleaner = unsafe { SignedZoneCleaner::new(self.data.clone(), !self.curr_signed_index) };

        let storage = CleaningSignedStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff: self.unsigned_diff,
        };

        (storage, cleaner)
    }

    /// Give up on the whole instance.
    ///
    /// The ongoing attempt to build a new instance of the zone will be
    /// abandoned, and any intermediate artifacts will be cleaned up. The
    /// upcoming unsigned instance of the zone will be cleared.
    pub fn give_up_whole(
        self,
        builder: SignedZoneBuilder,
    ) -> (PendingUnsignedCleanStorage, UnsignedZoneReviewer) {
        assert!(
            Arc::ptr_eq(builder.data(), &self.data),
            "'builder' is for a different zone"
        );

        let reviewer =
            unsafe { UnsignedZoneReviewer::new(self.data.clone(), self.curr_unsigned_index, None) };

        let storage = PendingUnsignedCleanStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, reviewer)
    }
}

//----------- BuildingResignedStorage ------------------------------------------

impl BuildingResignedStorage {
    /// Finish building.
    pub fn finish(self, built: SignedZoneBuilt) -> (PendingResignedReviewStorage, ZoneReviewer) {
        assert!(
            Arc::ptr_eq(&built.data, &self.data),
            "'built' is for a different zone"
        );

        let signed_diff = Arc::new(built.signed_diff);

        let reviewer = unsafe {
            ZoneReviewer::new(
                self.data.clone(),
                self.curr_unsigned_index,
                !self.curr_signed_index,
                None,
                Some(signed_diff.clone()),
            )
        };

        let storage = PendingResignedReviewStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            signed_diff,
        };

        (storage, reviewer)
    }

    /// Give up.
    ///
    /// The ongoing attempt to build a new instance of the zone will be
    /// abandoned, and any intermediate artifacts will be cleaned up.
    pub fn give_up(self, builder: SignedZoneBuilder) -> (CleaningStorage, ZoneCleaner) {
        assert!(
            Arc::ptr_eq(builder.data(), &self.data),
            "'builder' is for a different zone"
        );

        let cleaner = unsafe {
            ZoneCleaner::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                !self.curr_signed_index,
            )
        };

        let storage = CleaningStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, cleaner)
    }
}

//----------- PendingUnsignedReviewStorage -------------------------------------

impl PendingUnsignedReviewStorage {
    /// Start review.
    pub fn start(self, old_reviewer: UnsignedZoneReviewer) -> ReviewingUnsignedStorage {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.unsigned_index == self.curr_unsigned_index,
            "'old_reviewer' does not point to the current instance",
        );

        ReviewingUnsignedStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff: self.unsigned_diff,
        }
    }
}

//----------- PendingSignedReviewStorage ---------------------------------------

impl PendingSignedReviewStorage {
    /// Start review.
    pub fn start(self, old_reviewer: ZoneReviewer) -> ReviewingSignedStorage {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.unsigned_index == self.curr_unsigned_index
                && old_reviewer.signed_index == self.curr_signed_index,
            "'old_reviewer' does not point to the current instance",
        );

        ReviewingSignedStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff: self.unsigned_diff,
            signed_diff: self.signed_diff,
        }
    }
}

//----------- PendingResignedReviewStorage -------------------------------------

impl PendingResignedReviewStorage {
    /// Start review.
    pub fn start(self, old_reviewer: ZoneReviewer) -> ReviewingResignedStorage {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.unsigned_index == self.curr_unsigned_index
                && old_reviewer.signed_index == self.curr_signed_index,
            "'old_reviewer' does not point to the current instance",
        );

        ReviewingResignedStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            signed_diff: self.signed_diff,
        }
    }
}

//----------- PendingWholeReviewStorage ----------------------------------------

impl PendingWholeReviewStorage {
    /// Start unsigned review.
    pub fn start_unsigned(
        self,
        old_reviewer: UnsignedZoneReviewer,
    ) -> PendingWholeSignedReviewStorage {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.unsigned_index == self.curr_unsigned_index,
            "'old_reviewer' does not point to the current instance",
        );

        PendingWholeSignedReviewStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff: self.unsigned_diff,
            signed_diff: self.signed_diff,
        }
    }
}

//----------- PendingWholeSignedReviewStorage ----------------------------------

impl PendingWholeSignedReviewStorage {
    /// Start (signed) review.
    pub fn start(self, old_reviewer: ZoneReviewer) -> ReviewingWholeStorage {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.unsigned_index == self.curr_unsigned_index
                && old_reviewer.signed_index == self.curr_signed_index,
            "'old_reviewer' does not point to the current instance",
        );

        ReviewingWholeStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff: self.unsigned_diff,
            signed_diff: self.signed_diff,
        }
    }
}

//----------- ReviewingUnsignedStorage -----------------------------------------

impl ReviewingUnsignedStorage {
    /// Mark the instance as approved.
    pub fn mark_approved(self) -> (PersistingUnsignedStorage, UnsignedZonePersister) {
        let persister = unsafe {
            UnsignedZonePersister::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                self.unsigned_diff.clone(),
            )
        };

        let storage = PersistingUnsignedStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff: self.unsigned_diff,
        };

        (storage, persister)
    }

    /// Give up on the prepared instance.
    pub fn give_up(self) -> (PendingUnsignedCleanStorage, UnsignedZoneReviewer) {
        let reviewer =
            unsafe { UnsignedZoneReviewer::new(self.data.clone(), self.curr_unsigned_index, None) };

        let storage = PendingUnsignedCleanStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, reviewer)
    }
}

//----------- ReviewingSignedStorage -------------------------------------------

impl ReviewingSignedStorage {
    /// Mark the instance as approved.
    pub fn mark_approved(self) -> (PersistingStorage, ZonePersister) {
        // TODO: Don't persist the unsigned instance again.
        let persister = unsafe {
            ZonePersister::new(
                self.data.clone(),
                None,
                !self.curr_signed_index,
                None,
                self.signed_diff.clone(),
            )
        };

        let storage = PersistingStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            next_unsigned_index: !self.curr_unsigned_index,
            next_signed_index: !self.curr_signed_index,
        };

        (storage, persister)
    }

    /// Give up on the prepared signed instance.
    pub fn give_up(self) -> (PendingSignedCleanStorage, ZoneReviewer) {
        let reviewer = unsafe {
            ZoneReviewer::new(
                self.data.clone(),
                self.curr_unsigned_index,
                self.curr_signed_index,
                None,
                None,
            )
        };

        let storage = PendingSignedCleanStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff: self.unsigned_diff,
        };

        (storage, reviewer)
    }

    /// Give up on the whole prepared instance.
    pub fn give_up_whole(self) -> (PendingWholeCleanStorage, UnsignedZoneReviewer, ZoneReviewer) {
        let ureviewer =
            unsafe { UnsignedZoneReviewer::new(self.data.clone(), self.curr_unsigned_index, None) };

        let reviewer = unsafe {
            ZoneReviewer::new(
                self.data.clone(),
                self.curr_unsigned_index,
                self.curr_signed_index,
                None,
                None,
            )
        };

        let storage = PendingWholeCleanStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, ureviewer, reviewer)
    }
}

//----------- ReviewingResignedStorage -----------------------------------------

impl ReviewingResignedStorage {
    /// Mark the instance as approved.
    pub fn mark_approved(self) -> (PersistingStorage, ZonePersister) {
        let persister = unsafe {
            ZonePersister::new(
                self.data.clone(),
                None,
                !self.curr_signed_index,
                None,
                self.signed_diff.clone(),
            )
        };

        let storage = PersistingStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            next_unsigned_index: self.curr_unsigned_index,
            next_signed_index: !self.curr_signed_index,
        };

        (storage, persister)
    }

    /// Give up on the prepared instance.
    pub fn give_up(self) -> (PendingResignedCleanStorage, ZoneReviewer) {
        let reviewer = unsafe {
            ZoneReviewer::new(
                self.data.clone(),
                self.curr_unsigned_index,
                self.curr_signed_index,
                None,
                None,
            )
        };

        let storage = PendingResignedCleanStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, reviewer)
    }
}

//----------- ReviewingWholeStorage --------------------------------------------

impl ReviewingWholeStorage {
    /// Mark the instance as approved.
    pub fn mark_approved(self) -> (PersistingStorage, ZonePersister) {
        let persister = unsafe {
            ZonePersister::new(
                self.data.clone(),
                Some(!self.curr_unsigned_index),
                !self.curr_signed_index,
                Some(self.unsigned_diff.clone()),
                self.signed_diff.clone(),
            )
        };

        let storage = PersistingStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            next_unsigned_index: !self.curr_unsigned_index,
            next_signed_index: !self.curr_signed_index,
        };

        (storage, persister)
    }

    /// Give up on the prepared instance.
    pub fn give_up(self) -> (PendingWholeCleanStorage, UnsignedZoneReviewer, ZoneReviewer) {
        let ureviewer =
            unsafe { UnsignedZoneReviewer::new(self.data.clone(), self.curr_unsigned_index, None) };

        let reviewer = unsafe {
            ZoneReviewer::new(
                self.data.clone(),
                self.curr_unsigned_index,
                self.curr_signed_index,
                None,
                None,
            )
        };

        let storage = PendingWholeCleanStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, ureviewer, reviewer)
    }
}

//----------- PersistingUnsignedStorage ----------------------------------------

impl PersistingUnsignedStorage {
    /// Mark persistence as complete.
    pub fn mark_complete(
        self,
        persisted: UnsignedZonePersisted,
    ) -> (BuildingSignedStorage, SignedZoneBuilder) {
        assert!(
            Arc::ptr_eq(&persisted.data, &self.data),
            "'persisted' is for a different zone"
        );

        let builder = unsafe {
            SignedZoneBuilder::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                !self.curr_signed_index,
                Some(self.unsigned_diff.clone()),
            )
        };

        let storage = BuildingSignedStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff: self.unsigned_diff,
        };

        (storage, builder)
    }
}

//----------- PersistingStorage ------------------------------------------------

impl PersistingStorage {
    /// Mark persistence as complete.
    pub fn mark_complete(self, persisted: ZonePersisted) -> (SwitchingStorage, ZoneViewer) {
        assert!(
            Arc::ptr_eq(&persisted.data, &self.data),
            "'persisted' is for a different zone"
        );

        let viewer = unsafe {
            ZoneViewer::new(
                self.data.clone(),
                self.next_unsigned_index,
                self.next_signed_index,
            )
        };

        let storage = SwitchingStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            next_unsigned_index: self.next_unsigned_index,
            next_signed_index: self.next_signed_index,
        };

        (storage, viewer)
    }
}

//----------- PendingUnsignedCleanStorage --------------------------------------

impl PendingUnsignedCleanStorage {
    /// Stop reviewing the unsigned instance.
    pub fn stop_review(self, old_reviewer: UnsignedZoneReviewer) -> (CleaningStorage, ZoneCleaner) {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.unsigned_index != self.curr_unsigned_index,
            "'old_reviewer' does not point to the new instance",
        );

        let cleaner = unsafe {
            ZoneCleaner::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                !self.curr_signed_index,
            )
        };

        let storage = CleaningStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, cleaner)
    }
}

//----------- PendingSignedCleanStorage ----------------------------------------

impl PendingSignedCleanStorage {
    /// Stop reviewing the signed instance.
    pub fn stop_review(
        self,
        old_reviewer: ZoneReviewer,
    ) -> (CleaningSignedStorage, SignedZoneCleaner) {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.unsigned_index != self.curr_unsigned_index
                && old_reviewer.signed_index != self.curr_signed_index,
            "'old_reviewer' does not point to the new instance",
        );

        let cleaner = unsafe { SignedZoneCleaner::new(self.data.clone(), !self.curr_signed_index) };

        let storage = CleaningSignedStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff: self.unsigned_diff,
        };

        (storage, cleaner)
    }
}

//----------- PendingResignedCleanStorage --------------------------------------

impl PendingResignedCleanStorage {
    /// Stop reviewing the unsigned instance.
    pub fn stop_review(self, old_reviewer: ZoneReviewer) -> (CleaningStorage, ZoneCleaner) {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.unsigned_index == self.curr_unsigned_index
                && old_reviewer.signed_index != self.curr_signed_index,
            "'old_reviewer' does not point to the new instance",
        );

        let cleaner = unsafe {
            ZoneCleaner::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                !self.curr_signed_index,
            )
        };

        let storage = CleaningStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, cleaner)
    }
}

//----------- PendingWholeCleanStorage -----------------------------------------

impl PendingWholeCleanStorage {
    /// Stop reviewing the signed instance.
    pub fn stop_review(self, old_reviewer: ZoneReviewer) -> PendingUnsignedCleanStorage {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.unsigned_index != self.curr_unsigned_index
                && old_reviewer.signed_index != self.curr_signed_index,
            "'old_reviewer' does not point to the new instance",
        );

        PendingUnsignedCleanStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        }
    }
}

//----------- CleaningStorage --------------------------------------------------

impl CleaningStorage {
    /// Mark cleaning as complete.
    pub fn mark_complete(self, cleaned: ZoneCleaned) -> PassiveStorage {
        assert!(
            Arc::ptr_eq(&cleaned.data, &self.data),
            "'cleaned' is for a different zone"
        );

        PassiveStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
        }
    }
}

//----------- CleaningSignedStorage --------------------------------------------

impl CleaningSignedStorage {
    /// Mark cleaning as complete.
    pub fn mark_complete(
        self,
        cleaned: SignedZoneCleaned,
    ) -> (BuildingSignedStorage, SignedZoneBuilder) {
        assert!(
            Arc::ptr_eq(&cleaned.data, &self.data),
            "'cleaned' is for a different zone"
        );

        let builder = unsafe {
            SignedZoneBuilder::new(
                self.data.clone(),
                !self.curr_unsigned_index,
                !self.curr_signed_index,
                Some(self.unsigned_diff.clone()),
            )
        };

        let storage = BuildingSignedStorage {
            data: self.data,
            curr_unsigned_index: self.curr_unsigned_index,
            curr_signed_index: self.curr_signed_index,
            unsigned_diff: self.unsigned_diff,
        };

        (storage, builder)
    }
}

//----------- SwitchingStorage -------------------------------------------------

impl SwitchingStorage {
    /// Switch the zone viewer to the new instance.
    pub fn switch(self, old_viewer: ZoneViewer) -> (CleaningStorage, ZoneCleaner) {
        assert!(
            Arc::ptr_eq(old_viewer.data(), &self.data),
            "'old_viewer' is for a different zone"
        );
        assert!(
            old_viewer.unsigned_index == self.curr_unsigned_index
                && old_viewer.signed_index == self.curr_signed_index,
            "'old_viewer' does not point to the current instance"
        );

        let cleaner = unsafe {
            ZoneCleaner::new(
                self.data.clone(),
                !self.next_unsigned_index,
                !self.next_signed_index,
            )
        };

        let storage = CleaningStorage {
            data: self.data,
            curr_unsigned_index: self.next_unsigned_index,
            curr_signed_index: self.next_signed_index,
        };

        (storage, cleaner)
    }
}
