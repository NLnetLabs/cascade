//! Transitions between states.

use std::sync::Arc;

use crate::{
    LoadedZoneBuilder, LoadedZoneBuilt, LoadedZonePersisted, LoadedZonePersister,
    SignedZoneBuilder, SignedZoneBuilt, SignedZoneCleaned, SignedZoneCleaner, SignedZonePersisted,
    SignedZonePersister, ZoneCleaned, ZoneCleaner,
};

use super::{
    CleanLoadedPendingStorage, CleanSignedPendingStorage, CleanWholePendingStorage,
    CleaningSignedStorage, CleaningStorage, LoadedZoneReviewer, LoadingStorage, PassiveStorage,
    PersistingLoadedStorage, PersistingSignedStorage, ReviewLoadedPendingStorage,
    ReviewSignedPendingStorage, ReviewingLoadedStorage, ReviewingSignedStorage, SignedZoneReviewer,
    SigningStorage, SwitchingStorage, ZoneViewer,
};

//----------- PassiveStorage ---------------------------------------------------

impl PassiveStorage {
    /// Load a new instance.
    pub fn load(self) -> (LoadingStorage, LoadedZoneBuilder) {
        let builder = unsafe { LoadedZoneBuilder::new(self.data.clone(), !self.curr_loaded_index) };

        let storage = LoadingStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, builder)
    }

    /// Re-sign the current instance.
    pub fn resign(self) -> (SigningStorage, SignedZoneBuilder) {
        let builder = unsafe {
            SignedZoneBuilder::new(
                self.data.clone(),
                !self.curr_loaded_index,
                !self.curr_signed_index,
                None,
            )
        };

        let storage = SigningStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            loaded_diff: None,
        };

        (storage, builder)
    }
}

//----------- LoadingStorage ---------------------------------------------------

impl LoadingStorage {
    /// Finish loading.
    pub fn finish(
        self,
        built: LoadedZoneBuilt,
    ) -> (ReviewLoadedPendingStorage, LoadedZoneReviewer) {
        assert!(
            Arc::ptr_eq(&built.data, &self.data),
            "'built' is for a different zone"
        );

        let reviewer = unsafe {
            LoadedZoneReviewer::new(
                self.data.clone(),
                !self.curr_loaded_index,
                Some(built.diff.clone()),
            )
        };

        let storage = ReviewLoadedPendingStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            loaded_diff: built.diff,
        };

        (storage, reviewer)
    }

    /// Give up loading.
    ///
    /// The ongoing attempt to build a new instance of the zone will be
    /// abandoned, and any intermediate artifacts will be cleaned up.
    pub fn give_up(self, builder: LoadedZoneBuilder) -> (CleaningStorage, ZoneCleaner) {
        assert!(
            Arc::ptr_eq(builder.data(), &self.data),
            "'builder' is for a different zone"
        );

        let cleaner = unsafe {
            ZoneCleaner::new(
                self.data.clone(),
                !self.curr_loaded_index,
                !self.curr_signed_index,
            )
        };

        let storage = CleaningStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, cleaner)
    }
}

//----------- SigningStorage ---------------------------------------------------

impl SigningStorage {
    /// Finish signing.
    pub fn finish(
        self,
        built: SignedZoneBuilt,
    ) -> (ReviewSignedPendingStorage, SignedZoneReviewer) {
        assert!(
            Arc::ptr_eq(&built.data, &self.data),
            "'built' is for a different zone"
        );

        let reviewer = unsafe {
            SignedZoneReviewer::new(
                self.data.clone(),
                // Iff there is a loaded diff, use '!curr_loaded_index'.
                self.curr_loaded_index ^ self.loaded_diff.is_some(),
                !self.curr_signed_index,
                self.loaded_diff.clone(),
                Some(built.diff.clone()),
            )
        };

        let storage = ReviewSignedPendingStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            loaded_diff: self.loaded_diff,
            signed_diff: built.diff,
        };

        (storage, reviewer)
    }

    /// Retry signing.
    ///
    /// The ongoing attempt will be abandoned, and any intermediate artifacts
    /// will be cleaned up. The upcoming loaded instance (if any) will be
    /// preserved. Once the cleanup finishes, this state will be restored.
    pub fn retry(self, builder: SignedZoneBuilder) -> (CleaningSignedStorage, SignedZoneCleaner) {
        assert!(
            Arc::ptr_eq(builder.data(), &self.data),
            "'builder' is for a different zone"
        );

        let cleaner = unsafe { SignedZoneCleaner::new(self.data.clone(), !self.curr_signed_index) };

        let storage = CleaningSignedStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            loaded_diff: self.loaded_diff,
        };

        (storage, cleaner)
    }

    /// Give up signing.
    ///
    /// The ongoing attempt will be abandoned, and any intermediate artifacts
    /// (including an upcoming loaded instance) will be cleaned up.
    pub fn give_up(
        self,
        builder: SignedZoneBuilder,
    ) -> (CleanLoadedPendingStorage, LoadedZoneReviewer) {
        // NOTE: In case 'loaded_diff' is 'None', we could jump straight to
        // 'CleaningStorage'. But that would require introducing an 'enum'.

        assert!(
            Arc::ptr_eq(builder.data(), &self.data),
            "'builder' is for a different zone"
        );

        let reviewer =
            unsafe { LoadedZoneReviewer::new(self.data.clone(), self.curr_loaded_index, None) };

        let storage = CleanLoadedPendingStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, reviewer)
    }
}

//----------- ReviewLoadedPendingStorage ---------------------------------------

impl ReviewLoadedPendingStorage {
    /// Start review.
    pub fn start(self, old_reviewer: LoadedZoneReviewer) -> ReviewingLoadedStorage {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.loaded_index == self.curr_loaded_index,
            "'old_reviewer' does not point to the current instance",
        );

        ReviewingLoadedStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            loaded_diff: self.loaded_diff,
        }
    }
}

//----------- ReviewSignedPendingStorage ---------------------------------------

impl ReviewSignedPendingStorage {
    /// Start review.
    pub fn start(self, old_reviewer: SignedZoneReviewer) -> ReviewingSignedStorage {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.loaded_index == self.curr_loaded_index
                && old_reviewer.signed_index == self.curr_signed_index,
            "'old_reviewer' does not point to the current instance",
        );

        ReviewingSignedStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            loaded_diff: self.loaded_diff,
            signed_diff: self.signed_diff,
        }
    }
}

//----------- ReviewingLoadedStorage -------------------------------------------

impl ReviewingLoadedStorage {
    /// Mark the instance as approved.
    pub fn mark_approved(self) -> (PersistingLoadedStorage, LoadedZonePersister) {
        let persister = unsafe {
            LoadedZonePersister::new(
                self.data.clone(),
                !self.curr_loaded_index,
                self.loaded_diff.clone(),
            )
        };

        let storage = PersistingLoadedStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            loaded_diff: self.loaded_diff,
        };

        (storage, persister)
    }

    /// Give up on the prepared instance.
    pub fn give_up(self) -> (CleanLoadedPendingStorage, LoadedZoneReviewer) {
        let reviewer =
            unsafe { LoadedZoneReviewer::new(self.data.clone(), self.curr_loaded_index, None) };

        let storage = CleanLoadedPendingStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, reviewer)
    }
}

//----------- ReviewingSignedStorage -------------------------------------------

impl ReviewingSignedStorage {
    /// Mark the instance as approved.
    pub fn mark_approved(self) -> (PersistingSignedStorage, SignedZonePersister) {
        let persister = unsafe {
            SignedZonePersister::new(
                self.data.clone(),
                !self.curr_signed_index,
                self.signed_diff.clone(),
            )
        };

        let storage = PersistingSignedStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            // Iff there is a loaded diff, use '!curr_loaded_index'.
            next_loaded_index: self.curr_loaded_index ^ self.loaded_diff.is_some(),
            next_signed_index: !self.curr_signed_index,
        };

        (storage, persister)
    }

    /// Retry signing.
    ///
    /// The ongoing attempt will be abandoned, and any intermediate artifacts
    /// will be cleaned up. The upcoming loaded instance (if any) will be
    /// preserved. Once the cleanup finishes, this state will be restored.
    pub fn retry(self) -> (CleanSignedPendingStorage, SignedZoneReviewer) {
        let reviewer = unsafe {
            SignedZoneReviewer::new(
                self.data.clone(),
                self.curr_loaded_index,
                self.curr_signed_index,
                self.loaded_diff.clone(),
                None,
            )
        };

        let storage = CleanSignedPendingStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            loaded_diff: self.loaded_diff,
        };

        (storage, reviewer)
    }

    /// Give up signing.
    ///
    /// The ongoing attempt will be abandoned, and any intermediate artifacts
    /// (including an upcoming loaded instance) will be cleaned up.
    pub fn give_up(
        self,
    ) -> (
        CleanWholePendingStorage,
        LoadedZoneReviewer,
        SignedZoneReviewer,
    ) {
        let ureviewer =
            unsafe { LoadedZoneReviewer::new(self.data.clone(), self.curr_loaded_index, None) };

        let reviewer = unsafe {
            SignedZoneReviewer::new(
                self.data.clone(),
                self.curr_loaded_index,
                self.curr_signed_index,
                None,
                None,
            )
        };

        let storage = CleanWholePendingStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, ureviewer, reviewer)
    }
}

//----------- PersistingLoadedStorage ------------------------------------------

impl PersistingLoadedStorage {
    /// Mark persistence as complete.
    pub fn mark_complete(
        self,
        persisted: LoadedZonePersisted,
    ) -> (SigningStorage, SignedZoneBuilder) {
        assert!(
            Arc::ptr_eq(&persisted.data, &self.data),
            "'persisted' is for a different zone"
        );

        let builder = unsafe {
            SignedZoneBuilder::new(
                self.data.clone(),
                !self.curr_loaded_index,
                !self.curr_signed_index,
                Some(self.loaded_diff.clone()),
            )
        };

        let storage = SigningStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            loaded_diff: Some(self.loaded_diff),
        };

        (storage, builder)
    }
}

//----------- PersistingSignedStorage ------------------------------------------

impl PersistingSignedStorage {
    /// Mark persistence as complete.
    pub fn mark_complete(self, persisted: SignedZonePersisted) -> (SwitchingStorage, ZoneViewer) {
        assert!(
            Arc::ptr_eq(&persisted.data, &self.data),
            "'persisted' is for a different zone"
        );

        let viewer = unsafe {
            ZoneViewer::new(
                self.data.clone(),
                self.next_loaded_index,
                self.next_signed_index,
            )
        };

        let storage = SwitchingStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            next_loaded_index: self.next_loaded_index,
            next_signed_index: self.next_signed_index,
        };

        (storage, viewer)
    }
}

//----------- CleanLoadedPendingStorage ----------------------------------------

impl CleanLoadedPendingStorage {
    /// Stop reviewing the loaded instance.
    pub fn stop_review(self, old_reviewer: LoadedZoneReviewer) -> (CleaningStorage, ZoneCleaner) {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.loaded_index != self.curr_loaded_index,
            "'old_reviewer' does not point to the new instance",
        );

        let cleaner = unsafe {
            ZoneCleaner::new(
                self.data.clone(),
                !self.curr_loaded_index,
                !self.curr_signed_index,
            )
        };

        let storage = CleaningStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
        };

        (storage, cleaner)
    }
}

//----------- CleanSignedPendingStorage ----------------------------------------

impl CleanSignedPendingStorage {
    /// Stop reviewing the signed instance.
    pub fn stop_review(
        self,
        old_reviewer: SignedZoneReviewer,
    ) -> (CleaningSignedStorage, SignedZoneCleaner) {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.loaded_index != self.curr_loaded_index
                && old_reviewer.signed_index != self.curr_signed_index,
            "'old_reviewer' does not point to the new instance",
        );

        let cleaner = unsafe { SignedZoneCleaner::new(self.data.clone(), !self.curr_signed_index) };

        let storage = CleaningSignedStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            loaded_diff: self.loaded_diff,
        };

        (storage, cleaner)
    }
}

//----------- CleanWholePendingStorage -----------------------------------------

impl CleanWholePendingStorage {
    /// Stop reviewing the signed instance.
    pub fn stop_review(self, old_reviewer: SignedZoneReviewer) -> CleanLoadedPendingStorage {
        assert!(
            Arc::ptr_eq(old_reviewer.data(), &self.data),
            "'old_reviewer' is for a different zone"
        );
        assert!(
            old_reviewer.loaded_index != self.curr_loaded_index
                && old_reviewer.signed_index != self.curr_signed_index,
            "'old_reviewer' does not point to the new instance",
        );

        CleanLoadedPendingStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
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
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
        }
    }
}

//----------- CleaningSignedStorage --------------------------------------------

impl CleaningSignedStorage {
    /// Mark cleaning as complete.
    ///
    /// A [`SignedZoneBuilder`] is returned so that signing can be retried.
    pub fn mark_complete(self, cleaned: SignedZoneCleaned) -> (SigningStorage, SignedZoneBuilder) {
        assert!(
            Arc::ptr_eq(&cleaned.data, &self.data),
            "'cleaned' is for a different zone"
        );

        let builder = unsafe {
            SignedZoneBuilder::new(
                self.data.clone(),
                !self.curr_loaded_index,
                !self.curr_signed_index,
                self.loaded_diff.clone(),
            )
        };

        let storage = SigningStorage {
            data: self.data,
            curr_loaded_index: self.curr_loaded_index,
            curr_signed_index: self.curr_signed_index,
            loaded_diff: self.loaded_diff,
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
            old_viewer.loaded_index == self.curr_loaded_index
                && old_viewer.signed_index == self.curr_signed_index,
            "'old_viewer' does not point to the current instance"
        );

        let cleaner = unsafe {
            ZoneCleaner::new(
                self.data.clone(),
                !self.next_loaded_index,
                !self.next_signed_index,
            )
        };

        let storage = CleaningStorage {
            data: self.data,
            curr_loaded_index: self.next_loaded_index,
            curr_signed_index: self.next_signed_index,
        };

        (storage, cleaner)
    }
}
