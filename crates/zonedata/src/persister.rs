//! Persisting approved instances of zones.

use std::sync::Arc;

use crate::{Data, DiffData};

//----------- LoadedZonePersister ----------------------------------------------

/// A persister for a loaded instance of a zone.
///
/// A [`LoadedZonePersister`] persists a newly-approved loaded instance of a
/// zone to disk.
pub struct LoadedZonePersister {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the loaded instance to persist, if any.
    ///
    /// ## Invariants
    ///
    /// - `loaded-access`: `data.loaded[loaded_index]` is sound to access
    ///   immutably for the lifetime of `self`. It will not be modified.
    loaded_index: bool,

    /// The diff of the loaded component from the preceding instance.
    loaded_diff: Arc<DiffData>,
}

impl LoadedZonePersister {
    /// Construct a new [`LoadedZonePersister`].
    ///
    /// ## Safety
    ///
    /// `persister = LoadedZonePersister::new(data, loaded_index)` is sound if
    /// and only if all the following conditions are satisfied:
    ///
    /// - `data.loaded[loaded_index]` will not be modified for the lifetime
    ///   of `persister` (starting from this function call).
    pub(crate) unsafe fn new(
        data: Arc<Data>,
        loaded_index: bool,
        loaded_diff: Arc<DiffData>,
    ) -> Self {
        // Invariants:
        // - 'loaded-access' is guaranteed by the caller.
        Self {
            data,
            loaded_index,
            loaded_diff,
        }
    }
}

impl LoadedZonePersister {
    /// Perform the actual persisting.
    pub fn persist(self) -> LoadedZonePersisted {
        let LoadedZonePersister {
            data,
            loaded_index,
            loaded_diff,
        } = self;

        // TODO
        let _ = (loaded_index, loaded_diff);

        LoadedZonePersisted { data }
    }
}

//----------- SignedZonePersister ----------------------------------------------

/// A persister for a signed instance of a zone.
///
/// A [`SignedZonePersister`] persists a newly-approved signed instance of a
/// zone to disk.
pub struct SignedZonePersister {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the signed instance to persist, if any.
    ///
    /// ## Invariants
    ///
    /// - `signed-access`: `data.signed[signed_index]` is sound to access
    ///   immutably for the lifetime of `self`. It will not be modified.
    signed_index: bool,

    /// The diff of the signed component from the preceding instance.
    signed_diff: Arc<DiffData>,
}

impl SignedZonePersister {
    /// Construct a new [`SignedZonePersister`].
    ///
    /// ## Safety
    ///
    /// `persister = SignedZonePersister::new(data, signed_index)` is sound if
    /// and only if all the following conditions are satisfied:
    ///
    /// - `data.signed[signed_index]` will not be modified for the lifetime
    ///   of `persister` (starting from this function call).
    pub(crate) unsafe fn new(
        data: Arc<Data>,
        signed_index: bool,
        signed_diff: Arc<DiffData>,
    ) -> Self {
        // Invariants:
        // - 'signed-access' is guaranteed by the caller.
        Self {
            data,
            signed_index,
            signed_diff,
        }
    }
}

impl SignedZonePersister {
    /// Perform the actual persisting.
    pub fn persist(self) -> SignedZonePersisted {
        let SignedZonePersister {
            data,
            signed_index,
            signed_diff,
        } = self;

        // TODO
        let _ = (signed_index, signed_diff);

        SignedZonePersisted { data }
    }
}

//----------- LoadedZonePersisted --------------------------------------------

/// A proof from a [`LoadedZonePersister`] that a loaded instance of a zone
/// has been persisted.
pub struct LoadedZonePersisted {
    /// The underlying data.
    pub(crate) data: Arc<Data>,
}

//----------- SignedZonePersisted --------------------------------------------

/// A proof from a [`SignedZonePersister`] that a signed instance of a zone
/// has been persisted.
pub struct SignedZonePersisted {
    /// The underlying data.
    pub(crate) data: Arc<Data>,
}
