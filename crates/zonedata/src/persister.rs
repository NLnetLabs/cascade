//! Persisting approved instances of zones.

use std::sync::Arc;

use crate::{Data, DiffData, LoadedZoneReader, SignedZoneReader};

//----------- LoadedZonePersister ----------------------------------------------

/// A persister for a loaded instance of a zone.
///
/// A [`LoadedZonePersister`] persists a newly-approved loaded instance of a
/// zone to disk.
#[must_use]
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
    /// Read the instance needing persistence (if it is non-empty).
    pub fn read(&self) -> Option<LoadedZoneReader<'_>> {
        let loaded = &self.data.loaded[self.loaded_index as usize];

        // SAFETY: As per invariant 'loaded-access', 'loaded' will not be
        // modified for the lifetime of 'self', and thus it is sound to access
        // by shared reference.
        let loaded = unsafe { &*loaded.get() };

        loaded.soa.as_ref()?;

        // NOTE: As checked above, 'loaded' is complete (i.e. has a SOA record),
        // so 'LoadedZoneReader::new()' will not panic.
        Some(LoadedZoneReader::new(loaded))
    }

    /// The diff from the preceding instance to the current one.
    pub fn loaded_diff(&self) -> &Arc<DiffData> {
        &self.loaded_diff
    }

    /// Mark persistence as complete.
    ///
    /// This should be called once the instance has been read and persisted to
    /// disk.
    pub fn mark_complete(self) -> LoadedZonePersisted {
        LoadedZonePersisted { data: self.data }
    }
}

//----------- SignedZonePersister ----------------------------------------------

/// A persister for a signed instance of a zone.
///
/// A [`SignedZonePersister`] persists a newly-approved signed instance of a
/// zone to disk.
#[must_use]
pub struct SignedZonePersister {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the associated loaded instance, if any.
    ///
    /// ## Invariants
    ///
    /// - `loaded-access`: `data.loaded[loaded_index]` is sound to access
    ///   immutably for the lifetime of `self`. It will not be modified.
    loaded_index: bool,

    /// The index of the signed instance to persist, if any.
    ///
    /// ## Invariants
    ///
    /// - `signed-access`: `data.signed[signed_index]` is sound to access
    ///   immutably for the lifetime of `self`. It will not be modified.
    signed_index: bool,

    /// The diff of the loaded component from the prior instance, if any.
    loaded_diff: Option<Arc<DiffData>>,

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
        loaded_index: bool,
        signed_index: bool,
        loaded_diff: Option<Arc<DiffData>>,
        signed_diff: Arc<DiffData>,
    ) -> Self {
        // Invariants:
        // - 'signed-access' is guaranteed by the caller.
        Self {
            data,
            loaded_index,
            signed_index,
            loaded_diff,
            signed_diff,
        }
    }
}

impl SignedZonePersister {
    /// Read the instance needing persistence (if it is non-empty).
    pub fn read(&self) -> Option<SignedZoneReader<'_>> {
        let loaded = &self.data.loaded[self.loaded_index as usize];
        let signed = &self.data.signed[self.signed_index as usize];

        // SAFETY: As per invariant 'loaded-access', 'loaded' will not be
        // modified for the lifetime of 'self', and thus it is sound to access
        // by shared reference.
        let loaded = unsafe { &*loaded.get() };

        // SAFETY: As per invariant 'signed-access', 'signed' will not be
        // modified for the lifetime of 'self', and thus it is sound to access
        // by shared reference.
        let signed = unsafe { &*signed.get() };

        signed.soa.as_ref()?;

        // NOTE: As checked above, 'signed' is complete (i.e. has a SOA record),
        // and thus 'loaded' must also be complete, so 'SignedZoneReader::new()'
        // will not panic.
        Some(SignedZoneReader::new(loaded, signed))
    }

    /// The diff from the preceding loaded instance to the current one.
    ///
    /// This is `None` iff a re-signing occurred.
    pub fn loaded_diff(&self) -> Option<&Arc<DiffData>> {
        self.loaded_diff.as_ref()
    }

    /// The diff from the preceding signed instance to the current one.
    pub fn signed_diff(&self) -> &Arc<DiffData> {
        &self.signed_diff
    }

    /// Mark persistence as complete.
    ///
    /// This should be called once the instance has been read and persisted to
    /// disk.
    pub fn mark_complete(self) -> SignedZonePersisted {
        SignedZonePersisted { data: self.data }
    }
}

//----------- LoadedZonePersisted ----------------------------------------------

/// A proof from a [`LoadedZonePersister`] that a loaded instance of a zone
/// has been persisted.
pub struct LoadedZonePersisted {
    /// The underlying data.
    pub(crate) data: Arc<Data>,
}

//----------- SignedZonePersisted ----------------------------------------------

/// A proof from a [`SignedZonePersister`] that a signed instance of a zone
/// has been persisted.
pub struct SignedZonePersisted {
    /// The underlying data.
    pub(crate) data: Arc<Data>,
}
