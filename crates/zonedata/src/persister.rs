//! Persisting approved instances of zones.

use std::sync::Arc;

use crate::{Data, DiffData};

//----------- UnsignedZonePersister --------------------------------------------

/// A persister for an unsigned instance of a zone.
///
/// An [`UnsignedZonePersister`] persists a newly-approved unsigned component of
/// an upcoming instance of a zone to disk.
pub struct UnsignedZonePersister {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the unsigned component to persist, if any.
    ///
    /// ## Invariants
    ///
    /// - `unsigned-access`: `data.unsigned[unsigned_index]` is sound to access
    ///   immutably for the lifetime of `self`. It will not be modified.
    unsigned_index: bool,

    /// The diff of the unsigned component from the preceding instance.
    unsigned_diff: Arc<DiffData>,
}

impl UnsignedZonePersister {
    /// Construct a new [`UnsignedZonePersister`].
    ///
    /// ## Safety
    ///
    /// `persister = UnsignedZonePersister::new(data, signed_index)` is sound if
    /// and only if all the following conditions are satisfied:
    ///
    /// - `data.unsigned[unsigned_index]` will not be modified for the lifetime
    ///   of `persister` (starting from this function call).
    pub(crate) unsafe fn new(
        data: Arc<Data>,
        unsigned_index: bool,
        unsigned_diff: Arc<DiffData>,
    ) -> Self {
        // Invariants:
        // - 'unsigned-access' is guaranteed by the caller.
        Self {
            data,
            unsigned_index,
            unsigned_diff,
        }
    }
}

impl UnsignedZonePersister {
    /// Perform the actual persisting.
    pub fn persist(self) -> UnsignedZonePersisted {
        let UnsignedZonePersister {
            data,
            unsigned_index,
            unsigned_diff,
        } = self;

        // TODO
        let _ = (unsigned_index, unsigned_diff);

        UnsignedZonePersisted { data }
    }
}

//----------- UnsignedZonePersisted --------------------------------------------

/// A proof from a [`UnsignedZonePersister`] that an unsigned instance of a zone
/// has been persisted.
pub struct UnsignedZonePersisted {
    /// The underlying data.
    pub(crate) data: Arc<Data>,
}

//----------- ZonePersister ----------------------------------------------------

/// A persister for an instance of a zone.
///
/// A [`ZonePersister`] persists a newly-approved instance of a zone to disk.
pub struct ZonePersister {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the unsigned component to build into.
    ///
    /// ## Invariants
    ///
    /// - `unsigned-access`: `data.unsigned[unsigned_index]` is sound to access
    ///   immutably for the lifetime of `self`. It will not be modified.
    unsigned_index: Option<bool>,

    /// The index of the signed component to build into.
    ///
    /// ## Invariants
    ///
    /// - `signed-access`: `data.signed[signed_index]` is sound to access
    ///   immutably for the lifetime of `self`. It will not be modified.
    signed_index: bool,

    /// The diff of the unsigned component from the preceding instance.
    unsigned_diff: Option<Arc<DiffData>>,

    /// The diff of the signed component from the preceding instance.
    signed_diff: Arc<DiffData>,
}

impl ZonePersister {
    /// Construct a new [`ZonePersister`].
    ///
    /// ## Safety
    ///
    /// `persister = ZonePersister::new(data, unsigned_index, signed_index)` is
    /// sound if and only if all the following conditions are satisfied:
    ///
    /// - `data.unsigned[unsigned_index]` will not be modified for the lifetime
    ///   of `persister` (starting from this function call).
    ///
    /// - `data.signed[signed_index]` will not be modified for the lifetime of
    ///   `persister` (starting from this function call).
    pub(crate) unsafe fn new(
        data: Arc<Data>,
        unsigned_index: Option<bool>,
        signed_index: bool,
        unsigned_diff: Option<Arc<DiffData>>,
        signed_diff: Arc<DiffData>,
    ) -> Self {
        // Invariants:
        //
        // - 'unsigned-access' is guaranteed by the caller.
        // - 'signed-access' is guaranteed by the caller.
        Self {
            data,
            unsigned_index,
            signed_index,
            unsigned_diff,
            signed_diff,
        }
    }
}

impl ZonePersister {
    /// Perform the actual persisting.
    pub fn persist(self) -> ZonePersisted {
        let ZonePersister {
            data,
            unsigned_index,
            signed_index,
            unsigned_diff,
            signed_diff,
        } = self;

        // TODO
        let _ = (unsigned_index, signed_index, unsigned_diff, signed_diff);

        ZonePersisted { data }
    }
}

//----------- ZonePersisted ----------------------------------------------------

/// A proof from a [`ZonePersister`] that a zone has been persisted.
pub struct ZonePersisted {
    /// The underlying data.
    pub(crate) data: Arc<Data>,
}
