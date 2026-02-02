//! Viewing zones.
//!
//! This module provides high-level types through which zones can be accessed.
//! These types account for concurrent access to zones, and are part of
//! the zone instance lifecycle. They provide [`LoadedZoneReader`]s and
//! [`SignedZoneReader`]s.

use std::sync::Arc;

use crate::{Data, DiffData, LoadedZoneReader, SignedZoneReader};

//----------- ZoneViewer -------------------------------------------------------

/// A viewer for the authoritative instance of a zone.
///
/// [`ZoneViewer`] offers complete (read-only) access to the current
/// authoritative instance of a zone.
pub struct ZoneViewer {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the loaded component to use.
    ///
    /// ## Invariants
    ///
    /// - `loaded-access`: `data.loaded[loaded_index]` is sound to access
    ///   immutably for the lifetime of `self`.
    pub(crate) loaded_index: bool,

    /// The index of the signed component to use.
    ///
    /// ## Invariants
    ///
    /// - `signed-access`: `data.signed[signed_index]` is sound to access
    ///   immutably for the lifetime of `self`.
    pub(crate) signed_index: bool,
}

impl ZoneViewer {
    /// Construct a new [`ZoneViewer`].
    ///
    /// ## Panics
    ///
    /// Panics **unless**:
    ///
    /// - If `signed_index` is complete, `loaded_index` must also be complete.
    ///
    /// ## Safety
    ///
    /// `viewer = ZoneViewer::new(data, loaded_index, signed_index)` is sound
    /// if and only if all the following conditions are satisfied:
    ///
    /// - `data.loaded[loaded_index]` will not be modified as long as `viewer`
    ///   exists (starting from this function call).
    ///
    /// - `data.signed[signed_index]` will not be modified as long as `viewer`
    ///   exists (starting from this function call).
    pub(crate) unsafe fn new(data: Arc<Data>, loaded_index: bool, signed_index: bool) -> Self {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // modified.
        let loaded = unsafe { &*data.loaded[loaded_index as usize].get() };

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // modified.
        let signed = unsafe { &*data.signed[signed_index as usize].get() };

        assert!(
            loaded.soa.is_some() || signed.soa.is_none(),
            "a signed component cannot be provided without a loaded one"
        );

        // Invariants:
        // - 'loaded-access' is guaranteed by the caller.
        // - 'signed-access' is guaranteed by the caller.
        Self {
            data,
            loaded_index,
            signed_index,
        }
    }

    /// The underlying data.
    pub(crate) const fn data(&self) -> &Arc<Data> {
        &self.data
    }
}

impl ZoneViewer {
    /// Read the loaded component, if there is one.
    pub fn read_loaded(&self) -> Option<LoadedZoneReader<'_>> {
        let instance = &self.data.loaded[self.loaded_index as usize];

        // SAFETY: As per invariant 'loaded-access', 'instance' will not be
        // modified for the lifetime of 'self', and thus it is sound to access
        // by shared reference.
        let instance = unsafe { &*instance.get() };

        instance.soa.as_ref()?;

        // NOTE: As checked above, 'instance' is complete (i.e. has a SOA
        // record), so 'LoadedZoneReader::new()' will not panic.
        Some(LoadedZoneReader::new(instance))
    }

    /// Read the signed component, if there is one.
    ///
    /// If a signed component exists, a loaded component will also exist.
    pub fn read_signed(&self) -> Option<SignedZoneReader<'_>> {
        let instance = &self.data.signed[self.signed_index as usize];

        // SAFETY: As per invariant 'signed-access', 'instance' will not be
        // modified for the lifetime of 'self', and thus it is sound to access
        // by shared reference.
        let instance = unsafe { &*instance.get() };

        instance.soa.as_ref()?;

        // NOTE: As checked above, 'instance' is complete (i.e. has a SOA
        // record), so 'SignedZoneReader::new()' will not panic.
        Some(SignedZoneReader::new(instance))
    }
}

//----------- LoadedZoneReviewer ---------------------------------------------

/// A viewer for an upcoming instance of a zone.
///
/// [`LoadedZoneReviewer`] offers read-only access to the loaded component
/// of an upcoming instance of a zone, allowing its contents to be reviewed
/// before it is signed or it becomes authoritative.
pub struct LoadedZoneReviewer {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the loaded component to use, if any.
    ///
    /// ## Invariants
    ///
    /// - `loaded-access`: `data.loaded[loaded_index]` is sound to access
    ///   immutably for the lifetime of `self`.
    pub(crate) loaded_index: bool,

    /// The diff of the loaded component from the prior instance, if known.
    loaded_diff: Option<Arc<DiffData>>,
}

impl LoadedZoneReviewer {
    /// Construct a new [`LoadedZoneReviewer`].
    ///
    /// ## Safety
    ///
    /// `reviewer = LoadedZoneReviewer::new(data, loaded_index)` is sound
    /// if and only if all the following conditions are satisfied:
    ///
    /// - `data.loaded[loaded_index]` will not be modified as long as
    ///   `reviewer` exists (starting from this function call).
    pub(crate) unsafe fn new(
        data: Arc<Data>,
        loaded_index: bool,
        loaded_diff: Option<Arc<DiffData>>,
    ) -> Self {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // modified.
        let _ = unsafe { &*data.loaded[loaded_index as usize].get() };

        // Invariants:
        // - 'loaded-access' is guaranteed by the caller.
        // - 'loaded-complete' has been checked above.
        Self {
            data,
            loaded_index,
            loaded_diff,
        }
    }

    /// The underlying data.
    pub(crate) const fn data(&self) -> &Arc<Data> {
        &self.data
    }
}

impl LoadedZoneReviewer {
    /// Read the loaded component, if there is one.
    pub fn read_loaded(&self) -> Option<LoadedZoneReader<'_>> {
        let instance = &self.data.loaded[self.loaded_index as usize];

        // SAFETY: As per invariant 'loaded-access', 'instance' will not be
        // modified for the lifetime of 'self', and thus it is sound to access
        // by shared reference.
        let instance = unsafe { &*instance.get() };

        instance.soa.as_ref()?;

        // NOTE: As checked above, 'instance' is complete (i.e. has a SOA
        // record), so 'LoadedZoneReader::new()' will not panic.
        Some(LoadedZoneReader::new(instance))
    }

    /// The diff of the loaded component from the preceding instance.
    pub fn loaded_diff(&self) -> Option<&Arc<DiffData>> {
        self.loaded_diff.as_ref()
    }
}

//----------- SignedZoneReviewer -----------------------------------------------

/// A reviewer for a loaded instance of a zone.
///
/// [`SignedZoneReviewer`] offers complete (read-only) access to an upcoming
/// signed instance of a zone, allowing its contents to be reviewed before it
/// becomes authoritative.
pub struct SignedZoneReviewer {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the loaded component to use.
    ///
    /// ## Invariants
    ///
    /// - `loaded-access`: `data.loaded[loaded_index]` is sound to access
    ///   immutably for the lifetime of `self`.
    pub(crate) loaded_index: bool,

    /// The index of the signed component to use.
    ///
    /// ## Invariants
    ///
    /// - `signed-access`: `data.signed[signed_index]` is sound to access
    ///   immutably for the lifetime of `self`.
    pub(crate) signed_index: bool,

    /// The diff of the loaded component from the prior instance, if known.
    loaded_diff: Option<Arc<DiffData>>,

    /// The diff of the signed component from the prior instance, if known.
    signed_diff: Option<Arc<DiffData>>,
}

impl SignedZoneReviewer {
    /// Construct a new [`SignedZoneReviewer`].
    ///
    /// ## Panics
    ///
    /// Panics **unless**:
    ///
    /// - If the signed instance is complete, the loaded instance must also
    ///   be complete.
    ///
    /// ## Safety
    ///
    /// `reviewer = SignedZoneReviewer::new(data, loaded_index, signed_index)` is
    /// sound if and only if all the following conditions are satisfied:
    ///
    /// - `data.loaded[loaded_index]` will not be modified as long as
    ///   `reviewer` exists (starting from this function call).
    ///
    /// - `data.signed[signed_index]` will not be modified as long as `reviewer`
    ///   exists (starting from this function call).
    pub(crate) unsafe fn new(
        data: Arc<Data>,
        loaded_index: bool,
        signed_index: bool,
        loaded_diff: Option<Arc<DiffData>>,
        signed_diff: Option<Arc<DiffData>>,
    ) -> Self {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // modified.
        let loaded = unsafe { &*data.loaded[loaded_index as usize].get() };

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // modified.
        let signed = unsafe { &*data.signed[signed_index as usize].get() };

        assert!(
            loaded.soa.is_some() || signed.soa.is_none(),
            "a signed component cannot be provided without a loaded one"
        );

        // Invariants:
        // - 'loaded-access' is guaranteed by the caller.
        // - 'signed-access' is guaranteed by the caller.
        Self {
            data,
            loaded_index,
            signed_index,
            loaded_diff,
            signed_diff,
        }
    }

    /// The underlying data.
    pub(crate) const fn data(&self) -> &Arc<Data> {
        &self.data
    }
}

impl SignedZoneReviewer {
    /// Read the loaded component, if there is one.
    pub fn read_loaded(&self) -> Option<LoadedZoneReader<'_>> {
        let instance = &self.data.loaded[self.loaded_index as usize];

        // SAFETY: As per invariant 'loaded-access', 'instance' will not be
        // modified for the lifetime of 'self', and thus it is sound to access
        // by shared reference.
        let instance = unsafe { &*instance.get() };

        instance.soa.as_ref()?;

        // NOTE: As checked above, 'instance' is complete (i.e. has a SOA
        // record), so 'LoadedZoneReader::new()' will not panic.
        Some(LoadedZoneReader::new(instance))
    }

    /// The diff of the loaded component from the preceding instance.
    pub fn loaded_diff(&self) -> Option<&Arc<DiffData>> {
        self.loaded_diff.as_ref()
    }

    /// Read the signed component, if there is one.
    ///
    /// If a signed component exists, a loaded component will also exist.
    pub fn read_signed(&self) -> Option<SignedZoneReader<'_>> {
        let instance = &self.data.signed[self.signed_index as usize];

        // SAFETY: As per invariant 'signed-access', 'instance' will not be
        // modified for the lifetime of 'self', and thus it is sound to access
        // by shared reference.
        let instance = unsafe { &*instance.get() };

        instance.soa.as_ref()?;

        // NOTE: As checked above, 'instance' is complete (i.e. has a SOA
        // record), so 'SignedZoneReader::new()' will not panic.
        Some(SignedZoneReader::new(instance))
    }

    /// The diff of the signed component from the preceding instance.
    pub fn signed_diff(&self) -> Option<&Arc<DiffData>> {
        self.signed_diff.as_ref()
    }
}
