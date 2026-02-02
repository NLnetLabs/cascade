//! Viewing zones.
//!
//! This module provides high-level types through which zones can be accessed.
//! These types account for concurrent access to zones, and are part of
//! the zone instance lifecycle. They provide [`UnsignedZoneReader`]s and
//! [`SignedZoneReader`]s.

use std::sync::Arc;

use crate::{Data, DiffData, SignedZoneReader, UnsignedZoneReader};

//----------- ZoneViewer -------------------------------------------------------

/// A viewer for the authoritative instance of a zone.
///
/// [`ZoneViewer`] offers complete (read-only) access to the current
/// authoritative instance of a zone.
pub struct ZoneViewer {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the unsigned component to use.
    ///
    /// ## Invariants
    ///
    /// - `unsigned-access`: `data.unsigned[unsigned_index]` is sound to access
    ///   immutably for the lifetime of `self`.
    pub(crate) unsigned_index: bool,

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
    /// - If `signed_index` is complete, `unsigned_index` must also be complete.
    ///
    /// ## Safety
    ///
    /// `viewer = ZoneViewer::new(data, unsigned_index, signed_index)` is sound
    /// if and only if all the following conditions are satisfied:
    ///
    /// - `data.unsigned[unsigned_index]` will not be modified as long as
    ///   `viewer` exists (starting from this function call).
    ///
    /// - `data.signed[signed_index]` will not be modified as long as `viewer`
    ///   exists (starting from this function call).
    pub(crate) unsafe fn new(data: Arc<Data>, unsigned_index: bool, signed_index: bool) -> Self {
        // SAFETY: As per the caller, 'unsigned[unsigned_index]' will not be
        // modified.
        let unsigned = unsafe { &*data.unsigned[unsigned_index as usize].get() };

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // modified.
        let signed = unsafe { &*data.signed[signed_index as usize].get() };

        assert!(
            unsigned.soa.is_some() || signed.soa.is_none(),
            "a signed component cannot be provided without an unsigned one"
        );

        // Invariants:
        // - 'unsigned-access' is guaranteed by the caller.
        // - 'signed-access' is guaranteed by the caller.
        Self {
            data,
            unsigned_index,
            signed_index,
        }
    }

    /// The underlying data.
    pub(crate) const fn data(&self) -> &Arc<Data> {
        &self.data
    }
}

impl ZoneViewer {
    /// Read the unsigned component, if there is one.
    pub fn read_unsigned(&self) -> Option<UnsignedZoneReader<'_>> {
        let instance = &self.data.unsigned[self.unsigned_index as usize];

        // SAFETY: As per invariant 'unsigned-access', 'instance' will not be
        // modified for the lifetime of 'self', and thus it is sound to access
        // by shared reference.
        let instance = unsafe { &*instance.get() };

        instance.soa.as_ref()?;

        // NOTE: As checked above, 'instance' is complete (i.e. has a SOA
        // record), so 'UnsignedZoneReader::new()' will not panic.
        Some(UnsignedZoneReader::new(instance))
    }

    /// Read the signed component, if there is one.
    ///
    /// If a signed component exists, an unsigned component will also exist.
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

//----------- ZoneReviewer -----------------------------------------------------

/// A viewer for an upcoming instance of a zone.
///
/// [`ZoneReviewer`] offers complete (read-only) access to an upcoming
/// instance of a zone, allowing its contents to be reviewed before it becomes
/// authoritative.
pub struct ZoneReviewer {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the unsigned component to use.
    ///
    /// ## Invariants
    ///
    /// - `unsigned-access`: `data.unsigned[unsigned_index]` is sound to access
    ///   immutably for the lifetime of `self`.
    pub(crate) unsigned_index: bool,

    /// The index of the signed component to use.
    ///
    /// ## Invariants
    ///
    /// - `signed-access`: `data.signed[signed_index]` is sound to access
    ///   immutably for the lifetime of `self`.
    pub(crate) signed_index: bool,

    /// The diff of the unsigned component from the prior instance, if known..
    unsigned_diff: Option<Arc<DiffData>>,

    /// The diff of the signed component from the prior instance, if known.
    signed_diff: Option<Arc<DiffData>>,
}

impl ZoneReviewer {
    /// Construct a new [`ZoneReviewer`].
    ///
    /// ## Panics
    ///
    /// Panics **unless**:
    ///
    /// - If the signed instance is complete, the unsigned instance must also
    ///   be complete.
    ///
    /// ## Safety
    ///
    /// `reviewer = ZoneReviewer::new(data, unsigned_index, signed_index)` is
    /// sound if and only if all the following conditions are satisfied:
    ///
    /// - `data.unsigned[unsigned_index]` will not be modified as long as
    ///   `reviewer` exists (starting from this function call).
    ///
    /// - `data.signed[signed_index]` will not be modified as long as `reviewer`
    ///   exists (starting from this function call).
    pub(crate) unsafe fn new(
        data: Arc<Data>,
        unsigned_index: bool,
        signed_index: bool,
        unsigned_diff: Option<Arc<DiffData>>,
        signed_diff: Option<Arc<DiffData>>,
    ) -> Self {
        // SAFETY: As per the caller, 'unsigned[unsigned_index]' will not be
        // modified.
        let unsigned = unsafe { &*data.unsigned[unsigned_index as usize].get() };

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // modified.
        let signed = unsafe { &*data.signed[signed_index as usize].get() };

        assert!(
            unsigned.soa.is_some() || signed.soa.is_none(),
            "a signed component cannot be provided without an unsigned one"
        );

        // Invariants:
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

    /// The underlying data.
    pub(crate) const fn data(&self) -> &Arc<Data> {
        &self.data
    }
}

impl ZoneReviewer {
    /// Read the unsigned component, if there is one.
    pub fn read_unsigned(&self) -> Option<UnsignedZoneReader<'_>> {
        let instance = &self.data.unsigned[self.unsigned_index as usize];

        // SAFETY: As per invariant 'unsigned-access', 'instance' will not be
        // modified for the lifetime of 'self', and thus it is sound to access
        // by shared reference.
        let instance = unsafe { &*instance.get() };

        instance.soa.as_ref()?;

        // NOTE: As checked above, 'instance' is complete (i.e. has a SOA
        // record), so 'UnsignedZoneReader::new()' will not panic.
        Some(UnsignedZoneReader::new(instance))
    }

    /// The diff of the unsigned component from the preceding instance.
    pub fn unsigned_diff(&self) -> Option<&Arc<DiffData>> {
        self.unsigned_diff.as_ref()
    }

    /// Read the signed component, if there is one.
    ///
    /// If a signed component exists, an unsigned component will also exist.
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

//----------- UnsignedZoneReviewer ---------------------------------------------

/// A viewer for an upcoming instance of a zone.
///
/// [`UnsignedZoneReviewer`] offers read-only access to the unsigned component
/// of an upcoming instance of a zone, allowing its contents to be reviewed
/// before it is signed or it becomes authoritative.
pub struct UnsignedZoneReviewer {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the unsigned component to use, if any.
    ///
    /// ## Invariants
    ///
    /// - `unsigned-access`: `data.unsigned[unsigned_index]` is sound to access
    ///   immutably for the lifetime of `self`.
    pub(crate) unsigned_index: bool,

    /// The diff of the unsigned component from the prior instance, if known.
    unsigned_diff: Option<Arc<DiffData>>,
}

impl UnsignedZoneReviewer {
    /// Construct a new [`UnsignedZoneReviewer`].
    ///
    /// ## Safety
    ///
    /// `reviewer = UnsignedZoneReviewer::new(data, unsigned_index)` is sound
    /// if and only if all the following conditions are satisfied:
    ///
    /// - `data.unsigned[unsigned_index]` will not be modified as long as
    ///   `reviewer` exists (starting from this function call).
    pub(crate) unsafe fn new(
        data: Arc<Data>,
        unsigned_index: bool,
        unsigned_diff: Option<Arc<DiffData>>,
    ) -> Self {
        // SAFETY: As per the caller, 'unsigned[unsigned_index]' will not be
        // modified.
        let _ = unsafe { &*data.unsigned[unsigned_index as usize].get() };

        // Invariants:
        // - 'unsigned-access' is guaranteed by the caller.
        // - 'unsigned-complete' has been checked above.
        Self {
            data,
            unsigned_index,
            unsigned_diff,
        }
    }

    /// The underlying data.
    pub(crate) const fn data(&self) -> &Arc<Data> {
        &self.data
    }
}

impl UnsignedZoneReviewer {
    /// Read the unsigned component, if there is one.
    pub fn read_unsigned(&self) -> Option<UnsignedZoneReader<'_>> {
        let instance = &self.data.unsigned[self.unsigned_index as usize];

        // SAFETY: As per invariant 'unsigned-access', 'instance' will not be
        // modified for the lifetime of 'self', and thus it is sound to access
        // by shared reference.
        let instance = unsafe { &*instance.get() };

        instance.soa.as_ref()?;

        // NOTE: As checked above, 'instance' is complete (i.e. has a SOA
        // record), so 'UnsignedZoneReader::new()' will not panic.
        Some(UnsignedZoneReader::new(instance))
    }

    /// The diff of the unsigned component from the preceding instance.
    pub fn unsigned_diff(&self) -> Option<&Arc<DiffData>> {
        self.unsigned_diff.as_ref()
    }
}
