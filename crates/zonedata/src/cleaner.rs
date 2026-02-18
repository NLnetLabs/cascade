//! Cleaning old instances of zones.

use std::sync::Arc;

use crate::Data;

//----------- ZoneCleaner ------------------------------------------------------

/// A cleaner for a mid-removal instance of a zone.
///
/// A [`ZoneCleaner`] cleans up an instance of a zone, whether it was a previous
/// authoritative instance or a failed/rejected/partial upcoming instance.
pub struct ZoneCleaner {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the unsigned component to build into.
    ///
    /// ## Invariants
    ///
    /// - `unsigned-access`: `data.unsigned[unsigned_index]` is sound to access
    ///   mutably for the lifetime of `self`. It will not be accessed anywhere
    ///   else.
    unsigned_index: bool,

    /// The index of the signed component to build into.
    ///
    /// ## Invariants
    ///
    /// - `signed-access`: `data.signed[signed_index]` is sound to access
    ///   mutably for the lifetime of `self`. It will not be accessed anywhere
    ///   else.
    signed_index: bool,
}

impl ZoneCleaner {
    /// Construct a new [`ZoneCleaner`].
    ///
    /// ## Safety
    ///
    /// `cleaner = ZoneCleaner::new(data, unsigned_index, signed_index)` is
    /// sound if and only if all the following conditions are satisfied:
    ///
    /// - `data.unsigned[unsigned_index]` will not be accessed outside of
    ///   `cleaner` (starting from this function call).
    ///
    /// - `data.signed[signed_index]` will not be accessed outside of `cleaner`
    ///   (starting from this function call).
    pub(crate) unsafe fn new(data: Arc<Data>, unsigned_index: bool, signed_index: bool) -> Self {
        // Invariants:
        //
        // - 'unsigned-access' is guaranteed by the caller.
        // - 'signed-access' is guaranteed by the caller.
        Self {
            data,
            unsigned_index,
            signed_index,
        }
    }
}

impl ZoneCleaner {
    /// Perform the actual cleaning.
    pub fn clean(self) -> ZoneCleaned {
        // SAFETY: As per invariant 'unsigned-access',
        // 'unsigned[unsigned_index]' is sound to access mutably.
        let instance = unsafe { &mut *self.data.unsigned[self.unsigned_index as usize].get() };

        instance.soa = None;
        instance.records.clear();

        // SAFETY: As per invariant 'signed-access', 'signed[signed_index]'
        // is sound to access mutably.
        let instance = unsafe { &mut *self.data.signed[self.signed_index as usize].get() };

        instance.soa = None;
        instance.records.clear();

        ZoneCleaned { data: self.data }
    }
}

//----------- ZoneCleaned ------------------------------------------------------

/// A proof from a [`ZoneCleaner`] that a zone has been cleaned.
pub struct ZoneCleaned {
    /// The underlying data.
    pub(crate) data: Arc<Data>,
}

//----------- SignedZoneCleaner ------------------------------------------------

/// A cleaner for a mid-removal instance of a zone.
///
/// A [`SignedZoneCleaner`] cleans up the signed component of an instance
/// of a zone, whether it was a previous authoritative instance or a
/// failed/rejected/partial upcoming instance.
pub struct SignedZoneCleaner {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the signed component to build into.
    ///
    /// ## Invariants
    ///
    /// - `signed-access`: `data.signed[signed_index]` is sound to access
    ///   mutably for the lifetime of `self`. It will not be accessed anywhere
    ///   else.
    signed_index: bool,
}

impl SignedZoneCleaner {
    /// Construct a new [`SignedZoneCleaner`].
    ///
    /// ## Safety
    ///
    /// `cleaner = SignedZoneCleaner::new(data, signed_index)` is sound if and
    /// only if all the following conditions are satisfied:
    ///
    /// - `data.signed[signed_index]` will not be accessed outside of `cleaner`
    ///   (starting from this function call).
    pub(crate) unsafe fn new(data: Arc<Data>, signed_index: bool) -> Self {
        // Invariants:
        // - 'signed-access' is guaranteed by the caller.
        Self { data, signed_index }
    }
}

impl SignedZoneCleaner {
    /// Perform the actual cleaning.
    pub fn clean(self) -> SignedZoneCleaned {
        // SAFETY: As per invariant 'signed-access', 'signed[signed_index]'
        // is sound to access mutably.
        let instance = unsafe { &mut *self.data.signed[self.signed_index as usize].get() };

        instance.soa = None;
        instance.records.clear();

        SignedZoneCleaned { data: self.data }
    }
}

//----------- SignedZoneCleaned ------------------------------------------------

/// A proof from a [`SignedZoneCleaner`] that a zone has been cleaned.
pub struct SignedZoneCleaned {
    /// The underlying data.
    pub(crate) data: Arc<Data>,
}
