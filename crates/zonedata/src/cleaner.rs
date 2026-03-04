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

    /// The index of the loaded instance to build into.
    ///
    /// ## Invariants
    ///
    /// - `loaded-access`: `data.loaded[loaded_index]` is sound to access
    ///   mutably for the lifetime of `self`. It will not be accessed anywhere
    ///   else.
    loaded_index: bool,

    /// The index of the signed instance to build into.
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
    /// `cleaner = ZoneCleaner::new(data, loaded_index, signed_index)` is
    /// sound if and only if all the following conditions are satisfied:
    ///
    /// - `data.loaded[loaded_index]` will not be accessed outside of `cleaner`
    ///   (starting from this function call).
    ///
    /// - `data.signed[signed_index]` will not be accessed outside of `cleaner`
    ///   (starting from this function call).
    pub(crate) unsafe fn new(data: Arc<Data>, loaded_index: bool, signed_index: bool) -> Self {
        // Invariants:
        //
        // - 'loaded-access' is guaranteed by the caller.
        // - 'signed-access' is guaranteed by the caller.
        Self {
            data,
            loaded_index,
            signed_index,
        }
    }
}

impl ZoneCleaner {
    /// Perform the actual cleaning.
    pub fn clean(self) -> ZoneCleaned {
        // SAFETY: As per invariant 'loaded-access', 'loaded[loaded_index]' is
        // sound to access mutably.
        let instance = unsafe { &mut *self.data.loaded[self.loaded_index as usize].get() };

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

//----------- SignedZoneCleaner ------------------------------------------------

/// A cleaner for a mid-removal instance of a zone.
///
/// A [`SignedZoneCleaner`] cleans up a signed instance of a zone, whether it
/// was a previous authoritative instance or a failed/rejected/partial upcoming
/// instance.
pub struct SignedZoneCleaner {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the signed instance to build into.
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

//----------- ZoneCleaned ------------------------------------------------------

/// A proof from a [`ZoneCleaner`] that a zone has been cleaned.
pub struct ZoneCleaned {
    /// The underlying data.
    pub(crate) data: Arc<Data>,
}

//----------- SignedZoneCleaned ------------------------------------------------

/// A proof from a [`SignedZoneCleaner`] that a zone has been cleaned.
pub struct SignedZoneCleaned {
    /// The underlying data.
    pub(crate) data: Arc<Data>,
}
