//! Restoring persisted instances of zones.

use std::sync::Arc;

use crate::{
    Data, DiffData, LoadedZonePatcher, LoadedZoneReader, LoadedZoneReplacer, SignedZonePatcher,
    SignedZoneReader, SignedZoneReplacer,
};

//----------- ZoneRestorer -----------------------------------------------------

/// A restorer for a persisted instance of a zone.
///
/// A [`ZoneRestorer`] restores a persisted instance of a zone from disk, in
/// order to resume serving the zone when Cascade starts up.
pub struct ZoneRestorer {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the loaded instance to build into.
    loaded_index: bool,

    /// The index of the signed instance to build into.
    signed_index: bool,

    /// The diff of the built loaded instance.
    ///
    /// If the new loaded instance has been built, this field is `Some`, and it
    /// provides a diff mapping the current instance to the new one.
    //
    // TODO: It would be nice to use 'UniqueArc' here.
    loaded_diff: Option<Box<DiffData>>,

    /// The diff of the built signed instance.
    ///
    /// If the new signed instance has been built, this field is `Some`, and it
    /// provides a diff mapping the current instance to the new one.
    //
    // TODO: It would be nice to use 'UniqueArc' here.
    signed_diff: Option<Box<DiffData>>,
}

impl ZoneRestorer {
    /// Construct a new [`ZoneRestorer`].
    ///
    /// ## Panics
    ///
    /// Panics if `data.loaded[]` or `data.signed[]` are not empty.
    ///
    /// ## Safety
    ///
    /// `restorer = ZoneRestorer::new(...)` is sound if and only if all the
    /// following conditions are satisfied:
    ///
    /// - `data.loaded` will not be accessed outside of `restorer` (starting
    ///   from this function call).
    /// - `data.signed` will not be accessed outside of `restorer` (starting
    ///   from this function call).
    pub(crate) unsafe fn new(data: Arc<Data>) -> Self {
        // SAFETY: As per the caller, 'loaded[]' will not be accessed elsewhere,
        // and so is sound to access immutably.
        let target = unsafe { &*data.loaded[0].get() };
        assert!(target.soa.is_none(), "The target instance is not empty");
        let target = unsafe { &*data.loaded[1].get() };
        assert!(target.soa.is_none(), "The target instance is not empty");

        // SAFETY: As per the caller, 'signed[]' will not be accessed elsewhere,
        // and so is sound to access immutably.
        let target = unsafe { &*data.signed[0].get() };
        assert!(target.soa.is_none(), "The target instance is not empty");
        let target = unsafe { &*data.signed[1].get() };
        assert!(target.soa.is_none(), "The target instance is not empty");

        // Invariants:
        //
        // - 'loaded-access' is guaranteed by the caller.
        // - 'signed-access' is guaranteed by the caller.
        // - 'built':
        //   - 'loaded[loaded_index]' is empty as checked above.
        //   - 'signed[signed_index]' is empty as checked above.
        //   - 'loaded_diff' is 'None'.
        //   - 'signed_diff' is 'None'.
        Self {
            data,
            loaded_index: false,
            signed_index: false,
            loaded_diff: None,
            signed_diff: None,
        }
    }

    /// The underlying data.
    pub(crate) const fn data(&self) -> &Arc<Data> {
        &self.data
    }
}

impl ZoneRestorer {
    /// Build the new loaded instance from an absolute source.
    ///
    /// A [`LoadedZoneReplacer`] is returned, which can be used to write the
    /// records in the zone.
    ///
    /// If the instance has already been built, [`None`] is returned.
    ///
    /// Use [`Self::patch_loaded()`] to build the instance with diffs.
    pub fn fill_loaded(&mut self) -> Option<LoadedZoneReplacer<'_>> {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // mutably.
        let next = unsafe { &mut *self.data.loaded[self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let curr = unsafe { &*self.data.loaded[!self.loaded_index as usize].get() };

        if next.soa.is_some() {
            // Cannot build the initial instance again.
            return None;
        }

        // NOTE:
        // - 'next' is empty following 'LoadedZoneRestorer::new()'.
        // - 'next' may be modified by 'LoadedZoneReplacer' or
        //   'LoadedZonePatcher', but they will set 'built' on success, and
        //   clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'diff' is empty, as checked by 'built()' above.
        Some(LoadedZoneReplacer::new(curr, next, &mut self.loaded_diff))
    }

    /// Patch the loaded instance being built.
    ///
    /// A [`LoadedZonePatcher`] is returned, which can be used to restore the
    /// instance from a series of diffs.
    ///
    /// If an initial instance has not yet been built, [`None`] is returned.
    ///
    /// Use [`Self::fill_loaded()`] to build the initial instance.
    pub fn patch_loaded(&mut self) -> Option<LoadedZonePatcher<'_>> {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let mut curr = unsafe { &mut *self.data.loaded[self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let mut next = unsafe { &mut *self.data.loaded[!self.loaded_index as usize].get() };

        // If nothing was previously built, stop.
        curr.soa.as_ref()?;

        // If something new has already been built, switch to it.
        if next.soa.is_some() {
            std::mem::swap(&mut curr, &mut next);
            self.loaded_index = !self.loaded_index;
            next.soa = None;
            next.records.clear();
        }

        self.loaded_diff = None;

        // NOTE:
        // - 'curr' is complete, as checked above.
        // - 'next' is empty following 'ZoneRestorer::new()'.
        // - 'next' may be modified by 'LoadedZoneReplacer' or
        //   'LoadedZonePatcher', but they will set 'built_loaded' on success,
        //   and clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'diff' is empty, as checked by 'built()' above.
        Some(LoadedZonePatcher::new(curr, next, &mut self.loaded_diff))
    }

    /// The new loaded instance.
    ///
    /// If a new instance has been built (with [`Self::fill_loaded()`] or
    /// [`Self::patch_loaded()`]), it can be accessed here. Note that empty
    /// instances (as built by [`Self::clear()`]) cannot be accessed.
    pub fn next_loaded(&self) -> Option<LoadedZoneReader<'_>> {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let curr = unsafe { &*self.data.loaded[self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let next = unsafe { &*self.data.loaded[!self.loaded_index as usize].get() };

        // Pick the first complete instance between 'next' and 'curr'.
        [next, curr]
            .into_iter()
            .find(|inst| inst.soa.is_some())
            .map(LoadedZoneReader::new)
    }

    /// The diff from the preceding loaded instance to the current one.
    pub fn take_loaded_diff(&mut self) -> Option<Box<DiffData>> {
        self.loaded_diff.take()
    }
}

impl ZoneRestorer {
    /// Build the new signed instance from an absolute source.
    ///
    /// A [`SignedZoneReplacer`] is returned, which can be used to write the
    /// records in the zone.
    ///
    /// If the instance has already been built, [`None`] is returned.
    ///
    /// Use [`Self::patch_signed()`] to build the instance with diffs.
    pub fn fill_signed(&mut self) -> Option<SignedZoneReplacer<'_>> {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let curr_loaded = unsafe { &*self.data.loaded[self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let next_loaded = unsafe { &*self.data.loaded[!self.loaded_index as usize].get() };

        let next_loaded = next_loaded.soa.is_some().then_some(next_loaded);

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next_signed = unsafe { &mut *self.data.signed[self.signed_index as usize].get() };

        // SAFETY: As per the caller, 'signed[!signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let curr_signed = unsafe { &*self.data.signed[!self.signed_index as usize].get() };

        if next_signed.soa.is_some() {
            // Cannot build the initial instance again.
            return None;
        }

        // NOTE:
        // - 'next' is empty following 'SignedZoneRestorer::new()'.
        // - 'next' may be modified by 'SignedZoneReplacer' or
        //   'SignedZonePatcher', but they will set 'built' on success, and
        //   clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'diff' is empty, as checked by 'built()' above.
        Some(SignedZoneReplacer::new(
            curr_loaded,
            next_loaded,
            self.loaded_diff.as_deref(),
            curr_signed,
            next_signed,
            &mut self.signed_diff,
        ))
    }

    /// Patch the signed instance being built.
    ///
    /// A [`SignedZonePatcher`] is returned, which can be used to restore the
    /// instance from a series of diffs.
    ///
    /// If an initial instance has not yet been built, [`None`] is returned.
    ///
    /// Use [`Self::fill_signed()`] to build the initial instance.
    pub fn patch_signed(&mut self) -> Option<SignedZonePatcher<'_>> {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let curr_loaded = unsafe { &*self.data.loaded[self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let next_loaded = unsafe { &*self.data.loaded[!self.loaded_index as usize].get() };

        let next_loaded = next_loaded.soa.is_some().then_some(next_loaded);

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let mut curr_signed = unsafe { &mut *self.data.signed[self.signed_index as usize].get() };

        // SAFETY: As per the caller, 'signed[!loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let mut next_signed = unsafe { &mut *self.data.signed[!self.signed_index as usize].get() };

        // If nothing was previously built, stop.
        curr_signed.soa.as_ref()?;

        // If something new has already been built, switch to it.
        if next_signed.soa.is_some() {
            std::mem::swap(&mut curr_signed, &mut next_signed);
            self.signed_index = !self.signed_index;
            next_signed.soa = None;
            next_signed.records.clear();
        }

        self.signed_diff = None;

        // NOTE:
        // - 'curr' is complete, as checked above.
        // - 'next' is empty following 'ZoneRestorer::new()'.
        // - 'next' may be modified by 'SignedZoneReplacer' or
        //   'SignedZonePatcher', but they will set 'built_signed' on success,
        //   and clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'diff' is empty, as checked by 'built()' above.
        Some(SignedZonePatcher::new(
            curr_loaded,
            next_loaded,
            self.loaded_diff.as_deref(),
            curr_signed,
            next_signed,
            &mut self.signed_diff,
        ))
    }

    /// The new signed instance.
    ///
    /// If a new instance has been built (with [`Self::fill_signed()`] or
    /// [`Self::patch_signed()`]), it can be accessed here. Note that empty
    /// instances (as built by [`Self::clear()`]) cannot be accessed.
    pub fn next_signed(&self) -> Option<SignedZoneReader<'_>> {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let curr_loaded = unsafe { &*self.data.loaded[self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let next_loaded = unsafe { &*self.data.loaded[!self.loaded_index as usize].get() };

        // Pick the first complete instance between 'next' and 'curr'.
        let loaded = [next_loaded, curr_loaded]
            .into_iter()
            .find(|inst| inst.soa.is_some())?;

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let curr_signed = unsafe { &*self.data.signed[self.signed_index as usize].get() };

        // SAFETY: As per the caller, 'signed[!signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let next_signed = unsafe { &*self.data.signed[!self.signed_index as usize].get() };

        // Pick the first complete instance between 'next' and 'curr'.
        let signed = [next_signed, curr_signed]
            .into_iter()
            .find(|inst| inst.soa.is_some())?;

        Some(SignedZoneReader::new(loaded, signed))
    }

    /// The diff from the preceding signed instance to the current one.
    pub fn take_signed_diff(&mut self) -> Option<Box<DiffData>> {
        self.signed_diff.take()
    }
}

impl ZoneRestorer {
    /// Clear the loaded and signed instances.
    ///
    /// A new, empty instance is created. If a new instance was already built,
    /// it will be overwritten.
    pub fn clear(&mut self) {
        // Initialize the absolute data.

        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.loaded[self.loaded_index as usize].get() };
        next.soa = None;
        next.records.clear();

        // SAFETY: As per the caller, 'loaded[!loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let curr = unsafe { &mut *self.data.loaded[!self.loaded_index as usize].get() };
        curr.soa = None;
        curr.records.clear();

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.signed[self.signed_index as usize].get() };
        next.soa = None;
        next.records.clear();

        // SAFETY: As per the caller, 'signed[!signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let curr = unsafe { &mut *self.data.signed[!self.signed_index as usize].get() };
        curr.soa = None;
        curr.records.clear();

        // Clear the diffs.
        self.loaded_diff = Some(Box::new(DiffData::new()));
        self.signed_diff = Some(Box::new(DiffData::new()));
    }

    /// Finish restoring the instance.
    ///
    /// If a new loaded instance has been built (with [`Self::fill_loaded()`],
    /// [`Self::patch_loaded()`], or [`Self::clear()`]) and a new
    /// signed instance has been built (with [`Self::fill_signed()`],
    /// [`Self::patch_signed()`], or [`Self::clear()`]), a [`ZoneRestored`]
    /// marker is returned to prove it. Otherwise, `self` is returned to try
    /// again.
    pub fn finish(self) -> Result<ZoneRestored, Self> {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let curr_loaded = unsafe { &mut *self.data.loaded[self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next_loaded = unsafe { &mut *self.data.loaded[!self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let curr_signed = unsafe { &mut *self.data.signed[self.signed_index as usize].get() };

        // SAFETY: As per the caller, 'signed[!signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next_signed = unsafe { &mut *self.data.signed[!self.signed_index as usize].get() };

        let loaded_index = if next_loaded.soa.is_some() {
            // Make sure 'curr' is empty.
            curr_loaded.soa = None;
            curr_loaded.records.clear();

            !self.loaded_index
        } else if curr_loaded.soa.is_some() {
            self.loaded_index
        } else {
            return Err(self);
        };

        let signed_index = if next_signed.soa.is_some() {
            // Make sure 'curr' is empty.
            curr_signed.soa = None;
            curr_signed.records.clear();

            !self.signed_index
        } else if curr_signed.soa.is_some() {
            self.signed_index
        } else {
            return Err(self);
        };

        Ok(ZoneRestored {
            data: self.data,
            loaded_index,
            signed_index,
        })
    }
}

//----------- ZoneRestored -----------------------------------------------------

/// Proof that a loaded instance of a zone has been restored.
pub struct ZoneRestored {
    /// The underlying data.
    pub(crate) data: Arc<Data>,

    /// The index of the restored loaded instance.
    pub(crate) loaded_index: bool,

    /// The index of the restored signed instance.
    pub(crate) signed_index: bool,
}
