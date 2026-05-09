//! Restoring persisted instances of zones.

use std::sync::Arc;

use crate::{
    Data, DiffData, LoadedZonePatcher, LoadedZoneReader, LoadedZoneReplacer, SignedZonePatcher,
    SignedZoneReader, SignedZoneReplacer,
};

//----------- LoadedZoneRestorer -----------------------------------------------

/// A restorer for a persisted loaded instance of a zone.
///
/// A [`LoadedZoneRestorer`] restores a persisted instance of a zone from disk,
/// in order to resume serving the zone when Cascade starts up.
pub struct LoadedZoneRestorer {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the loaded instance to build into.
    index: bool,

    /// The diff of the built loaded instance.
    ///
    /// If the new loaded instance has been built, this field is `Some`, and it
    /// provides a diff mapping the current instance to the new one.
    //
    // TODO: It would be nice to use 'UniqueArc' here.
    diff: Option<Box<DiffData>>,
}

impl LoadedZoneRestorer {
    /// Construct a new [`LoadedZoneRestorer`].
    ///
    /// ## Panics
    ///
    /// Panics if `data.loaded[]` is not empty.
    ///
    /// ## Safety
    ///
    /// `restorer = LoadedZoneRestorer::new(...)` is sound if and only if all
    /// the following conditions are satisfied:
    ///
    /// - `data.loaded` will not be accessed outside of `restorer` (starting
    ///   from this function call).
    pub(crate) unsafe fn new(data: Arc<Data>) -> Self {
        // SAFETY: As per the caller, 'loaded[]' will not be accessed elsewhere,
        // and so is sound to access immutably.
        let target = unsafe { &*data.loaded[0].get() };
        assert!(target.soa.is_none(), "The target instance is not empty");
        let target = unsafe { &*data.loaded[1].get() };
        assert!(target.soa.is_none(), "The target instance is not empty");

        // Invariants:
        //
        // - 'loaded-access' is guaranteed by the caller.
        // - 'built':
        //   - 'loaded[index]' is empty as checked above.
        //   - 'diff' is 'None'.
        Self {
            data,
            index: false,
            diff: None,
        }
    }

    /// The underlying data.
    pub(crate) const fn data(&self) -> &Arc<Data> {
        &self.data
    }
}

impl LoadedZoneRestorer {
    /// Build the new instance from an absolute source.
    ///
    /// A [`LoadedZoneReplacer`] is returned, which can be used to write the
    /// records in the zone.
    ///
    /// If the instance has already been built, [`None`] is returned.
    ///
    /// Use [`Self::patch()`] to build the instance with diffs.
    pub fn fill(&mut self) -> Option<LoadedZoneReplacer<'_>> {
        // SAFETY: As per the caller, 'loaded[index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // mutably.
        let next = unsafe { &mut *self.data.loaded[self.index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // mutably.
        let curr = unsafe { &*self.data.loaded[!self.index as usize].get() };

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
        Some(LoadedZoneReplacer::new(curr, next, &mut self.diff))
    }

    /// Patch the instance being built.
    ///
    /// A [`LoadedZonePatcher`] is returned, which can be used to restore the
    /// instance from a series of diffs.
    ///
    /// If an initial instance has not yet been built, [`None`] is returned.
    ///
    /// Use [`Self::fill()`] to build the initial instance.
    pub fn patch(&mut self) -> Option<LoadedZonePatcher<'_>> {
        // SAFETY: As per the caller, 'loaded[index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let mut curr = unsafe { &mut *self.data.loaded[self.index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // mutably.
        let mut next = unsafe { &mut *self.data.loaded[!self.index as usize].get() };

        // If nothing was previously built, stop.
        curr.soa.as_ref()?;

        // If something new has already been built, switch to it.
        if next.soa.is_some() {
            std::mem::swap(&mut curr, &mut next);
            self.index = !self.index;
            next.soa = None;
            next.records.clear();
        }

        self.diff = None;

        // NOTE:
        // - 'curr' is complete, as checked above.
        // - 'next' is empty following 'ZoneRestorer::new()'.
        // - 'next' may be modified by 'LoadedZoneReplacer' or
        //   'LoadedZonePatcher', but they will set 'built_loaded' on success,
        //   and clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'diff' is empty, as checked by 'built()' above.
        Some(LoadedZonePatcher::new(curr, next, &mut self.diff))
    }

    /// Clear the instance.
    ///
    /// A new, empty instance is created. If a new instance was already built,
    /// it will be overwritten.
    pub fn clear(&mut self) {
        // Initialize the absolute data.

        // SAFETY: As per the caller, 'loaded[index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.loaded[self.index as usize].get() };
        next.soa = None;
        next.records.clear();

        // SAFETY: As per the caller, 'loaded[!index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let curr = unsafe { &mut *self.data.loaded[!self.index as usize].get() };
        curr.soa = None;
        curr.records.clear();

        // Set the diff.
        self.diff = Some(Box::new(DiffData::new()));
    }

    /// The new (loaded) instance.
    ///
    /// If a new instance has been built (with [`Self::fill()`] or
    /// [`Self::patch()`]), it can be accessed here. Note that empty instances
    /// (as built by [`Self::clear()`]) cannot be accessed.
    pub fn next(&self) -> Option<LoadedZoneReader<'_>> {
        // SAFETY: As per the caller, 'loaded[index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr = unsafe { &*self.data.loaded[self.index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // immutably.
        let next = unsafe { &*self.data.loaded[!self.index as usize].get() };

        // Pick the first complete instance between 'next' and 'curr'.
        [next, curr]
            .into_iter()
            .find(|inst| inst.soa.is_some())
            .map(LoadedZoneReader::new)
    }

    /// The diff from the preceding loaded instance to the current one.
    pub fn take_diff(&mut self) -> Option<Box<DiffData>> {
        self.diff.take()
    }
}

impl LoadedZoneRestorer {
    /// Finish restoring the instance.
    ///
    /// If a new instance has been built (with [`Self::fill()`],
    /// [`Self::patch()`], or [`Self::clear()`]), a [`LoadedZoneRestored`]
    /// marker is returned to prove it. Otherwise, `self` is returned to try
    /// again.
    pub fn finish(self) -> Result<LoadedZoneRestored, Self> {
        // SAFETY: As per the caller, 'loaded[index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // mutably.
        let curr = unsafe { &mut *self.data.loaded[self.index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // mutably.
        let next = unsafe { &mut *self.data.loaded[!self.index as usize].get() };

        if next.soa.is_some() {
            // Make sure 'curr' is empty.
            curr.soa = None;
            curr.records.clear();

            Ok(LoadedZoneRestored {
                data: self.data,
                index: !self.index,
            })
        } else if curr.soa.is_some() {
            Ok(LoadedZoneRestored {
                data: self.data,
                index: self.index,
            })
        } else {
            Err(self)
        }
    }
}

//----------- SignedZoneRestorer -----------------------------------------------

/// A restorer for a persisted signed instance of a zone.
///
/// A [`SignedZoneRestorer`] restores a persisted instance of a zone from disk,
/// in order to resume serving the zone when Cascade starts up.
pub struct SignedZoneRestorer {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the associated loaded instance.
    ///
    /// ## Invariants
    ///
    /// - `loaded-access`: `data.loaded[loaded_index]` is sound to access
    ///   immutably for the lifetime of `self`. It will not be modified.
    loaded_index: bool,

    /// The index of the signed instance to build into.
    index: bool,

    /// The diff of the built signed instance.
    ///
    /// If the new signed instance has been built, this field is `Some`, and it
    /// provides a diff mapping the current instance to the new one.
    //
    // TODO: It would be nice to use 'UniqueArc' here.
    diff: Option<Box<DiffData>>,
}

impl SignedZoneRestorer {
    /// Construct a new [`SignedZoneRestorer`].
    ///
    /// ## Panics
    ///
    /// Panics if `data.signed[]` is not empty.
    ///
    /// ## Safety
    ///
    /// `restorer = SignedZoneRestorer::new(...)` is sound if and only if all
    /// the following conditions are satisfied:
    ///
    /// - `data.loaded[loaded_index]` will not be modified for the lifetime of
    ///   `restorer` (starting from this function call).
    ///
    /// - `data.signed` will not be accessed outside of `restorer` (starting
    ///   from this function call).
    pub(crate) unsafe fn new(data: Arc<Data>, loaded_index: bool) -> Self {
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
        //   - 'signed[index]' is empty as checked above.
        //   - 'diff' is 'None'.
        Self {
            data,
            loaded_index,
            index: false,
            diff: None,
        }
    }

    /// The underlying data.
    pub(crate) const fn data(&self) -> &Arc<Data> {
        &self.data
    }
}

impl SignedZoneRestorer {
    /// Build the new instance from an absolute source.
    ///
    /// A [`SignedZoneReplacer`] is returned, which can be used to write the
    /// records in the zone.
    ///
    /// If the instance has already been built, [`None`] is returned.
    ///
    /// Use [`Self::patch()`] to build the instance with diffs.
    pub fn fill(&mut self) -> Option<SignedZoneReplacer<'_>> {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr_loaded = unsafe { &*self.data.signed[self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'signed[index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // mutably.
        let next = unsafe { &mut *self.data.signed[self.index as usize].get() };

        // SAFETY: As per the caller, 'signed[!index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // mutably.
        let curr = unsafe { &*self.data.signed[!self.index as usize].get() };

        if next.soa.is_some() {
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
            None,
            None,
            curr,
            next,
            &mut self.diff,
        ))
    }

    /// Patch the instance being built.
    ///
    /// A [`SignedZonePatcher`] is returned, which can be used to restore the
    /// instance from a series of diffs.
    ///
    /// If an initial instance has not yet been built, [`None`] is returned.
    ///
    /// Use [`Self::fill()`] to build the initial instance.
    pub fn patch(&mut self) -> Option<SignedZonePatcher<'_>> {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr_loaded = unsafe { &*self.data.signed[self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'signed[index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let mut curr = unsafe { &mut *self.data.signed[self.index as usize].get() };

        // SAFETY: As per the caller, 'signed[!index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // mutably.
        let mut next = unsafe { &mut *self.data.signed[!self.index as usize].get() };

        // If nothing was previously built, stop.
        curr.soa.as_ref()?;

        // If something new has already been built, switch to it.
        if next.soa.is_some() {
            std::mem::swap(&mut curr, &mut next);
            self.index = !self.index;
            next.soa = None;
            next.records.clear();
        }

        self.diff = None;

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
            None,
            None,
            curr,
            next,
            &mut self.diff,
        ))
    }

    /// Clear the instance.
    ///
    /// A new, empty instance is created. If a new instance was already built,
    /// it will be overwritten.
    pub fn clear(&mut self) {
        // Initialize the absolute data.

        // SAFETY: As per the caller, 'signed[index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.signed[self.index as usize].get() };
        next.soa = None;
        next.records.clear();

        // SAFETY: As per the caller, 'signed[!index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let curr = unsafe { &mut *self.data.signed[!self.index as usize].get() };
        curr.soa = None;
        curr.records.clear();

        // Set the diff.
        self.diff = Some(Box::new(DiffData::new()));
    }

    /// The new (signed) instance.
    ///
    /// If a new instance has been built (with [`Self::fill()`] or
    /// [`Self::patch()`]), it can be accessed here. Note that empty instances
    /// (as built by [`Self::clear()`]) cannot be accessed.
    pub fn next(&self) -> Option<SignedZoneReader<'_>> {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr_loaded = unsafe { &*self.data.signed[self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'signed[index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr = unsafe { &*self.data.signed[self.index as usize].get() };

        // SAFETY: As per the caller, 'signed[!index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // immutably.
        let next = unsafe { &*self.data.signed[!self.index as usize].get() };

        // Pick the first complete instance between 'next' and 'curr'.
        [next, curr]
            .into_iter()
            .find(|inst| inst.soa.is_some())
            .map(|inst| SignedZoneReader::new(curr_loaded, inst))
    }

    /// The diff from the preceding signed instance to the current one.
    pub fn take_diff(&mut self) -> Option<Box<DiffData>> {
        self.diff.take()
    }
}

impl SignedZoneRestorer {
    /// Finish restoring the instance.
    ///
    /// If a new instance has been built (with [`Self::fill()`],
    /// [`Self::patch()`], or [`Self::clear()`]), a [`SignedZoneRestored`]
    /// marker is returned to prove it. Otherwise, `self` is returned to try
    /// again.
    pub fn finish(self) -> Result<SignedZoneRestored, Self> {
        // SAFETY: As per the caller, 'signed[index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // mutably.
        let curr = unsafe { &mut *self.data.signed[self.index as usize].get() };

        // SAFETY: As per the caller, 'signed[!index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // mutably.
        let next = unsafe { &mut *self.data.signed[!self.index as usize].get() };

        if next.soa.is_some() {
            // Make sure 'curr' is empty.
            curr.soa = None;
            curr.records.clear();

            Ok(SignedZoneRestored {
                data: self.data,
                index: !self.index,
            })
        } else if curr.soa.is_some() {
            Ok(SignedZoneRestored {
                data: self.data,
                index: self.index,
            })
        } else {
            Err(self)
        }
    }
}

//----------- LoadedZoneRestored -----------------------------------------------

/// Proof that a loaded instance of a zone has been restored.
pub struct LoadedZoneRestored {
    /// The underlying data.
    pub(crate) data: Arc<Data>,

    /// The index of the restored instance.
    pub(crate) index: bool,
}

//----------- SignedZoneRestored -----------------------------------------------

/// Proof that a signed instance of a zone has been restored.
pub struct SignedZoneRestored {
    /// The underlying data.
    pub(crate) data: Arc<Data>,

    /// The index of the restored instance.
    pub(crate) index: bool,
}
