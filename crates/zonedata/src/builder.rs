//! Building new instances of zones.
//!
//! This module provides high-level types through which new instances of
//! zones can be built. These types account for concurrent access to zones,
//! and are part of the zone instance lifecycle. They provide types from the
//! [`crate::writer`] module for performing the actual writing.

use std::sync::Arc;

use crate::{
    Data, DiffData, LoadedZonePatcher, LoadedZoneReader, LoadedZoneReplacer, SignedZonePatcher,
    SignedZoneReader, SignedZoneReplacer,
};

//----------- LoadedZoneBuilder ------------------------------------------------

/// A builder for a new loaded instance of a zone.
///
/// [`LoadedZoneBuilder`] is used to load new instances of a zone from external
/// sources (e.g. zonefiles and DNS servers). It offers read-only access to the
/// current loaded instance of the zone, to support incremental loading.
pub struct LoadedZoneBuilder {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the loaded instance to build into.
    ///
    /// ## Invariants
    ///
    /// - `next-access`: `data.loaded[index]` is sound to access mutably for the
    ///   lifetime of `self`. It will not be accessed anywhere else.
    ///
    /// - `curr-access`: `data.loaded[!index]` is sound to access immutably for
    ///   the lifetime of `self`.
    ///
    /// - `built`: `data.loaded[index]` is empty iff `diff` is `None`.
    index: bool,

    /// The diff of the built loaded instance.
    ///
    /// If the new loaded instance has been built, this field is `Some`, and it
    /// provides a diff mapping the current instance to the new one.
    //
    // TODO: It would be nice to use 'UniqueArc' here.
    diff: Option<Box<DiffData>>,
}

impl LoadedZoneBuilder {
    /// Construct a new [`LoadedZoneBuilder`].
    ///
    /// ## Panics
    ///
    /// Panics if `data.loaded[index]` is not empty.
    ///
    /// ## Safety
    ///
    /// `builder = ZoneBuilder::new(data, index)` is sound if and only if
    /// all the following conditions are satisfied:
    ///
    /// - `data.loaded[!index]` will not be modified as long as `builder` exists
    ///   (starting from this function call).
    ///
    /// - `data.loaded[index]` will not be accessed outside of `builder`
    ///   (starting from this function call).
    pub(crate) unsafe fn new(data: Arc<Data>, index: bool) -> Self {
        // SAFETY: As per the caller, 'loaded[index]' will not be accessed
        // elsewhere, and so is sound to access immutably.
        let next = unsafe { &*data.loaded[index as usize].get() };
        assert!(next.soa.is_none(), "The target instance is not empty");

        // Invariants:
        //
        // - 'next-access' is guaranteed by the caller.
        // - 'curr-access' is guaranteed by the caller.
        // - 'built':
        //   - 'loaded[index]' is empty as checked above.
        //   - 'diff' is 'None'.
        Self {
            data,
            index,
            diff: None,
        }
    }

    /// The underlying data.
    pub(crate) const fn data(&self) -> &Arc<Data> {
        &self.data
    }
}

impl LoadedZoneBuilder {
    /// Replace the current (loaded) instance, building from scratch.
    ///
    /// A [`LoadedZoneReplacer`] is returned, which can be used to write the
    /// new records in the zone. The new instance cannot be built relative to
    /// the current one, but access to the current one (if it is non-empty)
    /// is provided.
    ///
    /// If the loaded zone has already been built, [`None`] is returned.
    ///
    /// Use [`Self::patch()`] to build the new instance relative to the current
    /// one.
    pub fn replace(&mut self) -> Option<LoadedZoneReplacer<'_>> {
        if self.built() {
            // Cannot build the instance again.
            return None;
        }

        // SAFETY: As per the caller, 'loaded[index]' will not be accessed
        // elsewhere for the lifetime of 'self', and so is sound to access
        // mutably.
        let next = unsafe { &mut *self.data.loaded[self.index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!index]' will not
        // be modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr = unsafe { &*self.data.loaded[!self.index as usize].get() };

        // NOTE:
        // - 'next' is empty following 'ZoneBuilder::new()'.
        // - 'next' may be modified by 'LoadedZoneReplacer' or
        //   'LoadedZonePatcher', but they will set 'built' on success, and
        //   clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'diff' is empty, as checked by 'built()' above.
        Some(LoadedZoneReplacer::new(curr, next, &mut self.diff))
    }

    /// Patch the current (loaded) instance.
    ///
    /// A [`LoadedZonePatcher`] is returned, which can be used to apply a diff
    /// to the current instance of the zone. This is ideal for applying an IXFR.
    ///
    /// If the current instance of the zone is empty, or a new instance has
    /// already been built, [`None`] is returned.
    ///
    /// Use [`Self::replace()`] to build the new instance without a diff.
    pub fn patch(&mut self) -> Option<LoadedZonePatcher<'_>> {
        if self.built() {
            // Cannot build the instance again.
            return None;
        }

        // SAFETY: As per the caller, 'loaded[index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.loaded[self.index as usize].get() };

        // SAFETY: As per the caller, 'loaded[!index]' will not
        // be modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr = unsafe { &*self.data.loaded[!self.index as usize].get() };

        curr.soa.as_ref()?;

        // NOTE:
        // - 'curr' is complete, as checked above.
        // - 'next' is empty following 'ZoneBuilder::new()'.
        // - 'next' may be modified by 'LoadedZoneReplacer' or
        //   'LoadedZonePatcher', but they will set 'built_loaded' on success,
        //   and clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'diff' is empty, as checked by 'built()' above.
        Some(LoadedZonePatcher::new(curr, next, &mut self.diff))
    }

    /// Clear the current (loaded) instance.
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

        // Create the diff.
        if let Some(reader) = self.curr() {
            self.diff = Some(Box::new(DiffData {
                removed_soa: Some(reader.soa().clone()),
                added_soa: None,
                removed_records: reader.records().to_vec(),
                added_records: Vec::new(),
            }));
        } else {
            self.diff = Some(Box::new(DiffData::new()));
        }
    }

    /// The current (loaded) instance.
    ///
    /// The current loaded instance of the zone, if non-empty, can be accessed
    /// here. Note that [`LoadedZoneReplacer`] and [`LoadedZonePatcher`] also
    /// provide access to it.
    pub fn curr(&self) -> Option<LoadedZoneReader<'_>> {
        // SAFETY: As per the caller, 'loaded[!index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let curr = unsafe { &*self.data.loaded[!self.index as usize].get() };

        curr.soa.as_ref()?;

        // NOTE:
        // - 'curr' is complete, as checked above.
        Some(LoadedZoneReader::new(curr))
    }

    /// Whether a new (loaded) instance has been built.
    pub fn built(&self) -> bool {
        self.diff.is_some()
    }

    /// The new (loaded) instance.
    ///
    /// If a new instance instance has been built (with [`Self::replace()`] or
    /// [`Self::patch()`]), it can be accessed here. Note that empty instances
    /// (as built by [`Self::clear()`]) cannot be accessed.
    pub fn next(&self) -> Option<LoadedZoneReader<'_>> {
        if !self.built() {
            // A new instance has not been built.
            return None;
        }

        // SAFETY: As per the caller, 'loaded[index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let next = unsafe { &*self.data.loaded[self.index as usize].get() };

        next.soa.as_ref()?;

        // NOTE:
        // - 'next' is complete, as checked above.
        Some(LoadedZoneReader::new(next))
    }

    /// The diff of the new instance.
    ///
    /// If a new instance has been built (with [`Self::replace()`],
    /// [`Self::patch()`], or [`Self::clear()`]), its diff can be accessed here.
    /// The diff maps the current instance of the zone (even if it is empty) to
    /// the new instance (even if it is empty).
    pub fn diff(&self) -> Option<&DiffData> {
        self.diff.as_deref()
    }
}

impl LoadedZoneBuilder {
    /// Finish building the instance.
    ///
    /// If a new instance has been built (with [`Self::replace()`],
    /// [`Self::patch()`], or [`Self::clear()`]), a [`ZoneBuilt`] marker is
    /// returned to prove it. Otherwise, `self` is returned to try again.
    pub fn finish(self) -> Result<LoadedZoneBuilt, Self> {
        if self.built() {
            Ok(LoadedZoneBuilt {
                data: self.data,
                diff: Arc::new(*self.diff.unwrap()),
            })
        } else {
            Err(self)
        }
    }
}

//----------- SignedZoneBuilder ------------------------------------------------

/// A builder for a new signed instance of a zone.
///
/// [`SignedZoneBuilder`] is used to sign newly loaded instances of a zone and
/// re-sign existing signed instances. It offers read-only access to the current
/// (loaded and signed) instance of the zone, and (if any) the new loaded
/// instance of the zone, to support incremental signing.
pub struct SignedZoneBuilder {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the loaded instance to build into.
    ///
    /// ## Invariants
    ///
    /// - `loaded-next-access`: `data.loaded[loaded_index]` is sound to
    ///   access immutably for the lifetime of `self`.
    ///
    /// - `loaded-curr-access`: `data.loaded[!loaded_index]` is sound to
    ///   access immutably for the lifetime of `self`.
    ///
    /// - `loaded-built`: `data.loaded[loaded_index]` is complete if and
    ///   only if `loaded_diff` is `Some`.
    loaded_index: bool,

    /// The diff of the loaded instance.
    ///
    /// If a new loaded instance has been built, this field is `Some`, and it
    /// provides a diff mapping the current loaded instance to the new one.
    loaded_diff: Option<Arc<DiffData>>,

    /// The index of the signed instance to build into.
    ///
    /// ## Invariants
    ///
    /// - `signed-next-access`: `data.signed[signed_index]` is sound to access
    ///   mutably for the lifetime of `self`. It will not be accessed anywhere
    ///   else.
    ///
    /// - `signed-curr-access`: `data.signed[!signed_index]` is sound to access
    ///   immutably for the lifetime of `self`.
    ///
    /// - `signed-built`: `data.signed[signed_index]` is empty if (but not only
    ///   if) `signed_diff` is `None`.
    signed_index: bool,

    /// The diff of the built signed instance.
    ///
    /// If the new signed instance has been built, this field is `Some`, and it
    /// provides a diff mapping the current instance to the new one.
    //
    // TODO: It would be nice to use 'UniqueArc' here.
    signed_diff: Option<Box<DiffData>>,
}

impl SignedZoneBuilder {
    /// Construct a new [`SignedZoneBuilder`].
    ///
    /// ## Panics
    ///
    /// Panics **unless**:
    ///
    /// - If `data.signed[!signed_index]` is complete,
    ///   `data.loaded[!loaded_index]` must also be complete.
    ///
    /// - `data.signed[signed_index]` is empty.
    ///
    /// ## Safety
    ///
    /// `builder = SignedZoneBuilder::new(data, ...)` is sound if and only if
    /// all the following conditions are satisfied:
    ///
    /// - `data.loaded[!loaded_index]` will not be modified as long as `builder`
    ///   exists (starting from this function call).
    ///
    /// - `data.loaded[loaded_index]` will not be modified as long as `builder`
    ///   exists (starting from this function call).
    ///
    /// - `data.signed[!signed_index]` will not be modified as long as `builder`
    ///   exists (starting from this function call).
    ///
    /// - `data.signed[signed_index]` will not be accessed outside of
    ///   `builder` (starting from this function call).
    pub(crate) unsafe fn new(
        data: Arc<Data>,
        loaded_index: bool,
        signed_index: bool,
        loaded_diff: Option<Arc<DiffData>>,
    ) -> Self {
        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // modified elsewhere, and so is sound to access immutably.
        let next_loaded = unsafe { &*data.loaded[loaded_index as usize].get() };
        assert!(
            next_loaded.soa.is_none() || loaded_diff.is_some(),
            "'loaded_diff' was 'None', but a built loaded instance was found"
        );

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere, and so is sound to access immutably.
        let next_signed = unsafe { &*data.signed[signed_index as usize].get() };
        assert!(
            next_signed.soa.is_none(),
            "The specified signed instance is not empty"
        );

        // SAFETY: As per the caller, 'loaded[!loaded_index]' will not be
        // modified elsewhere, and so is sound to access immutably.
        let curr_loaded = unsafe { &*data.loaded[!loaded_index as usize].get() };
        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // modified elsewhere, and so is sound to access immutably.
        let curr_signed = unsafe { &*data.signed[!signed_index as usize].get() };
        assert!(
            curr_signed.soa.is_none() || curr_loaded.soa.is_some(),
            "A current signed instance exists without a current loaded instance"
        );

        // Invariants:
        //
        // - 'loaded-next-access' is guaranteed by the caller.
        // - 'loaded-curr-access' is guaranteed by the caller.
        // - 'loaded-built' was checked above.
        //
        // - 'signed-next-access' is guaranteed by the caller.
        // - 'signed-curr-access' is guaranteed by the caller.
        // - 'signed-built':
        //   - 'built_signed' is false.
        //   - 'signed[signed_index]' is empty as checked above.
        Self {
            data,
            loaded_index,
            loaded_diff,
            signed_index,
            signed_diff: None,
        }
    }

    /// The underlying data.
    pub(crate) const fn data(&self) -> &Arc<Data> {
        &self.data
    }
}

impl SignedZoneBuilder {
    /// The current loaded instance.
    ///
    /// The current loaded instance of the zone, if non-empty, can be accessed
    /// here. If [`Self::have_next_loaded()`] is `false`, this is the instance
    /// to be signed.
    pub fn curr_loaded(&self) -> Option<LoadedZoneReader<'_>> {
        // SAFETY: As per the caller, 'loaded[!loaded_index]' will not
        // be modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr = unsafe { &*self.data.loaded[!self.loaded_index as usize].get() };

        curr.soa.as_ref()?;

        // NOTE:
        // - 'curr' is complete, as checked above.
        Some(LoadedZoneReader::new(curr))
    }

    /// Whether a new loaded instance exists.
    ///
    /// If this is true, and the new loaded instance is non-empty,
    /// [`Self::next_loaded()`] will return `Some` and provide access to it.
    pub fn have_next_loaded(&self) -> bool {
        self.loaded_diff.is_some()
    }

    /// The new loaded instance (if any).
    ///
    /// If a new loaded instance has been prepared, and is non-empty, it can be
    /// accessed here. Check [`Self::have_next_loaded()`] to determine whether
    /// the new instance exists but is empty. Use [`Self::loaded_diff()`] to
    /// examine the differences between the current and new instances.
    pub fn next_loaded(&self) -> Option<LoadedZoneReader<'_>> {
        if !self.have_next_loaded() {
            // The loaded component has not been built.
            return None;
        }

        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let next = unsafe { &*self.data.loaded[self.loaded_index as usize].get() };

        next.soa.as_ref()?;

        // NOTE:
        // - 'next' is complete, as checked above.
        Some(LoadedZoneReader::new(next))
    }

    /// The diff of the built loaded component.
    ///
    /// If the loaded component of the zone has been built, and the current
    /// authoritative instance of the zone has a loaded component, the diff
    /// between the two (from the old instance to the new one) can be accessed
    /// here.
    pub fn loaded_diff(&self) -> Option<&Arc<DiffData>> {
        self.loaded_diff.as_ref()
    }
}

impl SignedZoneBuilder {
    /// Build the signed instance from scratch.
    ///
    /// A [`SignedZoneReplacer`] is returned, which can be used to write the new
    /// records in the zone. It also provides access to the signed component of
    /// the current authoritative instance of the zone (if any).
    ///
    /// If the signed zone has already been built, [`None`] is returned.
    pub fn replace(&mut self) -> Option<SignedZoneReplacer<'_>> {
        if self.built() {
            // Cannot build the signed component again.
            return None;
        }

        // SAFETY: As per the caller, 'loaded[!loaded_index]' will not
        // be modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr_loaded = unsafe { &*self.data.loaded[!self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let next_loaded = self
            .have_next_loaded()
            .then(|| unsafe { &*self.data.loaded[self.loaded_index as usize].get() });

        let loaded_diff = self.loaded_diff.as_ref();

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.signed[self.signed_index as usize].get() };

        // SAFETY: As per the caller, 'signed[!signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let curr = unsafe { &*self.data.signed[!self.signed_index as usize].get() };

        // NOTE:
        // - 'next' is empty following 'SignedZoneBuilder::new()'.
        // - 'next' may be modified by 'SignedZoneReplacer' or
        //   'SignedZonePatcher', but they will set 'built_signed' on success,
        //   and clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'built_signed' is false, as checked above.
        // - 'diff' is only set if 'built_signed' is true.
        Some(SignedZoneReplacer::new(
            curr_loaded,
            next_loaded,
            loaded_diff,
            curr,
            next,
            &mut self.signed_diff,
        ))
    }

    /// Patch the current signed instance.
    ///
    /// A [`SignedZonePatcher`] is returned, through which a diff can be
    /// applied to signed component of the current instance of the zone. This is
    /// ideal for incremental signing.
    ///
    /// If the current instance of the zone does not have a signed component,
    /// or the signed zone has already been built, [`None`] is returned.
    pub fn patch(&mut self) -> Option<SignedZonePatcher<'_>> {
        if self.built() {
            // Cannot build the signed component again.
            return None;
        }

        // SAFETY: As per the caller, 'loaded[!loaded_index]' will not
        // be modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr_loaded = unsafe { &*self.data.loaded[!self.loaded_index as usize].get() };

        // SAFETY: As per the caller, 'loaded[loaded_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let next_loaded = self
            .have_next_loaded()
            .then(|| unsafe { &*self.data.loaded[self.loaded_index as usize].get() });

        let loaded_diff = self.loaded_diff.as_ref();

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.signed[self.signed_index as usize].get() };

        // SAFETY: As per the caller, 'signed[!signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let curr = unsafe { &*self.data.signed[!self.signed_index as usize].get() };

        curr.soa.as_ref()?;

        // NOTE:
        // - 'curr' is complete, as checked above.
        // - 'next' is empty following 'SignedZoneBuilder::new()'.
        // - 'next' may be modified by 'SignedZoneReplacer' or
        //   'SignedZonePatcher', but they will set 'built_signed' on success,
        //   and clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'built_signed' is false, as checked above.
        // - 'diff' is only set if 'built_signed' is true.
        Some(SignedZonePatcher::new(
            curr_loaded,
            next_loaded,
            loaded_diff,
            curr,
            next,
            &mut self.signed_diff,
        ))
    }

    /// Clear the signed instance.
    ///
    /// The instance is created, but is empty.
    pub fn clear(&mut self) {
        // Initialize the absolute data.

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.signed[self.signed_index as usize].get() };
        next.soa = None;
        next.records.clear();

        // Create the diff.
        if let Some(reader) = self.curr_signed() {
            self.signed_diff = Some(Box::new(DiffData {
                removed_soa: Some(reader.soa().clone()),
                added_soa: None,
                removed_records: reader.records().to_vec(),
                added_records: Vec::new(),
            }));
        } else {
            self.signed_diff = Some(Box::new(DiffData::new()));
        }
    }

    /// The signed component of the current instance of the zone.
    ///
    /// If the current authoritative instance of the zone has a signed
    /// component, it can be accessed here. Note that [`SignedZoneReplacer`] and
    /// [`SignedZonePatcher`] also provide access to this component.
    pub fn curr_signed(&self) -> Option<SignedZoneReader<'_>> {
        // SAFETY: As per the caller, 'signed[!signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let curr = unsafe { &*self.data.signed[!self.signed_index as usize].get() };

        curr.soa.as_ref()?;

        // NOTE:
        // - 'curr' is complete, as checked above.
        Some(SignedZoneReader::new(curr))
    }

    /// Whether the (signed) instance has been built.
    pub fn built(&self) -> bool {
        self.signed_diff.is_some()
    }

    /// The built signed component.
    ///
    /// If the signed component of the zone has been built, and it exists, it
    /// can be accessed here.
    pub fn next_signed(&self) -> Option<SignedZoneReader<'_>> {
        if !self.built() {
            // The signed component has not been built.
            return None;
        }

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let next = unsafe { &*self.data.signed[self.signed_index as usize].get() };

        next.soa.as_ref()?;

        // NOTE:
        // - 'next' is complete, as checked above.
        Some(SignedZoneReader::new(next))
    }

    /// The diff of the built signed component.
    ///
    /// If the signed component of the zone has been built, and the current
    /// authoritative instance of the zone has a signed component, the diff
    /// between the two (from the old instance to the new one) can be accessed
    /// here.
    pub fn signed_diff(&self) -> Option<&DiffData> {
        self.signed_diff.as_deref()
    }
}

impl SignedZoneBuilder {
    /// Finish building the instance.
    ///
    /// If the signed component of the zone has been built, a
    /// [`SignedZoneBuilt`] marker is returned to prove it. Otherwise, `self`
    /// is returned.
    pub fn finish(self) -> Result<SignedZoneBuilt, Self> {
        if self.built() {
            Ok(SignedZoneBuilt {
                data: self.data,
                diff: Arc::new(*self.signed_diff.unwrap()),
            })
        } else {
            Err(self)
        }
    }
}

//----------- LoadedZoneBuilt ------------------------------------------------

/// Proof that the loaded component of a zone has been built.
pub struct LoadedZoneBuilt {
    /// The underlying data.
    pub(crate) data: Arc<Data>,

    /// The diff.
    pub(crate) diff: Arc<DiffData>,
}

//----------- SignedZoneBuilt --------------------------------------------------

/// Proof that the signed component of a zone has been built.
pub struct SignedZoneBuilt {
    /// The underlying data.
    pub(crate) data: Arc<Data>,

    /// The diff.
    pub(crate) diff: Arc<DiffData>,
}
