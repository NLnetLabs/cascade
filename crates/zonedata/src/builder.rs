//! Building new instances of zones.
//!
//! This module provides high-level types through which new instances of
//! zones can be built. These types account for concurrent access to zones,
//! and are part of the zone instance lifecycle. They provide types from the
//! [`crate::writer`] module for performing the actual writing.

use std::sync::Arc;

use crate::{
    Data, DiffData, SignedZonePatcher, SignedZoneReader, SignedZoneReplacer, UnsignedZonePatcher,
    UnsignedZoneReader, UnsignedZoneReplacer,
};

//----------- ZoneBuilder ------------------------------------------------------

/// A builder for a new instance of a zone.
///
/// [`ZoneBuilder`] offers write access to a new instance of a zone, allowing
/// its unsigned and signed components to be written. It offers read-only access
/// to the current authoritative instance of the zone, so that the new instance
/// can be built relative to the old one.
pub struct ZoneBuilder {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the unsigned component to build into.
    ///
    /// ## Invariants
    ///
    /// - `unsigned-next-access`: `data.unsigned[unsigned_index]` is sound to
    ///   access mutably for the lifetime of `self`. It will not be accessed
    ///   anywhere else.
    ///
    /// - `unsigned-curr-access`: `data.unsigned[!unsigned_index]` is sound to
    ///   access immutably for the lifetime of `self`.
    ///
    /// - `unsigned-built`: `data.unsigned[unsigned_index]` is empty if (but
    ///   not only if) `unsigned_diff` is `None`.
    unsigned_index: bool,

    /// The diff of the built unsigned component.
    ///
    /// If the unsigned component has been built, and the current authoritative
    /// instance of the zone has an unsigned component, this field provides the
    /// diff from that older instance to the built one.
    ///
    /// If this is `Some`, the unsigned component has been prepared, and will
    /// not be modified further.
    unsigned_diff: Option<Box<DiffData>>,

    /// The index of the signed component to build into.
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

    /// The diff of the built signed component.
    ///
    /// If the signed component has been built, and the current authoritative
    /// instance of the zone has a signed component, this field provides the
    /// diff from that older instance to the built one.
    ///
    /// If this is `Some`, the signed component has been prepared, and will not
    /// be modified further.
    signed_diff: Option<Box<DiffData>>,
}

impl ZoneBuilder {
    /// Construct a new [`ZoneBuilder`].
    ///
    /// ## Panics
    ///
    /// Panics **unless**:
    ///
    /// - If `data.signed[!signed_index]` is complete,
    ///   `data.unsigned[!unsigned_index]` must also be complete.
    ///
    /// - `data.unsigned[unsigned_index]` is empty.
    ///
    /// - `data.signed[signed_index]` is empty.
    ///
    /// ## Safety
    ///
    /// `builder = ZoneBuilder::new(data, unsigned_index, signed_index)` is
    /// sound if and only if all the following conditions are satisfied:
    ///
    /// - `data.unsigned[!unsigned_index]` will not be modified as long as
    ///   `builder` exists (starting from this function call).
    ///
    /// - `data.unsigned[unsigned_index]` will not be accessed outside of
    ///   `builder` (starting from this function call).
    ///
    /// - `data.signed[!signed_index]` will not be modified as long as `builder`
    ///   exists (starting from this function call).
    ///
    /// - `data.signed[signed_index]` will not be accessed outside of `builder`
    ///   (starting from this function call).
    pub(crate) unsafe fn new(data: Arc<Data>, unsigned_index: bool, signed_index: bool) -> Self {
        // SAFETY: As per the caller, 'unsigned[unsigned_index]' will not be
        // accessed elsewhere, and so is sound to access immutably.
        let next_unsigned = unsafe { &*data.unsigned[unsigned_index as usize].get() };
        assert!(
            next_unsigned.soa.is_none(),
            "The specified unsigned instance is not empty"
        );

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere, and so is sound to access immutably.
        let next_signed = unsafe { &*data.signed[signed_index as usize].get() };
        assert!(
            next_signed.soa.is_none(),
            "The specified signed instance is not empty"
        );

        // SAFETY: As per the caller, 'unsigned[!unsigned_index]' will not be
        // modified elsewhere, and so is sound to access immutably.
        let curr_unsigned = unsafe { &*data.unsigned[!unsigned_index as usize].get() };
        // SAFETY: As per the caller, 'signed[!signed_index]' will not be
        // modified elsewhere, and so is sound to access immutably.
        let curr_signed = unsafe { &*data.signed[!signed_index as usize].get() };
        assert!(
            curr_signed.soa.is_none() || curr_unsigned.soa.is_some(),
            "A current signed instance exists without a current unsigned instance"
        );

        // Invariants:
        //
        // - 'unsigned-next-access' is guaranteed by the caller.
        // - 'unsigned-curr-access' is guaranteed by the caller.
        // - 'unsigned-built':
        //   - 'built_unsigned' is false.
        //   - 'unsigned[unsigned_index]' is empty as checked above.
        //
        // - 'signed-next-access' is guaranteed by the caller.
        // - 'signed-curr-access' is guaranteed by the caller.
        // - 'signed-built':
        //   - 'built_signed' is false.
        //   - 'signed[signed_index]' is empty as checked above.
        Self {
            data,
            unsigned_index,
            unsigned_diff: None,
            signed_index,
            signed_diff: None,
        }
    }

    /// The underlying data.
    pub(crate) const fn data(&self) -> &Arc<Data> {
        &self.data
    }
}

impl ZoneBuilder {
    /// Build the unsigned instance from scratch.
    ///
    /// An [`UnsignedZoneReplacer`] is returned, which can be used to write
    /// the new records in the zone. It also provides access to the unsigned
    /// component of the current authoritative instance of the zone (if any).
    ///
    /// If the unsigned zone has already been built, [`None`] is returned.
    pub fn replace_unsigned(&mut self) -> Option<UnsignedZoneReplacer<'_>> {
        if self.built_unsigned() {
            // Cannot build the unsigned component again.
            return None;
        }

        // SAFETY: As per the caller, 'unsigned[unsigned_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.unsigned[self.unsigned_index as usize].get() };

        // SAFETY: As per the caller, 'unsigned[!unsigned_index]' will not
        // be modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr = unsafe { &*self.data.unsigned[!self.unsigned_index as usize].get() };

        // NOTE:
        // - 'next' is empty following 'ZoneBuilder::new()'.
        // - 'next' may be modified by 'UnsignedZoneReplacer' or
        //   'UnsignedZonePatcher', but they will set 'built_unsigned' on
        //   success, and clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'built_unsigned' is false, as checked above.
        // - 'diff' is only set if 'built_unsigned' is true.
        Some(UnsignedZoneReplacer::new(
            curr,
            next,
            &mut self.unsigned_diff,
        ))
    }

    /// Patch the current unsigned instance.
    ///
    /// An [`UnsignedZonePatcher`] is returned, through which a diff can be
    /// applied to unsigned component of the current instance of the zone. This
    /// is ideal for applying an IXFR.
    ///
    /// If the current instance of the zone does not have an unsigned component,
    /// or the unsigned zone has already been built, [`None`] is returned.
    pub fn patch_unsigned(&mut self) -> Option<UnsignedZonePatcher<'_>> {
        if self.built_unsigned() {
            // Cannot build the unsigned component again.
            return None;
        }

        // SAFETY: As per the caller, 'unsigned[unsigned_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.unsigned[self.unsigned_index as usize].get() };

        // SAFETY: As per the caller, 'unsigned[!unsigned_index]' will not
        // be modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr = unsafe { &*self.data.unsigned[!self.unsigned_index as usize].get() };

        curr.soa.as_ref()?;

        // NOTE:
        // - 'curr' is complete, as checked above.
        // - 'next' is empty following 'ZoneBuilder::new()'.
        // - 'next' may be modified by 'UnsignedZoneReplacer' or
        //   'UnsignedZonePatcher', but they will set 'built_unsigned' on
        //   success, and clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'built_unsigned' is false, as checked above.
        // - 'diff' is only set if 'built_unsigned' is true.
        Some(UnsignedZonePatcher::new(
            curr,
            next,
            &mut self.unsigned_diff,
        ))
    }

    /// Clear the unsigned instance.
    ///
    /// The instance is created, but is empty.
    pub fn clear_unsigned(&mut self) {
        // Initialize the absolute data.

        // SAFETY: As per the caller, 'unsigned[unsigned_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.unsigned[self.unsigned_index as usize].get() };
        next.soa = None;
        next.records.clear();

        // Create the diff.
        if let Some(reader) = self.curr_unsigned() {
            self.unsigned_diff = Some(Box::new(DiffData {
                removed_soa: Some(reader.soa().clone()),
                added_soa: None,
                removed_records: reader.records().to_vec(),
                added_records: Vec::new(),
            }));
        } else {
            self.unsigned_diff = Some(Box::new(DiffData::new()));
        }
    }

    /// The unsigned component of the current instance of the zone.
    ///
    /// If the current authoritative instance of the zone has an unsigned
    /// component, it can be accessed here. Note that [`UnsignedZoneReplacer`]
    /// and [`UnsignedZonePatcher`] also provide access to this component.
    pub fn curr_unsigned(&self) -> Option<UnsignedZoneReader<'_>> {
        // SAFETY: As per the caller, 'unsigned[!unsigned_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let curr = unsafe { &*self.data.unsigned[!self.unsigned_index as usize].get() };

        curr.soa.as_ref()?;

        // NOTE:
        // - 'curr' is complete, as checked above.
        Some(UnsignedZoneReader::new(curr))
    }

    /// Whether the unsigned component has been built.
    pub fn built_unsigned(&self) -> bool {
        self.unsigned_diff.is_some()
    }

    /// The built unsigned component.
    ///
    /// If the unsigned component of the zone has been built, and it exists, it
    /// can be accessed here.
    pub fn next_unsigned(&self) -> Option<UnsignedZoneReader<'_>> {
        if !self.built_unsigned() {
            // The unsigned component has not been built.
            return None;
        }

        // SAFETY: As per the caller, 'unsigned[unsigned_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let next = unsafe { &*self.data.unsigned[self.unsigned_index as usize].get() };

        next.soa.as_ref()?;

        // NOTE:
        // - 'next' is complete, as checked above.
        Some(UnsignedZoneReader::new(next))
    }

    /// The diff of the built unsigned component.
    ///
    /// If the unsigned component of the zone has been built, and the current
    /// authoritative instance of the zone has an unsigned component, the diff
    /// between the two (from the old instance to the new one) can be accessed
    /// here.
    pub fn unsigned_diff(&self) -> Option<&DiffData> {
        self.unsigned_diff.as_deref()
    }
}

impl ZoneBuilder {
    /// Build the signed instance from scratch.
    ///
    /// A [`SignedZoneReplacer`] is returned, which can be used to write the new
    /// records in the zone. It also provides access to the signed component of
    /// the current authoritative instance of the zone (if any).
    ///
    /// If the signed zone has already been built, [`None`] is returned.
    pub fn replace_signed(&mut self) -> Option<SignedZoneReplacer<'_>> {
        if self.built_signed() {
            // Cannot build the signed component again.
            return None;
        }

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.signed[self.signed_index as usize].get() };

        // SAFETY: As per the caller, 'signed[!signed_index]' will not be
        // modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr = unsafe { &*self.data.signed[!self.signed_index as usize].get() };

        // NOTE:
        // - 'next' is empty following 'ZoneBuilder::new()'.
        // - 'next' may be modified by 'SignedZoneReplacer' or
        //   'SignedZonePatcher', but they will set 'built_signed' on success,
        //   and clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'built_signed' is false, as checked above.
        // - 'diff' is only set if 'built_signed' is true.
        Some(SignedZoneReplacer::new(curr, next, &mut self.signed_diff))
    }

    /// Patch the current signed instance.
    ///
    /// An [`SignedZonePatcher`] is returned, through which a diff can be
    /// applied to signed component of the current instance of the zone. This is
    /// ideal for applying an IXFR.
    ///
    /// If the current instance of the zone does not have a signed component,
    /// or the signed zone has already been built, [`None`] is returned.
    pub fn patch_signed(&mut self) -> Option<SignedZonePatcher<'_>> {
        if self.built_signed() {
            // Cannot build the signed component again.
            return None;
        }

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access mutably.
        let next = unsafe { &mut *self.data.signed[self.signed_index as usize].get() };

        // SAFETY: As per the caller, 'signed[!signed_index]' will not be
        // modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr = unsafe { &*self.data.signed[!self.signed_index as usize].get() };

        curr.soa.as_ref()?;

        // NOTE:
        // - 'curr' is complete, as checked above.
        // - 'next' is empty following 'ZoneBuilder::new()'.
        // - 'next' may be modified by 'SignedZoneReplacer' or
        //   'SignedZonePatcher', but they will set 'built_signed' on success,
        //   and clean up 'next' on failure (in drop).
        // - 'next' is only non-empty if a patcher/replacer was leaked, in which
        //   case a panic is appropriate.
        // - 'built_signed' is false, as checked above.
        // - 'diff' is only set if 'built_signed' is true.
        Some(SignedZonePatcher::new(curr, next, &mut self.signed_diff))
    }

    /// Clear the signed instance.
    ///
    /// The instance is created, but is empty.
    pub fn clear_signed(&mut self) {
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

    /// Whether the signed component has been built.
    pub fn built_signed(&self) -> bool {
        self.signed_diff.is_some()
    }

    /// The built signed component.
    ///
    /// If the signed component of the zone has been built, and it exists, it
    /// can be accessed here.
    pub fn next_signed(&self) -> Option<SignedZoneReader<'_>> {
        if !self.built_signed() {
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

impl ZoneBuilder {
    /// Finish building the complete instance.
    ///
    /// If both the unsigned and signed components of the zone have been built,
    /// a [`ZoneBuilt`] marker is returned to prove it. Otherwise, `self` is
    /// returned.
    pub fn finish(self) -> Result<ZoneBuilt, Self> {
        if self.built_unsigned() && self.built_signed() {
            Ok(ZoneBuilt {
                data: self.data,
                unsigned_diff: self.unsigned_diff.unwrap(),
                signed_diff: self.signed_diff.unwrap(),
            })
        } else {
            Err(self)
        }
    }

    /// Finish building (the unsigned component of) the instance.
    ///
    /// If the unsigned component of the zone has been built, **and not the
    /// signed component**, an [`UnsignedZoneBuilt`] marker is returned to prove
    /// it. Otherwise, `self` is returned.
    pub fn finish_unsigned(self) -> Result<UnsignedZoneBuilt, Self> {
        if self.built_unsigned() && !self.built_signed() {
            Ok(UnsignedZoneBuilt {
                data: self.data,
                unsigned_diff: self.unsigned_diff.unwrap(),
            })
        } else {
            Err(self)
        }
    }
}

//----------- SignedZoneBuilder ------------------------------------------------

/// A builder for a new signed instance of a zone.
///
/// [`SignedZoneBuilder`] offers write access to a new instance of a zone,
/// allowing its signed component to be written. It offers read-only access
/// to the current authoritative instance of the zone, and the new unsigned
/// component, so that the new instance can be built relative to the old one.
pub struct SignedZoneBuilder {
    /// The underlying data.
    data: Arc<Data>,

    /// The index of the unsigned component to build into.
    ///
    /// ## Invariants
    ///
    /// - `unsigned-next-access`: `data.unsigned[unsigned_index]` is sound to
    ///   access immutably for the lifetime of `self`.
    ///
    /// - `unsigned-curr-access`: `data.unsigned[!unsigned_index]` is sound to
    ///   access immutably for the lifetime of `self`.
    ///
    /// - `unsigned-built`: `data.unsigned[unsigned_index]` is complete if and
    ///   only if `unsigned_diff` is `Some`.
    unsigned_index: bool,

    /// The diff of the built unsigned component.
    ///
    /// If the unsigned component has been built, and the current authoritative
    /// instance of the zone has an unsigned component, this field provides the
    /// diff from that older instance to the built one.
    unsigned_diff: Option<Arc<DiffData>>,

    /// The index of the signed component to build into.
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

    /// The diff of the built signed component.
    ///
    /// If the signed component has been built, and the current authoritative
    /// instance of the zone has a signed component, this field provides the
    /// diff from that older instance to the built one.
    ///
    /// If this is `Some`, the signed component has been prepared, and will not
    /// be modified further.
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
    ///   `data.unsigned[!unsigned_index]` must also be complete.
    ///
    /// - `data.signed[signed_index]` is empty.
    ///
    /// ## Safety
    ///
    /// `SignedZoneBuilder::new()` is sound if and only if all the following
    /// conditions are satisfied:
    ///
    /// - `data.unsigned[!unsigned_index]` will not be modified as long as
    ///   `builder` exists (starting from this function call).
    ///
    /// - `data.unsigned[unsigned_index]` will not be accessed outside of
    ///   `builder` (starting from this function call).
    ///
    /// - `data.signed[!signed_index]` will not be modified as long as `builder`
    ///   exists (starting from this function call).
    ///
    /// - `data.signed[signed_index]` will not be modified as long as `builder`
    ///   exists (starting from this function call).
    pub(crate) unsafe fn new(
        data: Arc<Data>,
        unsigned_index: bool,
        signed_index: bool,
        unsigned_diff: Option<Arc<DiffData>>,
    ) -> Self {
        // SAFETY: As per the caller, 'unsigned[unsigned_index]' will not be
        // modified elsewhere, and so is sound to access immutably.
        let next_unsigned = unsafe { &*data.unsigned[unsigned_index as usize].get() };
        assert!(
            next_unsigned.soa.is_none() || unsigned_diff.is_some(),
            "'unsigned_diff' was 'None', but a built unsigned instance was found"
        );

        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // accessed elsewhere, and so is sound to access immutably.
        let next_signed = unsafe { &*data.signed[signed_index as usize].get() };
        assert!(
            next_signed.soa.is_none(),
            "The specified signed instance is not empty"
        );

        // SAFETY: As per the caller, 'unsigned[!unsigned_index]' will not be
        // modified elsewhere, and so is sound to access immutably.
        let curr_unsigned = unsafe { &*data.unsigned[!unsigned_index as usize].get() };
        // SAFETY: As per the caller, 'signed[signed_index]' will not be
        // modified elsewhere, and so is sound to access immutably.
        let curr_signed = unsafe { &*data.signed[!signed_index as usize].get() };
        assert!(
            curr_signed.soa.is_none() || curr_unsigned.soa.is_some(),
            "A current signed instance exists without a current unsigned instance"
        );

        // Invariants:
        //
        // - 'unsigned-next-access' is guaranteed by the caller.
        // - 'unsigned-curr-access' is guaranteed by the caller.
        // - 'unsigned-built' was checked above.
        //
        // - 'signed-next-access' is guaranteed by the caller.
        // - 'signed-curr-access' is guaranteed by the caller.
        // - 'signed-built':
        //   - 'built_signed' is false.
        //   - 'signed[signed_index]' is empty as checked above.
        Self {
            data,
            unsigned_index,
            unsigned_diff,
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
    /// The unsigned component of the current instance of the zone.
    ///
    /// If the current authoritative instance of the zone has an unsigned
    /// component, it can be accessed here. Note that [`UnsignedZoneReplacer`]
    /// and [`UnsignedZonePatcher`] also provide access to this component.
    pub fn curr_unsigned(&self) -> Option<UnsignedZoneReader<'_>> {
        // SAFETY: As per the caller, 'unsigned[!unsigned_index]' will not
        // be modified for the lifetime of 'self', and so is sound to access
        // immutably.
        let curr = unsafe { &*self.data.unsigned[!self.unsigned_index as usize].get() };

        curr.soa.as_ref()?;

        // NOTE:
        // - 'curr' is complete, as checked above.
        Some(UnsignedZoneReader::new(curr))
    }

    /// Whether a new unsigned component has been built.
    pub fn built_unsigned(&self) -> bool {
        self.unsigned_diff.is_some()
    }

    /// The built unsigned component.
    ///
    /// If the unsigned component of the zone has been built, and it exists, it
    /// can be accessed here.
    pub fn next_unsigned(&self) -> Option<UnsignedZoneReader<'_>> {
        if !self.built_unsigned() {
            // The unsigned component has not been built.
            return None;
        }

        // SAFETY: As per the caller, 'unsigned[unsigned_index]' will not be
        // accessed elsewhere for the lifetime of 'self', and so is sound to
        // access immutably.
        let next = unsafe { &*self.data.unsigned[self.unsigned_index as usize].get() };

        next.soa.as_ref()?;

        // NOTE:
        // - 'next' is complete, as checked above.
        Some(UnsignedZoneReader::new(next))
    }

    /// The diff of the built unsigned component.
    ///
    /// If the unsigned component of the zone has been built, and the current
    /// authoritative instance of the zone has an unsigned component, the diff
    /// between the two (from the old instance to the new one) can be accessed
    /// here.
    pub fn unsigned_diff(&self) -> Option<&Arc<DiffData>> {
        self.unsigned_diff.as_ref()
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
    pub fn replace_signed(&mut self) -> Option<SignedZoneReplacer<'_>> {
        if self.built_signed() {
            // Cannot build the signed component again.
            return None;
        }

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
        Some(SignedZoneReplacer::new(curr, next, &mut self.signed_diff))
    }

    /// Patch the current signed instance.
    ///
    /// An [`SignedZonePatcher`] is returned, through which a diff can be
    /// applied to signed component of the current instance of the zone. This is
    /// ideal for applying an IXFR.
    ///
    /// If the current instance of the zone does not have a signed component,
    /// or the signed zone has already been built, [`None`] is returned.
    pub fn patch_signed(&mut self) -> Option<SignedZonePatcher<'_>> {
        if self.built_signed() {
            // Cannot build the signed component again.
            return None;
        }

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
        Some(SignedZonePatcher::new(curr, next, &mut self.signed_diff))
    }

    /// Clear the signed instance.
    ///
    /// The instance is created, but is empty.
    pub fn clear_signed(&mut self) {
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

    /// Whether the signed component has been built.
    pub fn built_signed(&self) -> bool {
        self.signed_diff.is_some()
    }

    /// The built signed component.
    ///
    /// If the signed component of the zone has been built, and it exists, it
    /// can be accessed here.
    pub fn next_signed(&self) -> Option<SignedZoneReader<'_>> {
        if !self.built_signed() {
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
        if self.built_signed() {
            Ok(SignedZoneBuilt {
                data: self.data,
                signed_diff: self.signed_diff.unwrap(),
            })
        } else {
            Err(self)
        }
    }
}

//----------- UnsignedZoneBuilt ------------------------------------------------

/// Proof that the unsigned component of a zone has been built.
pub struct UnsignedZoneBuilt {
    /// The underlying data.
    pub(crate) data: Arc<Data>,

    /// The unsigned diff.
    pub(crate) unsigned_diff: Box<DiffData>,
}

//----------- ZoneBuilt --------------------------------------------------------

/// Proof that (all components of) a zone has been built.
pub struct ZoneBuilt {
    /// The underlying data.
    pub(crate) data: Arc<Data>,

    /// The unsigned diff.
    pub(crate) unsigned_diff: Box<DiffData>,

    /// The signed diff.
    pub(crate) signed_diff: Box<DiffData>,
}

//----------- SignedZoneBuilt --------------------------------------------------

/// Proof that the signed component of a zone has been built.
pub struct SignedZoneBuilt {
    /// The underlying data.
    pub(crate) data: Arc<Data>,

    /// The signed diff.
    pub(crate) signed_diff: Box<DiffData>,
}
