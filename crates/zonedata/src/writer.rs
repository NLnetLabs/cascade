//! Writing instances of zones.
//!
//! This module provides [`UnsignedZoneReplacer`], [`UnsignedZonePatcher`],
//! [`SignedZoneReplacer`], and [`SignedZonePatcher`]. These are simple safe
//! interfaces through which new instances zones can be written. These types do
//! not consider the concurrent access different instances of zone data; they
//! are limited to considering a single instance. They offer concurrency, but
//! only for parallelizing the writing of the zone, for efficiency.

use std::fmt;

use crate::{
    DiffData, InstanceData, RegularRecord, SignedZoneReader, SoaRecord, UnsignedZoneReader, merge,
};

//----------- UnsignedZoneReplacer ---------------------------------------------

/// A writer building an unsigned instance of a zone from scratch.
///
/// If the writer is dropped without calling [`apply()`](Self::apply()), all
/// pending changes will be erased.
pub struct UnsignedZoneReplacer<'d> {
    /// The current authoritative instance, if any.
    curr: &'d InstanceData,

    /// The instance being built.
    next: &'d mut InstanceData,

    /// The built diff.
    ///
    /// This exists iff building succeeds.
    diff: &'d mut Option<DiffData>,
}

impl<'d> UnsignedZoneReplacer<'d> {
    /// Construct a new [`UnsignedZoneReplacer`].
    ///
    /// ## Panics
    ///
    /// Panics if `next` is not empty or `diff` is [`Some`].
    pub(crate) const fn new(
        curr: &'d InstanceData,
        next: &'d mut InstanceData,
        diff: &'d mut Option<DiffData>,
    ) -> Self {
        assert!(next.soa.is_none(), "'next' is not empty");
        assert!(diff.is_none());

        Self { curr, next, diff }
    }

    /// Read the current authoritative instance data (if any).
    pub const fn curr(&self) -> Option<UnsignedZoneReader<'d>> {
        if self.curr.soa.is_none() {
            return None;
        }

        Some(UnsignedZoneReader::new(self.curr))
    }

    /// Set the SOA record.
    pub fn set_soa(&mut self, soa: SoaRecord) -> Result<(), ReplaceError> {
        if self.next.soa.is_some() {
            return Err(ReplaceError::MultipleSoas);
        }

        self.next.soa = Some(soa);
        Ok(())
    }

    /// Add a regular record.
    pub fn add(&mut self, record: RegularRecord) -> Result<(), ReplaceError> {
        self.next.records.push(record);
        Ok(())
    }

    /// Finish and apply the collected changes.
    ///
    /// The changes will be checked for consistency and applied to the upcoming
    /// unsigned instance.
    pub fn apply(self) -> Result<(), ReplaceError> {
        *self.diff = Some(apply_replacement(self.curr, self.next)?);

        Ok(())
    }
}

impl Drop for UnsignedZoneReplacer<'_> {
    /// Erase all pending changes.
    fn drop(&mut self) {
        if self.diff.is_some() {
            // The changes were built successfully.
            return;
        }

        // Clean up 'self.next'.
        self.next.soa = None;
        self.next.records.clear();
    }
}

//----------- UnsignedZonePatcher ----------------------------------------------

/// A writer building an unsigned instance of a zone from a diff.
///
/// If the writer is dropped without calling [`apply()`](Self::apply()), all
/// pending changes will be erased.
pub struct UnsignedZonePatcher<'d> {
    /// The authoritative instance.
    curr: &'d InstanceData,

    /// The upcoming instance.
    next: &'d mut InstanceData,

    /// The built diff.
    diff: &'d mut Option<DiffData>,

    /// An accumulated diff.
    accumulated: DiffData,

    /// The diff being built right now.
    immediate: DiffData,
}

impl<'d> UnsignedZonePatcher<'d> {
    /// Construct a new [`UnsignedZonePatcher`].
    ///
    /// ## Panics
    ///
    /// Panics **unless**:
    /// - `curr` is complete.
    /// - `next` is empty.
    /// - `diff` is `None`.
    pub(crate) const fn new(
        curr: &'d InstanceData,
        next: &'d mut InstanceData,
        diff: &'d mut Option<DiffData>,
    ) -> Self {
        assert!(curr.soa.is_some());
        assert!(next.soa.is_none());
        assert!(diff.is_none());

        Self {
            curr,
            next,
            diff,
            accumulated: DiffData::new(),
            immediate: DiffData::new(),
        }
    }

    /// Read the current authoritative instance data.
    pub const fn curr(&self) -> UnsignedZoneReader<'d> {
        UnsignedZoneReader::new(self.curr)
    }

    /// Remove the previous SOA record.
    pub fn remove_soa(&mut self, soa: SoaRecord) -> Result<(), PatchError> {
        if self.immediate.removed_soa.is_some() {
            return Err(PatchError::Inconsistency);
        }

        self.immediate.removed_soa = Some(soa);
        Ok(())
    }

    /// Add the new SOA record.
    pub fn add_soa(&mut self, soa: SoaRecord) -> Result<(), PatchError> {
        if self.immediate.added_soa.is_some() {
            return Err(PatchError::MultipleSoasAdded);
        }

        self.immediate.added_soa = Some(soa);
        Ok(())
    }

    /// Remove a previous regular record.
    pub fn remove(&mut self, record: RegularRecord) -> Result<(), PatchError> {
        self.immediate.removed_records.push(record);
        Ok(())
    }

    /// Add a new regular record.
    pub fn add(&mut self, record: RegularRecord) -> Result<(), PatchError> {
        self.immediate.added_records.push(record);
        Ok(())
    }

    /// Move to the next patchset.
    ///
    /// The records added and removed (including SOA) since the last call to
    /// [`Self::next_patchset()`] are considered as a single unit, a _patchset_.
    /// This patchset will be applied, on top of all previous patchsets, to the
    /// current authoritative instance.
    ///
    /// Patchsets occur, for example, in IXFRs; a single IXFR response can
    /// contain multiple distinct diffs, and later diffs may undo the changes
    /// caused by earlier ones. A whole IXFR can be consumed by calling this
    /// method after consuming each diff.
    pub fn next_patchset(&mut self) -> Result<(), PatchError> {
        next_patchset(self.curr, &mut self.immediate, &mut self.accumulated)
    }

    /// Finish and apply the collected changes.
    ///
    /// The changes will be checked for consistency and applied to the upcoming
    /// unsigned instance.
    pub fn apply(mut self) -> Result<(), PatchError> {
        // If there are pending changes, complete them.
        if !self.immediate.is_empty() {
            self.next_patchset()?;
        }

        *self.diff = Some(apply_patches(self.curr, self.next, &mut self.accumulated)?);

        Ok(())
    }
}

impl Drop for UnsignedZonePatcher<'_> {
    /// Erase all pending changes.
    fn drop(&mut self) {
        if self.diff.is_some() {
            // The changes were built successfully.
            return;
        }

        // Clean up 'self.next'.
        self.next.soa = None;
        self.next.records.clear();
    }
}

//----------- SignedZoneReplacer -----------------------------------------------

/// A writer building a signed instance of a zone from scratch.
///
/// If the writer is dropped without calling [`apply()`](Self::apply()), all
/// pending changes will be erased.
pub struct SignedZoneReplacer<'d> {
    /// The current authoritative instance, if any.
    curr: &'d InstanceData,

    /// The instance being built.
    next: &'d mut InstanceData,

    /// The built diff.
    ///
    /// This exists iff `curr.is_some()` and building succeeds.
    diff: &'d mut Option<DiffData>,
}

impl<'d> SignedZoneReplacer<'d> {
    /// Construct a new [`SignedZoneReplacer`].
    ///
    /// ## Panics
    ///
    /// Panics if `next` is not empty, or `diff` is [`Some`].
    pub(crate) const fn new(
        curr: &'d InstanceData,
        next: &'d mut InstanceData,
        diff: &'d mut Option<DiffData>,
    ) -> Self {
        assert!(next.soa.is_none(), "'next' is not empty");
        assert!(diff.is_none());

        Self { curr, next, diff }
    }

    /// Read the current authoritative instance data (if any).
    pub const fn curr(&self) -> Option<SignedZoneReader<'d>> {
        if self.curr.soa.is_none() {
            return None;
        }

        Some(SignedZoneReader::new(self.curr))
    }

    /// Set the SOA record.
    pub fn set_soa(&mut self, soa: SoaRecord) -> Result<(), ReplaceError> {
        if self.next.soa.is_some() {
            return Err(ReplaceError::MultipleSoas);
        }

        self.next.soa = Some(soa);
        Ok(())
    }

    /// Add a regular record.
    pub fn add(&mut self, record: RegularRecord) -> Result<(), ReplaceError> {
        self.next.records.push(record);
        Ok(())
    }

    /// Finish and apply the collected changes.
    ///
    /// The changes will be checked for consistency and applied to the upcoming
    /// signed instance.
    pub fn apply(self) -> Result<(), ReplaceError> {
        *self.diff = Some(apply_replacement(self.curr, self.next)?);

        Ok(())
    }
}

impl Drop for SignedZoneReplacer<'_> {
    /// Erase all pending changes.
    fn drop(&mut self) {
        if self.diff.is_some() {
            // The changes were built successfully.
            return;
        }

        // Clean up 'self.next'.
        self.next.soa = None;
        self.next.records.clear();
    }
}

//----------- SignedZonePatcher ------------------------------------------------

/// A writer building a signed instance of a zone from a diff.
///
/// If the writer is dropped without calling [`apply()`](Self::apply()), all
/// pending changes will be erased.
pub struct SignedZonePatcher<'d> {
    /// The authoritative instance.
    curr: &'d InstanceData,

    /// The upcoming instance.
    next: &'d mut InstanceData,

    /// The built diff.
    diff: &'d mut Option<DiffData>,

    /// An accumulated diff.
    accumulated: DiffData,

    /// The diff being built right now.
    immediate: DiffData,
}

impl<'d> SignedZonePatcher<'d> {
    /// Construct a new [`SignedZonePatcher`].
    ///
    /// ## Panics
    ///
    /// Panics **unless**:
    /// - `curr` is complete.
    /// - `next` is empty.
    /// - `diff` is `None`.
    pub(crate) const fn new(
        curr: &'d InstanceData,
        next: &'d mut InstanceData,
        diff: &'d mut Option<DiffData>,
    ) -> Self {
        assert!(curr.soa.is_some());
        assert!(next.soa.is_none());
        assert!(diff.is_none());

        Self {
            curr,
            next,
            diff,
            accumulated: DiffData::new(),
            immediate: DiffData::new(),
        }
    }

    /// Read the current authoritative instance data.
    pub const fn curr(&self) -> SignedZoneReader<'d> {
        SignedZoneReader::new(self.curr)
    }

    /// Remove the previous SOA record.
    pub fn remove_soa(&mut self, soa: SoaRecord) -> Result<(), PatchError> {
        if self.immediate.removed_soa.is_some() {
            return Err(PatchError::Inconsistency);
        }

        self.immediate.removed_soa = Some(soa);
        Ok(())
    }

    /// Add the new SOA record.
    pub fn add_soa(&mut self, soa: SoaRecord) -> Result<(), PatchError> {
        if self.immediate.added_soa.is_some() {
            return Err(PatchError::MultipleSoasAdded);
        }

        self.immediate.added_soa = Some(soa);
        Ok(())
    }

    /// Remove a previous regular record.
    pub fn remove(&mut self, record: RegularRecord) -> Result<(), PatchError> {
        self.immediate.removed_records.push(record);
        Ok(())
    }

    /// Add a new regular record.
    pub fn add(&mut self, record: RegularRecord) -> Result<(), PatchError> {
        self.immediate.added_records.push(record);
        Ok(())
    }

    /// Move to the next patchset.
    ///
    /// The records added and removed (including SOA) since the last call to
    /// [`Self::next_patchset()`] are considered as a single unit, a _patchset_.
    /// This patchset will be applied, on top of all previous patchsets, to the
    /// current authoritative instance.
    ///
    /// Patchsets occur, for example, in IXFRs; a single IXFR response can
    /// contain multiple distinct diffs, and later diffs may undo the changes
    /// caused by earlier ones. A whole IXFR can be consumed by calling this
    /// method after consuming each diff.
    pub fn next_patchset(&mut self) -> Result<(), PatchError> {
        next_patchset(self.curr, &mut self.immediate, &mut self.accumulated)
    }

    /// Finish and apply the collected changes.
    ///
    /// The changes will be checked for consistency and applied to the upcoming
    /// signed instance.
    pub fn apply(mut self) -> Result<(), PatchError> {
        // If there are pending changes, complete them.
        if !self.immediate.is_empty() {
            self.next_patchset()?;
        }

        *self.diff = Some(apply_patches(self.curr, self.next, &mut self.accumulated)?);

        Ok(())
    }
}

impl Drop for SignedZonePatcher<'_> {
    /// Erase all pending changes.
    fn drop(&mut self) {
        if self.diff.is_some() {
            // The changes were built successfully.
            return;
        }

        // Clean up 'self.next'.
        self.next.soa = None;
        self.next.records.clear();
    }
}

//------------------------------------------------------------------------------
//
// The following helpers reduce code duplication right now, but will need to be
// split once the signed and unsigned instances use independent representations.

/// Implementation of `{Signed,Unsigned}ZoneReplacer::apply()`.
fn apply_replacement(
    curr: &InstanceData,
    next: &mut InstanceData,
) -> Result<DiffData, ReplaceError> {
    let Some(soa) = &next.soa else {
        return Err(ReplaceError::MissingSoa);
    };

    next.records.sort_unstable();

    if curr.soa.is_some() {
        let mut removed_records = Vec::new();
        let mut added_records = Vec::new();

        for records in crate::merge([&curr.records, &next.records]) {
            match records {
                [None, None] => unreachable!(),

                // Record has been added.
                [None, Some(r)] => added_records.push(r.clone()),

                // Record has been removed.
                [Some(r), None] => removed_records.push(r.clone()),

                // Record still exists.
                [Some(_), Some(_)] => {}
            }
        }

        Ok(DiffData {
            removed_soa: curr.soa.clone(),
            added_soa: Some(soa.clone()),
            removed_records,
            added_records,
        })
    } else {
        Ok(DiffData {
            removed_soa: None,
            added_soa: Some(soa.clone()),
            removed_records: Vec::new(),
            added_records: next.records.clone(),
        })
    }
}

/// Implementation of `{Signed,Unsigned}ZonePatcher::next_patchset()`.
fn next_patchset(
    curr: &InstanceData,
    immediate: &mut DiffData,
    accumulated: &mut DiffData,
) -> Result<(), PatchError> {
    let (Some(removed_soa), Some(added_soa)) =
        (immediate.removed_soa.take(), immediate.added_soa.take())
    else {
        return Err(PatchError::MissingSoaChange);
    };

    immediate.removed_records.sort_unstable();
    immediate.added_records.sort_unstable();

    if accumulated.is_empty() {
        // There was no previous patchset; accumulate the current one.

        // Verify that this initial SOA removal is consistent.
        if removed_soa != *curr.soa.as_ref().unwrap() {
            return Err(PatchError::Inconsistency);
        }

        accumulated.removed_soa = Some(removed_soa);
        accumulated.added_soa = Some(added_soa);
        accumulated
            .removed_records
            .append(&mut immediate.removed_records);
        accumulated
            .added_records
            .append(&mut immediate.added_records);

        return Ok(());
    }

    // Accumulate the SOA record changes.
    if removed_soa != *accumulated.added_soa.as_ref().unwrap() {
        return Err(PatchError::Inconsistency);
    }
    accumulated.added_soa = Some(added_soa);

    // Accumulate the remaining changes.
    let mut removed_records = Vec::new();
    let mut added_records = Vec::new();
    for [ir, ia, ar, aa] in merge([
        immediate.removed_records.drain(..),
        immediate.added_records.drain(..),
        accumulated.removed_records.drain(..),
        accumulated.added_records.drain(..),
    ]) {
        match [ir, ia, ar, aa] {
            [None, None, None, None] => unreachable!(),

            // A single diff cannot remove and add the same record.
            [Some(_), Some(_), _, _] | [_, _, Some(_), Some(_)] => {
                return Err(PatchError::Inconsistency);
            }

            // Carry forward unchanged diffs.
            [None, Some(r), None, None] | [None, None, None, Some(r)] => {
                added_records.push(r);
            }
            [Some(r), None, None, None] | [None, None, Some(r), None] => {
                removed_records.push(r);
            }

            // The same record cannot be added or removed twice.
            [None, Some(_), None, Some(_)] | [Some(_), None, Some(_), None] => {
                return Err(PatchError::Inconsistency);
            }

            // The immediate diff has undone the accumulated diff.
            [Some(_), None, None, Some(_)] | [None, Some(_), Some(_), None] => {}
        }
    }
    accumulated.removed_records.append(&mut removed_records);
    accumulated.added_records.append(&mut added_records);

    Ok(())
}

/// Implementation of `{Signed,Unsigned}ZonePatcher::apply()`.
fn apply_patches(
    curr: &InstanceData,
    next: &mut InstanceData,
    accumulated: &mut DiffData,
) -> Result<DiffData, PatchError> {
    // Make sure changes happened.
    if accumulated.is_empty() {
        return Err(PatchError::Empty);
    }

    // 'accumulated.removed_soa' is already known to be valid.
    next.soa = Some(accumulated.added_soa.clone().unwrap());

    // Apply the accumulated diff to the existing set of records.
    for [o, r, a] in merge([
        &curr.records,
        &accumulated.removed_records,
        &accumulated.added_records,
    ]) {
        match [o, r, a] {
            [None, None, None] => unreachable!(),

            // Cannot remove and add a record.
            [_, Some(_), Some(_)] => return Err(PatchError::Inconsistency),

            // Cannot remove a nonexistent record or add an existing one.
            [None, Some(_), _] | [Some(_), _, Some(_)] => {
                return Err(PatchError::Inconsistency);
            }

            // Carry forward unchanged records.
            [Some(r), None, None] => next.records.push(r.clone()),

            // Apply an addition.
            [None, None, Some(r)] => next.records.push(r.clone()),

            // Apply a removal.
            [Some(_), Some(_), None] => {}
        }
    }

    Ok(std::mem::take(accumulated))
}

//============ Errors ==========================================================

//----------- ReplaceError -----------------------------------------------------

/// An error when replacing a zone instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplaceError {
    /// The built instance does not contain a SOA record.
    MissingSoa,

    /// The built instance contains multiple SOA records.
    MultipleSoas,
}

impl std::error::Error for ReplaceError {}

impl fmt::Display for ReplaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplaceError::MissingSoa => f.write_str("a SOA record was not provided"),
            ReplaceError::MultipleSoas => f.write_str("multiple SOA records were provided"),
        }
    }
}

//----------- PatchError -------------------------------------------------------

/// An error when patching a zone instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatchError {
    /// No patchsets were provided.
    Empty,

    /// A patchset did not change the SOA record.
    MissingSoaChange,

    /// A patchset contained multiple SOA record additions.
    MultipleSoasAdded,

    /// An inconsistency was detected.
    Inconsistency,
}

impl std::error::Error for PatchError {}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatchError::Empty => f.write_str("no patchsets were provided"),
            PatchError::MissingSoaChange => f.write_str("a patchset did not change the SOA record"),
            PatchError::MultipleSoasAdded => f.write_str("a patchset added multiple SOA records"),
            PatchError::Inconsistency => f.write_str("a patchset could not be applied"),
        }
    }
}
