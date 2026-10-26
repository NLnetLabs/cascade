//! Writing instances of zones.
//!
//! This module provides [`LoadedZoneReplacer`], [`LoadedZonePatcher`],
//! [`SignedZoneReplacer`], and [`SignedZonePatcher`]. These are simple safe
//! interfaces through which new instances zones can be written. These types do
//! not consider the concurrent access different instances of zone data; they
//! are limited to considering a single instance. They offer concurrency, but
//! only for parallelizing the writing of the zone, for efficiency.
//!
//! See the [`crate::builder`] module for high-level types that do consider
//! concurrent access.

use std::{collections::hash_map, fmt, sync::Arc};

use domain::{
    new::base::{
        RType, TTL,
        name::{NameBuf, RevName, RevNameBuf},
    },
    utils::dst::UnsizedCopy,
};
use rayon::slice::ParallelSliceMut;

use crate::{
    DiffData, InstanceData, LoadedZoneReader, RegularRecord, SignedZoneReader, SoaRecord, merge,
};

/// Record types for which RRsets may contain varying TTLs.
const VARYING_TTL_RTYPES: &[RType] = &[RType::RRSIG];

//----------- LoadedZoneReplacer -----------------------------------------------

/// A writer building a loaded instance of a zone from scratch.
///
/// If the writer is dropped without calling [`apply()`](Self::apply()), all
/// pending changes will be erased.
pub struct LoadedZoneReplacer<'d> {
    /// The current authoritative instance, if any.
    curr: &'d InstanceData,

    /// The instance being built.
    next: &'d mut InstanceData,

    /// A mapping of RRset keys to their TTLs, for verifying consistency.
    rrset_ttls: foldhash::HashMap<(Box<RevName>, RType), TTL>,

    /// The built diff.
    ///
    /// This exists iff building succeeds.
    diff: &'d mut Option<Box<DiffData>>,
}

impl<'d> LoadedZoneReplacer<'d> {
    /// Construct a new [`LoadedZoneReplacer`].
    ///
    /// ## Panics
    ///
    /// Panics if `next` is not empty or `diff` is [`Some`].
    pub(crate) fn new(
        curr: &'d InstanceData,
        next: &'d mut InstanceData,
        diff: &'d mut Option<Box<DiffData>>,
    ) -> Self {
        assert!(next.soa.is_none(), "'next' is not empty");
        assert!(diff.is_none());

        let rrset_ttls = Default::default();
        Self {
            curr,
            next,
            rrset_ttls,
            diff,
        }
    }

    /// Read the current authoritative instance data (if any).
    pub const fn curr(&self) -> Option<LoadedZoneReader<'d>> {
        if self.curr.soa.is_none() {
            return None;
        }

        Some(LoadedZoneReader::new(self.curr))
    }

    /// Set the SOA record.
    ///
    /// A copy of the record **must** be added as a regular record too.
    pub fn set_soa(&mut self, soa: SoaRecord) -> Result<(), ReplaceError> {
        if self.next.soa.is_some() {
            return Err(ReplaceError::MultipleSoas);
        }

        self.next.soa = Some(soa);
        Ok(())
    }

    /// Add a regular record.
    pub fn add(&mut self, record: RegularRecord) -> Result<(), ReplaceError> {
        if !VARYING_TTL_RTYPES.contains(&record.rtype)
            && let &mut prior = self
                .rrset_ttls
                .entry((record.rname.clone(), record.rtype))
                .or_insert(record.ttl)
            && prior != record.ttl
        {
            return Err(ReplaceError::InconsistentTtls(InconsistentTtlsError {
                owner: record.rname.clone(),
                rtype: record.rtype,
                ttls: [prior, record.ttl],
            }));
        }
        self.next.records.push(record);
        Ok(())
    }

    /// Set all records.
    ///
    /// The given [`Vec`] will replace all the records in the instance,
    /// including the SOA record; but a copy of the SOA record **must** be set
    /// via [`Self::set_soa()`]. The records must be sorted.
    pub fn set_records(&mut self, records: Vec<RegularRecord>) -> Result<(), ReplaceError> {
        self.next.records = records;
        Ok(())
    }

    /// Finish and apply the collected changes.
    ///
    /// The changes will be checked for consistency and applied to the upcoming
    /// loaded instance.
    pub fn apply(self) -> Result<(), ReplaceError> {
        *self.diff = Some(apply_replacement(self.curr, self.next)?);

        Ok(())
    }
}

impl Drop for LoadedZoneReplacer<'_> {
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

//----------- LoadedZonePatcher ------------------------------------------------

/// A writer building a loaded instance of a zone from a diff.
///
/// If the writer is dropped without calling [`apply()`](Self::apply()), all
/// pending changes will be erased.
pub struct LoadedZonePatcher<'d> {
    /// The authoritative instance.
    curr: &'d InstanceData,

    /// The upcoming instance.
    next: &'d mut InstanceData,

    /// A mapping of RRset keys to their TTLs and number of records, for
    /// verifying consistency.
    ///
    /// The number of records is tracked so that
    /// [`Self::inconsistent_ttl_rrsets`] can be correctly initialized if an
    /// inconsistency is detected later.
    ///
    /// If the number of records is 0, the RRset is inconsistent, and a list of
    /// all its TTLs is stored in [`Self::inconsistent_ttl_rrsets`].
    rrset_ttls: foldhash::HashMap<(Box<RevName>, RType), (TTL, usize)>,

    /// RRsets which currently have inconsistent TTLs.
    ///
    /// Inconsistencies are allowed until writing finishes.
    inconsistent_ttl_rrsets: foldhash::HashMap<(Box<RevName>, RType), Vec<TTL>>,

    /// The built diff.
    diff: &'d mut Option<Box<DiffData>>,

    /// An accumulated diff.
    accumulated: Box<DiffData>,

    /// The diff being built right now.
    immediate: Box<DiffData>,
}

impl<'d> LoadedZonePatcher<'d> {
    /// Construct a new [`LoadedZonePatcher`].
    ///
    /// ## Panics
    ///
    /// Panics **unless**:
    /// - `curr` is complete.
    /// - `next` is empty.
    /// - `diff` is `None`.
    pub(crate) fn new(
        curr: &'d InstanceData,
        next: &'d mut InstanceData,
        diff: &'d mut Option<Box<DiffData>>,
    ) -> Self {
        assert!(curr.soa.is_some());
        assert!(next.soa.is_none());
        assert!(diff.is_none());

        // Load information about existing TTLs.
        let mut rrset_ttls = foldhash::HashMap::default();
        for record in &curr.records {
            let (ttl, count) = rrset_ttls
                .entry((record.rname.clone(), record.rtype))
                .or_insert((record.ttl, 0));
            if *ttl != record.ttl {
                let owner = NameBuf::from(RevNameBuf::copy_from(&record.rname));
                tracing::warn!(
                    %owner, rtype = %record.rtype,
                    a = ?*ttl, b = ?record.ttl,
                    "bug: inconsistent TTLs in existing zone instance");
            }
            *count += 1;
        }
        let inconsistent_ttl_rrsets = Default::default();

        Self {
            curr,
            next,
            diff,
            rrset_ttls,
            inconsistent_ttl_rrsets,
            accumulated: Box::new(DiffData::new()),
            immediate: Box::new(DiffData::new()),
        }
    }

    /// Read the current authoritative instance data.
    pub const fn curr(&self) -> LoadedZoneReader<'d> {
        LoadedZoneReader::new(self.curr)
    }

    /// Remove the previous SOA record.
    ///
    /// A copy of the record **must** be removed as a regular record too.
    pub fn remove_soa(&mut self, soa: SoaRecord) -> Result<(), PatchError> {
        if self.immediate.removed_soa.is_some() {
            return Err(PatchError::Inconsistency);
        }

        self.immediate.removed_soa = Some(soa);
        Ok(())
    }

    /// Add the new SOA record.
    ///
    /// A copy of the record **must** be added as a regular record too.
    pub fn add_soa(&mut self, soa: SoaRecord) -> Result<(), PatchError> {
        if self.immediate.added_soa.is_some() {
            return Err(PatchError::MultipleSoasAdded);
        }

        self.immediate.added_soa = Some(soa);
        Ok(())
    }

    /// Remove a previous regular record.
    pub fn remove(&mut self, record: RegularRecord) -> Result<(), PatchError> {
        // Update TTL consistency data.
        let rrset = (record.rname.clone(), record.rtype);
        let (ttl, count) = self
            .rrset_ttls
            .get_mut(&rrset)
            .ok_or(PatchError::Inconsistency)?;
        if *count == 0 {
            // This RRset has inconsistent TTLs.
            let ttls = self.inconsistent_ttl_rrsets.get_mut(&rrset).unwrap();
            let pos = ttls
                .iter()
                .position(|&ttl| ttl == record.ttl)
                .ok_or(PatchError::Inconsistency)?;
            ttls.swap_remove(pos);
        } else {
            if *ttl != record.ttl {
                return Err(PatchError::Inconsistency);
            }
            *count -= 1;
            if *count == 0 {
                self.rrset_ttls.remove(&rrset).unwrap();
            }
        }

        self.immediate.removed_records.push(record);
        Ok(())
    }

    /// Add a new regular record.
    pub fn add(&mut self, record: RegularRecord) -> Result<(), PatchError> {
        // Update TTL consistency data.
        let rrset = (record.rname.clone(), record.rtype);
        match self.rrset_ttls.entry(rrset.clone()) {
            hash_map::Entry::Occupied(entry) => {
                let (ttl, count) = entry.into_mut();
                if *count == 0 {
                    // This RRset has inconsistent TTLs.
                    self.inconsistent_ttl_rrsets
                        .get_mut(&rrset)
                        .unwrap()
                        .push(record.ttl);
                } else if *ttl != record.ttl {
                    // This RRset has now become inconsistent.
                    self.inconsistent_ttl_rrsets.insert(
                        rrset,
                        std::iter::repeat_n(*ttl, *count)
                            .chain([record.ttl])
                            .collect(),
                    );
                    *count = 0;
                } else {
                    *count -= 1;
                }
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert((record.ttl, 1));
            }
        }

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
    /// loaded instance.
    pub fn apply(mut self) -> Result<(), PatchError> {
        // If there are pending changes, complete them.
        if !self.immediate.is_empty() {
            self.next_patchset()?;
        }

        // Ensure all RRsets are consistent.
        for ((owner, rtype), ttls) in self.inconsistent_ttl_rrsets.drain() {
            let Some(&first) = ttls.first() else {
                // All records have been removed.
                continue;
            };

            if let Some(ttl) = ttls.into_iter().find(|&ttl| ttl != first) {
                return Err(PatchError::InconsistentTtls(InconsistentTtlsError {
                    owner,
                    rtype,
                    ttls: [first, ttl],
                }));
            }
        }

        *self.diff = Some(apply_patches(self.curr, self.next, &mut self.accumulated)?);

        Ok(())
    }
}

impl Drop for LoadedZonePatcher<'_> {
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
    /// The current loaded instance, if any.
    curr_loaded: &'d InstanceData,

    /// The next loaded instance, if any.
    next_loaded: Option<&'d InstanceData>,

    /// The diff between the loaded instances, if any.
    loaded_diff: Option<&'d Arc<DiffData>>,

    /// The current signed instance, if any.
    curr: &'d InstanceData,

    /// The instance being built.
    next: &'d mut InstanceData,

    /// The built diff.
    ///
    /// This exists iff `curr.is_some()` and building succeeds.
    diff: &'d mut Option<Box<DiffData>>,
}

impl<'d> SignedZoneReplacer<'d> {
    /// Construct a new [`SignedZoneReplacer`].
    ///
    /// ## Panics
    ///
    /// Panics if `next` is not empty, or `diff` is [`Some`].
    pub(crate) const fn new(
        curr_loaded: &'d InstanceData,
        next_loaded: Option<&'d InstanceData>,
        loaded_diff: Option<&'d Arc<DiffData>>,
        curr: &'d InstanceData,
        next: &'d mut InstanceData,
        diff: &'d mut Option<Box<DiffData>>,
    ) -> Self {
        assert!(next.soa.is_none(), "'next' is not empty");
        assert!(diff.is_none());

        Self {
            curr_loaded,
            next_loaded,
            loaded_diff,
            curr,
            next,
            diff,
        }
    }

    /// Read the current loaded instance data (if any).
    pub const fn curr_loaded(&self) -> Option<LoadedZoneReader<'d>> {
        if self.curr_loaded.soa.is_none() {
            return None;
        }

        Some(LoadedZoneReader::new(self.curr_loaded))
    }

    /// Read the next loaded instance data (if any).
    pub const fn next_loaded(&self) -> Option<LoadedZoneReader<'d>> {
        let Some(next_loaded) = self.next_loaded else {
            return None;
        };

        if next_loaded.soa.is_none() {
            return None;
        }

        Some(LoadedZoneReader::new(next_loaded))
    }

    /// The difference between the current and next loaded instances (if any).
    ///
    /// If [`Self::next_loaded()`] returns [`Some`], this method returns the
    /// difference from [`Self::curr_loaded()`] to it.
    pub const fn loaded_diff(&self) -> Option<&'d Arc<DiffData>> {
        self.loaded_diff
    }

    /// Read the current signed instance data (if any).
    pub const fn curr(&self) -> Option<SignedZoneReader<'d>> {
        if self.curr.soa.is_none() {
            return None;
        }

        Some(SignedZoneReader::new(self.curr_loaded, self.curr))
    }

    /// Set the SOA record.
    ///
    /// A copy of the record **must** be added as a regular record too.
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

    /// Set all records.
    ///
    /// The given [`Vec`] will replace all the records in the instance,
    /// including the SOA record; but a copy of the SOA record **must** be set
    /// via [`Self::set_soa()`]. The records must be sorted.
    pub fn set_records(&mut self, records: Vec<RegularRecord>) -> Result<(), ReplaceError> {
        self.next.records = records;
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
    /// The current loaded instance, if any.
    curr_loaded: &'d InstanceData,

    /// The next loaded instance, if any.
    next_loaded: Option<&'d InstanceData>,

    /// The diff between the loaded instances, if any.
    loaded_diff: Option<&'d Arc<DiffData>>,

    /// The authoritative instance.
    curr: &'d InstanceData,

    /// The upcoming instance.
    next: &'d mut InstanceData,

    /// The built diff.
    diff: &'d mut Option<Box<DiffData>>,

    /// An accumulated diff.
    accumulated: Box<DiffData>,

    /// The diff being built right now.
    immediate: Box<DiffData>,
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
    pub(crate) fn new(
        curr_loaded: &'d InstanceData,
        next_loaded: Option<&'d InstanceData>,
        loaded_diff: Option<&'d Arc<DiffData>>,
        curr: &'d InstanceData,
        next: &'d mut InstanceData,
        diff: &'d mut Option<Box<DiffData>>,
    ) -> Self {
        assert!(curr.soa.is_some());
        assert!(next.soa.is_none());
        assert!(diff.is_none());

        Self {
            curr_loaded,
            next_loaded,
            loaded_diff,
            curr,
            next,
            diff,
            accumulated: Box::new(DiffData::new()),
            immediate: Box::new(DiffData::new()),
        }
    }

    /// Read the current loaded instance data (if any).
    pub const fn curr_loaded(&self) -> Option<LoadedZoneReader<'d>> {
        if self.curr_loaded.soa.is_none() {
            return None;
        }

        Some(LoadedZoneReader::new(self.curr_loaded))
    }

    /// Read the next loaded instance data (if any).
    pub const fn next_loaded(&self) -> Option<LoadedZoneReader<'d>> {
        let Some(next_loaded) = self.next_loaded else {
            return None;
        };

        if next_loaded.soa.is_none() {
            return None;
        }

        Some(LoadedZoneReader::new(next_loaded))
    }

    /// The difference between the current and next loaded instances (if any).
    ///
    /// If [`Self::next_loaded()`] returns [`Some`], this method returns the
    /// difference from [`Self::curr_loaded()`] to it.
    pub const fn loaded_diff(&self) -> Option<&'d Arc<DiffData>> {
        self.loaded_diff
    }

    /// The difference between the current and next loaded instances, in terms
    /// of unsigned records (if any).
    ///
    /// If [`Self::next_loaded()`] returns [`Some`], this method returns the
    /// difference from [`Self::curr_loaded()`] to it. It excludes records
    /// that would be generated by the zone signer (RRSIGs, NSECs, NSEC3s,
    /// NSEC3PARAMs, DNSKEYs, CDSs, CDNSKEYs, ZONEMDs).
    pub fn unsigned_diff(&self) -> Option<DiffData> {
        let diff = self.loaded_diff?;
        // TODO: 'RType::{CDS, CDNSKEY, ZONEMD}'.
        Some(DiffData {
            removed_soa: diff.removed_soa.clone(),
            added_soa: diff.added_soa.clone(),
            removed_records: diff
                .removed_records
                .iter()
                .filter(|&r| {
                    !matches!(
                        r.rtype,
                        RType::NSEC
                            | RType::NSEC3
                            | RType::NSEC3PARAM
                            | RType::DNSKEY
                            | RType::RRSIG
                    ) && !matches!(r.rtype.code.get(), 59 | 60 | 63)
                })
                .cloned()
                .collect(),
            added_records: diff
                .added_records
                .iter()
                .filter(|&r| {
                    !matches!(
                        r.rtype,
                        RType::NSEC
                            | RType::NSEC3
                            | RType::NSEC3PARAM
                            | RType::DNSKEY
                            | RType::RRSIG
                    ) && !matches!(r.rtype.code.get(), 59 | 60 | 63)
                })
                .cloned()
                .collect(),
        })
    }

    /// Read the current authoritative instance data.
    pub const fn curr(&self) -> SignedZoneReader<'d> {
        SignedZoneReader::new(self.curr_loaded, self.curr)
    }

    /// Remove the previous SOA record.
    ///
    /// A copy of the record **must** be removed as a regular record too.
    pub fn remove_soa(&mut self, soa: SoaRecord) -> Result<(), PatchError> {
        if self.immediate.removed_soa.is_some() {
            return Err(PatchError::Inconsistency);
        }

        self.immediate.removed_soa = Some(soa);
        Ok(())
    }

    /// Add the new SOA record.
    ///
    /// A copy of the record **must** be added as a regular record too.
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
// split once the loaded and signed instances use independent representations.

/// Implementation of `{Loaded,Signed}ZoneReplacer::apply()`.
fn apply_replacement(
    curr: &InstanceData,
    next: &mut InstanceData,
) -> Result<Box<DiffData>, ReplaceError> {
    let Some(soa) = &next.soa else {
        return Err(ReplaceError::MissingSoa);
    };

    next.records.par_sort_unstable();

    if let Some(curr_soa) = &curr.soa {
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

        // Only set the SOA if it changed.
        let soa_changed = curr_soa != soa;
        Ok(Box::new(DiffData {
            removed_soa: soa_changed.then_some(curr_soa.clone()),
            added_soa: soa_changed.then_some(soa.clone()),
            removed_records,
            added_records,
        }))
    } else {
        Ok(Box::new(DiffData {
            removed_soa: None,
            added_soa: Some(soa.clone()),
            removed_records: Vec::new(),
            added_records: next.records.clone(),
        }))
    }
}

/// Implementation of `{Loaded,Signed}ZonePatcher::next_patchset()`.
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

    immediate.removed_records.par_sort_unstable();
    immediate.added_records.par_sort_unstable();

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

/// Implementation of `{Loaded,Signed}ZonePatcher::apply()`.
fn apply_patches(
    curr: &InstanceData,
    next: &mut InstanceData,
    accumulated: &mut DiffData,
) -> Result<Box<DiffData>, PatchError> {
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

    Ok(Box::new(std::mem::take(accumulated)))
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

    /// An RRset had inconsistent TTLs.
    InconsistentTtls(InconsistentTtlsError),
}

impl std::error::Error for ReplaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InconsistentTtls(error) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Display for ReplaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSoa => f.write_str("a SOA record was not provided"),
            Self::MultipleSoas => f.write_str("multiple SOA records were provided"),
            Self::InconsistentTtls(error) => write!(f, "an RRset has inconsistent TTLs: {error}"),
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

    /// An RRset had inconsistent TTLs.
    InconsistentTtls(InconsistentTtlsError),
}

impl std::error::Error for PatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InconsistentTtls(error) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("no patchsets were provided"),
            Self::MissingSoaChange => f.write_str("a patchset did not change the SOA record"),
            Self::MultipleSoasAdded => f.write_str("a patchset added multiple SOA records"),
            Self::Inconsistency => f.write_str("a patchset could not be applied"),
            Self::InconsistentTtls(error) => write!(f, "an RRset has inconsistent TTLs: {error}"),
        }
    }
}

//----------- InconsistentTtlsError --------------------------------------------

/// An RRset contains inconsistent TTLs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InconsistentTtlsError {
    /// The owner name.
    pub owner: Box<RevName>,

    /// The record type.
    pub rtype: RType,

    /// The observed TTLs.
    pub ttls: [TTL; 2],
}

impl std::error::Error for InconsistentTtlsError {}

impl fmt::Display for InconsistentTtlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { owner, rtype, ttls } = self;
        let owner = NameBuf::from((**owner).unsized_copy_into::<RevNameBuf>());
        let [a, b] = ttls.map(|ttl| ttl.value.get());
        write!(f, "{rtype} records under {owner} had TTLs {a} and {b}")
    }
}
