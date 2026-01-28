//! Writing instances of zones.

use std::fmt;

use crate::{
    DiffData, InstanceHalf, RegularRecord, SignedZoneReader, SoaRecord, UnsignedZoneReader,
};

//----------- UnsignedZoneReplacer ---------------------------------------------

/// A writer building an unsigned instance of a zone from scratch.
pub struct UnsignedZoneReplacer<'d> {
    /// The authoritative instance.
    curr: Option<&'d InstanceHalf>,

    /// The upcoming instance.
    next: &'d mut Option<InstanceHalf>,

    /// Whether building was successful.
    built: &'d mut bool,

    /// The built diff.
    diff: &'d mut Option<DiffData>,

    /// The SOA record to write.
    soa: Option<SoaRecord>,

    /// The records to write.
    records: Vec<RegularRecord>,
}

impl<'d> UnsignedZoneReplacer<'d> {
    /// Construct a new [`UnsignedZoneReplacer`].
    ///
    /// ## Panics
    ///
    /// Panics if `next` is [`Some`], `built` is `true`, or `diff` is [`Some`].
    pub(crate) const fn new(
        curr: Option<&'d InstanceHalf>,
        next: &'d mut Option<InstanceHalf>,
        built: &'d mut bool,
        diff: &'d mut Option<DiffData>,
    ) -> Self {
        assert!(next.is_none());
        assert!(!*built);
        assert!(diff.is_none());

        Self {
            curr,
            next,
            built,
            diff,
            soa: None,
            records: Vec::new(),
        }
    }

    /// Read the current authoritative instance data (if any).
    pub const fn curr(&self) -> Option<UnsignedZoneReader<'d>> {
        if let Some(data) = self.curr {
            Some(UnsignedZoneReader { data })
        } else {
            None
        }
    }

    /// Set the SOA record.
    pub fn set_soa(&mut self, soa: SoaRecord) -> Result<(), ReplaceError> {
        if self.soa.is_some() {
            return Err(ReplaceError::MultipleSoas);
        }

        self.soa = Some(soa);
        Ok(())
    }

    /// Add a regular record.
    pub fn add(&mut self, record: RegularRecord) -> Result<(), ReplaceError> {
        self.records.push(record);
        Ok(())
    }

    /// Finish and apply the collected changes.
    ///
    /// The changes will be checked for consistency and applied to the upcoming
    /// unsigned instance.
    pub fn apply(self) -> Result<(), ReplaceError> {
        let (instance, diff) = apply_replacement(self.curr, self.soa, self.records)?;

        *self.next = Some(instance);
        *self.diff = diff;
        *self.built = true;
        Ok(())
    }
}

//----------- UnsignedZonePatcher ----------------------------------------------

/// A writer building an unsigned instance of a zone from a diff.
pub struct UnsignedZonePatcher<'d> {
    /// The authoritative instance.
    curr: &'d InstanceHalf,

    /// The upcoming instance.
    next: &'d mut Option<InstanceHalf>,

    /// Whether building was successful.
    built: &'d mut bool,

    /// The built diff.
    diff: &'d mut Option<DiffData>,

    /// The SOA record to remove.
    removed_soa: Option<(SoaRecord, usize)>,

    /// The SOA record to add.
    added_soa: Option<(SoaRecord, usize)>,

    /// The records to remove.
    removed_records: Vec<(RegularRecord, usize)>,

    /// The records to add.
    added_records: Vec<(RegularRecord, usize)>,

    /// The patchset counter.
    ///
    /// Multiple patches (i.e. sets of added/removed records) can be processed;
    /// this is incremented between patches, so it is unique, and later patches
    /// are preferred over earlier ones.
    patchset: usize,
}

impl<'d> UnsignedZonePatcher<'d> {
    /// Construct a new [`UnsignedZonePatcher`].
    ///
    /// ## Panics
    ///
    /// Panics if `next` is [`Some`], `built` is `true`, or `diff` is [`Some`].
    pub(crate) const fn new(
        curr: &'d InstanceHalf,
        next: &'d mut Option<InstanceHalf>,
        built: &'d mut bool,
        diff: &'d mut Option<DiffData>,
    ) -> Self {
        assert!(next.is_none());
        assert!(!*built);
        assert!(diff.is_none());

        Self {
            curr,
            next,
            built,
            diff,
            removed_soa: None,
            added_soa: None,
            removed_records: Vec::new(),
            added_records: Vec::new(),
            patchset: 0,
        }
    }

    /// Read the current authoritative instance data.
    pub const fn curr(&self) -> UnsignedZoneReader<'d> {
        UnsignedZoneReader { data: self.curr }
    }

    /// Remove the previous SOA record.
    pub fn remove_soa(&mut self, soa: SoaRecord) -> Result<(), PatchError> {
        if self
            .removed_soa
            .as_ref()
            .is_some_and(|(_, patchset)| *patchset == self.patchset)
        {
            return Err(PatchError::Inconsistency);
        }

        self.removed_soa = Some((soa, self.patchset));
        Ok(())
    }

    /// Add the new SOA record.
    pub fn add_soa(&mut self, soa: SoaRecord) -> Result<(), PatchError> {
        if self
            .added_soa
            .as_ref()
            .is_some_and(|(_, patchset)| *patchset == self.patchset)
        {
            return Err(PatchError::MultipleSoasAdded);
        }

        self.added_soa = Some((soa, self.patchset));
        Ok(())
    }

    /// Remove a previous regular record.
    pub fn remove(&mut self, record: RegularRecord) -> Result<(), PatchError> {
        self.removed_records.push((record, self.patchset));
        Ok(())
    }

    /// Add a new regular record.
    pub fn add(&mut self, record: RegularRecord) -> Result<(), PatchError> {
        self.added_records.push((record, self.patchset));
        Ok(())
    }

    /// Move to the next patchset.
    ///
    /// The current patchset will be checked for consistency, and a new patchset
    /// will be initialized for an independent set of additions and removals.
    ///
    /// This can be called, but does not have to be called, at the end of the
    /// last patchset.
    pub fn next_patchset(&mut self) -> Result<(), PatchError> {
        let (Some(removed_soa), Some(added_soa)) = (&self.removed_soa, &self.added_soa) else {
            return Err(PatchError::MissingSoaChange);
        };

        if self.patchset != removed_soa.1 || self.patchset != added_soa.1 {
            return Err(PatchError::MissingSoaChange);
        }

        self.patchset += 1;
        Ok(())
    }

    /// Finish and apply the collected changes.
    ///
    /// The changes will be checked for consistency and applied to the upcoming
    /// unsigned instance.
    pub fn apply(self) -> Result<(), PatchError> {
        let (instance, diff) = apply_patches(
            self.curr,
            self.removed_soa,
            self.added_soa,
            self.removed_records,
            self.added_records,
            self.patchset,
        )?;

        *self.next = Some(instance);
        *self.diff = Some(diff);
        *self.built = true;
        Ok(())
    }
}

//----------- SignedZoneReplacer -----------------------------------------------

/// A writer building a signed instance of a zone from scratch.
pub struct SignedZoneReplacer<'d> {
    /// The authoritative instance.
    curr: Option<&'d InstanceHalf>,

    /// The upcoming instance.
    next: &'d mut Option<InstanceHalf>,

    /// Whether building was successful.
    built: &'d mut bool,

    /// The built diff.
    diff: &'d mut Option<DiffData>,

    /// The SOA record to write.
    soa: Option<SoaRecord>,

    /// The records to write.
    records: Vec<RegularRecord>,
}

impl<'d> SignedZoneReplacer<'d> {
    /// Construct a new [`UnsignedZoneReplacer`].
    ///
    /// ## Panics
    ///
    /// Panics if `next` is [`Some`], `built` is `true`, or `diff` is [`Some`].
    pub(crate) const fn new(
        curr: Option<&'d InstanceHalf>,
        next: &'d mut Option<InstanceHalf>,
        built: &'d mut bool,
        diff: &'d mut Option<DiffData>,
    ) -> Self {
        assert!(next.is_none());
        assert!(!*built);
        assert!(diff.is_none());

        Self {
            curr,
            next,
            built,
            diff,
            soa: None,
            records: Vec::new(),
        }
    }

    /// Read the current authoritative instance data (if any).
    pub const fn curr(&self) -> Option<SignedZoneReader<'d>> {
        if let Some(data) = self.curr {
            Some(SignedZoneReader { data })
        } else {
            None
        }
    }

    /// Set the SOA record.
    pub fn set_soa(&mut self, soa: SoaRecord) -> Result<(), ReplaceError> {
        if self.soa.is_some() {
            return Err(ReplaceError::MultipleSoas);
        }

        self.soa = Some(soa);
        Ok(())
    }

    /// Add a regular record.
    pub fn add(&mut self, record: RegularRecord) -> Result<(), ReplaceError> {
        self.records.push(record);
        Ok(())
    }

    /// Finish and apply the collected changes.
    ///
    /// The changes will be checked for consistency and applied to the upcoming
    /// unsigned instance.
    pub fn apply(self) -> Result<(), ReplaceError> {
        let (instance, diff) = apply_replacement(self.curr, self.soa, self.records)?;

        *self.next = Some(instance);
        *self.diff = diff;
        *self.built = true;
        Ok(())
    }
}

//----------- SignedZonePatcher ------------------------------------------------

/// A writer building a signed instance of a zone from a diff.
pub struct SignedZonePatcher<'d> {
    /// The authoritative instance.
    curr: &'d InstanceHalf,

    /// The upcoming instance.
    next: &'d mut Option<InstanceHalf>,

    /// Whether building was successful.
    built: &'d mut bool,

    /// The built diff.
    diff: &'d mut Option<DiffData>,

    /// The SOA record to remove.
    removed_soa: Option<(SoaRecord, usize)>,

    /// The SOA record to add.
    added_soa: Option<(SoaRecord, usize)>,

    /// The records to remove.
    removed_records: Vec<(RegularRecord, usize)>,

    /// The records to add.
    added_records: Vec<(RegularRecord, usize)>,

    /// The patchset counter.
    ///
    /// Multiple patches (i.e. sets of added/removed records) can be processed;
    /// this is incremented between patches, so it is unique, and later patches
    /// are preferred over earlier ones.
    patchset: usize,
}

impl<'d> SignedZonePatcher<'d> {
    /// Construct a new [`SignedZonePatcher`].
    ///
    /// ## Panics
    ///
    /// Panics if `next` is [`Some`], `built` is `true`, or `diff` is [`Some`].
    pub(crate) const fn new(
        curr: &'d InstanceHalf,
        next: &'d mut Option<InstanceHalf>,
        built: &'d mut bool,
        diff: &'d mut Option<DiffData>,
    ) -> Self {
        assert!(next.is_none());
        assert!(!*built);
        assert!(diff.is_none());

        Self {
            curr,
            next,
            built,
            diff,
            removed_soa: None,
            added_soa: None,
            removed_records: Vec::new(),
            added_records: Vec::new(),
            patchset: 0,
        }
    }

    /// Read the current authoritative instance data.
    pub const fn curr(&self) -> UnsignedZoneReader<'d> {
        UnsignedZoneReader { data: self.curr }
    }

    /// Remove the previous SOA record.
    pub fn remove_soa(&mut self, soa: SoaRecord) -> Result<(), PatchError> {
        if self
            .removed_soa
            .as_ref()
            .is_some_and(|(_, patchset)| *patchset == self.patchset)
        {
            return Err(PatchError::Inconsistency);
        }

        self.removed_soa = Some((soa, self.patchset));
        Ok(())
    }

    /// Add the new SOA record.
    pub fn add_soa(&mut self, soa: SoaRecord) -> Result<(), PatchError> {
        if self
            .added_soa
            .as_ref()
            .is_some_and(|(_, patchset)| *patchset == self.patchset)
        {
            return Err(PatchError::MultipleSoasAdded);
        }

        self.added_soa = Some((soa, self.patchset));
        Ok(())
    }

    /// Remove a previous regular record.
    pub fn remove(&mut self, record: RegularRecord) -> Result<(), PatchError> {
        self.removed_records.push((record, self.patchset));
        Ok(())
    }

    /// Add a new regular record.
    pub fn add(&mut self, record: RegularRecord) -> Result<(), PatchError> {
        self.added_records.push((record, self.patchset));
        Ok(())
    }

    /// Move to the next patchset.
    ///
    /// The current patchset will be checked for consistency, and a new patchset
    /// will be initialized for an independent set of additions and removals.
    ///
    /// This can be called, but does not have to be called, at the end of the
    /// last patchset.
    pub fn next_patchset(&mut self) -> Result<(), PatchError> {
        let (Some(removed_soa), Some(added_soa)) = (&self.removed_soa, &self.added_soa) else {
            return Err(PatchError::MissingSoaChange);
        };

        if self.patchset != removed_soa.1 || self.patchset != added_soa.1 {
            return Err(PatchError::MissingSoaChange);
        }

        self.patchset += 1;
        Ok(())
    }

    /// Finish and apply the collected changes.
    ///
    /// The changes will be checked for consistency and applied to the upcoming
    /// unsigned instance.
    pub fn apply(self) -> Result<(), PatchError> {
        let (instance, diff) = apply_patches(
            self.curr,
            self.removed_soa,
            self.added_soa,
            self.removed_records,
            self.added_records,
            self.patchset,
        )?;

        *self.next = Some(instance);
        *self.diff = Some(diff);
        *self.built = true;
        Ok(())
    }
}

//------------------------------------------------------------------------------
//
// The following helpers reduce code duplication right now, but will need to be
// split once the signed and unsigned instances use independent representations.

/// Implementation of `{Signed,Unsigned}ZoneReplacer::apply()`.
fn apply_replacement(
    curr: Option<&InstanceHalf>,
    soa: Option<SoaRecord>,
    records: Vec<RegularRecord>,
) -> Result<(InstanceHalf, Option<DiffData>), ReplaceError> {
    let Some(soa) = soa else {
        return Err(ReplaceError::MissingSoa);
    };

    let mut all = records.into_boxed_slice();
    all.sort_unstable();

    let diff = curr.map(|curr| {
        let mut removed_records = Vec::new();
        let mut added_records = Vec::new();

        for records in crate::merge([curr.all.iter(), all.iter()]) {
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

        DiffData {
            removed_soa: curr.soa.clone(),
            added_soa: soa.clone(),
            removed_records: removed_records.into_boxed_slice(),
            added_records: added_records.into_boxed_slice(),
        }
    });

    Ok((InstanceHalf { soa, all }, diff))
}

/// Implementation of `{Signed,Unsigned}ZonePatcher::apply()`.
fn apply_patches(
    curr: &InstanceHalf,
    removed_soa: Option<(SoaRecord, usize)>,
    added_soa: Option<(SoaRecord, usize)>,
    removed_records: Vec<(RegularRecord, usize)>,
    added_records: Vec<(RegularRecord, usize)>,
    this_patchset: usize,
) -> Result<(InstanceHalf, DiffData), PatchError> {
    let Some((removed_soa, _)) = removed_soa.filter(|(_, patchset)| *patchset == this_patchset)
    else {
        return Err(PatchError::MissingSoaChange);
    };

    let Some((added_soa, _)) = added_soa.filter(|(_, patchset)| *patchset == this_patchset) else {
        return Err(PatchError::MissingSoaChange);
    };

    if curr.soa != removed_soa {
        return Err(PatchError::Inconsistency);
    }
    let soa = added_soa.clone();

    // Collect all records, tracking whether they were added or removed, and
    // in which patchset.
    let mut records = curr
        .all
        .iter()
        .map(|r| (r.clone(), None))
        .chain(
            removed_records
                .into_iter()
                .map(|(r, p)| (r, Some((p, false)))),
        )
        .chain(added_records.into_iter().map(|(r, p)| (r, Some((p, true)))))
        .collect::<Vec<_>>();
    records.sort_unstable();
    let mut records = records.into_iter().peekable();

    let mut all = Vec::new();
    let mut removed_records = Vec::new();
    let mut added_records = Vec::new();
    while let Some((record, patch)) = records.next() {
        if patch.is_some_and(|(_, added)| !added) {
            // Cannot remove a nonexistent record.
            return Err(PatchError::Inconsistency);
        }

        // Evaluate all changes to this record.
        let mut exists = true;
        let mut patched = patch.is_some();
        let mut patchset = patch.map(|(ps, _)| ps);

        while let Some((_, patch)) = records.next_if(|(r, _)| r == &record) {
            let Some((upd_patchset, added)) = patch else {
                // Duplicate record in 'self.curr'.
                return Err(PatchError::Inconsistency);
            };

            if exists == added {
                // Added and already exists or removed and did not exist.
                return Err(PatchError::Inconsistency);
            }

            if patchset >= Some(upd_patchset) {
                // Multiple changes in the same patchset.
                return Err(PatchError::Inconsistency);
            }

            patched = true;
            patchset = Some(upd_patchset);
            exists = added;
        }

        // Update the overall diff.
        if patched {
            if exists {
                added_records.push(record.clone());
            } else {
                removed_records.push(record.clone());
            }
        }

        // Decide whether the record will stay.
        if exists {
            all.push(record);
        }
    }
    let all = all.into_boxed_slice();

    let diff = DiffData {
        removed_soa,
        added_soa,
        removed_records: removed_records.into_boxed_slice(),
        added_records: added_records.into_boxed_slice(),
    };

    Ok((InstanceHalf { soa, all }, diff))
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
