//! Differences between instances.
//!
//! This module provides [`DiffData`]. All instances older than the current
//! authoritative instance store their data with this. Because there tend to be
//! few older instances of zones (and thus diffs) in memory, and diffs tend to
//! be quite small, there is relatively little need to optimize them. Their
//! primary purpose is for responding to IXFRs.

use std::iter::FusedIterator;

use domain::new::base::{RType, name::RevName};

use crate::{RegularRecord, SoaRecord, is_signing};

//----------- DiffData ---------------------------------------------------------

/// The difference between two instances of a zone.
///
/// [`DiffData`] is relative to two zones, a base and a target; it tracks the
/// steps necessary (in terms of records to remove and add) to transform the
/// base into the target. It is used for both unsigned and signed instances.
///
/// [`DiffData`] can be used to store the data for an old zone (where it is the
/// base, and the next newer zone is the target). This is perfect for serving
/// IXFR requests.
#[derive(Clone, Default)]
pub struct DiffData {
    /// The SOA record to remove.
    ///
    /// This record is present in the base, but not in the target.
    pub removed_soa: Option<SoaRecord>,

    /// The SOA record found in the target.
    ///
    /// This record is present in the target, but not in the base.
    pub added_soa: Option<SoaRecord>,

    /// Removed regular records.
    ///
    /// These records are present in the base, but not in the target. They
    /// **also** include the removed SOA record. They are sorted in DNSSEC
    /// canonical order.
    pub removed_records: Vec<RegularRecord>,

    /// Added regular records.
    ///
    /// These records are present in the target, but not in the base. They
    /// **also** include the added SOA record. They are sorted in DNSSEC
    /// canonical order.
    pub added_records: Vec<RegularRecord>,
}

impl DiffData {
    /// Construct a new, empty [`DiffData`].
    pub const fn new() -> Self {
        Self {
            removed_soa: None,
            added_soa: None,
            removed_records: Vec::new(),
            added_records: Vec::new(),
        }
    }

    /// Whether this diff is empty.
    pub const fn is_empty(&self) -> bool {
        self.removed_soa.is_none()
            && self.added_soa.is_none()
            && self.removed_records.is_empty()
            && self.added_records.is_empty()
    }

    /// Iterate over the removed non-SOA records.
    pub fn removed_non_soa<'a>(&'a self, origin: &'a RevName) -> RecordsIter<'a> {
        RecordsIter {
            iter: self.removed_records.iter(),
            pending_soa_filter: self.removed_soa.is_some(),
            origin,
        }
    }

    /// Iterate over the added non-SOA records.
    pub fn added_non_soa<'a>(&'a self, origin: &'a RevName) -> RecordsIter<'a> {
        RecordsIter {
            iter: self.added_records.iter(),
            pending_soa_filter: self.added_soa.is_some(),
            origin,
        }
    }

    /// Iterate over the *unsigned* removed non-SOA records.
    pub fn unsigned_removed_non_soa<'a>(&'a self, origin: &'a RevName) -> UnsignedRecordsIter<'a> {
        UnsignedRecordsIter {
            iter: self.removed_records.iter(),
            pending_soa_filter: self.removed_soa.is_some(),
            origin,
        }
    }

    /// Iterate over the *unsigned* added non-SOA records.
    pub fn unsigned_added_non_soa<'a>(&'a self, origin: &'a RevName) -> UnsignedRecordsIter<'a> {
        UnsignedRecordsIter {
            iter: self.added_records.iter(),
            pending_soa_filter: self.added_soa.is_some(),
            origin,
        }
    }
}

//----------- RecordsIter ------------------------------------------------------

/// Added or removed records from a [`DiffData`].
pub struct RecordsIter<'d> {
    /// The underlying iterator.
    iter: core::slice::Iter<'d, RegularRecord>,

    /// Whether a SOA record needs to be filtered out.
    pending_soa_filter: bool,

    /// The zone origin.
    ///
    /// Only used if `pending_soa_filter` is true.
    origin: &'d RevName,
}

impl<'d> Iterator for RecordsIter<'d> {
    type Item = &'d RegularRecord;

    fn next(&mut self) -> Option<Self::Item> {
        let record = self.iter.next()?;

        // Filter out a SOA record as needed.
        if self.pending_soa_filter && record.rtype == RType::SOA && *record.rname == *self.origin {
            self.pending_soa_filter = false;
            return self.iter.next();
        }

        Some(record)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }
}

impl DoubleEndedIterator for RecordsIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let record = self.iter.next_back()?;

        // Filter out a SOA record as needed.
        if self.pending_soa_filter && record.rtype == RType::SOA && *record.rname == *self.origin {
            self.pending_soa_filter = false;
            return self.iter.next_back();
        }

        Some(record)
    }
}

impl ExactSizeIterator for RecordsIter<'_> {
    fn len(&self) -> usize {
        self.iter
            .len()
            .checked_sub(self.pending_soa_filter as usize)
            .expect("`pending_soa_filter` is set but `iter` is empty")
    }
}

impl FusedIterator for RecordsIter<'_> {}

//----------- UnsignedRecordsIter ----------------------------------------------

/// Added or removed *unsigned* records from a [`DiffData`].
pub struct UnsignedRecordsIter<'d> {
    /// The underlying iterator.
    iter: core::slice::Iter<'d, RegularRecord>,

    /// Whether a SOA record needs to be filtered out.
    pending_soa_filter: bool,

    /// The zone origin.
    ///
    /// Only used if `pending_soa_filter` is true.
    origin: &'d RevName,
}

impl<'d> Iterator for UnsignedRecordsIter<'d> {
    type Item = &'d RegularRecord;

    fn next(&mut self) -> Option<Self::Item> {
        let record = loop {
            let record = self.iter.next()?;
            if !is_signing(record.rtype, || *record.rname == *self.origin) {
                break record;
            }
        };

        // Filter out a SOA record as needed.
        if self.pending_soa_filter && record.rtype == RType::SOA && *record.rname == *self.origin {
            self.pending_soa_filter = false;
            return self.next();
        }

        Some(record)
    }
}

impl DoubleEndedIterator for UnsignedRecordsIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let record = loop {
            let record = self.iter.next_back()?;
            if !is_signing(record.rtype, || *record.rname == *self.origin) {
                break record;
            }
        };

        // Filter out a SOA record as needed.
        if self.pending_soa_filter && record.rtype == RType::SOA && *record.rname == *self.origin {
            self.pending_soa_filter = false;
            return self.next_back();
        }

        Some(record)
    }
}

impl FusedIterator for UnsignedRecordsIter<'_> {}
