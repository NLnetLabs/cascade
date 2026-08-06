//! Differences between instances.

use std::iter::FusedIterator;

use domain::new::base::{RClass, RType, name::RevName};

use cascade_zonedata::{RegularRecord, SoaRecord, is_signing};
use rayon::{
    iter::{IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSlice,
};

//----------- InstanceDiff -----------------------------------------------------

/// The difference between two instances of a zone.
///
/// [`InstanceDiff`] is relative to two zones, a base and a target; it tracks
/// the steps necessary (in terms of records to remove and add) to transform the
/// base into the target. It is used for both unsigned and signed instances.
///
/// [`InstanceDiff`] can be used to store the data for an old zone (where it
/// is the base, and the next newer zone is the target). This is perfect for
/// serving IXFR requests.
#[derive(Clone, Default)]
pub struct InstanceDiff {
    /// The SOA record to remove.
    ///
    /// This record is present in the base, but not in the target.
    pub removed_soa: Option<Box<SoaRecord>>,

    /// The SOA record found in the target.
    ///
    /// This record is present in the target, but not in the base.
    pub added_soa: Option<Box<SoaRecord>>,

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

impl InstanceDiff {
    /// Check invariants.
    pub fn check_invariants(&self, origin: &RevName) {
        for (prefix, soa, records) in [
            ("removed_", &self.removed_soa, &self.removed_records),
            ("added_", &self.added_soa, &self.added_records),
        ] {
            if let Some(soa) = soa {
                assert_eq!(*soa.rname, *origin);
                assert_eq!(soa.rtype, RType::SOA);
                assert_eq!(soa.rclass, RClass::IN);
            }

            assert_eq!(
                records
                    .par_iter()
                    .filter(|&r| r.rtype == RType::SOA && *r.rname == *origin)
                    .cloned()
                    .collect::<Vec<_>>(),
                soa.iter()
                    .map(|r| RegularRecord::from((**r).clone()))
                    .collect::<Vec<_>>(),
                "`self.{prefix}records` must contain `self.{prefix}soa` and no other apex SOA records"
            );

            self.removed_records.par_iter().for_each(|r| {
                assert!(
                    r.rname.as_bytes().starts_with(origin.as_bytes()),
                    "{r:?} falls outside the zone origin {origin:?}"
                );
                assert_eq!(r.rclass, RClass::IN);
            });

            assert_eq!(
                records.par_array_windows::<2>().find_any(|&[a, b]| a > b),
                None,
                "`self.{prefix}records` must be sorted"
            );

            assert_eq!(
                records.par_array_windows::<2>().find_any(|&[a, b]| a == b),
                None,
                "`self.{prefix}records` must not contain duplicates"
            );

            assert_eq!(
                records
                    .par_array_windows::<2>()
                    .find_any(|&[a, b]| (&a.rname, a.rtype) == (&b.rname, b.rtype)
                        && a.rtype != RType::RRSIG
                        && a.ttl != b.ttl),
                None,
                "Non-RRSIG RRsets in `self.{prefix}records` must have consistent TTLs",
            );
        }

        let removed = self
            .removed_records
            .par_iter()
            .collect::<hashbrown::HashSet<_>>();
        let added = self
            .added_records
            .par_iter()
            .collect::<hashbrown::HashSet<_>>();
        assert_eq!(
            removed
                .par_intersection(&added)
                .copied()
                .collect::<Vec<_>>(),
            &[] as &[&RegularRecord],
            "`self.removed_records` and `self.added_records` must be disjoint"
        );
    }
}

impl InstanceDiff {
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
}

impl InstanceDiff {
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
