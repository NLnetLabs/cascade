//! Differences between instances.
//!
//! This module provides [`DiffData`]. All instances older than the current
//! authoritative instance store their data with this. Because there tend to be
//! few older instances of zones (and thus diffs) in memory, and diffs tend to
//! be quite small, there is relatively little need to optimize them. Their
//! primary purpose is for responding to IXFRs.

use crate::{RegularRecord, SoaRecord};

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
    /// These records are present in the base, but not in the target. They do
    /// not include the SOA record. They are sorted in DNSSEC canonical order.
    pub removed_records: Vec<RegularRecord>,

    /// Added regular records.
    ///
    /// These records are present in the target, but not in the base. They do
    /// not include the SOA record. They are sorted in DNSSEC canonical order.
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
}
