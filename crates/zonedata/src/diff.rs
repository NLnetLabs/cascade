//! Differences between instances.

use crate::{RegularRecord, SoaRecord};

/// The difference between two instances of a zone.
///
/// [`DiffData`] is a generic representation, storing records to remove and
/// records to add. It is used for both unsigned and signed instances; the
/// rarity and (usually) small size of diffs make significant optimization
/// unnecessary. Their primary purpose is serving over IXFR.
///
/// [`DiffData`] can be used to represent an instance of a zone relative to
/// another. This is used for representing instances older than the current
/// authoritative instance for a zone.
pub struct DiffData {
    /// The removed SOA record.
    pub removed_soa: SoaRecord,

    /// The added SOA record.
    pub added_soa: SoaRecord,

    /// Removed regular records.
    ///
    /// These are sorted in DNSSEC canonical order.
    pub removed_records: Box<[RegularRecord]>,

    /// Added regular records.
    ///
    /// These are sorted in DNSSEC canonical order.
    pub added_records: Box<[RegularRecord]>,
}
