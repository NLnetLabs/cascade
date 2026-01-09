//! Representing zone data relatively.

use crate::{Record, SoaRecord};

//----------- RelUnsignedData --------------------------------------------------

/// The data of an unsigned instance of a zone, as a diff relative to some base.
pub struct RelUnsignedData(Rel);

impl RelUnsignedData {
    /// Construct a new [`RelUnsignedData`].
    ///
    /// The records should be sorted in DNSSEC canonical order.
    pub fn from_sorted(
        removed_soa: SoaRecord,
        added_soa: SoaRecord,
        removed: impl IntoIterator<Item = Record>,
        added: impl IntoIterator<Item = Record>,
    ) -> Self {
        Self(Rel {
            remove_soa: removed_soa,
            remove: <Box<[_]>>::from_iter(removed),
            add_soa: added_soa,
            add: <Box<[_]>>::from_iter(added),
        })
    }

    /// The SOA record removed in this change.
    pub const fn removed_soa(&self) -> &SoaRecord {
        &self.0.remove_soa
    }

    /// The record sets removed in this change.
    pub const fn removed(&self) -> &[Record] {
        &self.0.remove
    }

    /// The SOA record added in this change.
    pub const fn added_soa(&self) -> &SoaRecord {
        &self.0.add_soa
    }

    /// The record sets added in this change.
    pub const fn added(&self) -> &[Record] {
        &self.0.add
    }
}

//----------- RelSignedData ----------------------------------------------------

/// The data of a signed instance of a zone, as a diff relative to some base.
pub struct RelSignedData(Rel);

impl RelSignedData {
    /// Construct a new [`RelSignedData`].
    ///
    /// The records should be sorted in DNSSEC canonical order.
    pub fn from_sorted(
        removed_soa: SoaRecord,
        added_soa: SoaRecord,
        removed: impl IntoIterator<Item = Record>,
        added: impl IntoIterator<Item = Record>,
    ) -> Self {
        Self(Rel {
            remove_soa: removed_soa,
            remove: <Box<[_]>>::from_iter(removed),
            add_soa: added_soa,
            add: <Box<[_]>>::from_iter(added),
        })
    }

    /// The SOA record removed in this change.
    pub const fn removed_soa(&self) -> &SoaRecord {
        &self.0.remove_soa
    }

    /// The record sets removed in this change.
    pub const fn removed(&self) -> &[Record] {
        &self.0.remove
    }

    /// The SOA record added in this change.
    pub const fn added_soa(&self) -> &SoaRecord {
        &self.0.add_soa
    }

    /// The record sets added in this change.
    pub const fn added(&self) -> &[Record] {
        &self.0.add
    }
}

//------------------------------------------------------------------------------

/// The data of an instance of a zone, as a diff relative to some base.
struct Rel {
    /// The removed SOA record.
    pub remove_soa: SoaRecord,

    /// Records to remove from the base.
    pub remove: Box<[Record]>,

    /// The added SOA record.
    pub add_soa: SoaRecord,

    /// Records to add to the base.
    pub add: Box<[Record]>,
}
