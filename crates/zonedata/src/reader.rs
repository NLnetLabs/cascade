//! Reading instances of zones.

use crate::{InstanceHalf, RegularRecord, SoaRecord};

//----------- UnsignedZoneReader -----------------------------------------------

/// A reader for an unsigned instance of a zone.
pub struct UnsignedZoneReader<'d> {
    /// The underlying data.
    pub(crate) data: &'d InstanceHalf,
}

impl<'d> UnsignedZoneReader<'d> {
    /// The SOA record.
    pub fn soa(&self) -> &'d SoaRecord {
        &self.data.soa
    }

    /// The records in the zone.
    ///
    /// The records are sorted in DNSSEC canonical order. The SOA record is not
    /// included.
    pub fn records(&self) -> &'d [RegularRecord] {
        &self.data.all
    }
}

//----------- SignedZoneReader -------------------------------------------------

/// A reader for a signed instance of a zone.
pub struct SignedZoneReader<'d> {
    /// The underlying data.
    pub(crate) data: &'d InstanceHalf,
}

impl<'d> SignedZoneReader<'d> {
    /// The SOA record.
    pub fn soa(&self) -> &'d SoaRecord {
        &self.data.soa
    }

    /// The records in the zone.
    ///
    /// The records are sorted in DNSSEC canonical order. The SOA record is not
    /// included.
    pub fn records(&self) -> &'d [RegularRecord] {
        &self.data.all
    }
}
