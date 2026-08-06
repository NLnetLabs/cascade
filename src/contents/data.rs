//! The raw storage for zone data.

use cascade_zonedata::{RegularRecord, SoaRecord};

//----------- LoadedInstanceData -----------------------------------------------

/// A loaded instance of a zone.
pub struct LoadedInstanceData {
    /// The SOA record.
    pub soa: Box<SoaRecord>,

    /// All records.
    ///
    /// Records are sorted in DNSSEC canonical order. The SOA record **is**
    /// included.
    pub records: Vec<RegularRecord>,
}

//----------- SignedInstanceData -----------------------------------------------

/// A signed instance of a zone.
///
/// This is relative to a [`LoadedInstanceData`]; it serves as a layer on top
/// that adds and removes records.
pub struct SignedInstanceData {
    /// The SOA record.
    ///
    /// This overrides the SOA record of the loaded instance.
    pub soa: Box<SoaRecord>,

    /// All generated records.
    ///
    /// These records are added during signing.
    ///
    /// Records are sorted in DNSSEC canonical order. The SOA record **is**
    /// included.
    pub records: Vec<RegularRecord>,
}
