//! Reading zone data.
//!
//! This module provides [`LoadedZoneReader`] and [`SignedZoneReader`], which
//! are simple safe interfaces through which authoritative and upcoming zone
//! data can be accessed. These types do not consider the concurrent access of
//! different instances of zone data; they are limited to considering a single
//! instance. They offer concurrency, but only for parallelizing access to one
//! instance, for efficiency.
//!
//! See the [`crate::viewer`] module for high-level types that do consider
//! concurrent access.

use crate::{InstanceData, RegularRecord, SoaRecord};

//----------- LoadedZoneReader -------------------------------------------------

/// A reader for a loaded instance of a zone.
///
/// [`LoadedZoneReader`] offers efficient access to the records of a loaded
/// instance of a zone (whether it is the current authoritative instance or a
/// prepared, upcoming one). This instance primarily consists of unsigned data.
pub struct LoadedZoneReader<'d> {
    /// The instance being accessed.
    ///
    /// Invariants:
    ///
    /// - `instance-init`: `instance` refers to a completed instance, i.e. one
    ///   with a SOA record and all other records available and immutable.
    instance: &'d InstanceData,
}

impl<'d> LoadedZoneReader<'d> {
    /// Construct a new [`LoadedZoneReader`].
    ///
    /// ## Panics
    ///
    /// Panics if `instance.soa` is not `Some`.
    pub(crate) const fn new(instance: &'d InstanceData) -> Self {
        assert!(instance.soa.is_some(), "'instance' is not completed");
        Self { instance }
    }
}

impl<'d> LoadedZoneReader<'d> {
    /// The SOA record.
    pub const fn soa(&self) -> &'d SoaRecord {
        self.instance
            .soa
            .as_ref()
            .expect("checked that 'instance.soa' is 'Some' in 'new()'")
    }

    /// Regular records in the zone.
    ///
    /// Records are sorted in DNSSEC canonical order. The SOA record **is not**
    /// included.
    pub const fn regular_records(&self) -> &'d [RegularRecord] {
        self.instance.records.as_slice()
    }

    /// All records in the zone.
    ///
    /// Records are sorted in DNSSEC canonical order. The SOA record **is**
    /// included.
    pub fn all_records(&self) -> impl IntoIterator<Item = RegularRecord> + use<'d> {
        let (soa, records) = (self.soa(), self.regular_records());
        let soa = RegularRecord::from(soa.clone());

        // Find the position to insert the SOA record.
        let pos = records
            .iter()
            .position(|r| soa <= *r)
            .unwrap_or(records.len());

        records[..pos]
            .iter()
            .cloned()
            .chain([soa])
            .chain(records[pos..].iter().cloned())
    }

    /// The unsigned records in the zone.
    ///
    /// DNSSEC related records that would be produced by Cascade's signer (e.g.
    /// RRSIGs, NSEC/NSEC3, etc.) are stripped. The records are sorted in DNSSEC
    /// canonical order. The SOA record **is not** included.
    pub fn unsigned_records(&self) -> impl IntoIterator<Item = RegularRecord> + use<'d> {
        // Filter out records that would be generated during signing.
        //
        // TODO: 'RType::{CDS, CDNSKEY, ZONEMD}'.
        self.instance
            .records
            .iter()
            .filter(|r| {
                !matches!(
                    r.rtype,
                    RType::NSEC | RType::NSEC3 | RType::NSEC3PARAM | RType::DNSKEY | RType::RRSIG
                ) && !matches!(r.rtype.code.get(), 59 | 60 | 63)
            })
            .cloned()
    }
}

//----------- SignedZoneReader -------------------------------------------------

/// A reader for the signed component of an instance of a zone.
///
/// [`SignedZoneReader`] offers efficient access to the records of a signed
/// instance of a zone (whether it is the current authoritative instance or a
/// prepared, upcoming one). This instance primarily consists of signature data.
pub struct SignedZoneReader<'d> {
    /// The instance being accessed.
    ///
    /// Invariants:
    ///
    /// - `instance-init`: `instance` refers to a completed instance, i.e. one
    ///   with a SOA record and all other records available and immutable.
    instance: &'d InstanceData,
}

impl<'d> SignedZoneReader<'d> {
    /// Construct a new [`SignedZoneReader`].
    ///
    /// ## Panics
    ///
    /// Panics if `instance.soa` is not `Some`.
    pub(crate) const fn new(instance: &'d InstanceData) -> Self {
        assert!(instance.soa.is_some(), "'instance' is not completed");
        Self { instance }
    }
}

impl SignedZoneReader<'_> {
    /// The SOA record.
    pub const fn soa(&self) -> &SoaRecord {
        self.instance
            .soa
            .as_ref()
            .expect("checked that 'instance.soa' is 'Some' in 'new()'")
    }

    /// All other records in the zone.
    ///
    /// Records are sorted in DNSSEC canonical order. The SOA record is not
    /// included.
    pub const fn records(&self) -> &[RegularRecord] {
        self.instance.records.as_slice()
    }
}
