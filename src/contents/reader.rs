//! Reading zone data.

use cascade_zonedata::{RegularRecord, SoaRecord, is_signing};
use domain::new::base::name::RevName;

use super::{LoadedInstanceData, SignedInstanceData};

//----------- LoadedZoneReader -------------------------------------------------

/// A reader for a loaded instance of a zone.
///
/// [`LoadedZoneReader`] offers efficient access to the records of a loaded
/// instance of a zone (whether it is the current authoritative instance or a
/// prepared, upcoming one). This instance primarily consists of unsigned data.
pub struct LoadedZoneReader<'d> {
    /// The instance being accessed.
    pub instance: &'d LoadedInstanceData,
}

impl LoadedZoneReader<'_> {
    /// Check invariants.
    pub fn check_invariants(&self) {
        self.instance.check_invariants();
    }
}

impl<'d> LoadedZoneReader<'d> {
    /// The zone origin.
    pub fn origin(&self) -> &'d RevName {
        &self.instance.soa.rname
    }

    /// The SOA record.
    pub fn soa(&self) -> &'d SoaRecord {
        &self.instance.soa
    }

    /// Regular records in the zone.
    ///
    /// Records are sorted in DNSSEC canonical order. The SOA record **is**
    /// included.
    pub const fn regular_records(&self) -> &'d [RegularRecord] {
        self.instance.records.as_slice()
    }

    /// The unsigned records in the zone.
    ///
    /// DNSSEC related records that would be produced by Cascade's signer (e.g.
    /// RRSIGs, NSEC/NSEC3, etc.) are stripped. The records are sorted in DNSSEC
    /// canonical order. The SOA record **is** included.
    pub fn unsigned_records(&self) -> impl Iterator<Item = &'d RegularRecord> + Send + use<'d> {
        // Filter out records that would be generated during signing.
        let origin = self.origin();
        self.instance
            .records
            .iter()
            .filter(|&r| !is_signing(r.rtype, || *r.rname == *origin))
    }
}

//----------- SignedZoneReader -------------------------------------------------

/// A reader for the signed component of an instance of a zone.
///
/// [`SignedZoneReader`] offers efficient access to the records of a signed
/// instance of a zone (whether it is the current authoritative instance or a
/// prepared, upcoming one). This instance primarily consists of signature data.
pub struct SignedZoneReader<'d> {
    /// The loaded instance being accessed.
    pub loaded_instance: &'d LoadedInstanceData,

    /// The signed instance being accessed.
    pub signed_instance: &'d SignedInstanceData,
}

impl SignedZoneReader<'_> {
    /// Check invariants.
    pub fn check_invariants(&self) {
        self.loaded_instance.check_invariants();
        self.signed_instance.check_invariants();

        assert_eq!(
            self.loaded_instance.soa.rname, self.signed_instance.soa.rname,
            "The loaded and signed instance must have the same origin"
        );
    }
}

impl<'d> SignedZoneReader<'d> {
    /// The zone origin.
    pub fn origin(&self) -> &'d RevName {
        &self.signed_instance.soa.rname
    }

    /// The SOA record.
    pub fn soa(&self) -> &'d SoaRecord {
        &self.signed_instance.soa
    }

    /// All records generated during signing.
    ///
    /// Records are sorted in DNSSEC canonical order. The SOA record **is**
    /// included.
    pub const fn generated_records(&self) -> &'d [RegularRecord] {
        self.signed_instance.records.as_slice()
    }

    /// The underlying loaded instance.
    pub const fn loaded(&self) -> LoadedZoneReader<'d> {
        LoadedZoneReader {
            instance: self.loaded_instance,
        }
    }

    /// Records from the loaded instance of the zone.
    ///
    /// Records are sorted in DNSSEC canonical order. Only records also present
    /// in the signed instance are included (the loaded SOA record, and loaded
    /// DNSKEY, RRSIG, CDS, CDNSKEY, ZONEMD records are excluded).
    pub fn loaded_records(&self) -> impl Iterator<Item = &'d RegularRecord> + Send + use<'d> {
        let soa = self.soa();
        self.loaded()
            .unsigned_records()
            .filter(|&r| r.rname != soa.rname || r.rtype != soa.rtype)
    }

    /// All records in the zone.
    ///
    /// Records are **unsorted**. The SOA record (of the signed instance) **is**
    /// included; unsigned records from the loaded instance **are** included.
    pub fn all_records(&self) -> impl Iterator<Item = &'d RegularRecord> + Send + use<'d> {
        self.generated_records().iter().chain(self.loaded_records())
    }
}
