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

use crate::{InstanceData, RegularRecord, SoaRecord, is_signing};

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
        let origin = &*self.instance.soa.as_ref().unwrap().rname;
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
    ///
    /// Invariants:
    ///
    /// - `loaded-instance-init`: `loaded_instance` refers to a completed
    ///   instance, i.e. one with a SOA record and all other records available
    ///   and immutable.
    loaded_instance: &'d InstanceData,

    /// The signed instance being accessed.
    ///
    /// Invariants:
    ///
    /// - `signed-instance-init`: `signed_instance` refers to a completed
    ///   instance, i.e. one with a SOA record and all other records available
    ///   and immutable.
    signed_instance: &'d InstanceData,
}

impl<'d> SignedZoneReader<'d> {
    /// Construct a new [`SignedZoneReader`].
    ///
    /// ## Panics
    ///
    /// Panics if `loaded_instance.soa` or `signed_instance.soa` is not `Some`.
    pub(crate) const fn new(
        loaded_instance: &'d InstanceData,
        signed_instance: &'d InstanceData,
    ) -> Self {
        assert!(
            loaded_instance.soa.is_some(),
            "'loaded_instance' is not completed"
        );
        assert!(
            signed_instance.soa.is_some(),
            "'signed_instance' is not completed"
        );
        Self {
            loaded_instance,
            signed_instance,
        }
    }
}

impl<'d> SignedZoneReader<'d> {
    /// The SOA record.
    pub const fn soa(&self) -> &'d SoaRecord {
        self.signed_instance
            .soa
            .as_ref()
            .expect("checked that 'instance.soa' is 'Some' in 'new()'")
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
        LoadedZoneReader::new(self.loaded_instance)
    }

    /// Records from the loaded instance of the zone.
    ///
    /// Records are sorted in DNSSEC canonical order. Only records also present
    /// in the signed instance are included (the loaded SOA record, and loaded
    /// DNSKEY, RRSIG, CDS, CDNSKEY, ZONEMD records are excluded).
    pub fn loaded_records(&self) -> impl Iterator<Item = &'d RegularRecord> + Send + use<'d> {
        let soa = self.soa();
        LoadedZoneReader::new(self.loaded_instance)
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
