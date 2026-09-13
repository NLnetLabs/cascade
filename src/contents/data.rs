//! The raw storage for zone data.

use cascade_zonedata::{RegularRecord, SoaRecord};
use domain::new::base::{RClass, RType};
use rayon::{
    iter::{IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSlice,
};

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

impl LoadedInstanceData {
    /// Check invariants.
    pub fn check_invariants(&self) {
        let origin = &*self.soa.rname;
        assert_eq!(self.soa.rtype, RType::SOA);
        assert_eq!(self.soa.rclass, RClass::IN);

        assert_eq!(
            self.records
                .par_iter()
                .filter(|&r| r.rtype == RType::SOA && *r.rname == *origin)
                .collect::<Vec<_>>(),
            vec![&RegularRecord::from((*self.soa).clone())],
            "`self.records` must contain `self.soa` and no other apex SOA records"
        );

        self.records.par_iter().for_each(|r| {
            assert!(
                r.rname.as_bytes().starts_with(self.soa.rname.as_bytes()),
                "{r:?} falls outside the zone origin {origin:?}"
            );
            assert_eq!(r.rclass, RClass::IN);
        });

        assert_eq!(
            self.records
                .par_array_windows::<2>()
                .find_any(|&[a, b]| a > b),
            None,
            "`self.records` must be sorted"
        );

        assert_eq!(
            self.records
                .par_array_windows::<2>()
                .find_any(|&[a, b]| a == b),
            None,
            "`self.records` must not contain duplicates"
        );

        assert_eq!(
            self.records
                .par_array_windows::<2>()
                .find_any(|&[a, b]| (&a.rname, a.rtype) == (&b.rname, b.rtype)
                    && a.rtype != RType::RRSIG
                    && a.ttl != b.ttl),
            None,
            "Non-RRSIG RRsets in `self.records` must have consistent TTLs",
        );
    }
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

impl SignedInstanceData {
    /// Check invariants.
    pub fn check_invariants(&self) {
        let origin = &*self.soa.rname;
        assert_eq!(self.soa.rtype, RType::SOA);
        assert_eq!(self.soa.rclass, RClass::IN);

        assert_eq!(
            self.records
                .par_iter()
                .filter(|&r| r.rtype == RType::SOA && *r.rname == *origin)
                .collect::<Vec<_>>(),
            vec![&RegularRecord::from((*self.soa).clone())],
            "`self.records` must contain `self.soa` and no other apex SOA records"
        );

        self.records.par_iter().for_each(|r| {
            assert!(
                r.rname.as_bytes().starts_with(self.soa.rname.as_bytes()),
                "{r:?} falls outside the zone origin {origin:?}"
            );
            assert_eq!(r.rclass, RClass::IN);
        });

        assert_eq!(
            self.records
                .par_array_windows::<2>()
                .find_any(|&[a, b]| a > b),
            None,
            "`self.records` must be sorted"
        );

        assert_eq!(
            self.records
                .par_array_windows::<2>()
                .find_any(|&[a, b]| a == b),
            None,
            "`self.records` must not contain duplicates"
        );

        assert_eq!(
            self.records
                .par_array_windows::<2>()
                .find_any(|&[a, b]| (&a.rname, a.rtype) == (&b.rname, b.rtype)
                    && a.rtype != RType::RRSIG
                    && a.ttl != b.ttl),
            None,
            "Non-RRSIG RRsets in `self.records` must have consistent TTLs",
        );
    }
}
