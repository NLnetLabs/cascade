//! Producing a downstream catalog zone.
//!
//! When a consumed catalog is configured with a `produced_catalog`, Cascade
//! mirrors its membership into a new catalog zone under a different apex. This
//! lets downstream secondaries transfer the produced catalog and, in turn,
//! automatically transfer the signed member zones Cascade serves.
//!
//! This module builds the produced catalog zone from the membership of the
//! consumed catalog, preserving member identifiers and `group` properties so
//! that the downstream view matches the upstream one. Serving the produced
//! zone is handled separately.

use bytes::Bytes;
use domain::base::{Name, Serial, Ttl};
use domain::catalog::{BuildCatalogError, Catalog, CatalogMember};
use domain::rdata::Soa;
use domain::zonetree::Zone;

/// The TTL used for records in produced catalog zones.
const PRODUCED_TTL: Ttl = Ttl::from_secs(3600);

/// The SOA EXPIRE used for produced catalog zones (4 weeks).
const PRODUCED_EXPIRE: Ttl = Ttl::from_secs(2_419_200);

/// Builds a produced catalog zone mirroring the given consumed catalog.
///
/// The produced zone uses `produced_apex` as its apex and lists exactly the
/// members of `source`, preserving their identifiers and `group` properties.
/// `refresh` and `retry` seed the produced zone's SOA timers (typically those
/// of the consumed catalog).
pub fn produce_zone(
    produced_apex: &Name<Bytes>,
    source: &Catalog,
    refresh: Ttl,
    retry: Ttl,
) -> Result<Zone, BuildCatalogError> {
    let mut mirror = Catalog::new(produced_apex.clone());
    for member in source.members() {
        let mut copy =
            CatalogMember::new(Bytes::copy_from_slice(member.id()), member.name().clone());
        if let Some(group) = member.group() {
            copy.set_group(Bytes::copy_from_slice(group));
        }
        mirror.push_member(copy);
    }

    let serial = source.serial().unwrap_or_else(|| Serial::from(1));
    let soa = Soa::new(
        produced_apex.clone(),
        produced_apex.clone(),
        serial,
        refresh,
        retry,
        PRODUCED_EXPIRE,
        PRODUCED_TTL,
    );
    let ns = [produced_apex.clone()];

    mirror.to_zone(soa, &ns, PRODUCED_TTL)
}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use bytes::Bytes;
    use domain::base::{Name, Ttl};
    use domain::catalog::{Catalog, CatalogMember};

    use super::produce_zone;

    fn name(text: &str) -> Name<Bytes> {
        Name::bytes_from_str(text).unwrap()
    }

    #[test]
    fn produced_catalog_mirrors_membership() {
        let mut source = Catalog::new(name("upstream.example."));
        source.push_member(CatalogMember::new(
            Bytes::from_static(b"id1"),
            name("one.example."),
        ));
        let mut grouped = CatalogMember::new(Bytes::from_static(b"id2"), name("two.example."));
        grouped.set_group(Bytes::from_static(b"production"));
        source.push_member(grouped);

        let produced_apex = name("downstream.example.");
        let zone = produce_zone(
            &produced_apex,
            &source,
            Ttl::from_secs(3600),
            Ttl::from_secs(600),
        )
        .unwrap();

        // Parsing the produced zone should recover the same membership.
        let parsed = Catalog::parse_zone(&zone).unwrap();
        assert_eq!(parsed.apex(), &produced_apex);
        assert_eq!(parsed.members().len(), 2);

        let mut names: Vec<_> = parsed.members().iter().map(|m| m.name().clone()).collect();
        names.sort_by_key(|name| name.to_string());
        assert_eq!(names, vec![name("one.example."), name("two.example.")]);

        let two = parsed
            .members()
            .iter()
            .find(|m| m.name() == &name("two.example."))
            .unwrap();
        assert_eq!(two.group(), Some(b"production".as_ref()));
    }
}
