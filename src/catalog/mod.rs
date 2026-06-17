//! Catalog zone support.
//!
//! Cascade can act as a [catalog zone] consumer and producer (RFC 9432). As a
//! consumer, it transfers a catalog zone from a primary, parses its
//! membership and automatically adds or removes the listed member zones,
//! signing and serving them according to a templated policy. As a producer,
//! it can serve a catalog zone downstream that mirrors the members it manages,
//! so that downstream secondaries automatically transfer the signed zones.
//!
//! This module defines the runtime representation of a registered catalog
//! ([`CatalogConfig`]) together with the logic that maps catalog members onto
//! Cascade zones ([`CatalogConfig::resolve_member`]) and reconciles the
//! membership of a parsed catalog against the zones Cascade already manages
//! ([`CatalogConfig::diff`]).
//!
//! [catalog zone]: https://datatracker.ietf.org/doc/html/rfc9432

use std::vec::Vec;

use bytes::Bytes;
use domain::base::Name;
use domain::catalog::{Catalog, CatalogMember};

use crate::api;

//----------- CatalogConfig --------------------------------------------------

/// A catalog zone registered with Cascade.
///
/// This captures everything needed to consume a catalog zone: how the catalog
/// itself is transferred, which policy and source apply to its members, and
/// the set of members currently managed on its behalf.
#[derive(Clone, Debug)]
pub struct CatalogConfig {
    /// The apex name of the catalog zone.
    pub name: Name<Bytes>,

    /// How the catalog zone itself is transferred.
    ///
    /// Members are, by default, transferred from the same primary as the
    /// catalog zone when this is an [`api::ZoneSource::Server`].
    pub source: api::ZoneSource,

    /// The policy applied to members without a matching group mapping.
    pub default_policy: Box<str>,

    /// Per-group configuration overrides.
    pub groups: Vec<CatalogGroupConfig>,

    /// The apex name of the catalog zone produced downstream, if any.
    pub produced_catalog: Option<Name<Bytes>>,

    /// The member zones currently managed on behalf of this catalog.
    pub members: foldhash::HashSet<Name<Bytes>>,
}

impl CatalogConfig {
    /// Creates a new catalog configuration with no managed members.
    pub fn new(
        name: Name<Bytes>,
        source: api::ZoneSource,
        default_policy: Box<str>,
        groups: Vec<CatalogGroupConfig>,
        produced_catalog: Option<Name<Bytes>>,
    ) -> Self {
        Self {
            name,
            source,
            default_policy,
            groups,
            produced_catalog,
            members: foldhash::HashSet::default(),
        }
    }

    /// Resolves a catalog member onto a Cascade zone configuration.
    ///
    /// The member's policy and source are determined by its `group` property:
    /// a matching [group mapping][CatalogGroupConfig] supplies the policy and,
    /// optionally, a source override; otherwise the catalog's default policy
    /// and primary apply.
    ///
    /// Returns `None` if no source can be determined for the member, for
    /// example when the catalog is itself loaded from a zonefile and the
    /// member's group provides no source override. Such members are skipped.
    pub fn resolve_member(&self, member: &CatalogMember) -> Option<ResolvedMember> {
        let group = member
            .group()
            .map(|g| String::from_utf8_lossy(g).into_owned());
        let mapping = group.as_deref().and_then(|g| self.group(g));

        let policy = mapping
            .map(|mapping| mapping.policy.clone())
            .unwrap_or_else(|| self.default_policy.clone());

        let source = mapping
            .and_then(|mapping| mapping.source.clone())
            .or_else(|| self.default_member_source())?;

        Some(ResolvedMember {
            name: member.name().clone(),
            policy,
            source,
        })
    }

    /// Computes the changes needed to reconcile this catalog's membership.
    ///
    /// Members listed in `catalog` but not currently managed are returned in
    /// [`CatalogDiff::to_add`] (resolved to a Cascade zone configuration);
    /// members currently managed but no longer listed are returned in
    /// [`CatalogDiff::to_remove`]. This does not mutate the managed member
    /// set; the caller is responsible for applying the changes and updating
    /// [`CatalogConfig::members`].
    pub fn diff(&self, catalog: &Catalog) -> CatalogDiff {
        let present: foldhash::HashSet<&Name<Bytes>> = catalog
            .members()
            .iter()
            .map(|member| member.name())
            .collect();

        let mut to_add = Vec::new();
        for member in catalog.members() {
            if !self.members.contains(member.name())
                && let Some(resolved) = self.resolve_member(member)
            {
                to_add.push(resolved);
            }
        }

        let to_remove = self
            .members
            .iter()
            .filter(|name| !present.contains(name))
            .cloned()
            .collect();

        CatalogDiff { to_add, to_remove }
    }

    /// Returns the group mapping for the given group value, if any.
    fn group(&self, group: &str) -> Option<&CatalogGroupConfig> {
        self.groups.iter().find(|mapping| mapping.group == group)
    }

    /// Returns the default member source derived from the catalog's primary.
    ///
    /// This is the catalog's own source when it is transferred from a server,
    /// and `None` otherwise.
    fn default_member_source(&self) -> Option<api::ZoneSource> {
        match &self.source {
            api::ZoneSource::Server { .. } => Some(self.source.clone()),
            _ => None,
        }
    }
}

//----------- CatalogGroupConfig ---------------------------------------------

/// A per-group configuration override for a catalog.
#[derive(Clone, Debug)]
pub struct CatalogGroupConfig {
    /// The value of the member `group` property this mapping applies to.
    pub group: String,

    /// The policy applied to members in this group.
    pub policy: Box<str>,

    /// An optional override for the source of member zones in this group.
    pub source: Option<api::ZoneSource>,
}

//----------- ResolvedMember -------------------------------------------------

/// A catalog member resolved to a Cascade zone configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMember {
    /// The name of the member zone.
    pub name: Name<Bytes>,

    /// The policy to apply to the member zone.
    pub policy: Box<str>,

    /// The source from which to transfer the member zone.
    pub source: api::ZoneSource,
}

//----------- CatalogDiff ----------------------------------------------------

/// The changes needed to reconcile a catalog's membership.
#[derive(Clone, Debug, Default)]
pub struct CatalogDiff {
    /// Members to add, resolved to Cascade zone configurations.
    pub to_add: Vec<ResolvedMember>,

    /// Names of members to remove.
    pub to_remove: Vec<Name<Bytes>>,
}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use std::net::SocketAddr;

    use bytes::Bytes;
    use domain::base::Name;
    use domain::catalog::{Catalog, CatalogMember};

    use crate::api;

    use super::{CatalogConfig, CatalogGroupConfig};

    fn name(text: &str) -> Name<Bytes> {
        Name::bytes_from_str(text).unwrap()
    }

    fn server(addr: &str) -> api::ZoneSource {
        api::ZoneSource::Server {
            addr: addr.parse::<SocketAddr>().unwrap(),
            tsig_key: None,
        }
    }

    fn member(id: &'static [u8], zone: &str, group: Option<&[u8]>) -> CatalogMember {
        let mut member = CatalogMember::new(Bytes::from_static(id), name(zone));
        if let Some(group) = group {
            member.set_group(Bytes::copy_from_slice(group));
        }
        member
    }

    fn config() -> CatalogConfig {
        CatalogConfig::new(
            name("catalog.example."),
            server("192.0.2.1:53"),
            "default-policy".into(),
            vec![CatalogGroupConfig {
                group: "production".into(),
                policy: "prod-policy".into(),
                source: Some(server("192.0.2.2:53")),
            }],
            None,
        )
    }

    #[test]
    fn ungrouped_member_uses_default_policy_and_catalog_primary() {
        let config = config();
        let resolved = config
            .resolve_member(&member(b"id1", "one.example.", None))
            .unwrap();
        assert_eq!(resolved.name, name("one.example."));
        assert_eq!(&*resolved.policy, "default-policy");
        assert_eq!(resolved.source, server("192.0.2.1:53"));
    }

    #[test]
    fn grouped_member_uses_group_policy_and_source() {
        let config = config();
        let resolved = config
            .resolve_member(&member(b"id2", "two.example.", Some(b"production")))
            .unwrap();
        assert_eq!(&*resolved.policy, "prod-policy");
        assert_eq!(resolved.source, server("192.0.2.2:53"));
    }

    #[test]
    fn unmapped_group_falls_back_to_default() {
        let config = config();
        let resolved = config
            .resolve_member(&member(b"id3", "three.example.", Some(b"staging")))
            .unwrap();
        assert_eq!(&*resolved.policy, "default-policy");
        assert_eq!(resolved.source, server("192.0.2.1:53"));
    }

    #[test]
    fn member_without_source_is_skipped() {
        let mut config = config();
        config.source = api::ZoneSource::Zonefile {
            path: "/tmp/catalog.zone".into(),
        };
        // No group mapping, so no source can be determined.
        assert!(
            config
                .resolve_member(&member(b"id1", "one.example.", None))
                .is_none()
        );
    }

    #[test]
    fn diff_adds_new_and_removes_absent_members() {
        let mut config = config();
        config.members.insert(name("old.example."));

        let mut catalog = Catalog::new(name("catalog.example."));
        catalog.push_member(member(b"id1", "one.example.", None));
        catalog.push_member(member(b"id2", "two.example.", Some(b"production")));

        let diff = config.diff(&catalog);

        let added: Vec<&Name<Bytes>> = diff.to_add.iter().map(|member| &member.name).collect();
        assert!(added.contains(&&name("one.example.")));
        assert!(added.contains(&&name("two.example.")));
        assert_eq!(diff.to_add.len(), 2);
        assert_eq!(diff.to_remove, vec![name("old.example.")]);
    }

    #[test]
    fn diff_ignores_already_managed_members() {
        let mut config = config();
        config.members.insert(name("one.example."));

        let mut catalog = Catalog::new(name("catalog.example."));
        catalog.push_member(member(b"id1", "one.example.", None));

        let diff = config.diff(&catalog);
        assert!(diff.to_add.is_empty());
        assert!(diff.to_remove.is_empty());
    }
}
