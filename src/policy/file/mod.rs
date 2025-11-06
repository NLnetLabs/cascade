//! The policy file.

use std::{fs, io, sync::Arc};

use camino::Utf8Path;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{center::Change, zone::ZoneByName};

use super::Policy;

pub mod v1;

//----------- FileSpec ---------------------------------------------------------

/// A policy file.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "version")]
pub enum Spec {
    /// The version 1 format.
    V1(v1::Spec),
}

//--- Conversion

impl Spec {
    /// Parse a new [`Policy`].
    pub fn parse(self, name: &str) -> Policy {
        let latest = Arc::new(match self {
            Self::V1(spec) => spec.parse(name),
        });

        Policy {
            latest: latest.clone(),
            mid_deletion: false,
            zones: Default::default(),
        }
    }

    /// Merge with an existing [`Policy`].
    ///
    /// Returns `true` if the policy has changed.
    #[allow(clippy::mutable_key_type)]
    pub fn parse_into(
        self,
        existing: &mut Policy,
        zones: &foldhash::HashSet<ZoneByName>,
        mut on_change: impl FnMut(Change),
    ) -> bool {
        let latest = &*existing.latest;
        let new = match self {
            Self::V1(spec) => spec.parse(&latest.name),
        };

        if *latest == new {
            // The policy has not changed.
            return false;
        }

        // The policy has changed.
        let new = Arc::new(new);
        let old = core::mem::replace(&mut existing.latest, new.clone());

        // Output change notifications.
        info!("Updated policy '{}'", new.name);
        (on_change)(Change::PolicyChanged(old.clone(), new.clone()));
        for zone in &existing.zones {
            let zone = zones.get(zone).expect("zones and policies are consistent");
            let mut state = zone.0.state.lock().unwrap();
            let old_for_zone = state.policy.replace(new.clone());
            assert_eq!(
                Some(&old.name),
                old_for_zone.as_ref().map(|z| &z.name),
                "zones and policies are consistent"
            );
            (on_change)(Change::ZonePolicyChanged {
                name: zone.0.name.clone(),
                old: Some(old.clone()),
                new: new.clone(),
            });
        }
        true
    }

    /// Build into this specification.
    pub fn build(policy: &Policy) -> Self {
        Self::V1(v1::Spec::build(&policy.latest))
    }
}

//--- Loading / Saving

impl Spec {
    /// Load and parse this specification from a file.
    pub fn load(path: &Utf8Path) -> io::Result<Self> {
        let text = fs::read_to_string(path)?;
        toml::from_str(&text).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    /// Build and save this specification to a file.
    pub fn save(&self, path: &Utf8Path) -> io::Result<()> {
        let text = toml::to_string_pretty(self)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        crate::util::write_file(path, text.as_bytes())
    }
}
