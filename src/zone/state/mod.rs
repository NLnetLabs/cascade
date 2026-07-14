//! Saving Cascade's zone state.

use std::{
    collections::hash_map,
    error::Error,
    fmt, fs,
    io::{self, BufReader},
    sync::Arc,
};

use bytes::Bytes;
use camino::Utf8Path;
use domain::{base::Name, dep::octseq::Array};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    loader::zone::LoaderState,
    persistence::zone::PersistenceState,
    policy::{Policy, PolicyVersion},
    tsig::TsigStore,
    zone::ZoneState,
};

pub mod v1;

//----------- ZoneStateSpec ----------------------------------------------------

/// A zone state file.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "version")]
pub enum Spec {
    /// The version 1 format.
    V1(v1::Spec),
}

//--- Conversion

impl Spec {
    /// Merge this specification with an existing zone state.
    pub fn parse(
        self,
        zone_name: &Name<Bytes>,
        policies: &mut foldhash::HashMap<Box<str>, Policy>,
        tsig_store: &TsigStore,
    ) -> Result<ZoneState, LoadError> {
        /// Synchronize a loaded policy with global state.
        fn sync_policy(
            known_version: PolicyVersion,
            policies: &mut foldhash::HashMap<Box<str>, Policy>,
        ) -> &mut Policy {
            // Check whether a policy of this name exists.
            match policies.entry(known_version.name.clone()) {
                hash_map::Entry::Occupied(entry) => {
                    // A policy of this name exists.  Compare to it.
                    let policy = entry.into_mut();
                    if *policy.latest != known_version {
                        // TODO: Continue using the older version of the policy, and
                        // enqueue an explicit change to the zone, so that any
                        // necessary hooks (e.g. re-signing) can be activated.
                        warn!(
                            "Detected an inconsistency between the details of policy '{}' last used with the zone and the policy details in the global state; switching to the global state's details",
                            known_version.name
                        );
                    }

                    policy
                }

                hash_map::Entry::Vacant(entry) => {
                    warn!(
                        "The policy '{}' used by the zone is not present in the global state; restoring it into the global state",
                        known_version.name
                    );

                    entry.insert(Policy {
                        latest: Arc::new(known_version),
                        mid_deletion: false,
                        zones: Default::default(),
                    })
                }
            }
        }

        match self {
            Self::V1(v1::Spec {
                policy,
                instances,
                source,
                min_expiration,
                next_min_expiration,
                apex_remove,
                apex_extra,
                key_tags,
                key_roll,
                last_signature_refresh,
                previous_serial,
                history,
                persisted_loaded_diffs,
                persisted_signed_diffs,
            }) => {
                let loader = LoaderState {
                    source: source
                        .parse(tsig_store)
                        .map_err(LoadError::MissingSourceTsigKey)?,
                    ..Default::default()
                };

                // TODO: Won't this always be a `Some`?
                let mut policy = policy.map(|policy| sync_policy(policy.parse(), policies));
                if let Some(policy) = &mut policy {
                    // Register that the policy is in use by this zone. It might
                    // already be registered; that's fine.
                    policy.zones.insert(zone_name.clone());
                }
                let policy = policy.map(|p| p.latest.clone());

                let persistence = PersistenceState {
                    loaded_diff_paths: persisted_loaded_diffs,
                    signed_diff_paths: persisted_signed_diffs
                        .into_iter()
                        .map(|(d, s)| (d, s.map(|s| domain::new::base::Serial::from(s.0))))
                        .collect(),
                    ..Default::default()
                };

                Ok(ZoneState {
                    policy,
                    instances: instances.parse(),
                    min_expiration,
                    next_min_expiration,
                    apex_remove,
                    apex_extra,
                    key_tags,
                    key_roll,
                    last_signature_refresh,
                    previous_serial,
                    loader,
                    history,
                    persistence,
                    ..Default::default()
                })
            }
        }
    }

    /// Build into this specification.
    pub fn build(zone: &ZoneState) -> Self {
        Self::V1(v1::Spec::build(zone))
    }
}

//--- Loading / Saving

impl Spec {
    /// Load and parse this specification from a file.
    pub fn load(path: &Utf8Path) -> io::Result<Self> {
        let file = BufReader::new(fs::File::open(path)?);
        let spec = serde_json::from_reader(file)?;
        Ok(spec)
    }

    /// Build and save this specification to a file.
    pub fn save(&self, path: &Utf8Path) -> io::Result<()> {
        let text = serde_json::to_string(self)?;
        crate::util::write_file(path, text.as_bytes())
    }
}

//============ Errors ==========================================================

//----------- LoadError --------------------------------------------------------

/// An error loading a zone state file.
#[derive(Debug)]
pub enum LoadError {
    /// The file could not be read.
    Read {
        /// The path being read from.
        path: Box<Utf8Path>,

        /// The I/O error.
        error: io::Error,
    },

    /// The TSIG key for the zone source could not be found.
    MissingSourceTsigKey(MissingTsigKeyError),
}

impl Error for LoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { error, .. } => Some(error),
            Self::MissingSourceTsigKey(error) => Some(error),
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, error } => {
                write!(f, "could not read the zone state file '{path}': {error}")
            }
            Self::MissingSourceTsigKey(error) => {
                write!(f, "could not load the zone source setting: {error}")
            }
        }
    }
}

//----------- MissingTsigKeyError ----------------------------------------------

/// A TSIG key could not be found.
///
/// A zone's state file indicated that it was using a TSIG key, but the key
/// could not be found in the configured TSIG key store.
#[derive(Clone, Debug)]
pub struct MissingTsigKeyError {
    /// The name of the TSIG key.
    pub name: Box<Name<Array<255>>>,
}

impl Error for MissingTsigKeyError {}

impl fmt::Display for MissingTsigKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TSIG key '{}' could not be found", self.name)
    }
}
