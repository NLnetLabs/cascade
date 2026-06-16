//! Serializing global state.

use std::{
    fs,
    io::{self, BufReader},
};

use bytes::Bytes;
use camino::Utf8Path;
use domain::base::Name;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::{
    center::{Center, State},
    policy::Policy,
};

pub mod v1;

//----------- Actions ----------------------------------------------------------

/// Persist the global state immediately.
pub fn save_now(center: &Center) {
    let spec = {
        // Load the global state.
        let mut state = center.state.lock().unwrap();

        // If there was an enqueued save operation, stop it.
        if let Some(save) = state.enqueued_save.take() {
            save.abort();
        }

        Spec::build(&state)
    };

    // Save the global state.
    let path = center.config.daemon.state_file.value();
    match spec.save(path) {
        Ok(()) => debug!("Saved the global state (to '{path}')"),
        Err(err) => {
            error!("Could not save the global state to '{path}': {err}");
        }
    }
}

//----------- StateSpec --------------------------------------------------------

/// A state file.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "version")]
pub enum Spec {
    /// The version 1 format.
    V1(v1::Spec),
}

//--- Conversion

impl Spec {
    /// Parse from this specification.
    ///
    /// `zones` will be set to the names of zones that need to be loaded.
    /// `policies` will be set to the set of policies from the global state
    /// file, that need to be parsed and inserted in the state.
    pub fn parse(
        self,
        zones: &mut foldhash::HashSet<Name<Bytes>>,
        policies: &mut foldhash::HashMap<Box<str>, PolicySpec>,
    ) -> State {
        match self {
            Self::V1(mut spec) => {
                // Extract and write out 'zones' and 'policies'.
                *zones = std::mem::take(&mut spec.zones);
                *policies = std::mem::take(&mut spec.policies)
                    .into_iter()
                    .map(|(k, v)| (k, PolicySpec::V1(v)))
                    .collect();

                spec.parse()
            }
        }
    }

    /// Build into this specification.
    pub fn build(state: &State) -> Self {
        Self::V1(v1::Spec::build(state))
    }
}

//--- Loading / Saving

impl Spec {
    /// Load and parse this specification from a file.
    pub fn load(path: &Utf8Path) -> io::Result<Self> {
        let file = BufReader::new(fs::File::open(path)?);
        serde_json::from_reader(file).map_err(|err| err.into())
    }

    /// Build and save this specification to a file.
    pub fn save(&self, path: &Utf8Path) -> io::Result<()> {
        // TODO: METRICS: set metric "state_last_saved = timestamp"?
        if path.parent().is_none() {
            return Err(io::ErrorKind::IsADirectory.into());
        }

        let text = serde_json::to_string(self)?;
        crate::util::write_file(path, text.as_bytes())
    }
}

//----------- PolicySpec -------------------------------------------------------

/// A policy serialized in global state.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "version")]
pub enum PolicySpec {
    /// The version 1 format.
    V1(v1::PolicySpec),
}

impl PolicySpec {
    /// Parse from this specification.
    pub fn parse(self, name: &str) -> Policy {
        match self {
            Self::V1(spec) => spec.parse(name),
        }
    }
}
