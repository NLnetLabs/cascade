//! The policy file.

use std::{fs, io};

use camino::Utf8Path;
use serde::{Deserialize, Serialize};

use crate::policy::PolicyVersion;

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
    /// Parse a new [`PolicyVersion`].
    pub fn parse(self, name: &str) -> PolicyVersion {
        match self {
            Self::V1(spec) => spec.parse(name),
        }
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
