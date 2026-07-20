//! Definitions for Cascade policy files.

use serde::{Deserialize, Serialize};

//--- Versions

pub mod v1;

//--- Helpers

mod datetime;

//----------- VersionedSpec ----------------------------------------------------

/// A versioned policy file specification.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "version")]
pub enum VersionedSpec {
    /// The version 1 format.
    V1(v1::Spec),
}

// TODO(idea @bal-e): Define a version-independent policy file specification?
// - Would be called `Spec`.
// - Initially reuse definitions from `v1`.
// - `Spec` could be converted to and from `VersionedSpec` explicitly.
//   - Convert from any version, always build the latest version.
// - Maybe also provide conversions to and from every individual version.
//   - Conversions _to_ individual versions might need to be fallible.
//   - Unclear if conversion to the latest version can/should be fallible.
// - It would let users write policy files without locking themselves to a
//   particular version.
