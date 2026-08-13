//! Storage for zone contents.

use std::fmt;
use std::sync::RwLock;

//--- Submodules

mod data;
pub use data::{LoadedInstanceData, SignedInstanceData};

mod diff;
pub use diff::InstanceDiff;

mod reader;
pub use reader::{LoadedZoneReader, SignedZoneReader};

mod apply;
pub use apply::Inconsistency;

//----------- ZoneContents -----------------------------------------------------

/// The contents of a zone.
pub struct ZoneContents {
    /// The current (published) loaded instance.
    pub loaded: RwLock<Option<LoadedInstanceData>>,

    /// The current (published) signed instance.
    pub signed: RwLock<Option<SignedInstanceData>>,
}

impl ZoneContents {
    /// Construct a new [`ZoneContents`].
    pub const fn new() -> Self {
        Self {
            loaded: RwLock::new(None),
            signed: RwLock::new(None),
        }
    }
}

impl Default for ZoneContents {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ZoneContents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneContents").finish_non_exhaustive()
    }
}
