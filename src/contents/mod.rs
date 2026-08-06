//! Storage for zone contents.

mod data;
pub use data::{LoadedInstanceData, SignedInstanceData};

mod diff;
pub use diff::InstanceDiff;

mod reader;
pub use reader::{LoadedZoneReader, SignedZoneReader};

mod apply;
pub use apply::Inconsistency;
