//! Storage for zone contents.

mod data;
pub use data::{LoadedInstanceData, SignedInstanceData};

mod diff;
pub use diff::InstanceDiff;
