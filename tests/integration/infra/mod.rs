//! Infrastructure for integration tests.

use std::sync::OnceLock;

use tokio::sync::Semaphore;

mod image;
pub use image::*;

mod container;
pub use container::*;

mod cascade;
pub use cascade::*;

mod services;
pub use services::*;

pub mod ports;

/// A counter of ongoing async drops.
///
/// When an object needs to be dropped asynchronously, it takes a permit from
/// this semaphore and executes the drop code in a Tokio task. When it finishes,
/// it returns the semaphore. The top-level runner code will wait (up to some
/// limit) for all async drops to finish before exiting.
pub static ONGOING_ASYNC_DROPS: Semaphore =
    Semaphore::const_new(Semaphore::MAX_PERMITS as u32 as usize);

/// Test configuration.
#[derive(Default)]
pub struct TestConfig {
    /// Leave containers behind on failure.
    pub leave_containers_on_failure: Option<bool>,

    /// The maximum size of a dumped tarball, in bytes.
    pub max_dump_size: Option<usize>,
}

/// The configuration for the current invocation.
pub static CURRENT_CONFIG: OnceLock<TestConfig> = OnceLock::new();
