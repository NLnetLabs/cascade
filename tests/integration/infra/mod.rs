//! Infrastructure for integration tests.

use std::{fmt::Debug, sync::OnceLock, time::Duration};

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

/// Repeat a measurement until it satisfies a predicate.
///
/// ## Panics
///
/// Panics if the measured object does not satisfy the predicate for too long.
pub async fn poll<S, T: Debug>(
    mut prepare: impl FnMut() -> S,
    mut measure: impl AsyncFnMut(S) -> T,
    pred: impl Fn(&T) -> bool,
) -> T {
    let timeout = Duration::from_secs(10);
    let frequency = Duration::from_millis(100);

    let mut last_seen = None::<T>;
    let result = tokio::time::timeout(timeout, async {
        loop {
            let state = (prepare)();
            let obj = last_seen.insert(measure(state).await);
            if (pred)(obj) {
                return last_seen.take().unwrap();
            }
            tokio::time::sleep(frequency).await;
        }
    })
    .await;

    match result {
        Ok(obj) => obj,
        Err(_) => {
            tracing::error!(?last_seen, "Polling failed");
            panic!("Polling failed")
        }
    }
}

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
