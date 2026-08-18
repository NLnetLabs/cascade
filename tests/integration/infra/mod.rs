//! Infrastructure for integration tests.

use std::{fmt::Debug, sync::OnceLock, time::Duration};

mod image;
pub use image::*;

mod container;
pub use container::*;

mod cascade;
pub use cascade::*;

mod services;
pub use services::*;

pub mod ports;

mod test;
pub use test::*;

pub mod runtime;
pub use runtime::async_drop;

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

/// Test configuration.
#[derive(Debug, Default)]
pub struct TestConfig {
    /// Correct tests where data mismatches occur.
    #[expect(dead_code)]
    pub bless: Option<bool>,

    /// Leave containers behind on failure.
    pub leave_containers_on_failure: Option<bool>,

    /// The maximum size of a dumped tarball, in bytes.
    pub max_dump_size: Option<usize>,
}

/// The configuration for the current invocation.
pub static CURRENT_CONFIG: OnceLock<TestConfig> = OnceLock::new();
