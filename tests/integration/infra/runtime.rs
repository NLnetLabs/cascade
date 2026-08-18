//! The async runtime.

use std::{convert::Infallible, pin::pin, time::Duration};

use tokio::{
    signal::unix::{SignalKind, signal},
    sync::Semaphore,
};
use tracing::Instrument;

/// Run a future in a Tokio runtime.
///
/// Async drops will be executed, including on interrupt.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let output = runtime.block_on(async {
        let future = pin!(future);
        let interruption = pin!(interruption());
        tokio::select! {
            output = future => Some(output),
            _ = interruption => None,
        }
    });

    runtime.block_on(async {
        const TIMEOUT: Duration = Duration::from_secs(5);
        const WARNING_TIME: Duration = Duration::from_millis(500);

        let drops = pin!(ONGOING_ASYNC_DROPS.acquire_many(Semaphore::MAX_PERMITS as u32));
        let timeout = pin!(tokio::time::sleep(TIMEOUT));
        let warning = pin!(async move {
            tokio::time::sleep(WARNING_TIME).await;
            tracing::warn!("Waiting for async drops to finish...");
            std::future::pending::<Infallible>().await
        });
        let interruption = pin!(interruption());

        tokio::select! {
            _ = drops => {},
            () = timeout => {
                tracing::warn!("Cancelling over-running async drops");
            }
            _ = warning => unreachable!(),
            _ = interruption => {},
        }
    });

    output.unwrap_or_else(|| std::process::exit(1))
}

/// Wait for an interruption.
async fn interruption() {
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();

    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
    }
}

/// A counter of ongoing async drops.
///
/// When an object needs to be dropped asynchronously, it takes a permit from
/// this semaphore and executes the drop code in a Tokio task. When it finishes,
/// it returns the semaphore. The top-level runner code will wait (up to some
/// limit) for all async drops to finish before exiting.
static ONGOING_ASYNC_DROPS: Semaphore =
    Semaphore::const_new(Semaphore::MAX_PERMITS as u32 as usize);

/// Execute drop glue asynchronously.
pub fn async_drop<F: Future<Output = ()> + Send + 'static>(span: tracing::Span, f: F) {
    let drop_permit = ONGOING_ASYNC_DROPS.try_acquire().unwrap();
    tokio::spawn(async move {
        f.instrument(span).await;
        std::mem::drop(drop_permit);
    });
}
