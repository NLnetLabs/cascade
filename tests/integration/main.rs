//! Integration tests.

use std::sync::Arc;

use tokio::sync::Semaphore;
use tracing_subscriber::EnvFilter;

mod infra;

fn main() {
    tracing_subscriber::fmt()
        // Filter out unnecessary noise.
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("h2=error".parse().unwrap())
                .add_directive("tonic=error".parse().unwrap())
                .add_directive("hyper_util=error".parse().unwrap())
                .add_directive("bollard=error".parse().unwrap()),
        )
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let docker = Arc::new(bollard::Docker::connect_with_defaults().unwrap());

        let image = infra::ImageBuilder::new(docker).build().await;

        let container = infra::ContainerBuilder::new(&image).build().await;

        let resolver = infra::UnboundResolver::start(&container).await;
        let parent = infra::BindParent::start(&container).await;
        let primary = infra::NsdPrimary::start(&container).await;
        let secondary = infra::NsdSecondary::start(&container).await;

        let cascade = infra::Cascade::start(&container).await;

        tracing::info!("Policy names: {:?}", cascade.policy_names().await);
    });

    runtime.block_on(async {
        let _ = infra::ONGOING_ASYNC_DROPS
            .acquire_many(Semaphore::MAX_PERMITS as u32)
            .await
            .unwrap();
    });
}
