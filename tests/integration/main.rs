//! Integration tests.

use std::sync::Arc;

use camino::Utf8Path;
use cascade_api as api;
use domain::base::{Rtype, iana::OptRcode};
use tokio::sync::Semaphore;
use tracing_subscriber::EnvFilter;

mod infra;
use infra::ports;

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

    let _ = infra::CURRENT_CONFIG.set(infra::TestConfig::default());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let docker = Arc::new(bollard::Docker::connect_with_defaults().unwrap());

        let image = Arc::new(infra::ImageBuilder::new(docker).build().await);

        let mut tests = tokio::task::JoinSet::new();

        tests.spawn(remove_zone(image.clone()));

        tests.join_all().await;
    });

    runtime.block_on(async {
        let _ = infra::ONGOING_ASYNC_DROPS
            .acquire_many(Semaphore::MAX_PERMITS as u32)
            .await
            .unwrap();
    });
}

#[tracing::instrument(level = "info", skip_all, fields(step))]
async fn remove_zone(image: Arc<infra::Image>) {
    let container = infra::ContainerBuilder::new(&image).build().await;
    let cascade = Arc::new(infra::Cascade::start(&container).await);

    tracing::info!("Add a zone");
    let zone_name: api::ZoneName = "example.test".parse().unwrap();
    cascade
        .add_zone(api::ZoneAdd {
            name: zone_name.clone(),
            source: api::ZoneSource::Zonefile {
                path: Utf8Path::new("/test/primary/example.test.zone").into(),
            },
            policy: "default".into(),
            key_imports: vec![],
        })
        .await
        .unwrap();

    tracing::info!("Cascade should list the zone");
    infra::poll(
        || cascade.clone(),
        async |c| c.zone_names().await,
        |names| names.contains(&zone_name),
    )
    .await;

    tracing::info!("Check zone status");
    let _ = infra::poll(
        || cascade.clone(),
        async |c| c.zone_status("example.test").await,
        |status| status.as_ref().is_ok_and(|s| s.last_published.is_some()),
    )
    .await;

    tracing::info!("Querying the zone should succeed");
    let res = container
        .dns_query(ports::PUBLICATION, "example.test", Rtype::SOA, None)
        .await;
    assert!(res.as_ref().is_ok_and(|r| r.no_error()), "{res:?}");

    tracing::info!("Remove the zone");
    cascade.remove_zone("example.test").await.unwrap();

    tracing::info!("Cascade should no longer list the zone");
    infra::poll(
        || cascade.clone(),
        async |c| c.zone_names().await,
        |names| !names.contains(&zone_name),
    )
    .await;

    tracing::info!("Querying the zone should now fail");
    let res = container
        .dns_query(ports::PUBLICATION, "example.test", Rtype::SOA, None)
        .await;
    assert!(
        res.as_ref()
            .is_ok_and(|r| r.opt_rcode() == OptRcode::REFUSED),
        "{res:?}"
    );

    tracing::info!("Check that Cascade is still running");
    assert!(cascade.health().await.unwrap().healthy);
}
