//! Integration tests.

use std::env;

use bollard::plugin::{ContainerCreateBody, HostConfig, Mount, MountType};
use tracing_subscriber::EnvFilter;

mod infra;
use infra::strs;

#[tokio::main]
async fn main() {
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

    let bollard = bollard::Docker::connect_with_defaults().unwrap();

    let daemon_path = env::var("CARGO_BIN_EXE_cascaded").unwrap();

    infra::build_image(&bollard).await;

    let response = bollard
        .create_container(
            None,
            ContainerCreateBody {
                exposed_ports: Some(vec![
                    format!("{}/tcp", infra::ports::REMOTE_CONTROL),
                    format!("{}/tcp", infra::ports::LOADED_REVIEW),
                    format!("{}/udp", infra::ports::LOADED_REVIEW),
                    format!("{}/tcp", infra::ports::SIGNED_REVIEW),
                    format!("{}/udp", infra::ports::SIGNED_REVIEW),
                    format!("{}/tcp", infra::ports::PUBLICATION),
                    format!("{}/udp", infra::ports::PUBLICATION),
                ]),
                env: Some(strs!["RUST_BACKTRACE=1"]),
                image: Some("nlnetlabs/cascade-tests-runner".into()),
                host_config: Some(HostConfig {
                    mounts: Some(vec![Mount {
                        target: Some("/test/bin/cascaded".into()),
                        source: Some(daemon_path),
                        typ: Some(MountType::BIND),
                        read_only: Some(true),
                        ..Default::default()
                    }]),
                    dns: Some(strs!["127.0.0.1"]),
                    // TODO: Copied from old `resolv.conf` file, are these needed?
                    dns_options: Some(strs!["edns0", "trust-ad"]),
                    publish_all_ports: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    for w in response.warnings {
        tracing::warn!("{w}");
    }

    let container_id = response.id;

    bollard.start_container(&container_id, None).await.unwrap();

    tracing::info!(id = container_id, "Launched container");

    let resolver = infra::UnboundResolver::start(&bollard, &container_id).await;
    let parent = infra::BindParent::start(&bollard, &container_id).await;
    let primary = infra::NsdPrimary::start(&bollard, &container_id).await;
    let secondary = infra::NsdSecondary::start(&bollard, &container_id).await;

    let cascade = infra::Cascade::start(&bollard, &container_id).await;

    tracing::info!("Policy names: {:?}", cascade.policy_names().await);
}
