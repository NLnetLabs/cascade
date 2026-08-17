//! Integration tests.

use testcontainers::{
    ImageExt,
    core::{ContainerPort, ExecCommand},
    runners::AsyncRunner,
};
use tracing_subscriber::EnvFilter;

mod infra;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        // Filter out unnecessary noise.
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("h2=error".parse().unwrap())
                .add_directive("bollard=error".parse().unwrap()),
        )
        .init();

    let image = infra::build_image().await;

    let container = image
        .clone()
        .with_exposed_port(ContainerPort::Tcp(53))
        .with_exposed_port(ContainerPort::Tcp(4539))
        .with_exposed_port(ContainerPort::Tcp(4540))
        .with_exposed_port(ContainerPort::Tcp(4541))
        .with_exposed_port(ContainerPort::Tcp(4542))
        .with_host_config_modifier(|config| {
            // Use the system resolver we spawn for DNS.
            config.dns = Some(vec!["127.0.0.1".into()]);
            // TODO: Copied from old `resolv.conf` file, are these needed?
            config.dns_options = Some(vec!["edns0".into(), "trust-ad".into()]);
        })
        .start()
        .await
        .unwrap();

    tracing::info!(id = container.id(), "Launched container");

    let bollard = testcontainers::core::client::docker_client_instance()
        .await
        .unwrap();

    let resolver = infra::UnboundResolver::start(&bollard, &container).await;
    let parent = infra::BindParent::start(&bollard, &container).await;
    let primary = infra::NsdPrimary::start(&bollard, &container).await;
    let secondary = infra::NsdSecondary::start(&bollard, &container).await;

    let mut spawned = container
        .exec(ExecCommand::new(["echo", "hi"]))
        .await
        .unwrap();

    let code = spawned.exit_code().await.unwrap();
    let stdout = spawned.stdout_to_vec().await.unwrap();
    let stderr = spawned.stderr_to_vec().await.unwrap();

    tracing::info!(
        ?spawned,
        ?code,
        stdout = ?stdout.utf8_chunks(),
        stderr = ?stderr.utf8_chunks(),
        "Ran `echo hi`");
}
