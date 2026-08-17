//! Integration tests.

use std::{env, path::PathBuf};

use testcontainers::{
    GenericBuildableImage,
    core::{ContainerPort, ExecCommand},
    runners::{AsyncBuilder, AsyncRunner},
};
use tracing_subscriber::EnvFilter;

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

    let base: PathBuf = env::var_os("CARGO_MANIFEST_DIR").unwrap().into();
    let daemon: PathBuf = env::var_os("CARGO_BIN_EXE_cascaded").unwrap().into();

    tracing::info!("Building image");

    let image = GenericBuildableImage::new("nlnetlabs/cascade-tests-runner", "latest")
        .with_dockerfile(base.join("tests/integration/Dockerfile"))
        .with_file(daemon, "cascaded")
        .build_image()
        .await
        .unwrap();

    tracing::info!("Built image");

    let container = image
        .clone()
        .with_exposed_port(ContainerPort::Tcp(53))
        .with_exposed_port(ContainerPort::Tcp(4539))
        .with_exposed_port(ContainerPort::Tcp(4540))
        .with_exposed_port(ContainerPort::Tcp(4541))
        .with_exposed_port(ContainerPort::Tcp(4542))
        // TODO: `.with_network()`?
        .start()
        .await
        .unwrap();

    tracing::info!(id = container.id(), "Launched container");

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
