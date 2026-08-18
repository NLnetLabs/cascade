//! Supporting services.

use bollard::{Docker, exec::StartExecOptions, plugin::ExecConfig};

//----------- ports ------------------------------------------------------------

/// Important hard-coded port numbers within the container.
#[allow(dead_code)]
pub mod ports {
    /// The system resolver.
    pub const RESOLVER: u16 = 53;

    /// The primary name server.
    pub const PRIMARY: u16 = 1055;

    /// The secondary name server.
    pub const SECONDARY: u16 = 1054;

    /// The Cascade remote control server.
    pub const REMOTE_CONTROL: u16 = 4539;

    /// The Cascade loaded review server.
    pub const LOADED_REVIEW: u16 = 4540;

    /// The Cascade signed review server.
    pub const SIGNED_REVIEW: u16 = 4541;

    /// The Cascade publication server.
    pub const PUBLICATION: u16 = 4542;
}

//----------- UnboundResolver --------------------------------------------------

/// The system resolver (Unbound).
pub struct UnboundResolver {
    /// The Docker exec ID.
    #[expect(dead_code)]
    exec_id: String,
}

impl UnboundResolver {
    /// Start the service.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn start(client: &Docker, container_id: &str) -> Self {
        let exec_id = exec_detached(
            client,
            container_id,
            strs!["unbound", "-c", "/test/resolver/unbound.conf"],
            "/test/resolver",
        )
        .await;
        Self { exec_id }
    }
}

//----------- BindParent -------------------------------------------------------

/// The parent name server (BIND).
pub struct BindParent {
    /// The Docker exec ID.
    #[expect(dead_code)]
    exec_id: String,
}

impl BindParent {
    /// Start the service.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn start(client: &Docker, container_id: &str) -> Self {
        let exec_id = exec_detached(
            client,
            container_id,
            strs![
                "named",
                "-c",
                "/test/parent/bind.conf",
                "-d",
                "-1",
                "-L",
                "/test/parent/bind.log",
            ],
            "/test/parent",
        )
        .await;
        Self { exec_id }
    }
}

//----------- NsdPrimary -------------------------------------------------------

/// The primary name server (NSD).
pub struct NsdPrimary {
    /// The Docker exec ID.
    #[expect(dead_code)]
    exec_id: String,
}

impl NsdPrimary {
    /// Start the service.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn start(client: &Docker, container_id: &str) -> Self {
        let exec_id = exec_detached(
            client,
            container_id,
            strs!["nsd", "-c", "/test/primary/nsd.conf"],
            "/test/primary",
        )
        .await;
        Self { exec_id }
    }
}

//----------- NsdSecondary -----------------------------------------------------

/// The secondary name server (NSD).
pub struct NsdSecondary {
    /// The Docker exec ID.
    #[expect(dead_code)]
    exec_id: String,
}

impl NsdSecondary {
    /// Start the service.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn start(client: &Docker, container_id: &str) -> Self {
        let exec_id = exec_detached(
            client,
            container_id,
            strs!["nsd", "-c", "/test/secondary/nsd.conf"],
            "/test/secondary",
        )
        .await;
        Self { exec_id }
    }
}

//------------------------------------------------------------------------------

/// Start a detached process in a container.
///
/// Returns the Docker exec ID.
#[tracing::instrument(level = "debug", skip(client), ret)]
async fn exec_detached(
    client: &Docker,
    container_id: &str,
    command: Vec<String>,
    working_dir: &str,
) -> String {
    let exec_cfg = ExecConfig {
        cmd: Some(command),
        working_dir: Some(working_dir.into()),
        ..Default::default()
    };
    let exec_id = client.create_exec(container_id, exec_cfg).await.unwrap().id;
    client
        .start_exec(
            &exec_id,
            Some(StartExecOptions {
                detach: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    exec_id
}

macro_rules! strs {
    [$($e:expr),*$(,)?] => {
        vec![$($e.to_string()),*]
    };
}
pub(crate) use strs;
