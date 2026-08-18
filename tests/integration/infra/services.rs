//! Supporting services.

use bollard::{exec::StartExecOptions, plugin::ExecConfig};

use super::Container;

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
    pub async fn start(container: &Container) -> Self {
        let exec_id = exec_detached(
            container,
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
    pub async fn start(container: &Container) -> Self {
        let exec_id = exec_detached(
            container,
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
    pub async fn start(container: &Container) -> Self {
        let exec_id = exec_detached(
            container,
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
    pub async fn start(container: &Container) -> Self {
        let exec_id = exec_detached(
            container,
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
#[tracing::instrument(level = "debug", ret)]
async fn exec_detached(container: &Container, command: Vec<String>, working_dir: &str) -> String {
    let exec_cfg = ExecConfig {
        cmd: Some(command),
        working_dir: Some(working_dir.into()),
        ..Default::default()
    };
    let exec_id = container
        .docker
        .create_exec(&container.id, exec_cfg)
        .await
        .unwrap()
        .id;
    container
        .docker
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
