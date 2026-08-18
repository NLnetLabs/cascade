//! Infrastructure for integration tests.

use core::fmt;
use std::{collections::HashMap, env, net::IpAddr, path::PathBuf};

use bollard::{
    Docker,
    plugin::{BuildInfoAux, ImageId, PortBinding},
    query_parameters::{BuildImageOptionsBuilder, BuilderVersion},
};
use futures_util::StreamExt;

mod cascade;
pub use cascade::*;

mod services;
pub use services::*;

/// Build the OCI image.
///
/// Identical in function to `tests/integration/build-image.sh`.
#[tracing::instrument(level = "info", skip_all)]
pub async fn build_image(client: &Docker) {
    tracing::info!("Building image");

    // Rely on Cargo to discover important sources.
    let base_dir: PathBuf = env::var_os("CARGO_MANIFEST_DIR").unwrap().into();
    tracing::trace!(?base_dir, "Identified sources");

    tracing::debug!("Preparing image context");

    let mut context = tar::Builder::new(vec![]);
    context.follow_symlinks(false);
    context.sparse(false);
    context.mode(tar::HeaderMode::Deterministic);
    context
        .append_path_with_name(base_dir.join("tests/integration/Dockerfile"), "Dockerfile")
        .unwrap();
    context
        .append_dir_all(".", base_dir.join("tests/integration/data"))
        .unwrap();
    let body = context.into_inner().unwrap();
    let body = bollard::body_full(body.into());

    tracing::debug!("Passing on to Docker");

    let session = uuid::Uuid::new_v4();
    let options = BuildImageOptionsBuilder::new()
        .t("nlnetlabs/cascade-tests-runner")
        .version(BuilderVersion::BuilderBuildKit)
        .session(&session.to_string())
        .build();

    let stream = client.build_image(options, None, Some(body));
    let mut stream = std::pin::pin!(stream);
    let mut image_id = None;

    while let Some(info) = stream.next().await {
        let info = match info {
            Ok(info) => info,
            Err(err) => {
                tracing::error!("Error while watching build: {err:?}");
                panic!("Could not build image")
            }
        };

        tracing::trace!(?info, "build info");

        let Some(id) = info.id else {
            tracing::warn!("Bug: missing ID in build info");
            continue;
        };

        match &*id {
            "moby.buildkit.trace" => {
                let Some(BuildInfoAux::BuildKit(resp)) = info.aux else {
                    tracing::warn!("Bug: Missing BuildKit aux data");
                    continue;
                };

                for v in resp.vertexes {
                    let digest = v.digest.strip_prefix("sha256:").unwrap_or(&v.digest);
                    if v.started.is_none() {
                        tracing::info!("[{digest:.8}] {}", v.name);
                    }
                }

                for s in resp.statuses {
                    let digest = s.vertex.strip_prefix("sha256:").unwrap_or(&s.vertex);
                    if s.started.is_none() {
                        tracing::info!("[{digest:.8}] {} {}/{}", s.id, s.current, s.total);
                    }
                }

                for l in resp.logs {
                    let digest = l.vertex.strip_prefix("sha256:").unwrap_or(&l.vertex);
                    if let Ok(msg) = std::str::from_utf8(&l.msg) {
                        tracing::info!("[{digest:.8}] {msg}");
                    } else {
                        let msg = l.msg.utf8_chunks();
                        tracing::info!("[{digest:.8}] {msg:?}");
                    }
                }

                for w in resp.warnings {
                    let digest = w.vertex.strip_prefix("sha256:").unwrap_or(&w.vertex);
                    if let Ok(msg) = std::str::from_utf8(&w.short) {
                        tracing::warn!("[{digest:.8}] {msg}");
                    } else {
                        let msg = w.short.utf8_chunks();
                        tracing::warn!("[{digest:.8}] {msg:?}");
                    }
                }
            }

            "moby.image.id" => {
                let Some(BuildInfoAux::Default(ImageId { id: Some(id) })) = info.aux else {
                    tracing::warn!("Bug: Missing image ID");
                    continue;
                };
                image_id = Some(id);
            }

            _ => {
                tracing::warn!("Bug: Unrecognized build info ID {id:?}");
            }
        }
    }

    if image_id.is_none() {
        panic!("Could not build image")
    }

    tracing::info!("Built image");
}

//------------------------------------------------------------------------------

/// An exposed DNS server port.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct ExposedDnsPort {
    /// The exposed UDP port.
    pub over_udp: ExposedPort,

    /// The exposed TCP port.
    pub over_tcp: ExposedPort,
}

impl ExposedDnsPort {
    /// Look up an exposed DNS port.
    pub fn get(ports: &HashMap<String, Option<Vec<PortBinding>>>, port: u16) -> Self {
        Self {
            over_udp: ExposedPort::get_udp(ports, port),
            over_tcp: ExposedPort::get_tcp(ports, port),
        }
    }
}

impl fmt::Debug for ExposedDnsPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.over_udp == self.over_tcp {
            write!(f, "ExposedDnsPort({})", self.over_udp)
        } else {
            f.debug_struct("ExposedDnsPort")
                .field("over_udp", &self.over_udp)
                .field("over_tcp", &self.over_tcp)
                .finish()
        }
    }
}

impl fmt::Display for ExposedDnsPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.over_udp == self.over_tcp {
            write!(f, "{}", self.over_udp)
        } else {
            write!(f, "{}(udp)/{}(tcp)", self.over_udp, self.over_tcp)
        }
    }
}

/// An exposed port.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct ExposedPort {
    /// The port number exposed on IPv4.
    pub on_ipv4: u16,

    /// The port number exposed on IPv6.
    pub on_ipv6: u16,
}

impl ExposedPort {
    /// Look up an exposed TCP port.
    #[tracing::instrument(level = "trace", skip(ports), ret)]
    pub fn get_tcp(ports: &HashMap<String, Option<Vec<PortBinding>>>, port: u16) -> Self {
        let bindings = ports.get(&format!("{port}/tcp")).unwrap().as_ref().unwrap();
        let (mut on_ipv4, mut on_ipv6) = (None, None);
        for binding in bindings {
            tracing::trace!(?binding, "Processing exposed port binding");
            let ip = binding.host_ip.as_ref().unwrap().parse::<IpAddr>().unwrap();
            let port = binding.host_port.as_ref().unwrap().parse::<u16>().unwrap();
            match ip {
                IpAddr::V4(_) => on_ipv4 = Some(port),
                IpAddr::V6(_) => on_ipv6 = Some(port),
            }
        }
        Self {
            on_ipv4: on_ipv4.unwrap(),
            on_ipv6: on_ipv6.unwrap(),
        }
    }

    /// Look up an exposed UDP port.
    #[tracing::instrument(level = "trace", skip(ports), ret)]
    pub fn get_udp(ports: &HashMap<String, Option<Vec<PortBinding>>>, port: u16) -> Self {
        let bindings = ports.get(&format!("{port}/udp")).unwrap().as_ref().unwrap();
        let (mut on_ipv4, mut on_ipv6) = (None, None);
        for binding in bindings {
            tracing::trace!(?binding, "Processing exposed port binding");
            let ip = binding.host_ip.as_ref().unwrap().parse::<IpAddr>().unwrap();
            let port = binding.host_port.as_ref().unwrap().parse::<u16>().unwrap();
            match ip {
                IpAddr::V4(_) => on_ipv4 = Some(port),
                IpAddr::V6(_) => on_ipv6 = Some(port),
            }
        }
        Self {
            on_ipv4: on_ipv4.unwrap(),
            on_ipv6: on_ipv6.unwrap(),
        }
    }
}

impl fmt::Debug for ExposedPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.on_ipv4 == self.on_ipv6 {
            write!(f, "ExposedPort({})", self.on_ipv4)
        } else {
            f.debug_struct("ExposedPort")
                .field("on_ipv4", &self.on_ipv4)
                .field("on_ipv6", &self.on_ipv6)
                .finish()
        }
    }
}

impl fmt::Display for ExposedPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.on_ipv4 == self.on_ipv6 {
            write!(f, "{}", self.on_ipv4)
        } else {
            write!(f, "{}(v4)/{}(v6)", self.on_ipv4, self.on_ipv6)
        }
    }
}
