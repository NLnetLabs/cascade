//! Infrastructure for integration tests.

use core::fmt;
use std::{env, path::PathBuf};

use testcontainers::{
    GenericBuildableImage, GenericImage,
    core::{ContainerPort, ports::Ports},
    runners::AsyncBuilder,
};

mod cascade;
pub use cascade::*;

mod services;
pub use services::*;

/// Build the OCI image.
///
/// Identical in function to `tests/integration/build-image.sh`.
#[tracing::instrument(level = "info")]
pub async fn build_image() -> GenericImage {
    tracing::info!("Building image");

    // Rely on Cargo to discover important sources.
    let base_dir: PathBuf = env::var_os("CARGO_MANIFEST_DIR").unwrap().into();
    let daemon_path: PathBuf = env::var_os("CARGO_BIN_EXE_cascaded").unwrap().into();
    tracing::trace!(?base_dir, ?daemon_path, "Identified sources");

    // TODO: Use `bollard` directly so we can show details of the build
    // process (it takes 1.5s on a perfect rebuild, up to a minute otherwise).

    tracing::debug!("Locating files for image context");

    let mut builder = GenericBuildableImage::new("nlnetlabs/cascade-tests-runner", "latest")
        .with_dockerfile(base_dir.join("tests/integration/Dockerfile"))
        .with_file(daemon_path, "bin/cascaded");

    // Walk the data directory and add all its files.
    let data_dir = base_dir.join("tests/integration/data");
    for entry in walkdir(data_dir.clone()) {
        let path = entry.path();
        let r#type = entry.file_type().unwrap();
        if r#type.is_file() {
            let dest = path.strip_prefix(&data_dir).unwrap();
            builder = builder.with_file(&path, dest.to_str().unwrap());
        } else if !r#type.is_dir() {
            tracing::warn!(
                "Excluding '{}' from image context: not a file or directory",
                path.display()
            );
        }
    }

    tracing::debug!("Passing on to Docker");

    let image = builder.build_image().await.unwrap();

    tracing::info!("Built image");

    image
}

/// Simple directory walker.
fn walkdir(path: PathBuf) -> impl Iterator<Item = std::fs::DirEntry> {
    let mut stack = vec![];
    stack.push(std::fs::read_dir(path).unwrap());
    std::iter::from_fn(move || {
        // Find a new entry at the deepest possible level in the stack.
        let entry = loop {
            let reader = stack.last_mut()?;
            if let Some(entry) = reader.next() {
                break entry.unwrap();
            }
            stack.pop();
        };

        if entry.file_type().unwrap().is_dir() {
            // Add to the stack.
            stack.push(std::fs::read_dir(entry.path()).unwrap());
        }

        Some(entry)
    })
}

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
    pub fn get(ports: &Ports, port: u16) -> Self {
        Self {
            over_udp: ExposedPort::get(ports, ContainerPort::Udp(port)),
            over_tcp: ExposedPort::get(ports, ContainerPort::Tcp(port)),
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
    /// Look up an exposed port.
    pub fn get(ports: &Ports, port: impl Into<ContainerPort>) -> Self {
        let port = port.into();
        Self {
            on_ipv4: ports.map_to_host_port_ipv4(port).unwrap(),
            on_ipv6: ports.map_to_host_port_ipv6(port).unwrap(),
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
