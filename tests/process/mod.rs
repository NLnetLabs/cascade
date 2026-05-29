//! Process tests.
//!
//! This module provides infrastructure for tests that launch Cascade as a
//! process and talk to it. They are more limited than integration tests; they
//! don't test Cascade's key management, because it uses the system DNS. They
//! are faster and easier to write.

// Relies on Unix system functionality.
#![cfg(unix)]

use std::{
    net::{Ipv6Addr, TcpListener, UdpSocket},
    os::fd::OwnedFd,
    process::Command,
};

use camino::{Utf8Path, Utf8PathBuf};
use command_fds::{CommandFdExt, FdMapping};

//----------- Daemon -----------------------------------------------------------

/// A running Cascade daemon.
#[derive(Debug)]
pub struct Daemon {
    /// The daemon process.
    pub process: std::process::Child,

    /// The configuration used by the daemon.
    pub config: cascade_cfg::file::Spec,

    /// The filesystem used by the daemon.
    pub filesystem: DaemonFilesystem,
}

impl Daemon {
    /// Launch the daemon.
    pub fn launch(mut builder: DaemonBuilder) -> Self {
        // Prepare the configuration file.
        let config = builder
            .config
            .take()
            .unwrap_or_else(|| builder.default_config());
        config.save_compact(&builder.filesystem.config).unwrap();

        // Launch the daemon.
        let fds = builder
            .sockets
            .unspool()
            .into_iter()
            .zip(3..)
            .map(|(parent_fd, child_fd)| FdMapping {
                parent_fd,
                child_fd,
            })
            .collect::<Vec<_>>();
        let process = Command::new(&*builder.path)
            .arg("--config")
            .arg(&*builder.filesystem.config)
            .arg("--state")
            .arg(&*builder.filesystem.state)
            .env("LISTEN_FDS", fds.len().to_string())
            .fd_mappings(fds)
            .unwrap()
            .current_dir(&*builder.filesystem.root)
            .spawn()
            .unwrap();

        Self {
            process,
            config,
            filesystem: builder.filesystem,
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Stop the daemon.
        // TODO: Use SIGTERM instead of SIGKILL?
        let _ = self.process.kill();
    }
}

//----------- DaemonBuilder ----------------------------------------------------

/// A builder for a new [`Daemon`].
pub struct DaemonBuilder {
    /// The path to the daemon executable.
    pub path: Box<Utf8Path>,

    /// The filesystem that will be used.
    pub filesystem: DaemonFilesystem,

    /// The sockets that will be used.
    pub sockets: DaemonSockets,

    /// The configuration used by the daemon.
    ///
    /// If [`None`], a default configuration will be prepared that uses
    /// [`Self::filesystem`] and [`Self::sockets`].
    pub config: Option<cascade_cfg::file::Spec>,
}

impl DaemonBuilder {
    /// Initialize a new [`DaemonBuilder`].
    pub fn new() -> Self {
        let cwd = Utf8PathBuf::try_from(std::env::current_dir().unwrap()).unwrap();
        Self {
            path: cwd.join("target/debug/cascaded").into_boxed_path(),
            filesystem: DaemonFilesystem::new(),
            sockets: DaemonSockets::new(),
            config: None,
        }
    }

    /// Launch the daemon.
    pub fn build(self) -> Daemon {
        Daemon::launch(self)
    }

    /// Build the default configuration.
    fn default_config(&self) -> cascade_cfg::file::Spec {
        use cascade_cfg::file::v1::*;

        let mut spec = Spec {
            policy_dir: self.filesystem.policies.clone(),
            zone_state_dir: self.filesystem.zone_state.clone(),
            tsig_store_path: self.filesystem.tsig_store.clone(),
            keys_dir: self.filesystem.keys.clone(),
            // TODO: Warn the user if they don't have 'dnst' installed.
            dnst_binary_path: "dnst".into(),
            kmip_credentials_store_path: self.filesystem.kmip_creds_store.clone(),
            kmip_server_state_dir: self.filesystem.kmip_server_state.clone(),

            ..Default::default()
        };

        spec.remote_control.servers = vec![self.sockets.remote_control.local_addr().unwrap()];

        spec.daemon.log_level = Some(LogLevelSpec::Trace);
        spec.daemon.log_target = Some(LogTargetSpec::File {
            path: self.filesystem.log.clone(),
        });
        spec.daemon.daemonize = Some(false);

        spec.loader.review.servers = vec![SocketSpec::Simple(SimpleSocketSpec::TCPUDP {
            addr: self.sockets.loader_review.0.local_addr().unwrap(),
        })];
        spec.signer.review.servers = vec![SocketSpec::Simple(SimpleSocketSpec::TCPUDP {
            addr: self.sockets.signer_review.0.local_addr().unwrap(),
        })];
        spec.server.servers = vec![SocketSpec::Simple(SimpleSocketSpec::TCPUDP {
            addr: self.sockets.publication.0.local_addr().unwrap(),
        })];

        cascade_cfg::file::Spec::V1(spec)
    }
}

impl Default for DaemonBuilder {
    fn default() -> Self {
        Self::new()
    }
}

//----------- DaemonFilesystem -------------------------------------------------

/// The filesystem used by a Cascade daemon.
#[derive(Debug)]
pub struct DaemonFilesystem {
    /// The temporary directory containing everything else.
    pub tempdir: tempfile::TempDir,

    /// The path to the root of `tempdir`.
    pub root: Box<Utf8Path>,

    /// The configuration file.
    pub config: Box<Utf8Path>,

    /// The global state file.
    pub state: Box<Utf8Path>,

    /// The directory storing zone policies.
    pub policies: Box<Utf8Path>,

    /// The directory storing per-zone state files.
    pub zone_state: Box<Utf8Path>,

    /// The TSIG key store.
    pub tsig_store: Box<Utf8Path>,

    /// The KMIP credential store.
    pub kmip_creds_store: Box<Utf8Path>,

    /// The directory storing keyset state and on-disk cryptographic keys.
    pub keys: Box<Utf8Path>,

    /// The directory storing KMIP server state.
    pub kmip_server_state: Box<Utf8Path>,

    /// The log file.
    pub log: Box<Utf8Path>,
}

impl DaemonFilesystem {
    /// Build a new [`DaemonFs`].
    ///
    /// ## Panics
    ///
    /// Panics if the filesystem cannot be set up.
    pub fn new() -> Self {
        let tempdir = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tempdir.path()).unwrap();

        // Specify a file or directory, and create empty directories.
        let entry = |p: &str| {
            let path = root.join(p).into_boxed_path();
            if p.ends_with('/') {
                std::fs::create_dir_all(&*path).unwrap();
            } else if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            path
        };

        Self {
            config: entry("config.toml"),
            state: entry("state.db"),
            policies: entry("policies/"),
            zone_state: entry("zone-state/"),
            tsig_store: entry("tsig-store.db"),
            kmip_creds_store: entry("kmip/creds.db"),
            keys: entry("keys/"),
            kmip_server_state: entry("kmip/"),
            log: entry("cascaded.log"),

            root: root.into(),
            tempdir,
        }
    }
}

impl Default for DaemonFilesystem {
    fn default() -> Self {
        Self::new()
    }
}

//----------- DaemonSockets ----------------------------------------------------

/// The sockets used by a Cascade daemon.
pub struct DaemonSockets {
    /// The HTTP API server.
    pub remote_control: TcpListener,

    /// The loader review server.
    pub loader_review: (UdpSocket, TcpListener),

    /// The signer review server.
    pub signer_review: (UdpSocket, TcpListener),

    /// The publication server.
    pub publication: (UdpSocket, TcpListener),
}

impl DaemonSockets {
    /// Build a new [`DaemonSockets`].
    ///
    /// ## Panics
    ///
    /// Panics if sockets cannot be obtained.
    pub fn new() -> Self {
        const LOCAL_ANY: (Ipv6Addr, u16) = (Ipv6Addr::LOCALHOST, 0);

        /// Try to obtain a TCP-UDP socket pair at the same address.
        fn obtain_tcp_udp_pair() -> (UdpSocket, TcpListener) {
            const NUM_TRIES: usize = 5;

            for _ in 0..NUM_TRIES {
                let tcp = TcpListener::bind(LOCAL_ANY).unwrap();
                let addr = tcp.local_addr().unwrap();
                let Ok(udp) = UdpSocket::bind(addr) else {
                    continue;
                };

                return (udp, tcp);
            }

            panic!("failed to bind a UDP-TCP socket pair after {NUM_TRIES} tries")
        }

        Self {
            remote_control: TcpListener::bind(LOCAL_ANY).unwrap(),
            loader_review: obtain_tcp_udp_pair(),
            signer_review: obtain_tcp_udp_pair(),
            publication: obtain_tcp_udp_pair(),
        }
    }

    /// Unspool the sockets into raw file descriptors.
    pub fn unspool(self) -> impl IntoIterator<Item = OwnedFd> {
        [
            self.remote_control.into(),
            self.loader_review.0.into(),
            self.loader_review.1.into(),
            self.signer_review.0.into(),
            self.signer_review.1.into(),
            self.publication.0.into(),
            self.publication.1.into(),
        ]
    }
}

impl Default for DaemonSockets {
    fn default() -> Self {
        Self::new()
    }
}
