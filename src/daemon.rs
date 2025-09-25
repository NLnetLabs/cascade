//! Functionality relating to daemon mode applications.
//!
//! A daemon is typically an application that runs as a long lived service
//! in the background, often with restricted access to the host system and
//! able to run initially as a privileged user to, for example, bind to
//! restricted ports (<1024) and then switch to running as a non-privileged
//! user once the privileged access is no longer required.
use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener, UdpSocket},
};

use camino::Utf8Path;
use daemonbase::process::{EnvSockets, EnvSocketsError, Process};

use crate::config::{DaemonConfig, GroupId, UserId};

/// Apply changes to the identity and access rights of the running application
/// in accordance with the provided settings.
pub fn daemonize(config: &DaemonConfig) -> Result<(), String> {
    let mut daemon_config = daemonbase::process::Config::default();

    if let Some((user_id, group_id)) = &config.identity {
        match (user_id, group_id) {
            (UserId::Named(user), GroupId::Named(group)) => {
                daemon_config = daemon_config
                    .with_user(user)
                    .map_err(|err| format!("Invalid user name: {err}"))?
                    .with_group(group)
                    .map_err(|err| format!("Invalid group name: {err}"))?;
            }
            _ => {
                // daemonbase doesn't support configuration from user id or
                // group id.
                return Err(
                    "Failed to drop privileges: user and group must be names, not IDs".to_string(),
                );
            }
        }
    }

    // TODO: implement chroot fully, i.e. make use of daemonbase::config::ConfigPathi
    // to ensure that paths are correct for the chroot.
    // if let Some(chroot) = &config.chroot {
    //     daemon_config = daemon_config.with_chroot(into_daemon_path(chroot.clone()));
    // }

    if let Some(pid_file) = &config.pid_file {
        daemon_config = daemon_config.with_pid_file(into_daemon_path(pid_file.clone()));
    }

    let mut process = Process::from_config(daemon_config);

    if *config.daemonize.value() {
        log::debug!("Becoming daemon process");
        if process.setup_daemon(true).is_err() {
            return Err("Failed to become daemon process: unknown error".to_string());
        }
    }

    if let Some((user, group)) = &config.identity {
        log::debug!("Dropping privileges to {user} {group}");
        if process.drop_privileges().is_err() {
            return Err("Failed to drop privileges: unknown error".to_string());
        }
    }

    Ok(())
}

fn into_daemon_path(p: Box<Utf8Path>) -> daemonbase::config::ConfigPath {
    let p = p.into_path_buf().into_std_path_buf();
    daemonbase::config::ConfigPath::from(p)
}

//------------ SocketType ----------------------------------------------------

/// The type of a socket.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SocketType {
    Udp,
    Tcp,
}

impl std::fmt::Display for SocketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketType::Udp => f.write_str("UDP"),
            SocketType::Tcp => f.write_str("TCP"),
        }
    }
}

//------------ PreBindError --------------------------------------------------

/// An error occurred while attepmting to pre-bind to a socket address.
#[derive(Debug)]
pub struct PreBindError {
    /// The type of socket which could not be bound.
    socket_type: SocketType,

    /// The address which could not be bound to.
    socket_addr: SocketAddr,

    /// The actual error that occurred.
    error: std::io::Error,
}

impl std::fmt::Display for PreBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} could not be bound: {}",
            self.socket_type, self.socket_addr, self.error
        )
    }
}

impl PreBindError {
    /// Create a [`PreBindError`] for a UDP socket binding failure.
    fn udp(socket_addr: SocketAddr, error: std::io::Error) -> Self {
        Self {
            socket_type: SocketType::Udp,
            socket_addr,
            error,
        }
    }

    /// Create a [`PreBindError`] for a TCP socket binding failure.
    fn tcp(socket_addr: SocketAddr, error: std::io::Error) -> Self {
        Self {
            socket_type: SocketType::Tcp,
            socket_addr,
            error,
        }
    }
}

//------------ SocketProvider ------------------------------------------------

/// A wrapper around [`EnvSockets`] for also offering directly bound sockets.
///
/// Can bind directly to listen addresses as well as expose the alternate
/// (systemd provided) sockets, allowing the caller to take the desired socket
/// irrespective of whether it was bound by us or systemd via a single common
/// interface.
///
/// See: [`daemonbase::process::EnvSockets`]
#[derive(Debug, Default)]
pub struct SocketProvider {
    /// Sockets received from systemd, if any.
    env_sockets: EnvSockets,

    /// Directly bound UDP sockets, if any.
    own_udp_sockets: BTreeMap<SocketAddr, UdpSocket>,

    /// Directly bound TCP sockets, if any.
    own_tcp_listeners: BTreeMap<SocketAddr, TcpListener>,
}

impl SocketProvider {
    /// Create an empty provider.
    ///
    /// Attempts to take/pop tcp/udp will fail until either
    /// [`init_from_env()`], [`pre_bind_udp()`] or [`pre_bind_tcp()`] have
    /// been called to add at least one socket to the set managed by this
    /// provider.
    pub fn new() -> Self {
        Default::default()
    }

    /// Capture socket file descriptors from environment variables.
    ///
    /// Uses the following environment variables per [`sd_listen_fds()``]:
    ///   - LISTEN_PID: Must match our own PID.
    ///   - LISTEN_FDS: The number of FDs being passed to the application.
    ///
    /// Only sockets of type AF_INET UDP and AF_INET TCP, whose address can
    /// be determined, will be captured by this function. Other socket file
    /// descriptors will be ignored.
    ///
    /// If needed one can restrict the set of number of file descriptors
    /// to be obtained from the environment to a maximum via the
    /// [`max_fds_to_process`] argument, which may be useful if expecting a
    /// fixed number or not intending to bind an excessive number of sockets.
    ///
    /// [`sd_listen_fds()`]: https://www.man7.org/linux/man-pages/man3/sd_listen_fds.3.html#NOTES
    pub fn init_from_env(&mut self, max_fds_to_process: Option<usize>) {
        if let Err(err) = self.env_sockets.init_from_env(max_fds_to_process) {
            match err {
                EnvSocketsError::AlreadyInitialized => { /* No problem, ignore */ }
                EnvSocketsError::NotForUs => { /* No problem, ignore */ }
                EnvSocketsError::NotAvailable => { /* No problem, ignore */ }
                EnvSocketsError::Malformed => {
                    log::warn!(
                    "Ignoring malformed systemd LISTEN_PID/LISTEN_FDS environment variable value"
                );
                }
                EnvSocketsError::Unusable => {
                    log::warn!(
                        "Ignoring unusable systemd LISTEN_FDS environment variable socket(s)"
                    );
                }
            }
        }
    }

    /// Bind a UDP socket for use later.
    ///
    /// Will silently succeed if a socket of the same type and address has
    /// already been bound, either by the application or systemd. This allows
    /// an application to attempt to bind to the port but not do so (as it
    /// would fail if attempted) if the port was already bound by systemd.
    //
    // TODO: Should we also support being passed existing bound sockets?
    pub fn pre_bind_udp(&mut self, addr: SocketAddr) -> Result<(), PreBindError> {
        if !self.env_sockets.has_udp(&addr) {
            let socket = UdpSocket::bind(addr).map_err(|err| PreBindError::udp(addr, err))?;
            let _ = self.own_udp_sockets.insert(addr, socket);
        }
        Ok(())
    }

    /// Bind a TCP socket for use later.
    ///
    /// Will silently succeed if a socket of the same type and address has
    /// already been bound, either by the application or systemd. This allows
    /// an application to attempt to bind to the port but not do so (as it
    /// would fail if attempted) if the port was already bound by systemd.
    //
    // TODO: Should we also support being passed existing bound sockets?
    pub fn pre_bind_tcp(&mut self, addr: SocketAddr) -> Result<(), PreBindError> {
        if !self.env_sockets.has_tcp(&addr) {
            let listener = TcpListener::bind(addr).map_err(|err| PreBindError::tcp(addr, err))?;
            let _ = self.own_tcp_listeners.insert(addr, listener);
        }
        Ok(())
    }

    /// Returns a UDP socket that was pre-bound to the specified local
    /// address, whether supplied via the environment or bound directly, if
    /// available.
    ///
    /// Subsequent attempts to remove the same UDP socket, or any other
    /// non-existing socket, will return None.
    pub fn take_udp(&mut self, local_addr: &SocketAddr) -> Option<tokio::net::UdpSocket> {
        self.env_sockets
            .take_udp(local_addr)
            .or_else(|| self.own_udp_sockets.remove(local_addr))
            .and_then(Self::prepare_udp_socket)
    }

    /// Returns the first available UDP socket from those received via the
    /// environment or registered directly.
    ///
    /// Available sockets are those received via [`init_from_env()`] or
    /// [`pre_bind`] and not yet removed via [`pop_udp()`] or [`take_udp()`].
    ///
    /// Returns None if no more UDP sockets are available.
    pub fn pop_udp(&mut self) -> Option<tokio::net::UdpSocket> {
        self.env_sockets
            .pop_udp()
            .or_else(|| self.own_udp_sockets.pop_first().map(|(_k, v)| v))
            .and_then(Self::prepare_udp_socket)
    }

    /// Returns a TCP socket that was pre-bound to the specified local
    /// address, whether supplied via the environment or bound directly, if
    /// available.
    ///
    /// Subsequent attempts to remove the same TCP socket, or any other
    /// non-existing socket, will return None.
    pub fn take_tcp(&mut self, local_addr: &SocketAddr) -> Option<tokio::net::TcpListener> {
        self.env_sockets
            .take_tcp(local_addr)
            .or_else(|| self.own_tcp_listeners.remove(local_addr))
            .and_then(Self::prepare_tcp_listener)
    }

    /// Returns the first available TCP socket from those received via the
    /// environment or registered directly.
    ///
    /// Available sockets are those received via [`init_from_env()`] or
    /// [`pre_bind`] and not yet removed via [`pop_tcp()`] or [`take_tcp()`].
    ///
    /// Returns None if no more TCP sockets are available.
    pub fn pop_tcp(&mut self) -> Option<tokio::net::TcpListener> {
        self.env_sockets
            .pop_tcp()
            .or_else(|| self.own_tcp_listeners.pop_first().map(|(_k, v)| v))
            .and_then(Self::prepare_tcp_listener)
    }

    /// Ensure the given UDP socket is ready for use by the application.
    ///
    /// Set to non-blocking to avoid blocking Tokio when interacting with
    /// the socket and convert it into a Tokio type.
    fn prepare_udp_socket(sock: UdpSocket) -> Option<tokio::net::UdpSocket> {
        if let Err(err) = sock.set_nonblocking(true) {
            log::debug!("Cannot use UDP socket as setting it to non-blocking failed: {err}");
            return None;
        }

        tokio::net::UdpSocket::from_std(sock)
            .inspect_err(|err| {
                log::debug!("Cannot use UDP socket as type conversion failed: {err}")
            })
            .ok()
    }

    /// Ensure the given TCP listener is ready for use by the application.
    ///
    /// Set to non-blocking to avoid blocking Tokio when interacting with
    /// the socket and convert it into a Tokio type.
    fn prepare_tcp_listener(listener: TcpListener) -> Option<tokio::net::TcpListener> {
        if let Err(err) = listener.set_nonblocking(true) {
            log::debug!("Cannot use TCP listener as setting it to non-blocking failed: {err}");
            return None;
        }

        tokio::net::TcpListener::from_std(listener)
            .inspect_err(|err| {
                log::debug!("Cannot use TCP listener as type conversion failed: {err}")
            })
            .ok()
    }
}
