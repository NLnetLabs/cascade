use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener, UdpSocket},
};

use camino::Utf8Path;
use daemonbase::process::{EnvSockets, EnvSocketsError, Process};

use crate::config::{DaemonConfig, GroupId, UserId};

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

    if let Some(chroot) = &config.chroot {
        daemon_config = daemon_config.with_chroot(into_daemon_path(chroot.clone()));
    }

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

//------------ SocketProvider ------------------------------------------------

#[derive(Debug, Default)]
pub struct SocketProvider {
    env_sockets: EnvSockets,

    own_udp_sockets: BTreeMap<SocketAddr, UdpSocket>,

    own_tcp_listeners: BTreeMap<SocketAddr, TcpListener>,
}

impl SocketProvider {
    pub fn new() -> Self {
        Default::default()
    }

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

    pub fn pre_bind_udp(
        &mut self,
        addr: SocketAddr,
    ) -> Result<(), (&'static str, SocketAddr, std::io::Error)> {
        if !self.env_sockets.has_udp(&addr) {
            let socket = UdpSocket::bind(addr).map_err(|err| ("UDP", addr, err))?;
            let _ = self.own_udp_sockets.insert(addr, socket);
        }
        Ok(())
    }

    pub fn pre_bind_tcp(
        &mut self,
        addr: SocketAddr,
    ) -> Result<(), (&'static str, SocketAddr, std::io::Error)> {
        if !self.env_sockets.has_tcp(&addr) {
            let listener = TcpListener::bind(addr).map_err(|err| ("TCP", addr, err))?;
            let _ = self.own_tcp_listeners.insert(addr, listener);
        }
        Ok(())
    }

    pub fn has_udp(&self, addr: &SocketAddr) -> bool {
        self.env_sockets.has_udp(addr) || self.own_udp_sockets.contains_key(addr)
    }

    pub fn has_tcp(&self, addr: &SocketAddr) -> bool {
        self.env_sockets.has_tcp(addr) || self.own_tcp_listeners.contains_key(addr)
    }

    pub fn take_udp(&mut self, local_addr: &SocketAddr) -> Option<tokio::net::UdpSocket> {
        self.env_sockets
            .take_udp(local_addr)
            .or_else(|| self.own_udp_sockets.remove(local_addr))
            .and_then(Self::prepare_udp_socket)
    }

    pub fn pop_udp(&mut self) -> Option<tokio::net::UdpSocket> {
        self.env_sockets
            .pop_udp()
            .or_else(|| self.own_udp_sockets.pop_first().map(|(_k, v)| v))
            .and_then(Self::prepare_udp_socket)
    }

    pub fn take_tcp(&mut self, local_addr: &SocketAddr) -> Option<tokio::net::TcpListener> {
        self.env_sockets
            .take_tcp(local_addr)
            .or_else(|| self.own_tcp_listeners.remove(local_addr))
            .and_then(Self::prepare_tcp_listener)
    }

    pub fn pop_tcp(&mut self) -> Option<tokio::net::TcpListener> {
        self.env_sockets
            .pop_tcp()
            .or_else(|| self.own_tcp_listeners.pop_first().map(|(_k, v)| v))
            .and_then(Self::prepare_tcp_listener)
    }

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
