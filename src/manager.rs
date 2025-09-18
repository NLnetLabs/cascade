//! Controlling the entire operation.

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use crate::center::Center;
use crate::comms::{ApplicationCommand, Terminated};
use crate::daemon::SocketProvider;
use crate::payload::Update;
use crate::targets::central_command::CentralCommand;
use crate::units::http_server::HttpServer;
use crate::units::key_manager::KeyManagerUnit;
use crate::units::zone_loader::ZoneLoader;
use crate::units::zone_server::{self, ZoneServerUnit};
use crate::units::zone_signer::{KmipServerConnectionSettings, ZoneSignerUnit};
use daemonbase::process::EnvSocketsError;
use domain::zonetree::StoredName;
use futures::future::join_all;
use log::debug;
use tokio::sync::mpsc::{self};
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::RecvError;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    EnvSockets(EnvSocketsError),
    Terminated,
}

impl From<EnvSocketsError> for Error {
    fn from(err: EnvSocketsError) -> Self {
        Error::EnvSockets(err)
    }
}

impl From<Terminated> for Error {
    fn from(_: Terminated) -> Self {
        Error::Terminated
    }
}

impl From<RecvError> for Error {
    fn from(_err: RecvError) -> Self {
        Error::Terminated
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::EnvSockets(err) => err.fmt(f),
            Error::Terminated => Terminated.fmt(f),
        }
    }
}

/// Spawn all targets.
pub async fn spawn(
    center: &Arc<Center>,
    update_rx: mpsc::UnboundedReceiver<Update>,
    center_tx_slot: &mut Option<mpsc::UnboundedSender<TargetCommand>>,
    unit_tx_slots: &mut foldhash::HashMap<String, mpsc::UnboundedSender<ApplicationCommand>>,
    socket_provider: SocketProvider,
) -> Result<(), Error> {
    let socket_provider = Arc::new(Mutex::new(socket_provider));

    // Spawn the central command.
    log::info!("Starting target 'CC'");
    let target = CentralCommand {
        center: center.clone(),
    };
    let (center_tx, center_rx) = mpsc::unbounded_channel();
    tokio::spawn(target.run(center_rx, update_rx));
    *center_tx_slot = Some(center_tx);

    let mut kmip_server_conn_settings = HashMap::new();

    let hsm_relay_host = std::env::var("KMIP2PKCS11_HOST").ok();
    let hsm_relay_port = std::env::var("KMIP2PKCS11_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok());

    if let Some(server_addr) = hsm_relay_host {
        if let Some(server_port) = hsm_relay_port {
            kmip_server_conn_settings.insert(
                "hsmrelay".to_string(),
                KmipServerConnectionSettings {
                    server_addr,
                    server_port,
                    server_insecure: true,
                    server_username: std::env::var("KMIP2PKCS11_USERNAME").ok(),
                    server_password: std::env::var("KMIP2PKCS11_PASSWORD").ok(),
                    ..Default::default()
                },
            );
        }
    }

    let zone_name =
        StoredName::from_str(&std::env::var("ZL_IN_ZONE").unwrap_or("example.com.".to_string()))
            .unwrap();
    let xfr_out = std::env::var("PS_XFR_OUT").unwrap_or("127.0.0.1:8055 KEY sec1-key".into());

    // Collate oneshot unit ready signal receivers by unit name.
    let mut unit_ready_rxs = vec![];
    let mut unit_join_handles = HashMap::new();

    // Spawn the zone loader.
    log::info!("Starting unit 'ZL'");
    let unit = ZoneLoader {
        center: center.clone(),
    };
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    unit_ready_rxs.push(ready_rx);
    unit_join_handles.insert("ZL", tokio::spawn(unit.run(cmd_rx, ready_tx)));
    unit_tx_slots.insert("ZL".into(), cmd_tx);

    // Spawn the unsigned zone review server.
    log::info!("Starting unit 'RS'");
    let unit = ZoneServerUnit {
        center: center.clone(),
        _xfr_out: HashMap::from([(zone_name.clone(), xfr_out)]),
        mode: zone_server::Mode::Prepublish,
        source: zone_server::Source::UnsignedZones,
        http_api_path: Arc::new(String::from("/_unit/rs/")),
    };
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    unit_ready_rxs.push(ready_rx);
    unit_join_handles.insert(
        "RS",
        tokio::spawn(unit.run(cmd_rx, ready_tx, socket_provider.clone())),
    );
    unit_tx_slots.insert("RS".into(), cmd_tx);

    // Spawn the key manager.
    log::info!("Starting unit 'KM'");
    let unit = KeyManagerUnit {
        center: center.clone(),
    };
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    unit_ready_rxs.push(ready_rx);
    unit_join_handles.insert("KM", tokio::spawn(unit.run(cmd_rx, ready_tx)));
    unit_tx_slots.insert("KM".into(), cmd_tx);

    // Spawn the zone signer.
    log::info!("Starting unit 'ZS'");
    let unit = ZoneSignerUnit {
        center: center.clone(),
        treat_single_keys_as_csks: true,
        max_concurrent_operations: 1,
        max_concurrent_rrsig_generation_tasks: 32,
        use_lightweight_zone_tree: false,
        kmip_server_conn_settings,
    };
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    unit_ready_rxs.push(ready_rx);
    unit_join_handles.insert("ZS", tokio::spawn(unit.run(cmd_rx, ready_tx)));
    unit_tx_slots.insert("ZS".into(), cmd_tx);

    // Spawn the signed zone review server.
    log::info!("Starting unit 'RS2'");
    let unit = ZoneServerUnit {
        center: center.clone(),
        http_api_path: Arc::new(String::from("/_unit/rs2/")),
        _xfr_out: HashMap::from([(zone_name.clone(), "127.0.0.1:8055 KEY sec1-key".into())]),
        mode: zone_server::Mode::Prepublish,
        source: zone_server::Source::SignedZones,
    };
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    unit_ready_rxs.push(ready_rx);
    unit_join_handles.insert(
        "RS2",
        tokio::spawn(unit.run(cmd_rx, ready_tx, socket_provider.clone())),
    );
    unit_tx_slots.insert("RS2".into(), cmd_tx);

    // Spawn the HTTP server.
    log::info!("Starting unit 'HS'");
    let unit = HttpServer {
        center: center.clone(),
    };
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    unit_ready_rxs.push(ready_rx);
    unit_join_handles.insert(
        "HS",
        tokio::spawn(unit.run(cmd_rx, ready_tx, socket_provider.clone())),
    );
    unit_tx_slots.insert("HS".into(), cmd_tx);

    // Wait for the units above to be ready, then we know that all systemd
    // activation sockets that are needed by the units above have been taken
    // and can reliably let the PS unit take any remaining sockets.
    join_all(unit_ready_rxs).await;

    // None of the units above should have exited already.
    if let Some(failed_unit) = unit_join_handles
        .iter()
        .find_map(|(unit, handle)| handle.is_finished().then_some(unit))
    {
        log::error!("Unit '{failed_unit}' terminated unexpectedly. Aborting.");
        return Err(Terminated.into());
    }

    log::info!("Starting unit 'PS'");
    let unit = ZoneServerUnit {
        center: center.clone(),
        http_api_path: Arc::new(String::from("/_unit/ps/")),
        _xfr_out: HashMap::from([(zone_name, "127.0.0.1:8055".into())]),
        mode: zone_server::Mode::Publish,
        source: zone_server::Source::PublishedZones,
    };
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let _join_handle = tokio::spawn(unit.run(cmd_rx, ready_tx, socket_provider.clone()));
    unit_tx_slots.insert("PS".into(), cmd_tx);

    ready_rx.await?;

    log::info!("All units report ready.");

    Ok(())
}

/// Forward application commands.
//
// TODO: Eliminate this function entirely.
pub async fn forward_app_cmds(
    rx: &mut mpsc::UnboundedReceiver<(String, ApplicationCommand)>,
    unit_txs: &foldhash::HashMap<String, mpsc::UnboundedSender<ApplicationCommand>>,
) {
    while let Some((unit_name, data)) = rx.recv().await {
        if let Some(tx) = unit_txs.get(&*unit_name) {
            debug!("Forwarding application command to unit '{unit_name}'");
            tx.send(data).unwrap();
        } else {
            debug!("Unrecognized unit: {unit_name}");
        }
    }
}

pub enum TargetCommand {
    Terminate,
}

impl Display for TargetCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetCommand::Terminate => f.write_str("Terminate"),
        }
    }
}
