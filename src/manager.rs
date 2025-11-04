//! Controlling the entire operation.

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::sync::{Arc, Mutex};

use crate::center::Center;
use crate::comms::{ApplicationCommand, Terminated};
use crate::daemon::SocketProvider;
use crate::payload::Update;
use crate::targets::central_command::CentralCommand;
use crate::units::http_server::HttpServer;
use crate::units::key_manager::KeyManagerUnit;
use crate::units::zone_loader::ZoneLoader;
use crate::units::zone_server::{self, ZoneServer};
use crate::units::zone_signer::ZoneSigner;
use daemonbase::process::EnvSocketsError;
use futures::future::join_all;
use tokio::sync::mpsc::{self};
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::RecvError;
use tracing::{debug, error, info};

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

pub struct Manager {
    /// The zone loader.
    pub zone_loader: Arc<ZoneLoader>,

    /// The review server for unsigned zones.
    pub unsigned_review: Arc<ZoneServer>,

    /// The zone signer.
    pub zone_signer: Arc<ZoneSigner>,

    /// The review server for signed zones.
    pub signed_review: Arc<ZoneServer>,

    /// The zone server.
    pub zone_server: Arc<ZoneServer>,
}

/// Spawn all targets.
pub async fn spawn(
    center: &Arc<Center>,
    update_rx: mpsc::UnboundedReceiver<Update>,
    center_tx_slot: &mut Option<mpsc::UnboundedSender<TargetCommand>>,
    unit_tx_slots: &mut foldhash::HashMap<String, mpsc::UnboundedSender<ApplicationCommand>>,
    socket_provider: SocketProvider,
) -> Result<Manager, Error> {
    let socket_provider = Arc::new(Mutex::new(socket_provider));

    // Spawn the central command.
    info!("Starting target 'CC'");
    let target = CentralCommand {
        center: center.clone(),
    };
    let (center_tx, center_rx) = mpsc::unbounded_channel();
    tokio::spawn(target.run(center_rx, update_rx));
    *center_tx_slot = Some(center_tx);

    // Collate oneshot unit ready signal receivers by unit name.
    let mut unit_ready_rxs = vec![];
    let mut unit_join_handles = HashMap::new();

    // Spawn the zone loader.
    info!("Starting unit 'ZL'");
    let zone_loader = Arc::new(ZoneLoader::launch(center.clone()));

    // Spawn the unsigned zone review server.
    info!("Starting unit 'RS'");
    let unsigned_review = Arc::new(ZoneServer::launch(
        center.clone(),
        zone_server::Source::Unsigned,
        &mut socket_provider.lock().unwrap(),
    )?);

    // Spawn the key manager.
    info!("Starting unit 'KM'");
    let unit = KeyManagerUnit {
        center: center.clone(),
    };
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    unit_ready_rxs.push(ready_rx);
    unit_join_handles.insert("KM", tokio::spawn(unit.run(cmd_rx, ready_tx)));
    unit_tx_slots.insert("KM".into(), cmd_tx);

    // Spawn the zone signer.
    info!("Starting unit 'ZS'");
    let zone_signer = ZoneSigner::launch(center.clone());

    // Spawn the signed zone review server.
    info!("Starting unit 'RS2'");
    let signed_review = Arc::new(ZoneServer::launch(
        center.clone(),
        zone_server::Source::Signed,
        &mut socket_provider.lock().unwrap(),
    )?);

    // Spawn the HTTP server.
    info!("Starting unit 'HS'");
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
        error!("Unit '{failed_unit}' terminated unexpectedly. Aborting.");
        return Err(Terminated.into());
    }

    info!("Starting unit 'PS'");
    let zone_server = Arc::new(ZoneServer::launch(
        center.clone(),
        zone_server::Source::Published,
        &mut socket_provider.lock().unwrap(),
    )?);

    info!("All units report ready.");

    Ok(Manager {
        zone_loader,
        unsigned_review,
        zone_signer,
        signed_review,
        zone_server,
    })
}

/// Forward application commands.
//
// TODO: Eliminate this function entirely.
pub async fn forward_app_cmds(
    manager: &mut Manager,
    rx: &mut mpsc::UnboundedReceiver<(String, ApplicationCommand)>,
    unit_txs: &foldhash::HashMap<String, mpsc::UnboundedSender<ApplicationCommand>>,
) {
    while let Some((unit_name, data)) = rx.recv().await {
        if let Some(tx) = unit_txs.get(&*unit_name) {
            debug!("Forwarding application command to unit '{unit_name}'");
            tx.send(data).unwrap();
        } else if unit_name == "ZL" {
            tokio::spawn({
                let unit = manager.zone_loader.clone();
                async move { unit.on_command(data).await }
            });
        } else if unit_name == "RS" {
            tokio::spawn({
                let unit = manager.unsigned_review.clone();
                async move { unit.on_command(data).await }
            });
        } else if unit_name == "ZS" {
            tokio::spawn({
                let unit = manager.zone_signer.clone();
                async move { unit.on_command(data).await }
            });
        } else if unit_name == "RS2" {
            tokio::spawn({
                let unit = manager.signed_review.clone();
                async move { unit.on_command(data).await }
            });
        } else if unit_name == "PS" {
            tokio::spawn({
                let unit = manager.zone_server.clone();
                async move { unit.on_command(data).await }
            });
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
