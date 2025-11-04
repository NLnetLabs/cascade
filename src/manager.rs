//! Controlling the entire operation.

use std::fmt::{Debug, Display};
use std::sync::Arc;

use crate::center::Center;
use crate::comms::{ApplicationCommand, Terminated};
use crate::daemon::SocketProvider;
use crate::payload::Update;
use crate::targets::central_command::CentralCommand;
use crate::units::http_server::HttpServer;
use crate::units::key_manager::KeyManager;
use crate::units::zone_loader::ZoneLoader;
use crate::units::zone_server::{self, ZoneServer};
use crate::units::zone_signer::ZoneSigner;
use daemonbase::process::EnvSocketsError;
use tokio::sync::mpsc;
use tracing::{debug, info};

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

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::EnvSockets(err) => err.fmt(f),
            Error::Terminated => Terminated.fmt(f),
        }
    }
}

pub struct Manager {
    /// The HTTP server.
    pub http_server: Arc<HttpServer>,

    /// The zone loader.
    pub zone_loader: Arc<ZoneLoader>,

    /// The review server for unsigned zones.
    pub unsigned_review: Arc<ZoneServer>,

    /// The key manager.
    pub key_manager: Arc<KeyManager>,

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
    mut socket_provider: SocketProvider,
) -> Result<Manager, Error> {
    // Spawn the central command.
    info!("Starting target 'CC'");
    let target = CentralCommand {
        center: center.clone(),
    };
    let (center_tx, center_rx) = mpsc::unbounded_channel();
    tokio::spawn(target.run(center_rx, update_rx));
    *center_tx_slot = Some(center_tx);

    // Spawn the zone loader.
    info!("Starting unit 'ZL'");
    let zone_loader = Arc::new(ZoneLoader::launch(center.clone()));

    // Spawn the unsigned zone review server.
    info!("Starting unit 'RS'");
    let unsigned_review = Arc::new(ZoneServer::launch(
        center.clone(),
        zone_server::Source::Unsigned,
        &mut socket_provider,
    )?);

    // Spawn the key manager.
    info!("Starting unit 'KM'");
    let key_manager = KeyManager::launch(center.clone());

    // Spawn the zone signer.
    info!("Starting unit 'ZS'");
    let zone_signer = ZoneSigner::launch(center.clone());

    // Spawn the signed zone review server.
    info!("Starting unit 'RS2'");
    let signed_review = Arc::new(ZoneServer::launch(
        center.clone(),
        zone_server::Source::Signed,
        &mut socket_provider,
    )?);

    // Spawn the HTTP server.
    info!("Starting unit 'HS'");
    let http_server = HttpServer::launch(center.clone(), &mut socket_provider)?;

    info!("Starting unit 'PS'");
    let zone_server = Arc::new(ZoneServer::launch(
        center.clone(),
        zone_server::Source::Published,
        &mut socket_provider,
    )?);

    info!("All units report ready.");

    Ok(Manager {
        http_server,
        zone_loader,
        unsigned_review,
        key_manager,
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
) {
    while let Some((unit_name, data)) = rx.recv().await {
        if unit_name == "ZL" {
            tokio::spawn({
                let unit = manager.zone_loader.clone();
                async move { unit.on_command(data).await }
            });
        } else if unit_name == "RS" {
            tokio::spawn({
                let unit = manager.unsigned_review.clone();
                async move { unit.on_command(data).await }
            });
        } else if unit_name == "KM" {
            tokio::spawn({
                let unit = manager.key_manager.clone();
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
