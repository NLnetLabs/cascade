//! Controlling the entire operation.

use std::sync::Arc;

use crate::api;
use crate::center::{get_zone, halt_zone, Center, Change};
use crate::comms::{ApplicationCommand, Terminated};
use crate::daemon::SocketProvider;
use crate::payload::Update;
use crate::units::http_server::HttpServer;
use crate::units::key_manager::KeyManager;
use crate::units::zone_loader::ZoneLoader;
use crate::units::zone_server::{self, ZoneServer};
use crate::units::zone_signer::ZoneSigner;
use crate::zone::{HistoricalEvent, PipelineMode, SigningTrigger};
use daemonbase::process::EnvSocketsError;
use domain::base::Serial;
use domain::zonetree::StoredName;
use tracing::{debug, info, warn};

//----------- Manager ----------------------------------------------------------

/// Cascade's top-level manager.
///
/// The manager is basically Cascade's runtime -- it contains all of Cascade's
/// components and handles the interactions between them.
pub struct Manager {
    /// The center.
    pub center: Arc<Center>,

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

impl Manager {
    /// Spawn all targets.
    pub async fn spawn(
        center: Arc<Center>,
        mut socket_provider: SocketProvider,
    ) -> Result<Self, Error> {
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

        Ok(Self {
            center,
            http_server,
            zone_loader,
            unsigned_review,
            key_manager,
            zone_signer,
            signed_review,
            zone_server,
        })
    }

    /// Process an application update command.
    pub fn on_app_cmd(&self, unit: &str, cmd: ApplicationCommand) {
        match unit {
            "ZL" => tokio::spawn({
                let unit = self.zone_loader.clone();
                async move { unit.on_command(cmd).await }
            }),
            "RS" => tokio::spawn({
                let unit = self.unsigned_review.clone();
                async move { unit.on_command(cmd).await }
            }),
            "KM" => tokio::spawn({
                let unit = self.key_manager.clone();
                async move { unit.on_command(cmd).await }
            }),
            "ZS" => tokio::spawn({
                let unit = self.zone_signer.clone();
                async move { unit.on_command(cmd).await }
            }),
            "RS2" => tokio::spawn({
                let unit = self.signed_review.clone();
                async move { unit.on_command(cmd).await }
            }),
            "PS" => tokio::spawn({
                let unit = self.zone_server.clone();
                async move { unit.on_command(cmd).await }
            }),
            _ => unreachable!(),
        };
    }

    /// Process an update command.
    pub fn on_update(&self, update: Update) {
        debug!("[CC]: Event received: {update:?}");
        let (msg, target, cmd) = match update {
            Update::Changed(change) => {
                match &change {
                    Change::ConfigChanged
                    | Change::PolicyAdded(_)
                    | Change::PolicyChanged(..)
                    | Change::PolicyRemoved(_) => { /* No zone name, nothing to do */ }

                    Change::ZoneAdded(name) => {
                        record_zone_event(&self.center, name, HistoricalEvent::Added, None);
                    }
                    Change::ZonePolicyChanged { name, .. } => {
                        record_zone_event(&self.center, name, HistoricalEvent::PolicyChanged, None);
                    }
                    Change::ZoneSourceChanged(name, _) => {
                        record_zone_event(&self.center, name, HistoricalEvent::SourceChanged, None);
                    }
                    Change::ZoneRemoved(name) => {
                        record_zone_event(&self.center, name, HistoricalEvent::Removed, None);
                    }
                }

                // Inform all units about the change.
                for name in ["ZL", "RS", "KM", "ZS", "RS2", "PS"] {
                    self.on_app_cmd(name, ApplicationCommand::Changed(change.clone()));
                }
                return;
            }

            Update::RefreshZone {
                zone_name,
                source,
                serial,
            } => (
                "Instructing zone loader to refresh the zone",
                "ZL",
                ApplicationCommand::RefreshZone {
                    zone_name,
                    source,
                    serial,
                },
            ),

            Update::ReviewZone {
                name,
                stage,
                serial,
                decision,
            } => (
                "Passing back zone review",
                match stage {
                    api::ZoneReviewStage::Unsigned => "RS",
                    api::ZoneReviewStage::Signed => "RS2",
                },
                ApplicationCommand::ReviewZone {
                    name,
                    serial,
                    decision,
                    tx: tokio::sync::oneshot::channel().0,
                },
            ),

            Update::UnsignedZoneUpdatedEvent {
                zone_name,
                zone_serial,
            } => {
                record_zone_event(
                    &self.center,
                    &zone_name,
                    HistoricalEvent::NewVersionReceived,
                    Some(zone_serial),
                );

                if let Some(zone) = get_zone(&self.center, &zone_name) {
                    if let Ok(mut zone_state) = zone.state.lock() {
                        match zone_state.pipeline_mode.clone() {
                            PipelineMode::Running => {}
                            PipelineMode::SoftHalt(message) => {
                                info!("[CC]: Restore the pipeline for '{zone_name}' from soft-halt ({message}) to running");
                                zone_state.resume();
                            }
                            PipelineMode::HardHalt(_) => {
                                warn!("[CC]: NOT instructing review server to publish the unsigned zone as the pipeline for the zone is hard halted");
                                return;
                            }
                        }
                    }
                }

                (
                    "Instructing review server to publish the unsigned zone",
                    "RS",
                    ApplicationCommand::SeekApprovalForUnsignedZone {
                        zone_name,
                        zone_serial,
                    },
                )
            }

            Update::UnsignedZoneRejectedEvent {
                zone_name,
                zone_serial,
            } => {
                halt_zone(
                    &self.center,
                    &zone_name,
                    false,
                    "Unsigned zone was rejected at the review stage.",
                );

                record_zone_event(
                    &self.center,
                    &zone_name,
                    HistoricalEvent::UnsignedZoneReview {
                        status: api::ZoneReviewStatus::Rejected,
                    },
                    Some(zone_serial),
                );
                return;
            }

            Update::UnsignedZoneApprovedEvent {
                zone_name,
                zone_serial,
            } => {
                record_zone_event(
                    &self.center,
                    &zone_name,
                    HistoricalEvent::UnsignedZoneReview {
                        status: api::ZoneReviewStatus::Approved,
                    },
                    Some(zone_serial),
                );
                (
                    "Instructing zone signer to sign the approved zone",
                    "ZS",
                    ApplicationCommand::SignZone {
                        zone_name,
                        zone_serial: Some(zone_serial),
                        trigger: SigningTrigger::ZoneChangesApproved,
                    },
                )
            }

            Update::ResignZoneEvent { zone_name, trigger } => (
                "Instructing zone signer to re-sign the zone",
                "ZS",
                ApplicationCommand::SignZone {
                    zone_name,
                    zone_serial: None,
                    trigger,
                },
            ),

            Update::ZoneSignedEvent {
                zone_name,
                zone_serial,
                trigger,
            } => {
                record_zone_event(
                    &self.center,
                    &zone_name,
                    HistoricalEvent::SigningSucceeded { trigger },
                    Some(zone_serial),
                );
                (
                    "Instructing review server to publish the signed zone",
                    "RS2",
                    ApplicationCommand::SeekApprovalForSignedZone {
                        zone_name,
                        zone_serial,
                    },
                )
            }

            Update::SignedZoneApprovedEvent {
                zone_name,
                zone_serial,
            } => {
                record_zone_event(
                    &self.center,
                    &zone_name,
                    HistoricalEvent::SignedZoneReview {
                        status: api::ZoneReviewStatus::Approved,
                    },
                    Some(zone_serial),
                );
                // Send a copy of PublishSignedZone to ZS to trigger a
                // re-scan of when to re-sign next.
                let psz = ApplicationCommand::PublishSignedZone {
                    zone_name: zone_name.clone(),
                    zone_serial,
                };
                self.center.app_cmd_tx.send(("ZS".into(), psz)).unwrap();
                (
                    "Instructing publication server to publish the signed zone",
                    "PS",
                    ApplicationCommand::PublishSignedZone {
                        zone_name,
                        zone_serial,
                    },
                )
            }

            Update::SignedZoneRejectedEvent {
                zone_name,
                zone_serial,
            } => {
                halt_zone(
                    &self.center,
                    &zone_name,
                    false,
                    "Signed zone was rejected at the review stage.",
                );

                record_zone_event(
                    &self.center,
                    &zone_name,
                    HistoricalEvent::SignedZoneReview {
                        status: api::ZoneReviewStatus::Rejected,
                    },
                    Some(zone_serial),
                );
                return;
            }

            Update::ZoneSigningFailedEvent {
                zone_name,
                zone_serial,
                trigger,
                reason,
            } => {
                halt_zone(&self.center, &zone_name, true, reason.as_str());

                record_zone_event(
                    &self.center,
                    &zone_name,
                    HistoricalEvent::SigningFailed { trigger, reason },
                    zone_serial,
                );
                return;
            }
        };

        info!("[CC]: {msg}");
        self.center.app_cmd_tx.send((target.into(), cmd)).unwrap();
    }
}

pub fn record_zone_event(
    center: &Arc<Center>,
    name: &StoredName,
    event: HistoricalEvent,
    serial: Option<Serial>,
) {
    if let Some(zone) = get_zone(center, name) {
        let mut zone_state = zone.state.lock().unwrap();
        zone_state.record_event(event, serial);
        zone.mark_dirty(&mut zone_state, center);
    }
}
//----------- Error ------------------------------------------------------------

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
            Error::EnvSockets(err) => write!(f, "{err:?}"),
            Error::Terminated => f.write_str("terminated"),
        }
    }
}
