//! Controlling the entire operation.

use std::sync::Arc;

use crate::api;
use crate::center::{Center, Change, get_zone, halt_zone};
use crate::daemon::SocketProvider;
use crate::loader::Loader;
use crate::metrics::MetricsCollection;
use crate::units::http_server::HTTP_UNIT_NAME;
use crate::units::http_server::HttpServer;
use crate::units::key_manager::KeyManager;
use crate::units::zone_server::{self, ZoneServer};
use crate::units::zone_signer::ZoneSigner;
use crate::util::AbortOnDrop;
use crate::zone::{HistoricalEvent, PipelineMode, SigningTrigger};
use daemonbase::process::EnvSocketsError;
use domain::base::Serial;
use domain::zonetree::StoredName;
use tracing::{debug, error, info, warn};

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

    /// Handles to tasks that should abort when we exit Cascade
    _handles: Vec<AbortOnDrop>,
}

impl Manager {
    /// Spawn all targets.
    pub fn spawn(center: Arc<Center>, mut socket_provider: SocketProvider) -> Result<Self, Error> {
        let metrics = MetricsCollection::new();

        // Initialize the components.
        {
            let mut state = center.state.lock().unwrap();
            Loader::init(&center, &mut state);
        }

        let mut handles = Vec::new();

        // Spawn the zone loader.
        info!("Starting unit 'ZL'");
        handles.push(Loader::run(center.clone()));

        // Spawn the unsigned zone review server.
        info!("Starting unit 'RS'");
        handles.extend(ZoneServer::run(
            center.clone(),
            zone_server::Source::Unsigned,
            &mut socket_provider,
        )?);

        // Spawn the key manager.
        info!("Starting unit 'KM'");
        handles.push(KeyManager::run(center.clone()));

        // Spawn the zone signer.
        info!("Starting unit 'ZS'");
        handles.push(ZoneSigner::run(center.clone()));

        // Spawn the signed zone review server.
        info!("Starting unit 'RS2'");
        handles.extend(ZoneServer::run(
            center.clone(),
            zone_server::Source::Signed,
            &mut socket_provider,
        )?);

        // Take out HTTP listen sockets before PS takes them all.
        debug!("Pre-fetching listen sockets for 'HS'");
        let http_sockets = center
            .config
            .remote_control
            .servers
            .iter()
            .map(|addr| {
                socket_provider.take_tcp(addr).ok_or_else(|| {
                    error!("[{HTTP_UNIT_NAME}]: No socket available for TCP {addr}",);
                    Terminated
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        info!("Starting unit 'PS'");
        handles.extend(ZoneServer::run(
            center.clone(),
            zone_server::Source::Published,
            &mut socket_provider,
        )?);

        // Register any Manager metrics here, before giving the metrics to the HttpServer

        // Spawn the HTTP server.
        info!("Starting unit 'HS'");
        let http_server = HttpServer::launch(center.clone(), http_sockets, metrics)?;

        info!("All units report ready.");

        Ok(Self {
            center,
            http_server,
            _handles: handles,
        })
    }

    /// Process an update command.
    pub fn on_update(&self, update: Update) {
        debug!("[CC]: Event received: {update:?}");
        let center = &self.center;
        match update {
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
                    Change::ZoneSourceChanged(name) => {
                        record_zone_event(&self.center, name, HistoricalEvent::SourceChanged, None);
                    }
                    Change::ZoneRemoved(name) => {
                        record_zone_event(&self.center, name, HistoricalEvent::Removed, None);
                    }
                }

                // Inform all units about the change.
                center.loader.on_change(center, change.clone());
                center.zone_signer.on_change(center, change.clone());
                center.key_manager.on_change(center, change.clone());
                center.unsigned_review.on_change(center, change.clone());
                center.signed_review.on_change(center, change.clone());
                center.zone_server.on_change(center, change.clone());
            }
            Update::RefreshZone { zone_name } => {
                info!("[CC]: Instructing zone loader to refresh the zone");
                center.loader.on_refresh_zone(center, zone_name);
            }
            Update::ReviewZone {
                name,
                stage,
                serial,
                decision,
            } => {
                info!("[CC]: Passing back zone review");

                let server = match stage {
                    api::ZoneReviewStage::Unsigned => &center.unsigned_review,
                    api::ZoneReviewStage::Signed => &center.signed_review,
                };

                let _ = server.on_zone_review(center, name, serial, decision);
            }

            Update::UnsignedZoneUpdatedEvent {
                zone_name,
                zone_serial,
            } => {
                record_zone_event(
                    center,
                    &zone_name,
                    HistoricalEvent::NewVersionReceived,
                    Some(zone_serial),
                );

                if let Some(zone) = get_zone(center, &zone_name)
                    && let Ok(mut zone_state) = zone.state.lock()
                {
                    match zone_state.pipeline_mode.clone() {
                        PipelineMode::Running => {}
                        PipelineMode::SoftHalt(message) => {
                            info!(
                                "[CC]: Restore the pipeline for '{zone_name}' from soft-halt ({message}) to running"
                            );
                            zone_state.resume();
                        }
                        PipelineMode::HardHalt(_) => {
                            warn!(
                                "[CC]: NOT instructing review server to publish the unsigned zone as the pipeline for the zone is hard halted"
                            );
                            return;
                        }
                    }
                }

                info!("[CC]: Instructing review server to publish the unsigned zone");
                center
                    .unsigned_review
                    .on_seek_approval_for_zone(center, zone_name, zone_serial);
            }

            Update::UnsignedZoneRejectedEvent {
                zone_name,
                zone_serial,
            } => {
                halt_zone(
                    center,
                    &zone_name,
                    false,
                    "Unsigned zone was rejected at the review stage.",
                );

                record_zone_event(
                    center,
                    &zone_name,
                    HistoricalEvent::UnsignedZoneReview {
                        status: api::ZoneReviewStatus::Rejected,
                    },
                    Some(zone_serial),
                );
            }

            Update::UnsignedZoneApprovedEvent {
                zone_name,
                zone_serial,
            } => {
                record_zone_event(
                    center,
                    &zone_name,
                    HistoricalEvent::UnsignedZoneReview {
                        status: api::ZoneReviewStatus::Approved,
                    },
                    Some(zone_serial),
                );
                info!("[CC]: Instructing zone signer to sign the approved zone");
                center.zone_signer.on_sign_zone(
                    center,
                    zone_name,
                    Some(zone_serial),
                    SigningTrigger::ZoneChangesApproved,
                );
            }

            Update::ResignZoneEvent { zone_name, trigger } => {
                info!("[CC]: Instructing zone signer to re-sign the zone");
                center
                    .zone_signer
                    .on_sign_zone(center, zone_name, None, trigger);
            }

            Update::ZoneSignedEvent {
                zone_name,
                zone_serial,
                trigger,
            } => {
                record_zone_event(
                    center,
                    &zone_name,
                    HistoricalEvent::SigningSucceeded { trigger },
                    Some(zone_serial),
                );

                info!("Instructing review server to publish the signed zone");
                center
                    .signed_review
                    .on_seek_approval_for_zone(center, zone_name, zone_serial);
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

                // Send a message to the zone signer to trigger a re-scan of
                // when to re-sign next.
                center.zone_signer.on_publish_signed_zone(center);

                info!("[CC]: Instructing publication server to publish the signed zone");
                center
                    .zone_server
                    .on_publish_signed_zone(center, zone_name, zone_serial);
            }

            Update::SignedZoneRejectedEvent {
                zone_name,
                zone_serial,
            } => {
                halt_zone(
                    center,
                    &zone_name,
                    false,
                    "Signed zone was rejected at the review stage.",
                );

                record_zone_event(
                    center,
                    &zone_name,
                    HistoricalEvent::SignedZoneReview {
                        status: api::ZoneReviewStatus::Rejected,
                    },
                    Some(zone_serial),
                );
            }

            Update::ZoneSigningFailedEvent {
                zone_name,
                zone_serial,
                trigger,
                reason,
            } => {
                halt_zone(center, &zone_name, true, reason.as_str());

                record_zone_event(
                    center,
                    &zone_name,
                    HistoricalEvent::SigningFailed { trigger, reason },
                    zone_serial,
                );
            }
        };
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

//------------ Update --------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Update {
    /// A change has occurred.
    Changed(Change),

    /// A request to refresh a zone.
    ///
    /// This is sent by the publication server when it receives an appropriate
    /// NOTIFY message.
    RefreshZone {
        /// The name of the zone to refresh.
        zone_name: StoredName,
    },

    /// Review a zone.
    ReviewZone {
        /// The name of the zone.
        name: StoredName,

        /// The stage of review.
        stage: api::ZoneReviewStage,

        /// The serial number of the zone.
        serial: Serial,

        /// Whether to approve or reject the zone.
        decision: api::ZoneReviewDecision,
    },

    UnsignedZoneUpdatedEvent {
        zone_name: StoredName,
        zone_serial: Serial,
    },

    UnsignedZoneApprovedEvent {
        zone_name: StoredName,
        zone_serial: Serial,
    },

    UnsignedZoneRejectedEvent {
        zone_name: StoredName,
        zone_serial: Serial,
    },

    ZoneSignedEvent {
        zone_name: StoredName,
        zone_serial: Serial,
        trigger: SigningTrigger,
    },

    ZoneSigningFailedEvent {
        zone_name: StoredName,
        zone_serial: Option<Serial>,
        trigger: SigningTrigger,
        reason: String,
    },

    SignedZoneApprovedEvent {
        zone_name: StoredName,
        zone_serial: Serial,
    },

    SignedZoneRejectedEvent {
        zone_name: StoredName,
        zone_serial: Serial,
    },

    ResignZoneEvent {
        zone_name: StoredName,
        trigger: SigningTrigger,
    },
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

//----------- Terminated -------------------------------------------------------

/// An error signalling that a unit has been terminated.
///
/// In response to this error, a unit’s run function should return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terminated;
