use std::sync::Arc;

use domain::base::Serial;
use domain::zonetree::StoredName;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::api::{self, ZoneReviewStatus};
use crate::center::{get_zone, halt_zone, Center, Change};
use crate::comms::ApplicationCommand;
use crate::payload::Update;
use crate::zone::{HistoricalEvent, PipelineMode, SigningTrigger};

pub struct CentralCommand {}

impl CentralCommand {
    /// Launch the central command.
    pub fn launch(center: Arc<Center>, mut update_rx: mpsc::UnboundedReceiver<Update>) -> Self {
        tokio::task::spawn({
            async move {
                while let Some(update) = update_rx.recv().await {
                    direct_update(&center, update).await;
                }
            }
        });

        Self {}
    }
}

async fn direct_update(center: &Arc<Center>, event: Update) {
    debug!("[CC]: Event received: {event:?}");
    let (msg, target, cmd) = match event {
        Update::Changed(change) => {
            {
                match &change {
                    Change::ConfigChanged
                    | Change::PolicyAdded(_)
                    | Change::PolicyChanged(..)
                    | Change::PolicyRemoved(_) => { /* No zone name, nothing to do */ }

                    Change::ZoneAdded(name) => {
                        record_zone_event(center, name, HistoricalEvent::Added, None);
                    }
                    Change::ZonePolicyChanged { name, .. } => {
                        record_zone_event(center, name, HistoricalEvent::PolicyChanged, None);
                    }
                    Change::ZoneSourceChanged(name, _) => {
                        record_zone_event(center, name, HistoricalEvent::SourceChanged, None);
                    }
                    Change::ZoneRemoved(name) => {
                        record_zone_event(center, name, HistoricalEvent::Removed, None);
                    }
                }
            }
            // Inform all units about the change.
            for name in ["ZL", "RS", "KM", "ZS", "RS2", "PS"] {
                center
                    .app_cmd_tx
                    .send((name.into(), ApplicationCommand::Changed(change.clone())))
                    .unwrap();
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
                center,
                &zone_name,
                HistoricalEvent::NewVersionReceived,
                Some(zone_serial),
            );

            if let Some(zone) = get_zone(center, &zone_name) {
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
                center,
                &zone_name,
                false,
                "Unsigned zone was rejected at the review stage.",
            );

            record_zone_event(
                center,
                &zone_name,
                HistoricalEvent::UnsignedZoneReview {
                    status: ZoneReviewStatus::Rejected,
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
                center,
                &zone_name,
                HistoricalEvent::UnsignedZoneReview {
                    status: ZoneReviewStatus::Approved,
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
                center,
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
                center,
                &zone_name,
                HistoricalEvent::SignedZoneReview {
                    status: ZoneReviewStatus::Approved,
                },
                Some(zone_serial),
            );
            // Send a copy of PublishSignedZone to ZS to trigger a
            // re-scan of when to re-sign next.
            let psz = ApplicationCommand::PublishSignedZone {
                zone_name: zone_name.clone(),
                zone_serial,
            };
            center.app_cmd_tx.send(("ZS".into(), psz)).unwrap();
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
                center,
                &zone_name,
                false,
                "Signed zone was rejected at the review stage.",
            );

            record_zone_event(
                center,
                &zone_name,
                HistoricalEvent::SignedZoneReview {
                    status: ZoneReviewStatus::Rejected,
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
            halt_zone(center, &zone_name, true, reason.as_str());

            record_zone_event(
                center,
                &zone_name,
                HistoricalEvent::SigningFailed { trigger, reason },
                zone_serial,
            );
            return;
        }
    };

    info!("[CC]: {msg}");
    center.app_cmd_tx.send((target.into(), cmd)).unwrap();
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
