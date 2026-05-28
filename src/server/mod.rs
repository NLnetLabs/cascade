//! Serving zone data.

use std::{fmt, sync::Arc};

use cascade_zonedata::{LoadedZoneReviewer, SignedZoneReviewer, ZoneViewer};
use domain::base::Serial;
use tracing::{debug, error, info, trace};

use crate::{
    center::Center,
    daemon::SocketProvider,
    manager::Terminated,
    policy::OnReject,
    units::zone_server::{Source, ZoneServer},
    util::AbortOnDrop,
    zone::{UpcomingInstance, Zone, ZoneHandle, machine::ZoneStateMachine},
};

mod notify;
mod request;
mod service;

use service::{ZoneService, ZoneServiceHandle};

//----------- LoadedReviewServer -----------------------------------------------

/// The review server for loaded instances of zones.
pub struct LoadedReviewServer {
    /// The underlying service.
    service: ZoneService<LoadedZoneReviewer>,

    /// A handle for controlling the service.
    handle: ZoneServiceHandle<LoadedZoneReviewer>,
}

impl LoadedReviewServer {
    /// Construct a new [`LoadedReviewServer`].
    pub fn new() -> Self {
        let (service, handle) = ZoneService::new(service::ServiceMode::LoadedReview);
        Self { service, handle }
    }

    /// Drive the server.
    pub fn run(
        center: &Arc<Center>,
        socket_provider: &mut SocketProvider,
    ) -> Result<Vec<AbortOnDrop>, Terminated> {
        // TODO: Inline.
        ZoneServer::run(
            center,
            Source::Unsigned,
            socket_provider,
            center.loaded_review_server.service.clone(),
        )
    }

    /// Start reviewing a newly loaded instance.
    pub fn start_review(
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        zone_serial: Serial,
    ) -> Option<Result<(), Terminated>> {
        // TODO: Inline.
        ZoneServer::new(Source::Unsigned).on_seek_approval_for_zone(center, zone, zone_serial)
    }

    /// Process a review of the upcoming loaded instance.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %zone.name, r#type = "loaded", zone_serial, ?decision)
    )]
    pub fn process_review(
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        zone_serial: Serial,
        decision: cascade_api::ZoneReviewDecision,
    ) -> cascade_api::ZoneReviewResult {
        let mut state = zone.state.lock().unwrap();
        let mut handle = ZoneHandle {
            zone,
            state: &mut state,
            center,
        };

        // Ensure the zone is in loader review.
        let ZoneStateMachine::LoadedReview(machine) = &mut handle.state.machine else {
            debug!("The zone is not in loaded-review state");

            return Err(cascade_api::ZoneReviewError::NotUnderReview);
        };
        if machine.decided {
            debug!("The instance has already been reviewed");

            return Err(cascade_api::ZoneReviewError::NotUnderReview);
        }

        // Look up the upcoming instance.
        let Some(UpcomingInstance {
            loaded: Some(loaded),
            signed: None,
        }) = &handle.state.instances.upcoming
        else {
            unreachable!("'UpcomingInstance' is inconsistent with 'LoadedReview'")
        };

        // Ensure the serial number is correct.
        if Serial(loaded.serial().into()) != zone_serial {
            debug!(
                "The upcoming loaded instance has serial '{}', not '{zone_serial}'",
                loaded.serial()
            );

            return Err(cascade_api::ZoneReviewError::NotUnderReview);
        }

        // Remember that a review has been received.
        machine.decided = true;

        match decision {
            cascade_api::ZoneReviewDecision::Approve => {
                info!("Approving the upcoming loaded instance");

                handle.approve_loaded();
            }

            cascade_api::ZoneReviewDecision::Reject => {
                error!("Rejecting the upcoming loaded instance");

                let policy = handle.state.policy.as_ref().unwrap();
                match policy.loader.review.on_reject {
                    OnReject::Discard => {
                        handle.soft_reject_loaded();
                    }

                    OnReject::Halt => {
                        handle.hard_reject_loaded();
                    }
                }
            }
        }

        Ok(cascade_api::ZoneReviewOutput {})
    }

    /// Register a new zone.
    pub fn add_zone(center: &Arc<Center>, zone: Arc<Zone>, viewer: LoadedZoneReviewer) {
        let handle = &center.loaded_review_server.handle;
        handle.add_zone(zone, viewer)
    }

    /// Update the viewer of a zone.
    #[tracing::instrument(level = "trace", skip_all, fields(zone = %zone.name))]
    pub async fn update_viewer(
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        viewer: LoadedZoneReviewer,
    ) -> LoadedZoneReviewer {
        let handle = &center.loaded_review_server.handle;
        handle.update_viewer(zone, viewer).await
    }

    /// Remove a zone.
    pub fn remove_zone(center: &Arc<Center>, zone: &Arc<Zone>) {
        let handle = &center.loaded_review_server.handle;
        handle.remove_zone(zone);
    }
}

impl Default for LoadedReviewServer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LoadedReviewServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedReviewServer").finish_non_exhaustive()
    }
}

//----------- SignedReviewServer -----------------------------------------------

/// The review server for signed instances of zones.
pub struct SignedReviewServer {
    /// The underlying service.
    service: ZoneService<SignedZoneReviewer>,

    /// A handle for controlling the service.
    handle: ZoneServiceHandle<SignedZoneReviewer>,
}

impl SignedReviewServer {
    /// Construct a new [`SignedReviewServer`].
    pub fn new() -> Self {
        let (service, handle) = ZoneService::new(service::ServiceMode::SignedReview);
        Self { service, handle }
    }

    /// Drive the server.
    pub fn run(
        center: &Arc<Center>,
        socket_provider: &mut SocketProvider,
    ) -> Result<Vec<AbortOnDrop>, Terminated> {
        // TODO: Inline.
        ZoneServer::run(
            center,
            Source::Signed,
            socket_provider,
            center.signed_review_server.service.clone(),
        )
    }

    /// Start reviewing a newly signed instance.
    pub fn start_review(
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        zone_serial: Serial,
    ) -> Option<Result<(), Terminated>> {
        // TODO: Inline.
        ZoneServer::new(Source::Signed).on_seek_approval_for_zone(center, zone, zone_serial)
    }

    /// Process a review of the upcoming signed instance.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %zone.name, r#type = "signed", zone_serial, ?decision)
    )]
    pub fn process_review(
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        zone_serial: Serial,
        decision: cascade_api::ZoneReviewDecision,
    ) -> cascade_api::ZoneReviewResult {
        let mut state = zone.state.lock().unwrap();
        let mut handle = ZoneHandle {
            zone,
            state: &mut state,
            center,
        };

        // Ensure the zone is in signer review.
        let ZoneStateMachine::SignedReview(machine) = &mut handle.state.machine else {
            debug!("The zone is not in signed-review state");

            return Err(cascade_api::ZoneReviewError::NotUnderReview);
        };
        if machine.decided {
            debug!("The instance has already been reviewed");

            return Err(cascade_api::ZoneReviewError::NotUnderReview);
        }

        // Look up the upcoming instance.
        let Some(UpcomingInstance {
            loaded: _,
            signed: Some(signed),
        }) = &handle.state.instances.upcoming
        else {
            unreachable!("'UpcomingInstance' is inconsistent with 'LoadedReview'")
        };

        // Ensure the serial number is correct.
        if Serial(signed.serial().into()) != zone_serial {
            debug!(
                "The upcoming signed instance has serial '{}', not '{zone_serial}'",
                signed.serial()
            );

            return Err(cascade_api::ZoneReviewError::NotUnderReview);
        }

        // Remember that a review has been received.
        machine.decided = true;

        match decision {
            cascade_api::ZoneReviewDecision::Approve => {
                info!("Approving the upcoming signed instance");

                handle.approve_signed();
            }

            cascade_api::ZoneReviewDecision::Reject => {
                error!("Rejecting the upcoming signed instance");

                let policy = handle.state.policy.as_ref().unwrap();
                match policy.signer.review.on_reject {
                    OnReject::Discard => {
                        handle.soft_reject_signed();
                    }

                    OnReject::Halt => {
                        handle.hard_reject_signed();
                    }
                }
            }
        }

        Ok(cascade_api::ZoneReviewOutput {})
    }

    /// Register a new zone.
    pub fn add_zone(center: &Arc<Center>, zone: Arc<Zone>, viewer: SignedZoneReviewer) {
        let handle = &center.signed_review_server.handle;
        handle.add_zone(zone, viewer)
    }

    /// Update the viewer of a zone.
    #[tracing::instrument(level = "trace", skip_all, fields(zone = %zone.name))]
    pub async fn update_viewer(
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        viewer: SignedZoneReviewer,
    ) -> SignedZoneReviewer {
        let handle = &center.signed_review_server.handle;
        handle.update_viewer(zone, viewer).await
    }

    /// Remove a zone.
    pub fn remove_zone(center: &Arc<Center>, zone: &Arc<Zone>) {
        let handle = &center.signed_review_server.handle;
        handle.remove_zone(zone);
    }
}

impl Default for SignedReviewServer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SignedReviewServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedReviewServer").finish_non_exhaustive()
    }
}

//----------- PublicationServer ------------------------------------------------

/// The server for published instances of zones.
pub struct PublicationServer {
    /// The underlying service.
    service: ZoneService<ZoneViewer>,

    /// A handle for controlling the service.
    handle: ZoneServiceHandle<ZoneViewer>,
}

impl PublicationServer {
    /// Construct a new [`PublicationServer`].
    pub fn new() -> Self {
        let (service, handle) = ZoneService::new(service::ServiceMode::Publication);
        Self { service, handle }
    }

    /// Drive the server.
    pub fn run(
        center: &Arc<Center>,
        socket_provider: &mut SocketProvider,
    ) -> Result<Vec<AbortOnDrop>, Terminated> {
        ZoneServer::run(
            center,
            Source::Published,
            socket_provider,
            center.publication_server.service.clone(),
        )
    }

    /// Send NOTIFY messages to downstream servers after publication.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %handle.zone.name),
    )]
    pub fn notify_downstream(handle: &mut ZoneHandle<'_>) {
        let Some(policy) = handle.state.policy.clone() else {
            trace!("Can't send NOTIFY messages: missing policy");
            return;
        };

        let Some(instance) = &handle.state.instances.current else {
            trace!("Can't send NOTIFY messages: no published instance");
            return;
        };

        let soa = instance.signed.soa.clone();

        let targets = &policy.server.outbound.send_notify_to;
        if targets.is_empty() {
            trace!("Can't send NOTIFY messages: no downstream servers configured");
            return;
        }
        trace!("NOTIFY targets: {targets:?}");

        let addrs = targets.iter().filter(|s| s.addr.port() != 0);

        notify::send_notify_to_addrs(handle.zone.name.clone(), soa, addrs, handle.center);
    }

    /// Register a new zone.
    pub fn add_zone(center: &Arc<Center>, zone: Arc<Zone>, viewer: ZoneViewer) {
        let handle = &center.publication_server.handle;
        handle.add_zone(zone, viewer)
    }

    /// Update the viewer of a zone.
    #[tracing::instrument(level = "trace", skip_all, fields(zone = %zone.name))]
    pub async fn update_viewer(
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        viewer: ZoneViewer,
    ) -> ZoneViewer {
        let handle = &center.publication_server.handle;
        handle.update_viewer(zone, viewer).await
    }

    /// Remove a zone.
    pub fn remove_zone(center: &Arc<Center>, zone: &Arc<Zone>) {
        let handle = &center.publication_server.handle;
        handle.remove_zone(zone);
    }
}

impl Default for PublicationServer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PublicationServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicationServer").finish_non_exhaustive()
    }
}
