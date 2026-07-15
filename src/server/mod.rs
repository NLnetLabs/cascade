//! Serving zone data.

use std::{fmt, sync::Arc};

use domain::base::Serial;
use tracing::{debug, error, info, trace, warn};

use crate::{
    center::Center,
    daemon::SocketProvider,
    manager::Terminated,
    policy::OnReject,
    units::zone_server::{Source, ZoneServer},
    util::AbortOnDrop,
    zone::{Zone, ZoneHandle, machine::ZoneStateMachine},
    zonedata::{LoadedZoneReviewer, SignedZoneReviewer, ZoneViewer},
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

    /// Process a review of a served instance.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %zone.name, serial = %zone_serial.0, ?decision),
    )]
    pub fn process_review(
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        zone_serial: Serial,
        decision: crate::api::ZoneReviewDecision,
    ) -> crate::api::ZoneReviewResult {
        let mut handle = zone.write_handle(center);

        if !matches!(handle.state.machine, ZoneStateMachine::LoadedReview(_)) {
            debug!("The zone is not undergoing loaded review");
            return Err(crate::api::ZoneReviewError::NotUnderReview);
        }

        let instance = handle
            .state
            .instances
            .upcoming
            .as_ref()
            .and_then(|i| i.loaded.as_ref())
            .expect("There must be an upcoming instance in the `LoadedReview` state");

        if instance.serial().get() != zone_serial.0 {
            debug!(
                "A review of a loaded instance with SOA serial {} was received, \
                but the loaded instance under review actually has SOA serial {}",
                zone_serial.0,
                instance.serial().get()
            );
            return Err(crate::api::ZoneReviewError::NotUnderReview);
        }

        let Some(policy) = handle.state.policy.as_ref() else {
            warn!("Bug: zone has no policy, it might be mid removal");
            return Err(crate::api::ZoneReviewError::NoSuchZone);
        };

        match decision {
            crate::api::ZoneReviewDecision::Approve => {
                info!(
                    "The loaded instance of zone '{}' (SOA serial {}) has been approved.",
                    zone.name, zone_serial.0
                );

                handle.get().approve_loaded();
            }

            crate::api::ZoneReviewDecision::Reject => {
                error!(
                    "The loaded instance of zone '{}' (SOA serial {}) has been rejected.",
                    zone.name, zone_serial.0
                );

                match policy.loader.review.on_reject {
                    OnReject::Discard => {
                        handle.get().soft_reject_loaded();
                    }
                    OnReject::Halt => {
                        handle.get().hard_reject_loaded();
                    }
                }
            }
        }

        Ok(crate::api::ZoneReviewOutput {})
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

    /// Process a review of a served instance.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %zone.name, serial = %zone_serial.0, ?decision),
    )]
    pub fn process_review(
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        zone_serial: Serial,
        decision: crate::api::ZoneReviewDecision,
    ) -> crate::api::ZoneReviewResult {
        let mut handle = zone.write_handle(center);

        if !matches!(handle.state.machine, ZoneStateMachine::SignedReview(_)) {
            debug!("The zone is not undergoing signed review");
            return Err(crate::api::ZoneReviewError::NotUnderReview);
        }

        let instance = handle
            .state
            .instances
            .upcoming
            .as_ref()
            .and_then(|i| i.signed.as_ref())
            .expect("There must be an upcoming instance in the `SignedReview` state");

        if instance.serial().get() != zone_serial.0 {
            debug!(
                "A review of a signed instance with SOA serial {} was received, \
                but the signed instance under review actually has SOA serial {}",
                zone_serial.0,
                instance.serial().get()
            );
            return Err(crate::api::ZoneReviewError::NotUnderReview);
        }

        let Some(policy) = handle.state.policy.as_ref() else {
            warn!("Bug: zone has no policy, it might be mid removal");
            return Err(crate::api::ZoneReviewError::NoSuchZone);
        };

        match decision {
            crate::api::ZoneReviewDecision::Approve => {
                info!(
                    "The signed instance of zone '{}' (SOA serial {}) has been approved.",
                    zone.name, zone_serial.0
                );

                handle.get().approve_signed();
            }

            crate::api::ZoneReviewDecision::Reject => {
                error!(
                    "The signed instance of zone '{}' (SOA serial {}) has been rejected.",
                    zone.name, zone_serial.0
                );

                match policy.signer.review.on_reject {
                    OnReject::Discard => {
                        handle.get().soft_reject_signed();
                    }
                    OnReject::Halt => {
                        handle.get().hard_reject_signed();
                    }
                }
            }
        }

        Ok(crate::api::ZoneReviewOutput {})
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

    /// React to the publication of an instance.
    ///
    /// Sends NOTIFY messages to downstream servers if configured to do so.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %handle.zone.name),
    )]
    pub fn after_publication(handle: &mut ZoneHandle<'_>) {
        let instance = handle
            .state
            .instances
            .current
            .as_ref()
            .expect("A published zone must have a current instance");
        let policy = handle
            .state
            .policy
            .as_ref()
            .expect("A published zone always has a policy");

        let targets = policy
            .server
            .outbound
            .send_notify_to
            .iter()
            .filter(|&s| s.addr.port() != 0)
            .collect::<Vec<_>>();

        debug!(
            "Sending NOTIFY messages to {} downstream name servers",
            targets.len()
        );

        if targets.is_empty() {
            return;
        }

        trace!("Target name servers: {targets:?}");

        self::notify::send_notify_to_addrs(
            handle.zone.name.clone(),
            instance.signed.soa.clone(),
            targets.into_iter(),
            handle.center,
        );
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

    /// Get the viewer for this zone.
    ///
    /// If Cascade is still starting up there may not be a viewer for the zone
    /// yet.
    pub fn viewer(&self, zone: &Arc<Zone>) -> Option<Arc<tokio::sync::RwLock<ZoneViewer>>> {
        self.handle.viewer(zone)
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
