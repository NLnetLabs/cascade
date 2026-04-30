//! Serving zone data.

use std::{fmt, sync::Arc};

use cascade_api::{ZoneReviewDecision, ZoneReviewResult};
use cascade_zonedata::{LoadedZoneReviewer, SignedZoneReviewer, ZoneViewer};
use domain::base::Serial;

use crate::{
    center::Center,
    daemon::SocketProvider,
    manager::Terminated,
    units::zone_server::{Source, ZoneServer},
    util::AbortOnDrop,
    zone::Zone,
};

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
        let (service, handle) = ZoneService::new();
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
    pub fn process_review(
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        zone_serial: Serial,
        decision: ZoneReviewDecision,
    ) -> ZoneReviewResult {
        // TODO: Inline.
        ZoneServer::new(Source::Unsigned).on_zone_review(center, zone, zone_serial, decision)
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
        let (service, handle) = ZoneService::new();
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
    pub fn process_review(
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        zone_serial: Serial,
        decision: ZoneReviewDecision,
    ) -> ZoneReviewResult {
        // TODO: Inline.
        ZoneServer::new(Source::Signed).on_zone_review(center, zone, zone_serial, decision)
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
        let (service, handle) = ZoneService::new();
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

    /// Publish an instance.
    pub fn publish(center: &Arc<Center>, zone: &Arc<Zone>, zone_serial: Serial) {
        // TODO: Inline.
        ZoneServer::new(Source::Published).on_publish_signed_zone(center, zone, zone_serial)
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
