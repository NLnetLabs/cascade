//! Serving zone data.

use std::sync::Arc;

use cascade_api::{ZoneReviewDecision, ZoneReviewResult};
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

//----------- LoadedReviewServer -----------------------------------------------

/// The review server for loaded instances of zones.
#[derive(Debug)]
pub struct LoadedReviewServer {}

impl LoadedReviewServer {
    /// Construct a new [`LoadedReviewServer`].
    pub fn new() -> Self {
        Self {}
    }

    /// Drive the server.
    pub fn run(
        center: &Arc<Center>,
        socket_provider: &mut SocketProvider,
    ) -> Result<Vec<AbortOnDrop>, Terminated> {
        // TODO: Inline.
        ZoneServer::run(center, Source::Unsigned, socket_provider)
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
}

impl Default for LoadedReviewServer {
    fn default() -> Self {
        Self::new()
    }
}

//----------- SignedReviewServer -----------------------------------------------

/// The review server for signed instances of zones.
#[derive(Debug)]
pub struct SignedReviewServer {}

impl SignedReviewServer {
    /// Construct a new [`SignedReviewServer`].
    pub fn new() -> Self {
        Self {}
    }

    /// Drive the server.
    pub fn run(
        center: &Arc<Center>,
        socket_provider: &mut SocketProvider,
    ) -> Result<Vec<AbortOnDrop>, Terminated> {
        // TODO: Inline.
        ZoneServer::run(center, Source::Signed, socket_provider)
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
}

impl Default for SignedReviewServer {
    fn default() -> Self {
        Self::new()
    }
}

//----------- PublicationServer ------------------------------------------------

/// The server for published instances of zones.
#[derive(Debug)]
pub struct PublicationServer {}

impl PublicationServer {
    /// Construct a new [`PublicationServer`].
    pub fn new() -> Self {
        Self {}
    }

    /// Drive the server.
    pub fn run(
        center: &Arc<Center>,
        socket_provider: &mut SocketProvider,
    ) -> Result<Vec<AbortOnDrop>, Terminated> {
        ZoneServer::run(center, Source::Published, socket_provider)
    }

    /// Publish an instance.
    pub fn publish(center: &Arc<Center>, zone: &Arc<Zone>, zone_serial: Serial) {
        // TODO: Inline.
        ZoneServer::new(Source::Published).on_publish_signed_zone(center, zone, zone_serial)
    }
}

impl Default for PublicationServer {
    fn default() -> Self {
        Self::new()
    }
}
