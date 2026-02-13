//! Controlling the entire operation.

use std::sync::Arc;

use crate::center::{Center, get_zone};
use crate::daemon::SocketProvider;
use crate::loader::Loader;
use crate::metrics::MetricsCollection;
use crate::units::http_server::HTTP_UNIT_NAME;
use crate::units::http_server::HttpServer;
use crate::units::key_manager::KeyManager;
use crate::units::zone_server::{self, ZoneServer};
use crate::units::zone_signer::ZoneSigner;
use crate::util::AbortOnDrop;
use crate::zone::HistoricalEvent;
use daemonbase::process::EnvSocketsError;
use domain::base::Serial;
use domain::zonetree::StoredName;
use tracing::{debug, error, info};

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

//----------- Terminated -------------------------------------------------------

/// An error signalling that a unit has been terminated.
///
/// In response to this error, a unit’s run function should return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terminated;
