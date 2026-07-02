//! Controlling the entire operation.

use std::sync::Arc;

use crate::center::Center;
use crate::daemon::SocketProvider;
use crate::loader::Loader;
use crate::metrics::MetricsCollection;
use crate::persistence::Restorer;
use crate::server::{LoadedReviewServer, PublicationServer, SignedReviewServer};
use crate::units::http_server::HTTP_UNIT_NAME;
use crate::units::http_server::HttpServer;
use crate::units::key_manager::KeyManager;
use crate::units::zone_signer::ZoneSigner;
use crate::util::AbortOnDrop;
use crate::zone::{HistoricalEvent, Zone};
use daemonbase::process::EnvSocketsError;
use domain::base::Serial;
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
    pub fn spawn(
        center: Arc<Center>,
        mut socket_provider: SocketProvider,
        metrics: MetricsCollection,
    ) -> Result<Self, Error> {
        // Initialize the components.
        {
            let mut state = center.state.lock().unwrap();
            Loader::init(&center, &mut state);
        }

        let mut handles = Vec::new();

        // Spawn the zone data restorer.
        debug!("Starting the zone data restorer");
        handles.push(Restorer::run(center.clone()));

        // Spawn the zone loader.
        debug!("Starting the zone loader");
        handles.push(Loader::run(center.clone()));

        // Spawn the loaded zone review server.
        debug!("Starting the loaded review server");
        handles.extend(LoadedReviewServer::run(&center, &mut socket_provider)?);

        // Spawn the key manager.
        debug!("Starting the key manager");
        handles.push(KeyManager::run(center.clone()));

        // Spawn the zone signer.
        debug!("Starting the zone signer");
        handles.push(ZoneSigner::run(center.clone()));

        // Spawn the signed zone review server.
        debug!("Starting the signed review server");
        handles.extend(SignedReviewServer::run(&center, &mut socket_provider)?);

        // Take out HTTP listen sockets before the publication server takes them all.
        debug!("Pre-fetching listen sockets for the remote-control server");
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
        for socket in &http_sockets {
            // Unwrap, because there should always be a valid IPv4/IPv6
            // address. Otherwise this socket couldn't have been created.
            let addr = socket.local_addr().unwrap();
            info!(
                "Obtained a TCP listener for the remote-control and metrics server on address {addr}"
            );
        }

        debug!("Starting the publication server");
        handles.extend(PublicationServer::run(&center, &mut socket_provider)?);

        // TODO: Register any `Manager` metrics here, before giving the metrics to `HttpServer`.

        // Spawn the remote-control server.
        debug!("Starting the HTTP remote-control server");
        let http_server = HttpServer::launch(center.clone(), http_sockets, metrics)?;

        Ok(Self {
            center,
            http_server,
            _handles: handles,
        })
    }
}

pub fn record_zone_event(
    center: &Arc<Center>,
    zone: &Arc<Zone>,
    event: HistoricalEvent,
    serial: Option<Serial>,
) {
    zone.write_handle(center).state.record_event(event, serial);
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
