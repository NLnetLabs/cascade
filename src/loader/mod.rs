//! Loading zones.
//!
//! The zone loader is responsible for maintaining up-to-date copies of the DNS
//! zones known to Cascade.  Every zone has a configured source (e.g. zonefile,
//! DNS server, etc.) that will be monitored for changes.

use std::{
    cmp::Ordering,
    fmt,
    net::SocketAddr,
    sync::{Arc, MutexGuard},
};

use camino::Utf8Path;
use domain::{new::base::Serial, tsig};
use tracing::{debug, trace};

use crate::{
    center::{Center, Change},
    manager::{ApplicationCommand, Terminated},
    util::AbortOnDrop,
    zone::{
        LoaderState, Zone, ZoneContents, ZoneState, contents,
        loader::{LoaderMetrics, Source},
    },
};

mod refresh;
mod server;
mod zonefile;

pub use refresh::RefreshMonitor;

//----------- Loader -----------------------------------------------------------

/// The loader.
pub struct Loader {
    /// The refresh monitor.
    pub refresh_monitor: RefreshMonitor,

    /// A sender for updates from the loader.
    pub center: Arc<Center>,
}

impl Loader {
    /// Construct a new [`Loader`].
    pub fn launch(center: Arc<Center>) -> Arc<Self> {
        let this = Arc::new(Self {
            refresh_monitor: RefreshMonitor::new(),
            center,
        });

        {
            let state = this.center.state.lock().unwrap();

            for zone in &state.zones {
                this.enqueue_refresh(&zone.0);
            }
        }

        this
    }

    /// Drive this [`Loader`].
    pub fn run(self: &Arc<Self>) -> AbortOnDrop {
        let this = self.clone();
        AbortOnDrop::from(tokio::spawn(async move {
            this.refresh_monitor.run(&this).await
        }))
    }

    pub async fn on_command(self: &Arc<Self>, cmd: ApplicationCommand) -> Result<(), Terminated> {
        debug!("Received cmd: {cmd:?}");
        match cmd {
            ApplicationCommand::Changed(change) => {
                match change {
                    // This event is also fired at zone add so we don't need
                    // a specific case for that.
                    Change::ZoneSourceChanged(name) => {
                        let zone =
                            crate::center::get_zone(&self.center, &name).expect("zone exists");
                        self.enqueue_refresh(&zone);
                        Ok(())
                    }
                    Change::ZoneRemoved(name) => {
                        // We have to get the reference to the zone from our refresh monitor
                        // because it doesn't exist in center.zones anymore!
                        // Ideally, the ZoneRemoved command would pass the zone as Arc<Zone>
                        // instead of just giving the same. That would make this more performant.
                        if let Some(zone) = self
                            .refresh_monitor
                            .scheduled
                            .lock()
                            .unwrap()
                            .iter()
                            .find(|z| z.zone.0.name == name)
                        {
                            self.disable(&zone.zone.0);
                        }
                        Ok(())
                    }
                    _ => Ok(()), // ignore other changes
                }
            }
            ApplicationCommand::RefreshZone { zone_name } => {
                let zone = crate::center::get_zone(&self.center, &zone_name).expect("zone exists");
                let mut state = zone.state.lock().expect("lock is not poisoned");
                LoaderState::enqueue_refresh(&mut state, &zone, false, self);
                Ok(())
            }
            ApplicationCommand::ReloadZone { zone_name } => {
                let zone = crate::center::get_zone(&self.center, &zone_name).expect("zone exists");
                let mut state = zone.state.lock().expect("lock is not poisoned");
                LoaderState::enqueue_refresh(&mut state, &zone, true, self);
                Ok(())
            }
            _ => panic!("Got an unexpected command!"),
        }
    }

    fn enqueue_refresh(self: &Arc<Self>, zone: &Arc<Zone>) {
        let mut state = zone.state.lock().unwrap();
        LoaderState::enqueue_refresh(&mut state, zone, false, self);
    }

    fn disable(self: &Arc<Self>, zone: &Arc<Zone>) {
        let mut state = zone.state.lock().unwrap();
        state.loader.source = Source::None;
        LoaderState::enqueue_refresh(&mut state, zone, true, self);
    }
}

//----------- refresh() --------------------------------------------------------

/// Refresh a zone from DNS server.
///
/// The DNS server will be queried for the latest version of the zone; if a
/// local copy of this version is not already available, it will be loaded.
/// Where possible, an incremental zone transfer will be used to communicate
/// more efficiently.
pub async fn refresh_server<'z>(
    metrics: &LoaderMetrics,
    zone: &'z Arc<Zone>,
    addr: &std::net::SocketAddr,
    tsig_key: &Option<Arc<domain::tsig::Key>>,
    latest: Option<Arc<ZoneContents>>,
) -> (
    Result<Option<Serial>, RefreshError>,
    Option<MutexGuard<'z, ZoneState>>,
) {
    trace!("Refreshing {:?} from server {addr:?}", zone.name);

    let tsig_key = tsig_key.as_ref().map(|k| (**k).clone());

    let old_serial = latest.as_ref().map(|l| l.soa.rdata.serial);
    let mut contents = latest;
    let result = server::refresh(metrics, zone, addr, tsig_key, &mut contents).await;

    match result {
        Ok(()) => {}
        Err(error) => return (Err(error), None),
    }

    let new_contents = contents.unwrap();
    let remote_serial = new_contents.soa.rdata.serial;

    if old_serial == Some(remote_serial) {
        // The local copy is up-to-date.
        return (Ok(None), None);
    }

    // Integrate the results with the zone state.

    // Lock the zone state.
    let mut lock = zone.state.lock().unwrap();

    // If no previous version of the zone exists (or if the zone
    // contents have been cleared since the start of the refresh),
    // insert the remote copy directly.
    let Some(contents) = &mut lock.contents else {
        lock.contents = Some(new_contents);

        return (Ok(Some(remote_serial)), Some(lock));
    };

    // Compare the _current_ latest version of the zone against the
    // remote.
    let local_serial = contents.soa.rdata.serial;
    match local_serial.partial_cmp(&remote_serial) {
        Some(Ordering::Less) => {}

        Some(Ordering::Equal) => {
            // The local copy was updated externally, and is now
            // up-to-date with respect to the remote copy.  Stop.
            return (Ok(None), Some(lock));
        }

        Some(Ordering::Greater) | None => {
            // The local copy was updated externally, and is now more
            // recent than the remote copy.  While it is possible the remote
            // copy has also been updated, we will assume it's unchanged,
            // and report that the remote has become outdated.
            return (
                Err(RefreshError::OutdatedRemote {
                    local_serial,
                    remote_serial,
                }),
                Some(lock),
            );
        }
    }

    *contents = new_contents;
    (Ok(Some(remote_serial)), Some(lock))
}

//----------- reload() ---------------------------------------------------------

/// Reload a zone.
///
/// The complete contents of the zone will be loaded from the source, without
/// relying on the local copy at all.  If this results in a new version of the
/// zone, it is registered in the zone storage; otherwise, the loaded data is
/// compared to the local copy of the same zone version.  If an inconsistency is
/// detected, an error is returned, and the zone storage is unchanged.
pub async fn reload_server<'z>(
    metrics: &LoaderMetrics,
    zone: &'z Arc<Zone>,
    addr: &SocketAddr,
    tsig_key: &Option<Arc<tsig::Key>>,
) -> (
    Result<Option<Serial>, RefreshError>,
    Option<MutexGuard<'z, ZoneState>>,
) {
    let mut contents = None;
    let tsig_key = tsig_key.as_ref().map(|k| (**k).clone());
    let result = server::axfr(metrics, zone, addr, tsig_key, &mut contents)
        .await
        .map_err(RefreshError::Axfr);

    match result {
        Ok(()) => (),
        Err(error) => return (Err(error), None),
    };

    let contents = contents.unwrap();
    let serial = contents.soa.rdata.serial;

    // Lock the zone state.
    let mut lock = zone.state.lock().unwrap();
    lock.contents = Some(contents);

    (Ok(Some(serial)), Some(lock))
}

pub async fn load_zonefile<'z>(
    metrics: &LoaderMetrics,
    zone: &'z Arc<Zone>,
    path: &Utf8Path,
) -> (
    Result<Option<Serial>, RefreshError>,
    Option<MutexGuard<'z, ZoneState>>,
) {
    let mut contents = None;
    let result = zonefile::load(metrics, zone, path, &mut contents).map_err(RefreshError::Zonefile);

    match result {
        Ok(()) => {}
        Err(error) => return (Err(error), None),
    };

    let contents = contents.unwrap();
    let serial = contents.soa.rdata.serial;

    // Lock the zone state.
    let mut lock = zone.state.lock().unwrap();
    lock.contents = Some(contents);

    (Ok(Some(serial)), Some(lock))
}

//============ Errors ==========================================================

//----------- RefreshError -----------------------------------------------------

/// An error when refreshing a zone.
#[derive(Debug)]
pub enum RefreshError {
    /// The source of the zone appears to be outdated.
    OutdatedRemote {
        /// The SOA serial of the local copy.
        local_serial: Serial,

        /// The SOA serial of the remote copy.
        remote_serial: Serial,
    },

    /// An IXFR from the server failed.
    Ixfr(server::IxfrError),

    /// An AXFR from the server failed.
    Axfr(server::AxfrError),

    /// The zonefile could not be loaded.
    Zonefile(zonefile::Error),

    /// An IXFR's diff was internally inconsistent.
    MergeIxfr(contents::MergeError),

    /// An IXFR's diff was not consistent with the local copy.
    ForwardIxfr(contents::ForwardError),

    /// While we were processing a refresh another refresh or reload happened, changing the serial
    LocalSerialChanged,
}

impl std::error::Error for RefreshError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OutdatedRemote { .. } => None,
            Self::LocalSerialChanged => None,
            Self::Ixfr(error) => Some(error),
            Self::Axfr(error) => Some(error),
            Self::Zonefile(error) => Some(error),
            Self::MergeIxfr(error) => Some(error),
            Self::ForwardIxfr(error) => Some(error),
        }
    }
}

impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefreshError::OutdatedRemote {
                local_serial,
                remote_serial,
            } => {
                write!(
                    f,
                    "the source of the zone is reporting an outdated SOA ({remote_serial}, while the latest local copy is {local_serial})"
                )
            }
            RefreshError::LocalSerialChanged => {
                write!(
                    f,
                    "Local serial changed while processing a refreshed zone. This will be fixed by a retry."
                )
            }
            RefreshError::Ixfr(error) => {
                write!(f, "the IXFR failed: {error}")
            }
            RefreshError::Axfr(error) => {
                write!(f, "the AXFR failed: {error}")
            }
            RefreshError::Zonefile(error) => {
                write!(f, "the zonefile could not be loaded: {error}")
            }
            RefreshError::MergeIxfr(error) => {
                write!(f, "the IXFR was internally inconsistent: {error}")
            }
            RefreshError::ForwardIxfr(error) => {
                write!(
                    f,
                    "the IXFR was inconsistent with the local zone contents: {error}"
                )
            }
        }
    }
}

//--- Conversion

impl From<server::IxfrError> for RefreshError {
    fn from(v: server::IxfrError) -> Self {
        Self::Ixfr(v)
    }
}

impl From<server::AxfrError> for RefreshError {
    fn from(v: server::AxfrError) -> Self {
        Self::Axfr(v)
    }
}

impl From<contents::MergeError> for RefreshError {
    fn from(v: contents::MergeError) -> Self {
        Self::MergeIxfr(v)
    }
}

impl From<contents::ForwardError> for RefreshError {
    fn from(v: contents::ForwardError) -> Self {
        Self::ForwardIxfr(v)
    }
}
