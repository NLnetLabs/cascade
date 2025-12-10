//! Loading zones.//!
//! The zone loader is responsible for maintaining up-to-date copies of the DNS
//! zones known to Nameshed.  Every zone has a configured source (e.g. zonefile,
//! DNS server, etc.) that will be monitored for changes.

use std::{
    cmp::Ordering,
    collections::VecDeque,
    fmt,
    sync::{Arc, MutexGuard},
};

use domain::new::base::Serial;
use tokio::task::AbortHandle;
use tracing::{debug, trace, warn};

use crate::{
    center::{Center, Change},
    manager::{ApplicationCommand, Terminated},
    zone::{
        self, contents,
        loader::{LoaderMetrics, Source},
        LoaderState, Zone, ZoneContents, ZoneState,
    },
};

mod refresh;
mod server;
mod zonefile;

pub use refresh::RefreshMonitor;

//----------- AbortOnDrop ------------------------------------------------------

pub struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

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

        #[allow(clippy::mutable_key_type)]
        let initial_zones = {
            let state = this.center.state.lock().unwrap();
            state.zones.clone()
        };

        for zone in initial_zones {
            let zone_state = zone.0.state.lock().unwrap();
            let source = zone_state.source.clone();
            drop(zone_state);
            this.set_source(&zone.0, source);
        }

        this
    }

    /// Drive this [`Loader`].
    pub fn run(self: &Arc<Self>) -> AbortOnDrop {
        let this = self.clone();
        AbortOnDrop(
            tokio::spawn(async move { this.refresh_monitor.run(&this).await }).abort_handle(),
        )
    }

    pub async fn on_command(self: &Arc<Self>, cmd: ApplicationCommand) -> Result<(), Terminated> {
        debug!("Received cmd: {cmd:?}");
        match cmd {
            ApplicationCommand::Changed(change) => {
                match change {
                    // This event is also fired at zone add so we don't need
                    // a specific case for that.
                    Change::ZoneSourceChanged(name, zone_load_source) => {
                        let zone = {
                            let center = self.center.state.lock().unwrap();
                            let zone = center.zones.get(&name).unwrap();
                            zone.0.clone()
                        };
                        self.set_source(&zone, zone_load_source);
                        Ok(())
                    }
                    Change::ZoneRemoved(name) => {
                        // We have to get the reference to the zone from our refresh monitor
                        // because it doesn't exist in center.zones anymore!
                        if let Some(zone) = self
                            .refresh_monitor
                            .scheduled
                            .lock()
                            .unwrap()
                            .iter()
                            .find(|z| z.zone.0.name == name)
                        {
                            self.set_source(&zone.zone.0, zone::ZoneLoadSource::None);
                        }
                        Ok(())
                    }
                    _ => Ok(()), // ignore other changes
                }
            }
            ApplicationCommand::RefreshZone { zone_name } => {
                let zone = {
                    let center = self.center.state.lock().unwrap();
                    let zone = center.zones.get(&zone_name).unwrap();
                    zone.0.clone()
                };
                let mut state = zone.state.lock().unwrap();
                LoaderState::enqueue_refresh(&mut state, &zone, false, self);
                Ok(())
            }
            ApplicationCommand::ReloadZone { zone_name } => {
                let zone = {
                    let center = self.center.state.lock().unwrap();
                    let zone = center.zones.get(&zone_name).unwrap();
                    zone.0.clone()
                };
                let mut state = zone.state.lock().unwrap();
                LoaderState::enqueue_refresh(&mut state, &zone, true, self);
                Ok(())
            }
            _ => panic!("Got an unexpected command!"),
        }
    }

    fn set_source(self: &Arc<Self>, zone: &Arc<Zone>, source: zone::ZoneLoadSource) {
        let source = match source {
            zone::ZoneLoadSource::None => Source::None,
            zone::ZoneLoadSource::Zonefile { path } => Source::Zonefile { path },
            zone::ZoneLoadSource::Server { addr, tsig_key } => {
                let addr = zone::loader::DnsServerAddr {
                    ip: addr.ip(),
                    tcp_port: addr.port(),
                    udp_port: None,
                };
                Source::Server {
                    addr,
                    tsig_key: tsig_key.map(Arc::unwrap_or_clone),
                }
            }
        };
        let mut state = zone.state.lock().unwrap();
        LoaderState::set_source(&mut state, zone, source, self);
    }
}

//----------- refresh() --------------------------------------------------------

/// Refresh a zone from DNS server.
///
/// The DNS server will be queried for the latest version of the zone; if a
/// local copy of this version is not already available, it will be loaded.
/// Where possible, an incremental zone transfer will be used to communicate
/// more efficiently.
pub async fn refresh<'z>(
    metrics: &LoaderMetrics,
    zone: &'z Arc<Zone>,
    source: &zone::loader::Source,
    latest: Option<Arc<contents::Uncompressed>>,
) -> (
    Result<Option<Serial>, RefreshError>,
    Option<MutexGuard<'z, ZoneState>>,
) {
    // Perform the source-specific refresh operation.
    let refresh = match source {
        // Refreshing a zone without a source is a no-op.
        zone::loader::Source::None => {
            warn!("Cannot refresh {:?} because no source is set", zone.name);

            return (Ok(None), None);
        }

        zone::loader::Source::Zonefile { .. } => {
            warn!("Cannot refresh {:?} because the source is a zonefile, use the zone reload command instead", zone.name);

            return (Ok(None), None);
        }

        zone::loader::Source::Server { addr, tsig_key } => {
            trace!("Refreshing {:?} from server {addr:?}", zone.name);

            server::refresh(metrics, zone, addr, tsig_key.clone(), latest).await
        }
    };

    // Process the result.
    let Refresh {
        uncompressed,
        mut compressed,
    } = match refresh {
        // The local copy is up-to-date.
        Ok(None) => return (Ok(None), None),

        // The local copy is outdated.
        Ok(Some(refresh)) => refresh,

        // An error occurred.
        Err(error) => return (Err(error), None),
    };

    // Integrate the results with the zone state.
    let remote_serial = uncompressed.soa.rdata.serial;
    loop {
        // TODO: A limitation in Rust's coroutine witness tracking means that
        // the more idiomatic representation of the following block forces the
        // future to '!Send'.  This is used as a workaround.

        /// An action to do after examining the zone state.
        enum Action {
            /// Compress a local copy relative to the remote copy.
            Compress(Arc<contents::Uncompressed>),
        }

        let action = 'lock: {
            // Lock the zone state.
            let mut lock = zone.state.lock().unwrap();

            // If no previous version of the zone exists (or if the zone
            // contents have been cleared since the start of the refresh),
            // insert the remote copy directly.
            let Some(contents) = &mut lock.contents else {
                lock.contents = Some(ZoneContents {
                    latest: uncompressed,
                    previous: VecDeque::new(),
                });

                return (Ok(Some(remote_serial)), Some(lock));
            };

            // Compare the _current_ latest version of the zone against the
            // remote.
            let local_serial = contents.latest.soa.rdata.serial;
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

            // If 'compressed' is up-to-date, use it.
            if let Some((compressed, _)) = compressed
                .take()
                .filter(|(_, l)| l.soa.rdata.serial == local_serial)
            {
                contents.latest = uncompressed;
                contents.previous.push_back(compressed);
                return (Ok(Some(remote_serial)), Some(lock));
            }

            // 'compressed' needs to be updated.
            let local = contents.latest.clone();
            break 'lock Action::Compress(local);
        };

        match action {
            Action::Compress(local) => {
                let remote = uncompressed.clone();
                compressed = tokio::task::spawn_blocking(move || {
                    Some((Arc::new(local.compress(&remote)), local))
                })
                .await
                .unwrap();
            }
        }
    }
}

/// The internal result of a zone refresh.
struct Refresh {
    /// The uncompressed remote copy.
    ///
    /// If the remote provided an uncompressed copy, this holds it verbatim.
    /// If the remote provided a compressed copy, it is uncompressed relative
    /// to the latest local copy and stored here.
    uncompressed: Arc<contents::Uncompressed>,

    /// A compressed version of the local copy.
    ///
    /// This is a compressed version of the local copy -- the latest version
    /// known when the refresh began.  This will forward the local copy to the
    /// remote copy.  It holds the corresponding uncompressed local copy.
    compressed: Option<(Arc<contents::Compressed>, Arc<contents::Uncompressed>)>,
}

//----------- reload() ---------------------------------------------------------

/// Reload a zone.
///
/// The complete contents of the zone will be loaded from the source, without
/// relying on the local copy at all.  If this results in a new version of the
/// zone, it is registered in the zone storage; otherwise, the loaded data is
/// compared to the local copy of the same zone version.  If an inconsistency is
/// detected, an error is returned, and the zone storage is unchanged.
pub async fn reload<'z>(
    metrics: &LoaderMetrics,
    zone: &'z Arc<Zone>,
    source: &zone::loader::Source,
) -> (
    Result<Option<Serial>, ReloadError>,
    Option<MutexGuard<'z, ZoneState>>,
) {
    // Perform the source-specific reload operation.
    let reload = match source {
        // Reloading a zone without a source is a no-op.
        zone::loader::Source::None => {
            warn!("Cannot reload {:?} because no source is set", zone.name);

            return (Ok(None), None);
        }

        zone::loader::Source::Zonefile { path } => {
            trace!("Reloading {:?} from zonefile {path:?}", zone.name);

            let zone = zone.clone();
            let path = path.clone();
            let metrics = metrics.clone();
            tokio::task::spawn_blocking(move || zonefile::load(&metrics, &zone, &path))
                .await
                .unwrap()
                .map_err(ReloadError::Zonefile)
        }

        zone::loader::Source::Server { addr, tsig_key } => {
            trace!("Reloading {:?} from server {addr:?}", zone.name);

            server::axfr(metrics, zone, addr, tsig_key.clone())
                .await
                .map_err(ReloadError::Axfr)
        }
    };

    // Process the result.
    let remote = match reload {
        Ok(remote) => Arc::new(remote),
        Err(error) => return (Err(error), None),
    };

    // Integrate the results with the zone state.
    let remote_serial = remote.soa.rdata.serial;
    let mut compressed: Option<(Arc<contents::Compressed>, Arc<contents::Uncompressed>)> = None;
    let mut local_match = None;
    loop {
        // TODO: A limitation in Rust's coroutine witness tracking means that
        // the more idiomatic representation of the following block forces the
        // future to '!Send'.  This is used as a workaround.

        /// An action to do after examining the zone state.
        enum Action {
            /// Compare a local copy to the remote copy.
            Compare(Arc<contents::Uncompressed>),

            /// Compress a local copy relative to the remote copy.
            Compress(Arc<contents::Uncompressed>),
        }

        let action = 'lock: {
            // Lock the zone state.
            let mut lock = zone.state.lock().unwrap();

            // If no previous version of the zone exists (or if the zone
            // contents have been cleared since the start of the refresh),
            // insert the remote copy directly.
            let Some(contents) = &mut lock.contents else {
                lock.contents = Some(ZoneContents {
                    latest: remote,
                    previous: VecDeque::new(),
                });

                return (Ok(Some(remote_serial)), Some(lock));
            };

            // Compare the _current_ latest version of the zone against the remote.
            let local_serial = contents.latest.soa.rdata.serial;
            match local_serial.partial_cmp(&remote_serial) {
                Some(Ordering::Less) => {}

                Some(Ordering::Equal) => {
                    // The local copy was updated externally, and is now up-to-date
                    // with respect to the remote copy.  Compare the contents of the
                    // two.

                    // If the two have already been compared, end now.
                    if local_match
                        .take()
                        .is_some_and(|l| Arc::ptr_eq(&l, &contents.latest))
                    {
                        return (Ok(None), Some(lock));
                    }

                    // Compare 'latest' and 'remote'.
                    let latest = contents.latest.clone();
                    break 'lock Action::Compare(latest);
                }

                Some(Ordering::Greater) | None => {
                    // The local copy was updated externally, and is now more
                    // recent than the remote copy.  While it is possible the remote
                    // copy has also been updated, we will assume it's unchanged,
                    // and report that the remote has become outdated.
                    return (
                        Err(ReloadError::OutdatedRemote {
                            local_serial,
                            remote_serial,
                        }),
                        Some(lock),
                    );
                }
            }

            // If 'compressed' is up-to-date w.r.t. the current local copy, use it.
            if let Some((compressed, _)) = compressed
                .take()
                .filter(|(_, l)| l.soa.rdata.serial == local_serial)
            {
                contents.latest = remote;
                contents.previous.push_back(compressed);
                return (Ok(Some(remote_serial)), Some(lock));
            }

            let local = contents.latest.clone();
            break 'lock Action::Compress(local);
        };

        match action {
            Action::Compare(latest) => {
                let latest_copy = latest.clone();
                let remote_copy = remote.clone();
                let matches =
                    tokio::task::spawn_blocking(move || remote_copy.eq_unsigned(&latest_copy))
                        .await
                        .unwrap();

                if matches {
                    local_match = Some(latest);
                    continue;
                } else {
                    return (Err(ReloadError::Inconsistent), None);
                }
            }

            Action::Compress(local) => {
                // 'compressed' needs to be updated relative to the current local copy.
                let remote = remote.clone();
                compressed = tokio::task::spawn_blocking(move || {
                    Some((Arc::new(local.compress(&remote)), local))
                })
                .await
                .unwrap();
                continue;
            }
        }
    }
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
}

impl std::error::Error for RefreshError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OutdatedRemote { .. } => None,
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
                write!(f, "the source of the zone is reporting an outdated SOA ({remote_serial}, while the latest local copy is {local_serial})")
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

//----------- ReloadError ------------------------------------------------------

/// An error when reloading a zone.
#[derive(Debug)]
pub enum ReloadError {
    /// The source of the zone appears to be outdated.
    OutdatedRemote {
        /// The SOA serial of the local copy.
        local_serial: Serial,

        /// The SOA serial of the remote copy.
        remote_serial: Serial,
    },

    /// The local and remote copies have different contents.
    Inconsistent,

    /// An AXFR from the server failed.
    Axfr(server::AxfrError),

    /// The zonefile could not be loaded.
    Zonefile(zonefile::Error),
}

impl std::error::Error for ReloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReloadError::OutdatedRemote { .. } => None,
            ReloadError::Inconsistent => None,
            ReloadError::Axfr(error) => Some(error),
            ReloadError::Zonefile(error) => Some(error),
        }
    }
}

impl fmt::Display for ReloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReloadError::OutdatedRemote {
                local_serial,
                remote_serial,
            } => {
                write!(f, "the source of the zone is reporting an outdated SOA ({remote_serial}, while the latest local copy is {local_serial})")
            }
            ReloadError::Inconsistent => write!(f, "the local and remote copies are inconsistent"),
            ReloadError::Axfr(error) => write!(f, "the AXFR failed: {error}"),
            ReloadError::Zonefile(error) => write!(f, "the zonefile could not be loaded: {error}"),
        }
    }
}

//--- Conversion

impl From<server::AxfrError> for ReloadError {
    fn from(value: server::AxfrError) -> Self {
        Self::Axfr(value)
    }
}

impl From<zonefile::Error> for ReloadError {
    fn from(v: zonefile::Error) -> Self {
        Self::Zonefile(v)
    }
}
