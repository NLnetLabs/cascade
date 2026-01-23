//! Loading zones.
//!
//! The zone loader is responsible for maintaining up-to-date copies of the DNS
//! zones known to Cascade.  Every zone has a configured source (e.g. zonefile,
//! DNS server, etc.) that will be monitored for changes.

use std::{
    fmt,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{self, AtomicUsize},
    },
    time::{Duration, Instant, SystemTime},
};

use camino::Utf8Path;
use domain::{new::base::Serial, tsig};
use tracing::{debug, trace};

use crate::{
    center::{Center, Change},
    loader::zone::LoaderState,
    manager::{ApplicationCommand, Terminated},
    util::AbortOnDrop,
    zone::{Zone, ZoneContents, contents},
};

mod refresh;
mod server;
pub mod zone;
mod zonefile;

pub use refresh::RefreshMonitor;
pub use zone::Source;

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
pub async fn refresh_server(
    zone: &Arc<Zone>,
    addr: &std::net::SocketAddr,
    tsig_key: &Option<Arc<domain::tsig::Key>>,
    contents: &mut Option<ZoneContents>,
    metrics: &ActiveLoadMetrics,
) -> Result<Option<Serial>, RefreshError> {
    trace!("Refreshing {:?} from server {addr:?}", zone.name);

    let tsig_key = tsig_key.as_ref().map(|k| (**k).clone());

    let old_serial = contents.as_ref().map(|c| c.soa.rdata.serial);
    server::refresh(zone, addr, tsig_key, contents, metrics).await?;

    let new_contents = contents.as_ref().unwrap();
    let remote_serial = new_contents.soa.rdata.serial;

    if old_serial == Some(remote_serial) {
        // The local copy is up-to-date.
        return Ok(None);
    }

    Ok(Some(remote_serial))
}

//----------- reload() ---------------------------------------------------------

/// Reload a zone.
///
/// The complete contents of the zone will be loaded from the source, without
/// relying on the local copy at all.  If this results in a new version of the
/// zone, it is registered in the zone storage; otherwise, the loaded data is
/// compared to the local copy of the same zone version.  If an inconsistency is
/// detected, an error is returned, and the zone storage is unchanged.
pub async fn reload_server(
    zone: &Arc<Zone>,
    addr: &SocketAddr,
    tsig_key: &Option<Arc<tsig::Key>>,
    contents: &mut Option<ZoneContents>,
    metrics: &ActiveLoadMetrics,
) -> Result<Option<Serial>, RefreshError> {
    let tsig_key = tsig_key.as_ref().map(|k| (**k).clone());
    server::axfr(zone, addr, tsig_key, contents, metrics).await?;

    let new_contents = contents.as_ref().unwrap();
    let serial = new_contents.soa.rdata.serial;
    Ok(Some(serial))
}

pub async fn load_zonefile(
    zone: &Arc<Zone>,
    path: &Utf8Path,
    contents: &mut Option<ZoneContents>,
    metrics: &ActiveLoadMetrics,
) -> Result<Option<Serial>, RefreshError> {
    zonefile::load(zone, path, contents, metrics)?;

    let new_contents = contents.as_ref().unwrap();
    let serial = new_contents.soa.rdata.serial;
    Ok(Some(serial))
}

//============ Metrics =========================================================

//----------- LoadMetrics ------------------------------------------------------

/// Metrics for a (completed) zone load.
///
/// Every refresh (i.e. load) of a zone is paired with [`LoadMetrics`]. It's
/// important to note that not _all_ refreshes lead to new zone instances. A
/// refresh can also report up-to-date or fail.
///
/// This is built from [`ActiveLoadMetrics::finish()`].
#[derive(Clone, Debug)]
pub struct LoadMetrics {
    /// When the load began.
    ///
    /// All actions/requests relating to the load will begin after this time.
    pub start: SystemTime,

    /// When the load ended.
    ///
    /// All actions/requests relating to the load will finish before this time.
    pub end: SystemTime,

    /// How long the load took.
    ///
    /// This should be preferred over `end - start`, as they are affected by
    /// discontinuous changes to the system clock. This duration is measured
    /// using a monotonic clock.
    pub duration: Duration,

    /// The (approximate) number of bytes loaded.
    ///
    /// This may include network overhead (e.g. TCP/UDP/IP headers, DNS message
    /// headers, extraneous DNS records). If multiple network requests are
    /// performed (e.g. IXFR before falling back to AXFR), it may include counts
    /// from previous requests. It should be treated as a measure of effort, not
    /// information about the new instance of the zone being built.
    pub num_loaded_bytes: usize,

    /// The (approximate) number of DNS records loaded.
    ///
    /// When loading from a DNS server, this count may include deleted records,
    /// delimiting SOA records, and additional-section records (e.g. DNS
    /// COOKIEs). If multiple network requests are performed (e.g. IXFR before
    /// falling back to AXFR), it may include counts from earlier requests. It
    /// should be treated as a measure of effort, not information about the new
    /// instance of the zone being built.
    pub num_loaded_records: usize,
}

//----------- ActiveLoadMetrics ------------------------------------------------

/// Metrics for an active zone load.
///
/// An instance of [`ActiveLoadMetrics`] is available when a load (refresh or
/// reload of a particular zone) is ongoing. It can be used to report statistics
/// about the ongoing load (e.g. on queries for Cascade's status).
///
/// When the load completes, [`Self::finish()`] will convert it into
/// [`LoadMetrics`]. [`ActiveLoadMetrics`] has a subset of its fields.
#[derive(Debug)]
pub struct ActiveLoadMetrics {
    /// When the load began.
    ///
    /// See [`LoadMetrics::start`].
    pub start: (Instant, SystemTime),

    /// The (approximate) number of bytes loaded thus far.
    ///
    /// See [`LoadMetrics::num_loaded_bytes`].
    pub num_loaded_bytes: AtomicUsize,

    /// The (approximate) number of DNS records loaded thus far.
    ///
    /// See [`LoadMetrics::num_loaded_records`].
    pub num_loaded_records: AtomicUsize,
}

impl ActiveLoadMetrics {
    /// Begin (the metrics for) a new load.
    pub fn begin() -> Self {
        Self {
            start: (Instant::now(), SystemTime::now()),
            num_loaded_bytes: AtomicUsize::new(0),
            num_loaded_records: AtomicUsize::new(0),
        }
    }

    /// Finish this load.
    ///
    /// This does not take `self` by value; observers of the load may still be
    /// using it, so it is hard to take back ownership of it synchronously.
    pub fn finish(&self) -> LoadMetrics {
        // It is expected that the caller was the loader, and so was responsible
        // for setting the atomic variables being read here; there should not be
        // any need for synchronization.

        let end = (Instant::now(), SystemTime::now());
        LoadMetrics {
            start: self.start.1,
            end: end.1,
            duration: end.0.duration_since(self.start.0),
            num_loaded_bytes: self.num_loaded_bytes.load(atomic::Ordering::Relaxed),
            num_loaded_records: self.num_loaded_records.load(atomic::Ordering::Relaxed),
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

impl From<zonefile::Error> for RefreshError {
    fn from(v: zonefile::Error) -> Self {
        Self::Zonefile(v)
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
