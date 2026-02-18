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
use cascade_api::ZoneReloadError;
use cascade_zonedata::ZoneBuilder;
use domain::{new::base::Serial, tsig, zonetree::StoredName};
use tracing::{debug, error, info};

use crate::{
    center::{Center, Change, State},
    loader::zone::EnqueuedRefresh,
    util::AbortOnDrop,
    zone::{Zone, ZoneHandle},
};

mod refresh;
mod server;
pub mod zone;
mod zonefile;

pub use refresh::RefreshMonitor;

//----------- Loader -----------------------------------------------------------

/// The zone loader.
#[derive(Debug)]
pub struct Loader {
    /// A monitor for SOA-based zone refreshes.
    refresh_monitor: RefreshMonitor,
}

impl Loader {
    /// Construct a new [`Loader`].
    pub fn new() -> Self {
        Self {
            refresh_monitor: RefreshMonitor::new(),
        }
    }

    /// Initialize the loader, synchronously.
    pub fn init(center: &Arc<Center>, state: &mut State) {
        // Enqueue refreshes for all known zones.
        for zone in &state.zones {
            let mut state = zone.0.state.lock().unwrap();
            ZoneHandle {
                zone: &zone.0,
                state: &mut state,
                center,
            }
            .loader()
            .enqueue_refresh(false);
        }
    }

    /// Drive this [`Loader`].
    pub fn run(center: Arc<Center>) -> AbortOnDrop {
        AbortOnDrop::from(tokio::spawn(async move {
            center.loader.refresh_monitor.run(&center).await
        }))
    }

    pub fn on_change(&self, center: &Arc<Center>, change: Change) {
        let Change::ZoneRemoved(name) = change else {
            return;
        };
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
            let mut state = zone.zone.0.state.lock().unwrap();
            ZoneHandle {
                zone: &zone.zone.0,
                state: &mut state,
                center,
            }
            .loader()
            .prep_removal();
        }
    }

    pub fn on_refresh_zone(&self, center: &Arc<Center>, zone_name: StoredName) {
        let zone = crate::center::get_zone(center, &zone_name).expect("zone exists");
        let mut state = zone.state.lock().expect("lock is not poisoned");
        ZoneHandle {
            zone: &zone,
            state: &mut state,
            center,
        }
        .loader()
        .enqueue_refresh(false);
    }

    pub fn on_reload_zone(
        &self,
        center: &Arc<Center>,
        zone_name: StoredName,
    ) -> Result<(), ZoneReloadError> {
        let zone =
            crate::center::get_zone(center, &zone_name).ok_or(ZoneReloadError::ZoneDoesNotExist)?;
        let mut zone_state = zone.state.lock().expect("lock is not poisoned");
        if let Some(reason) = zone_state.halted(true) {
            return Err(ZoneReloadError::ZoneHalted(reason));
        }
        if let Source::None = zone_state.loader.source {
            return Err(ZoneReloadError::ZoneWithoutSource);
        }
        ZoneHandle {
            zone: &zone,
            state: &mut zone_state,
            center,
        }
        .loader()
        .enqueue_refresh(true);
        Ok(())
    }
}

impl Default for Loader {
    fn default() -> Self {
        Self::new()
    }
}

//----------- refresh() --------------------------------------------------------

/// Refresh a zone.
#[tracing::instrument(
    level = "debug",
    skip_all,
    fields(zone = %zone.name, source = ?source),
)]
async fn refresh(
    zone: Arc<Zone>,
    source: Source,
    refresh: EnqueuedRefresh,
    mut builder: ZoneBuilder,
    center: Arc<Center>,
    metrics: Arc<ActiveLoadMetrics>,
) {
    info!("Refreshing {:?}", zone.name);
    let force = refresh == EnqueuedRefresh::Reload;

    // Perform the source-specific reload into the zone contents.
    let result = match source {
        Source::None => Ok(false),
        Source::Zonefile { path } => {
            // Zonefile loading is a synchronous process, so it is executing on
            // its own blocking task. It cannot borrow 'builder', so 'builder'
            // is moved and returned by value.
            let zone = zone.clone();
            let metrics = metrics.clone();
            let result;
            (builder, result) = tokio::task::spawn_blocking(move || {
                let result = zonefile::load(&zone, &path, &mut builder, &metrics);
                (builder, result)
            })
            .await
            .unwrap();
            result.map(|()| true).map_err(Into::into)
        }
        Source::Server { addr, tsig_key } if force => {
            let tsig_key = tsig_key.as_deref().cloned();
            server::axfr(&zone, &addr, tsig_key, &mut builder, &metrics)
                .await
                .map(|()| true)
                .map_err(Into::into)
        }
        Source::Server { addr, tsig_key } => {
            let tsig_key = tsig_key.as_deref().cloned();
            server::refresh(&zone, &addr, tsig_key, &mut builder, &metrics).await
        }
    };

    let mut state = zone.state.lock().unwrap();
    let mut handle = ZoneHandle {
        zone: &zone,
        state: &mut state,
        center: &center,
    };

    // Finalize the load metrics.
    let start_time = metrics.start.0;
    handle.state.loader.active_load_metrics = None;
    handle.state.loader.last_load_metrics = Some(metrics.finish());

    // Update the SOA refresh timer state.
    //
    // NOTE: Zonefiles don't use the SOA refresh timers. They are only
    // (re)loaded by user request.
    if matches!(handle.state.loader.source, Source::Server { .. }) {
        // Load the SOA.
        let soa = if matches!(result, Ok(true)) {
            Some(builder.next_unsigned().unwrap().soa().clone())
        } else {
            builder.curr_unsigned().map(|r| r.soa().clone())
        };

        let refresh_timer = &mut handle.state.loader.refresh_timer;
        let refresh_monitor = &center.loader.refresh_monitor;
        if result.is_ok() {
            refresh_timer.schedule_refresh(&zone, start_time, soa.as_ref(), refresh_monitor);
        } else {
            refresh_timer.schedule_retry(&zone, start_time, soa.as_ref(), refresh_monitor);
        }
    }

    // Clean up the background task.
    let task = handle
        .state
        .loader
        .refreshes
        .ongoing
        .take()
        .expect("The loader task is set correctly");
    assert_eq!(
        task.handle.id(),
        tokio::task::id(),
        "A different loader task is registered"
    );

    // Process the result of the reload.
    match result {
        Ok(false) => {
            debug!(
                zone = %zone.name,
                "The zone is up-to-date"
            );

            // Cancel the load from the perspective of zone storage.
            handle.storage().give_up_load(builder);
        }

        Ok(true) => {
            let soa = builder.next_unsigned().unwrap().soa().clone();

            debug!(
                zone = %zone.name,
                serial = ?soa.rdata.serial,
                "Loaded a new instance of the zone"
            );

            // Inform the zone storage of completion; it will initiate unsigned
            // review automatically.
            let built = builder.finish_unsigned().unwrap_or_else(|_| {
                unreachable!("source-specific loading succeeded and must have filled 'builder'")
            });
            handle.storage().finish_load(built);
        }

        Err(err) => {
            error!(
                zone = %zone.name,
                "Could not load the zone: {err}"
            );

            // Cancel the load from the perspective of zone storage.
            handle.storage().give_up_load(builder);
        }
    }
}

//----------- Source -----------------------------------------------------------

/// The source of a zone.
#[derive(Clone, Debug, Default)]
pub enum Source {
    /// The lack of a source.
    ///
    /// The zone will not be loaded from any external source.  This is the
    /// default state for new zones.
    #[default]
    None,

    /// A zonefile on disk.
    ///
    /// The specified path should point to a regular file (possibly through
    /// symlinks, as per OS limitations) containing the contents of the zone in
    /// the conventional "DNS zonefile" format.
    ///
    /// In addition to the default zone refresh triggers, the zonefile will also
    /// be monitored for changes (through OS-specific mechanisms), and will be
    /// refreshed when a change is detected.
    Zonefile {
        /// The path to the zonefile.
        path: Box<Utf8Path>,
    },

    /// A DNS server.
    ///
    /// The specified server will be queried for the contents of the zone using
    /// incremental and authoritative zone transfers (IXFRs and AXFRs).
    Server {
        /// The address of the server.
        addr: SocketAddr,

        /// The TSIG key for communicating with the server, if any.
        tsig_key: Option<Arc<tsig::Key>>,
    },
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

    /// The source loaded from.
    pub source: Source,

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

    /// The source being loaded from.
    ///
    /// See [`LoadMetrics::source`].
    pub source: Source,

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
    pub fn begin(source: Source) -> Self {
        Self {
            start: (Instant::now(), SystemTime::now()),
            source,
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
            source: self.source.clone(),
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
