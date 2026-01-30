//! Zone-specific loader state.
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tracing::{debug, info};

use crate::{
    center::Center,
    util::AbortOnDrop,
    zone::{HistoricalEvent, Zone, ZoneState, contents::SoaRecord},
};

use super::{ActiveLoadMetrics, LoadMetrics, RefreshMonitor, Source};

//----------- LoaderZoneHandle -------------------------------------------------

/// A handle for loader-related operations on a [`Zone`].
pub struct LoaderZoneHandle<'a> {
    /// The zone being operated on.
    pub zone: &'a Arc<Zone>,

    /// The locked zone state.
    pub state: &'a mut ZoneState,

    /// Cascade's global state.
    pub center: &'a Arc<Center>,
}

impl LoaderZoneHandle<'_> {
    /// Set the source of this zone.
    ///
    /// A (soft) refresh will be initiated via [`Self::enqueue_refresh()`].
    pub fn set_source(&mut self, source: Source) {
        info!(
            "Setting source of zone '{}' from '{:?}' to '{source:?}'",
            self.zone.name, self.state.loader.source
        );

        self.state.loader.source = source;

        self.state
            .record_event(HistoricalEvent::SourceChanged, None);

        self.zone.mark_dirty(self.state, self.center);

        self.enqueue_refresh(false);
    }

    /// Enqueue a refresh of this zone.
    ///
    /// If the zone is not being refreshed already, a new refresh will be
    /// initiated.  Otherwise, a refresh will be enqueued; if one is enqueued
    /// already, the two will be merged.  If `reload` is true, the refresh will
    /// verify the local copy of the zone by loading the entire zone from
    /// scratch.
    ///
    /// # Standards
    ///
    /// Complies with [RFC 1996, section 4.4], when this is used to enqueue a
    /// refresh in response to a `QTYPE=SOA` NOTIFY message.
    ///
    /// > 4.4. A slave which receives a valid NOTIFY should defer action on any
    /// > subsequent NOTIFY with the same \<QNAME,QCLASS,QTYPE\> until it has
    /// > completed the transaction begun by the first NOTIFY.  This duplicate
    /// > rejection is necessary to avoid having multiple notifications lead to
    /// > pummeling the master server.
    ///
    /// [RFC 1996, section 4.4]: https://datatracker.ietf.org/doc/html/rfc1996#section-4
    pub fn enqueue_refresh(&mut self, reload: bool) {
        debug!("Enqueueing a refresh for {:?}", self.zone.name);

        if let Source::None = self.state.loader.source {
            self.state
                .loader
                .refresh_timer
                .disable(self.zone, &self.center.loader.refresh_monitor);
            return;
        }

        let refresh = match reload {
            false => EnqueuedRefresh::Refresh,
            true => EnqueuedRefresh::Reload,
        };

        // Determine whether a refresh is ongoing.
        if let Some(refreshes) = &mut self.state.loader.refreshes {
            // There is an ongoing refresh.  Enqueue a new one, which will
            // start when the ongoing one finishes.  If a refresh is already
            // enqueued, the two will be merged.
            refreshes.enqueue(refresh);
        } else {
            // Start this refresh immediately.
            self.start(refresh);
        }
    }

    /// Start an enqueued refresh.
    pub(super) fn start(&mut self, refresh: EnqueuedRefresh) {
        let source = self.state.loader.source.clone();
        let metrics = Arc::new(ActiveLoadMetrics::begin(source.clone()));
        let contents = self.state.contents.clone().try_lock_owned().unwrap();

        let handle = tokio::task::spawn(super::refresh(
            self.zone.clone(),
            source,
            refresh == EnqueuedRefresh::Reload,
            contents,
            self.center.clone(),
            metrics.clone(),
        ));

        let handle = AbortOnDrop::from(handle);
        let ongoing = OngoingRefresh { handle };
        self.state.loader.active_load_metrics = Some(metrics);
        self.state.loader.refreshes = Some(Refreshes::new(ongoing));
    }

    /// Prepare for the removal of this zone.
    pub fn prep_removal(&mut self) {
        // Remove the zone from the refresh monitor.
        self.state
            .loader
            .refresh_timer
            .disable(self.zone, &self.center.loader.refresh_monitor);
    }
}

//----------- LoaderState ------------------------------------------------------

/// State for loading new versions of a zone.
#[derive(Debug, Default)]
pub struct LoaderState {
    /// The source of the zone.
    pub source: Source,

    /// The refresh timer state of the zone.
    pub refresh_timer: RefreshTimerState,

    /// Ongoing and enqueued refreshes of the zone.
    pub refreshes: Option<Refreshes>,

    /// Metrics for an active load, if any.
    //
    // TODO: Embed in a state machine.
    pub active_load_metrics: Option<Arc<ActiveLoadMetrics>>,

    /// Metrics for the last finished load, if any.
    ///
    /// This is [`None`] if we have never attempted to load this zone.
    //
    // TODO: Make part of zone history?
    pub last_load_metrics: Option<LoadMetrics>,
}

//----------- RefreshTimerState ------------------------------------------------

/// State for the refresh timer of a zone.
#[derive(Debug, Default)]
pub enum RefreshTimerState {
    /// The refresh timer is disabled.
    ///
    /// The zone will not be refreshed automatically.  This is the default state
    /// for new zones, and is used when a local copy of the zone is unavailable.
    #[default]
    Disabled,

    /// Following up a previous successful refresh.
    ///
    /// The zone was recently refreshed successfully.  A new refresh will be
    /// enqueued following the SOA REFRESH timer.
    Refresh {
        /// When the previous (successful) refresh started.
        previous: Instant,

        /// The scheduled time for the next refresh.
        ///
        /// This is equal to `previous + soa.refresh`.  If the SOA record
        /// changes (e.g. due to a new version of the zone being loaded), this
        /// is recomputed, and the refresh is rescheduled accordingly.
        scheduled: Instant,
    },

    /// Following up a previous failing refresh.
    ///
    /// A previous refresh of the zone failed.  A new refresh will be enqueued
    /// following the SOA RETRY timer.
    Retry {
        /// When the previous (failing) refresh started.
        previous: Instant,

        /// The scheduled time for the next refresh.
        ///
        /// This is equal to `previous + soa.retry`.  If the SOA record changes
        /// (e.g. due to a new version of the zone being loaded), this is
        /// recomputed, and the refresh is rescheduled accordingly.
        scheduled: Instant,
    },
}

impl RefreshTimerState {
    /// The currently scheduled refresh time, if any.
    pub const fn scheduled_time(&self) -> Option<Instant> {
        match *self {
            Self::Disabled => None,
            Self::Refresh { scheduled, .. } => Some(scheduled),
            Self::Retry { scheduled, .. } => Some(scheduled),
        }
    }

    /// Disable zone refreshing.
    ///
    /// This is called when the zone contents are wiped or the zone source is
    /// removed.
    pub fn disable(&mut self, zone: &Arc<Zone>, monitor: &RefreshMonitor) {
        monitor.update(zone, self.scheduled_time(), None);
        *self = Self::Disabled;
    }

    /// Schedule a refresh.
    ///
    /// This is called when a previous refresh completes successfully.
    pub fn schedule_refresh(
        &mut self,
        zone: &Arc<Zone>,
        previous: Instant,
        soa: Option<&SoaRecord>,
        monitor: &RefreshMonitor,
    ) {
        // If a SOA record is unavailable, don't schedule anything.
        let Some(soa) = soa else {
            monitor.update(zone, self.scheduled_time(), None);
            *self = Self::Disabled;
            return;
        };

        let refresh = Duration::from_secs(soa.rdata.refresh.get().into());
        let scheduled = previous + refresh;
        monitor.update(zone, self.scheduled_time(), Some(scheduled));
        *self = Self::Refresh {
            previous,
            scheduled,
        };
    }

    /// Schedule a retry.
    ///
    /// This is called when a previous refresh fails.
    pub fn schedule_retry(
        &mut self,
        zone: &Arc<Zone>,
        previous: Instant,
        soa: Option<&SoaRecord>,
        monitor: &RefreshMonitor,
    ) {
        // If a SOA record is unavailable, don't schedule anything.
        let Some(soa) = soa else {
            monitor.update(zone, self.scheduled_time(), None);
            *self = Self::Disabled;
            return;
        };

        let retry = Duration::from_secs(soa.rdata.retry.get().into());
        let scheduled = previous + retry;
        monitor.update(zone, self.scheduled_time(), Some(scheduled));
        *self = Self::Retry {
            previous,
            scheduled,
        };
    }
}

//----------- Refreshes --------------------------------------------------------

/// Ongoing and enqueued refreshes of a zone.
#[derive(Debug)]
pub struct Refreshes {
    /// A handle to an ongoing refresh.
    pub ongoing: OngoingRefresh,

    /// An enqueued refresh.
    ///
    /// If multiple refreshes/reloads are enqueued, they are merged together.
    pub enqueued: Option<EnqueuedRefresh>,
}

impl Refreshes {
    /// Construct a new [`Refreshes`].
    pub fn new(ongoing: OngoingRefresh) -> Self {
        Self {
            ongoing,
            enqueued: None,
        }
    }

    /// Enqueue a refresh/reload.
    ///
    /// If one is already enqueued, the two will be merged.
    pub fn enqueue(&mut self, refresh: EnqueuedRefresh) {
        self.enqueued = self.enqueued.take().max(Some(refresh));
    }
}

//----------- OngoingRefresh ---------------------------------------------------

/// An ongoing refresh or reload of a zone.
#[derive(Debug)]
pub struct OngoingRefresh {
    /// A handle to the refresh.
    pub(super) handle: AbortOnDrop,
}

//----------- EnqueuedRefresh --------------------------------------------------

/// An enqueued refresh or reload of a zone.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EnqueuedRefresh {
    /// An enqueued refresh.
    Refresh,

    /// An enqueued reload.
    Reload,
}
