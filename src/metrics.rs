//! Maintaining and outputting metrics.
//!
//! Relevant sources for selecting metrics, metric names, and labels:
//! - https://prometheus.io/docs/practices/naming/
//! - https://prometheus.io/docs/instrumenting/writing_exporters/#labels
//! - https://prometheus.io/docs/practices/instrumentation/
//! - https://github.com/prometheus/OpenMetrics/blob/main/specification/OpenMetrics.md

use core::sync::atomic::AtomicU64;
use std::fmt::{self, Debug, Write};
// use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use domain::base::Name;
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::info::Info;
use prometheus_client::registry::{Metric, Registry, Unit};

use crate::center::Center;

// Furhter Metrics to track?:
// - last time batching operation for zone signing succeeded (push to central metrics collection)
// -> turn log messages into counters: (https://prometheus.io/docs/practices/instrumentation/#logging)
//  - num of keyset errors per zone
//  - num of signing errors ...
//  - num of errors/warning/info total/global
// -> turn errors into a counter (https://prometheus.io/docs/practices/instrumentation/#failures)
//  - future: in code increment counter for attempts to do X and increment counter on failure
// -> threads (https://prometheus.io/docs/practices/instrumentation/#threadpools)
// -> collector meta stats: (https://prometheus.io/docs/practices/instrumentation/#collectors)
//  - time it took to collect metrics
//  - errors encountered

//------------ Module Configuration ------------------------------------------

/// The application prefix to use in the names of Prometheus metrics.
const PROMETHEUS_PREFIX: &str = "cascade";

//------------ MetricsCollection ---------------------------------------------

// TODO: document how to register metrics
#[derive(Debug)]
pub struct MetricsCollection {
    /// The metrics registry for all metrics in Cascade. Units need to
    /// register their metrics with this registry.
    pub cascade: Registry,

    /// The metrics assemble time only relevant for metrics that get collected
    /// on scraping. If we remove all metrics that get built (from state) on
    /// each scrape, then this timer will be useless and should be removed.
    _assemble_time_metric: Gauge<u64, AtomicU64>,

    /// This metric is a "fake" metric and only there to expose the software
    /// build information via labels and will always be 1.
    // _cascade_version: Family<Vec<(String, String)>, ConstGauge>,

    /// A collection of metrics that get collected from state on each metrics
    /// scrape.
    _state_metrics: StateMetrics,
}

impl MetricsCollection {
    pub fn new() -> Self {
        let mut col = Self {
            cascade: Registry::with_prefix(PROMETHEUS_PREFIX),
            _assemble_time_metric: Default::default(),
            // _cascade_version: Family::new_with_constructor(|| ConstGauge::new(1)),
            _state_metrics: Default::default(),
        };

        let _cascade_version = Info::new(vec![("version", clap::crate_version!())]);

        // The prometheus docs linked to
        // https://www.robustperception.io/exposing-the-software-version-to-prometheus/
        // for exposing software version information. And
        // [`prometheus_client`] exposes the [`Info`] type. However, I don't
        // know if we really need this. It would be more useful if it would
        // include build information like <branch> and <revision>.
        col.cascade
            // .register("build", "Cascade build information", col._cascade_version);
            .register("build", "Cascade build information", _cascade_version);

        col.cascade.register_with_unit(
            "metrics_assemble_duration",
            "The time taken in milliseconds to assemble the last metric snapshot",
            Unit::Other("milliseconds".into()),
            col._assemble_time_metric.clone(),
        );

        col._state_metrics.register_metrics(&mut col.cascade);

        col
    }

    /// Turn metrics into a [`String`] (and fetch metrics from State that
    /// aren't updated live during the running system)
    pub fn assemble(&self, center: Arc<Center>) -> Result<String, fmt::Error> {
        let start_time = Instant::now();

        let metrics = &self._state_metrics;

        let zones_configured: i64;
        let mut zones_loaded: i64 = 0;
        let mut zones_active: i64 = 0;
        let zones_unsigned: i64;
        let zones_signed: i64;
        let zones_waiting: i64;
        let zones_published: i64;

        // Using Family::clear() to delete all metrics and label sets
        metrics.zones_halted.clear();
        {
            zones_unsigned = center.unsigned_zones.load().as_ref().iter_zones().count() as i64;
            zones_signed = center.signed_zones.load().as_ref().iter_zones().count() as i64;
            zones_waiting = center.signable_zones.load().as_ref().iter_zones().count() as i64;
            zones_published = center.published_zones.load().as_ref().iter_zones().count() as i64;
            let state = center.state.lock().unwrap();
            // We won't have 2^63 zones in cascade
            zones_configured = state.zones.len() as i64;

            for zone in &state.zones {
                let zone = zone.0.clone();
                let zone_state = zone.state.lock().unwrap();

                // Don't count a zone that doesn't have a source
                if matches!(zone_state.source, crate::zone::ZoneLoadSource::None) {
                    continue;
                } else {
                    zones_loaded += 1;
                }

                match zone_state.pipeline_mode {
                    crate::zone::PipelineMode::Running => {
                        zones_active += 1;
                    }
                    crate::zone::PipelineMode::SoftHalt(_) => {
                        metrics
                            .zones_halted
                            .get_or_create(&ZoneHaltMode {
                                zone: StoredName(zone.name.clone()),
                                mode: HaltMode::SoftHalt,
                            })
                            .inc();
                    }
                    crate::zone::PipelineMode::HardHalt(_) => {
                        metrics
                            .zones_halted
                            .get_or_create(&ZoneHaltMode {
                                zone: StoredName(zone.name.clone()),
                                mode: HaltMode::HardHalt,
                            })
                            .inc();
                    }
                }
            }
        }

        metrics.zones_configured.set(zones_configured);
        metrics.zones_loaded.set(zones_loaded);
        metrics.zones_active.set(zones_active);
        metrics.zones_unsigned.set(zones_unsigned);
        metrics.zones_signed.set(zones_signed);
        metrics.zones_waiting.set(zones_waiting);
        metrics.zones_published.set(zones_published);

        // u64::MAX milliseconds is around 585_000_000 years
        let assemble_ms = start_time.elapsed().as_millis() as u64;
        self._assemble_time_metric.set(assemble_ms);
        String::try_from(self)
    }

    /// Register a metric with the [`Registry`].
    ///
    /// Note: In the Open Metrics text exposition format some metric types have
    /// a special suffix, e.g. the
    /// [`Counter`](crate::metrics::counter::Counter`) metric with `_total`.
    /// These suffixes are inferred through the metric type and must not be
    /// appended to the metric name manually by the user.
    ///
    /// Note: A full stop punctuation mark (`.`) is automatically added to the
    /// passed help text.
    ///
    /// Use [`Registry::register_with_unit`] whenever a unit for the given
    /// metric is known.
    ///
    /// ```
    /// # use prometheus_client::metrics::counter::{Atomic as _, Counter};
    /// # use prometheus_client::registry::{Registry, Unit};
    /// # let mut metrics = Registry::default();
    /// let counter: Counter = Counter::default();
    ///
    /// metrics.register("my_counter", "This is my counter", counter.clone());
    /// ```
    // This docstring is based on prometheus-client's docstring on the same
    // method.
    pub fn register<N: Into<String>, H: Into<String>>(
        &mut self,
        name: N,
        help: H,
        metric: impl Metric,
    ) {
        self.cascade.register(name, help, metric)
    }

    /// Register a metric with the [`Registry`] specifying the metric's unit.
    ///
    /// See [`Registry::register`] for additional documentation.
    ///
    /// Note: In the Open Metrics text exposition format units are appended to
    /// the metric name. This is done automatically. Users must not append the
    /// unit to the name manually.
    ///
    /// ```
    /// # use prometheus_client::metrics::counter::{Atomic as _, Counter};
    /// # use prometheus_client::registry::{Registry, Unit};
    /// # let mut metrics = Registry::default();
    /// let counter: Counter = Counter::default();
    ///
    /// metrics.register_with_unit(
    ///   "my_counter",
    ///   "This is my counter",
    ///   Unit::Seconds,
    ///   counter.clone(),
    /// );
    /// ```
    // This docstring is based on prometheus-client's docstring on the same
    // method.
    pub fn register_with_unit<N: Into<String>, H: Into<String>>(
        &mut self,
        name: N,
        help: H,
        unit: Unit,
        metric: impl Metric,
    ) {
        self.cascade.register_with_unit(name, help, unit, metric)
    }
}

impl TryFrom<&MetricsCollection> for String {
    type Error = fmt::Error;

    fn try_from(metrics: &MetricsCollection) -> Result<Self, Self::Error> {
        let mut buffer = String::new();
        encode(&mut buffer, &metrics.cascade)?;
        Ok(buffer)
    }
}

impl Default for MetricsCollection {
    fn default() -> Self {
        Self::new()
    }
}

//------------ StoredName ----------------------------------------------------

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct StoredName(Name<Bytes>);

impl EncodeLabelValue for StoredName {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), std::fmt::Error> {
        encoder.write_str(&self.0.to_string())
    }
}

//------------ ZoneHaltMode --------------------------------------------------

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ZoneHaltMode {
    zone: StoredName,
    mode: HaltMode,
}

//------------ HaltMode ------------------------------------------------------

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelValue)]
enum HaltMode {
    SoftHalt,
    HardHalt,
}

//------------ StateMetrics --------------------------------------------------

#[derive(Debug, Default)]
struct StateMetrics {
    /// The number of known zones
    zones_configured: Gauge,
    zones_loaded: Gauge,
    zones_active: Gauge,
    zones_unsigned: Gauge,
    zones_signed: Gauge,
    // waiting in signing queue
    zones_waiting: Gauge,
    zones_published: Gauge,
    zones_halted: Family<ZoneHaltMode, Gauge>,
}

impl StateMetrics {
    pub fn register_metrics(&self, reg: &mut Registry) {
        reg.register(
            "zones_configured",
            "Number of zones known to Cascade",
            self.zones_configured.clone(),
        );
        reg.register(
            "zones_loaded",
            "Number of zones loaded by Cascade",
            self.zones_loaded.clone(),
        );
        reg.register(
            "zones_active",
            "Number of active zones",
            self.zones_active.clone(),
        );
        reg.register(
            "zones_unsigned",
            "Number of unsigned zones",
            self.zones_unsigned.clone(),
        );
        reg.register(
            "zones_signed",
            "Number of signed zones",
            self.zones_signed.clone(),
        );
        reg.register(
            "zones_waiting",
            "Number of zones waiting to be signed",
            self.zones_waiting.clone(),
        );
        reg.register(
            "zones_published",
            "Number of published zones",
            self.zones_published.clone(),
        );
        reg.register(
            "zones_halted",
            "Number of halted zones",
            self.zones_halted.clone(),
        );
    }
}
