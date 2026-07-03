//! Maintaining and outputting metrics.
//!
//! Relevant sources for selecting metrics, metric names, and labels:
//! - <https://prometheus.io/docs/practices/naming/>
//! - <https://prometheus.io/docs/instrumenting/writing_exporters/#labels>
//! - <https://prometheus.io/docs/practices/instrumentation/>
//! - <https://github.com/prometheus/OpenMetrics/blob/main/specification/OpenMetrics.md>

use core::sync::atomic::AtomicU64;
use std::fmt::{self, Debug, Write};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use domain::base::Name;
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::info::Info;
use prometheus_client::registry::{Registry, Unit};

use crate::center::Center;
use crate::zone::ZoneByName;
use crate::zone::machine::ZoneStateMachine;

// Further metrics to track?:
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

#[derive(Debug)]
pub struct Metrics {
    /// The metrics registry for all metrics in Cascade. Units need to
    /// register their metrics with this registry.
    registry: Registry,

    /// Metrics that are available per zone.
    per_zone_metrics: PerZoneMetrics,

    /// The metrics assemble time only relevant for metrics that get collected
    /// on scraping. If we remove all metrics that get built (from state) on
    /// each scrape, then this timer will be useless and should be removed.
    assemble_time_metric: Gauge<u64, AtomicU64>,

    /// A collection of metrics that get collected from state on each metrics
    /// scrape.
    state_metrics: StateMetrics,
}

impl Metrics {
    pub fn new() -> Self {
        let mut col = Self {
            registry: Registry::with_prefix(PROMETHEUS_PREFIX),
            per_zone_metrics: Default::default(),
            assemble_time_metric: Default::default(),
            state_metrics: Default::default(),
        };

        // This metric is a "fake" metric and only there to expose the
        // software build information via labels and will always be 1. It
        // cannot be stored inside of `MetricsCollection` as it does not
        // implement Clone.
        let _cascade_version = Info::new(vec![
            ("version", clap::crate_version!()),
            ("commit", env!("CASCADE_BUILD_COMMIT")),
        ]);

        // See the prometheus docs at
        // https://www.robustperception.io/exposing-the-software-version-to-prometheus/
        // for exposing software version information. And `prometheus_client`
        // exposes the `Info` type, which we use here to expose cascade
        // version information just like `cascaded --version`.
        col.registry
            .register("build", "Cascade build information", _cascade_version);

        col.registry.register_with_unit(
            "metrics_assemble_duration",
            "The time taken in milliseconds to assemble the last metric snapshot",
            Unit::Other("milliseconds".into()),
            col.assemble_time_metric.clone(),
        );

        col.state_metrics.register_metrics(&mut col.registry);
        col.per_zone_metrics.register_metrics(&mut col.registry);

        col
    }

    /// Turn metrics into a [`String`] (and fetch metrics from State that
    /// aren't updated live during the running system)
    pub fn assemble(&self, center: Arc<Center>) -> Result<String, fmt::Error> {
        let start_time = Instant::now();

        let metrics = &self.state_metrics;

        let zones_configured: i64;
        let mut zones_loaded: i64 = 0;
        let mut zones_active: i64 = 0;
        let mut zones_unsigned: i64 = 0;
        let mut zones_signed: i64 = 0;
        let mut zones_published: i64 = 0;

        // Using Family::clear() to delete all metrics and label sets
        metrics.zones_halted.clear();
        {
            let state = center.state.lock().unwrap();
            // We won't have 2^63 zones in cascade
            zones_configured = state.zones.len() as i64;

            for ZoneByName(zone) in &state.zones {
                let zone_state = zone.state.read();

                if !matches!(zone_state.loader.source, crate::loader::Source::None) {
                    zones_loaded += 1;
                }

                // Check whether an instance has been published.
                // TODO: Use a more appropriate check.
                if zone_state.min_expiration.is_some() {
                    zones_published += 1;
                    zones_signed += 1;
                    zones_unsigned += 1;
                } else {
                    match zone_state.machine {
                        ZoneStateMachine::Waiting(_) | ZoneStateMachine::Loading(_) => {}

                        ZoneStateMachine::LoadedReview(_)
                        | ZoneStateMachine::HaltLoaded(_)
                        | ZoneStateMachine::Signing(_) => {
                            zones_unsigned += 1;
                        }

                        ZoneStateMachine::SigningFailed(_)
                        | ZoneStateMachine::SignedReview(_)
                        | ZoneStateMachine::HaltSigned(_) => {
                            zones_signed += 1;
                            zones_unsigned += 1;
                        }

                        ZoneStateMachine::Poisoned => unreachable!(),
                    }
                }

                if zone_state.machine.is_halted() {
                    metrics
                        .zones_halted
                        .get_or_create(&ZoneHaltMode {
                            zone: StoredName(zone.name.clone()),
                            mode: HaltMode::HardHalt,
                        })
                        .inc();
                } else {
                    zones_active += 1;
                }
            }
        }

        metrics.zones_configured.set(zones_configured);
        metrics.zones_loaded.set(zones_loaded);
        metrics.zones_active.set(zones_active);
        metrics.zones_unsigned.set(zones_unsigned);
        metrics.zones_signed.set(zones_signed);
        metrics.zones_published.set(zones_published);

        // u64::MAX milliseconds is around 585_000_000 years
        let assemble_ms = start_time.elapsed().as_millis() as u64;
        self.assemble_time_metric.set(assemble_ms);
        String::try_from(self)
    }

    pub fn get_zone_metrics(&self, name: Name<Bytes>) -> ZoneMetrics {
        ZoneMetrics {
            per_zone_metrics: self.per_zone_metrics.clone(),
            zone_name: name.into(),
        }
    }
}

impl TryFrom<&Metrics> for String {
    type Error = fmt::Error;

    fn try_from(metrics: &Metrics) -> Result<Self, Self::Error> {
        let mut buffer = String::new();
        encode(&mut buffer, &metrics.registry)?;
        Ok(buffer)
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

//------------ StoredName ----------------------------------------------------

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct StoredName(Name<Bytes>);

impl EncodeLabelValue for StoredName {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), std::fmt::Error> {
        encoder.write_str(&self.0.to_string())
    }
}

impl From<Name<Bytes>> for StoredName {
    fn from(value: Name<Bytes>) -> Self {
        Self(value)
    }
}

//------------ ZoneLabel -----------------------------------------------------

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ZoneLabel {
    pub zone: StoredName,
}

//------------ ZoneHaltMode --------------------------------------------------

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ZoneHaltMode {
    pub zone: StoredName,
    pub mode: HaltMode,
}

//------------ HaltMode ------------------------------------------------------

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum HaltMode {
    HardHalt,
}

//------------ XfrLabels -----------------------------------------------------

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct XfrLabels {
    pub zone: StoredName,
    pub r#type: XfrType,
    pub transport: XfrTransport,
}

//------------ XfrType -------------------------------------------------------

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum XfrType {
    AXFR,
    IXFR,
}

//------------ XfrTransport --------------------------------------------------

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum XfrTransport {
    TCP,
    UDP,
}

//------------ StateMetrics --------------------------------------------------

#[derive(Debug, Default)]
struct StateMetrics {
    /// The number of known zones
    zones_configured: Gauge,
    zones_loaded: Gauge,
    zones_active: Gauge,
    zones_unsigned: Gauge,
    // TODO: Track how many zones are waiting to be signed.
    zones_signed: Gauge,
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

//------------ PerZoneMetrics ------------------------------------------------

#[derive(Debug, Default, Clone)]
struct PerZoneMetrics {
    /// The number of zone transfers attempted by Cascade to the upstream
    xfr_requests_to_upstream_attempted: Family<XfrLabels, Counter>,

    /// The number of zone transfers succeeded by Cascade to the upstream
    xfr_requests_to_upstream_succeeded: Family<XfrLabels, Counter>,

    /// The number of records loaded in the last successful load (file or transfer)
    zone_loaded_last_successful_records: Family<ZoneLabel, Gauge>,

    /// The number of bytes loaded in the last successful load (file or transfer)
    zone_loaded_last_successful_bytes: Family<ZoneLabel, Gauge>,

    /// The number of records loaded in the last load (file or transfer),
    /// regardless of wether it was successful or aborted due to failure
    zone_loaded_last_records: Family<ZoneLabel, Gauge>,

    /// The number of bytes loaded in the last load (file or transfer),
    /// regardless of wether it was successful or aborted due to failure
    zone_loaded_last_bytes: Family<ZoneLabel, Gauge>,
}

impl PerZoneMetrics {
    fn register_metrics(&self, metrics: &mut Registry) {
        metrics.register(
            "xfr_requests_to_upstream_attempted",
            "Number of zone transfers attempted by Cascade towards the upstream primary",
            self.xfr_requests_to_upstream_attempted.clone(),
        );

        metrics.register(
            "xfr_requests_to_upstream_succeeded",
            "Number of succesful zone transfers by Cascade towards the upstream primary",
            self.xfr_requests_to_upstream_succeeded.clone(),
        );

        metrics.register(
            "zone_loaded_last_successful_records",
            "Number of records loaded in last successful zone transfer or zonefile load",
            self.zone_loaded_last_successful_records.clone(),
        );

        metrics.register_with_unit(
            "zone_loaded_last_successful_size",
            "Number of bytes loaded in last successful zone transfer or zonefile load",
            Unit::Bytes,
            self.zone_loaded_last_successful_bytes.clone(),
        );

        metrics.register(
            "zone_loaded_last_records",
            "Number of records loaded in last attempted zone transfer or zonefile load",
            self.zone_loaded_last_records.clone(),
        );

        metrics.register_with_unit(
            "zone_loaded_last_size",
            "Number of bytes loaded in last attempted zone transfer or zonefile load",
            Unit::Bytes,
            self.zone_loaded_last_bytes.clone(),
        );
    }
}

//------------ ZoneMetrics ---------------------------------------------------

/// An instantiation of `PerZoneMetrics` for a zone.
#[derive(Debug, Clone)]
pub struct ZoneMetrics {
    per_zone_metrics: PerZoneMetrics,
    zone_name: StoredName,
}

impl ZoneMetrics {
    pub fn inc_xfr_requests_to_upstream_attempted(&self, ty: XfrType, transport: XfrTransport) {
        self.per_zone_metrics
            .xfr_requests_to_upstream_attempted
            .get_or_create(&XfrLabels {
                zone: self.zone_name.clone(),
                r#type: ty,
                transport,
            })
            .inc();
    }

    pub fn inc_xfr_requests_to_upstream_succeeded(&self, ty: XfrType, transport: XfrTransport) {
        self.per_zone_metrics
            .xfr_requests_to_upstream_succeeded
            .get_or_create(&XfrLabels {
                zone: self.zone_name.clone(),
                r#type: ty,
                transport,
            })
            .inc();
    }

    pub fn zone_loaded_last_successful_records(&self, n: i64) {
        self.per_zone_metrics
            .zone_loaded_last_successful_records
            .get_or_create(&ZoneLabel {
                zone: self.zone_name.clone(),
            })
            .set(n);
    }

    pub fn zone_loaded_last_records(&self, n: i64) {
        self.per_zone_metrics
            .zone_loaded_last_records
            .get_or_create(&ZoneLabel {
                zone: self.zone_name.clone(),
            })
            .set(n);
    }

    pub fn zone_loaded_last_successful_bytes(&self, n: i64) {
        self.per_zone_metrics
            .zone_loaded_last_successful_bytes
            .get_or_create(&ZoneLabel {
                zone: self.zone_name.clone(),
            })
            .set(n);
    }

    pub fn zone_loaded_last_bytes(&self, n: i64) {
        self.per_zone_metrics
            .zone_loaded_last_bytes
            .get_or_create(&ZoneLabel {
                zone: self.zone_name.clone(),
            })
            .set(n);
    }
}
