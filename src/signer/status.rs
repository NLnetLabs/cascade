//! Tracking the status of zone signing.

use std::time::{Duration, SystemTime};

use cascade_api::{
    SigningFinishedReport, SigningInProgressReport, SigningReport, SigningRequestedReport,
    SigningStageReport,
};
use serde::Serialize;
use tokio::time::Instant;

use crate::util::{
    serialize_duration_as_secs, serialize_instant_as_duration_secs, serialize_opt_duration_as_secs,
};

#[derive(Debug)]
pub struct SigningStatusPerZone {
    pub current_action: String,
    pub status: ZoneSigningStatus,
}

impl SigningStatusPerZone {
    pub fn mk_signing_report(&self) -> Option<SigningReport> {
        let now = Instant::now();
        let now_t = SystemTime::now();
        let stage_report = match self.status {
            ZoneSigningStatus::Requested(s) => {
                Some(SigningStageReport::Requested(SigningRequestedReport {
                    requested_at: now_t.checked_sub(now.duration_since(s.requested_at))?,
                }))
            }
            ZoneSigningStatus::InProgress(s) => {
                Some(SigningStageReport::InProgress(SigningInProgressReport {
                    requested_at: now_t.checked_sub(now.duration_since(s.requested_at))?,
                    zone_serial: domain::base::Serial(s.zone_serial.into()),
                    started_at: now_t.checked_sub(now.duration_since(s.started_at))?,
                    unsigned_rr_count: s.unsigned_rr_count,
                    walk_time: s.walk_time,
                    sort_time: s.sort_time,
                    denial_rr_count: s.denial_rr_count,
                    denial_time: s.denial_time,
                    rrsig_count: s.rrsig_count,
                    rrsig_reused_count: s.rrsig_reused_count,
                    rrsig_time: s.rrsig_time,
                    total_time: s.total_time,
                    threads_used: s.threads_used,
                }))
            }
            ZoneSigningStatus::Finished(s) => {
                Some(SigningStageReport::Finished(SigningFinishedReport {
                    requested_at: now_t.checked_sub(now.duration_since(s.requested_at))?,
                    zone_serial: domain::base::Serial(s.zone_serial.into()),
                    started_at: now_t.checked_sub(now.duration_since(s.started_at))?,
                    unsigned_rr_count: s.unsigned_rr_count,
                    walk_time: s.walk_time,
                    sort_time: s.sort_time,
                    denial_rr_count: s.denial_rr_count,
                    denial_time: s.denial_time,
                    rrsig_count: s.rrsig_count,
                    rrsig_reused_count: s.rrsig_reused_count,
                    rrsig_time: s.rrsig_time,
                    total_time: s.total_time,
                    threads_used: s.threads_used,
                    finished_at: now_t.checked_sub(now.duration_since(s.finished_at))?,
                    succeeded: s.succeeded,
                }))
            }
            ZoneSigningStatus::Aborted => None,
        };

        stage_report.map(|stage_report| SigningReport {
            current_action: self.current_action.clone(),
            stage_report,
        })
    }
}

// TODO: Why does this need to be serialized?
#[derive(Copy, Clone, Debug, Serialize)]
pub enum ZoneSigningStatus {
    Requested(RequestedStatus),

    InProgress(InProgressStatus),

    Finished(FinishedStatus),

    Aborted,
}

impl ZoneSigningStatus {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::Requested(RequestedStatus::new())
    }

    #[allow(clippy::result_unit_err)] // TODO
    pub fn start(&mut self, zone_serial: domain::new::base::Serial) -> Result<(), ()> {
        match *self {
            ZoneSigningStatus::Requested(s) => {
                *self = Self::InProgress(InProgressStatus::new(s, zone_serial));
                Ok(())
            }
            ZoneSigningStatus::Aborted
            | ZoneSigningStatus::InProgress(_)
            | ZoneSigningStatus::Finished(_) => Err(()),
        }
    }

    pub fn finish(&mut self, succeeded: bool) {
        match *self {
            ZoneSigningStatus::Requested(_) => {
                *self = Self::Aborted;
            }
            ZoneSigningStatus::InProgress(status) => {
                *self = Self::Finished(FinishedStatus::new(status, succeeded))
            }
            ZoneSigningStatus::Finished(_) | ZoneSigningStatus::Aborted => { /* Nothing to do */ }
        }
    }
}

impl std::fmt::Display for ZoneSigningStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZoneSigningStatus::Requested(_) => f.write_str("Requested"),
            ZoneSigningStatus::InProgress(_) => f.write_str("InProgress"),
            ZoneSigningStatus::Finished(_) => f.write_str("Finished"),
            ZoneSigningStatus::Aborted => f.write_str("Aborted"),
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize)]
pub struct RequestedStatus {
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    pub requested_at: tokio::time::Instant,
}

impl RequestedStatus {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            requested_at: Instant::now(),
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize)]
pub struct InProgressStatus {
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    pub requested_at: tokio::time::Instant,
    pub zone_serial: domain::base::Serial,
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    pub started_at: tokio::time::Instant,
    pub unsigned_rr_count: Option<usize>,
    #[serde(serialize_with = "serialize_opt_duration_as_secs")]
    pub walk_time: Option<Duration>,
    #[serde(serialize_with = "serialize_opt_duration_as_secs")]
    pub sort_time: Option<Duration>,
    pub denial_rr_count: Option<usize>,
    #[serde(serialize_with = "serialize_opt_duration_as_secs")]
    pub denial_time: Option<Duration>,
    pub rrsig_count: Option<usize>,
    pub rrsig_reused_count: Option<usize>,
    #[serde(serialize_with = "serialize_opt_duration_as_secs")]
    pub rrsig_time: Option<Duration>,
    #[serde(serialize_with = "serialize_opt_duration_as_secs")]
    pub total_time: Option<Duration>,
    pub threads_used: Option<usize>,
}

impl InProgressStatus {
    pub fn new(requested_status: RequestedStatus, zone_serial: domain::new::base::Serial) -> Self {
        Self {
            requested_at: requested_status.requested_at,
            zone_serial: domain::base::Serial(zone_serial.into()),
            started_at: Instant::now(),
            unsigned_rr_count: None,
            walk_time: None,
            sort_time: None,
            denial_rr_count: None,
            denial_time: None,
            rrsig_count: None,
            rrsig_reused_count: None,
            rrsig_time: None,
            total_time: None,
            threads_used: None,
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize)]
pub struct FinishedStatus {
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    pub requested_at: tokio::time::Instant,
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    pub started_at: tokio::time::Instant,
    pub zone_serial: domain::base::Serial,
    pub unsigned_rr_count: usize,
    #[serde(serialize_with = "serialize_duration_as_secs")]
    pub walk_time: Duration,
    #[serde(serialize_with = "serialize_duration_as_secs")]
    pub sort_time: Duration,
    pub denial_rr_count: usize,
    #[serde(serialize_with = "serialize_duration_as_secs")]
    pub denial_time: Duration,
    pub rrsig_count: usize,
    pub rrsig_reused_count: usize,
    #[serde(serialize_with = "serialize_duration_as_secs")]
    pub rrsig_time: Duration,
    #[serde(serialize_with = "serialize_duration_as_secs")]
    pub total_time: Duration,
    pub threads_used: usize,
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    pub finished_at: tokio::time::Instant,
    pub succeeded: bool,
}

impl FinishedStatus {
    fn new(in_progress_status: InProgressStatus, succeeded: bool) -> Self {
        Self {
            requested_at: in_progress_status.requested_at,
            zone_serial: in_progress_status.zone_serial,
            started_at: Instant::now(),
            unsigned_rr_count: in_progress_status.unsigned_rr_count.unwrap_or_default(),
            walk_time: in_progress_status.walk_time.unwrap_or_default(),
            sort_time: in_progress_status.sort_time.unwrap_or_default(),
            denial_rr_count: in_progress_status.denial_rr_count.unwrap_or_default(),
            denial_time: in_progress_status.denial_time.unwrap_or_default(),
            rrsig_count: in_progress_status.rrsig_count.unwrap_or_default(),
            rrsig_reused_count: in_progress_status.rrsig_reused_count.unwrap_or_default(),
            rrsig_time: in_progress_status.rrsig_time.unwrap_or_default(),
            total_time: in_progress_status.total_time.unwrap_or_default(),
            threads_used: in_progress_status.threads_used.unwrap_or_default(),
            finished_at: Instant::now(),
            succeeded,
        }
    }
}
