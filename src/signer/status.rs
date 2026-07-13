//! Tracking the status of zone signing.

use std::time::SystemTime;

use serde::Serialize;
use tokio::time::Instant;

use crate::api::{
    SigningFinishedReport, SigningInProgressReport, SigningReport, SigningRequestedReport,
    SigningStageReport,
};
use crate::util::serialize_instant_as_duration_secs;

#[derive(Debug)]
pub struct SigningStatusPerZone {
    pub step: SigningStep,
    pub status: ZoneSigningStatus,
}

#[derive(Debug)]
pub enum SigningStep {
    Full(FullSigningStep),
    Incremental(IncrementalSigningStep),
}

#[derive(Debug)]
pub enum FullSigningStep {
    CollectingRecords,
    FetchingKeys,
    SortingRecords,
    GeneratingDenialRecords,
    GeneratingSignatureRecords,
}

#[derive(Debug)]
pub enum IncrementalSigningStep {
    CollectingRecords,
    GeneratingSignatures,
    GeneratingDiffs,
    DeterminingMinExpirationTime,
}

impl SigningStep {
    fn to_api(&self) -> cascade_api::SigningStep {
        match self {
            SigningStep::Full(s) => cascade_api::SigningStep::Full(match s {
                FullSigningStep::CollectingRecords => {
                    cascade_api::FullSigningStep::CollectingRecords
                }
                FullSigningStep::FetchingKeys => cascade_api::FullSigningStep::FetchingKeys,
                FullSigningStep::SortingRecords => cascade_api::FullSigningStep::SortingRecords,
                FullSigningStep::GeneratingDenialRecords => {
                    cascade_api::FullSigningStep::GeneratingDenialRecords
                }
                FullSigningStep::GeneratingSignatureRecords => {
                    cascade_api::FullSigningStep::GeneratingSignatureRecords
                }
            }),
            SigningStep::Incremental(s) => cascade_api::SigningStep::Incremental(match s {
                IncrementalSigningStep::CollectingRecords => {
                    cascade_api::IncrementalSigningStep::CollectingRecords
                }
                IncrementalSigningStep::GeneratingSignatures => {
                    cascade_api::IncrementalSigningStep::GeneratingSignatures
                }
                IncrementalSigningStep::GeneratingDiffs => {
                    cascade_api::IncrementalSigningStep::GeneratingDiffs
                }
                IncrementalSigningStep::DeterminingMinExpirationTime => {
                    cascade_api::IncrementalSigningStep::DeterminingMinExpirationTime
                }
            }),
        }
    }
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
                    step: self.step.to_api(),
                    requested_at: now_t.checked_sub(now.duration_since(s.requested_at))?,
                    loaded_serial: domain::base::Serial(s.loaded_serial.into()),
                    signed_serial: domain::base::Serial(s.signed_serial.into()),
                    started_at: now_t.checked_sub(now.duration_since(s.started_at))?,
                }))
            }
            ZoneSigningStatus::Finished(s) => {
                Some(SigningStageReport::Finished(SigningFinishedReport {
                    requested_at: now_t.checked_sub(now.duration_since(s.requested_at))?,
                    loaded_serial: domain::base::Serial(s.loaded_serial.into()),
                    signed_serial: domain::base::Serial(s.signed_serial.into()),
                    started_at: now_t.checked_sub(now.duration_since(s.started_at))?,
                    finished_at: now_t.checked_sub(now.duration_since(s.finished_at))?,
                }))
            }
            ZoneSigningStatus::Aborted => None,
        };

        stage_report.map(|stage_report| SigningReport { stage_report })
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
    pub fn start(
        &mut self,
        loaded_serial: domain::new::base::Serial,
        signed_serial: domain::new::base::Serial,
    ) -> Result<(), ()> {
        match *self {
            ZoneSigningStatus::Requested(s) => {
                *self = Self::InProgress(InProgressStatus::new(s, loaded_serial, signed_serial));
                Ok(())
            }
            ZoneSigningStatus::Aborted
            | ZoneSigningStatus::InProgress(_)
            | ZoneSigningStatus::Finished(_) => Err(()),
        }
    }

    pub fn finish(&mut self) {
        match *self {
            ZoneSigningStatus::Requested(_) => {
                *self = Self::Aborted;
            }
            ZoneSigningStatus::InProgress(status) => {
                *self = Self::Finished(FinishedStatus::new(status))
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
    pub loaded_serial: domain::base::Serial,
    pub signed_serial: domain::base::Serial,
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    pub started_at: tokio::time::Instant,
}

impl InProgressStatus {
    pub fn new(
        requested_status: RequestedStatus,
        loaded_serial: domain::new::base::Serial,
        signed_serial: domain::new::base::Serial,
    ) -> Self {
        Self {
            requested_at: requested_status.requested_at,
            loaded_serial: domain::base::Serial(loaded_serial.into()),
            signed_serial: domain::base::Serial(signed_serial.into()),
            started_at: Instant::now(),
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize)]
pub struct FinishedStatus {
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    pub requested_at: tokio::time::Instant,
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    pub started_at: tokio::time::Instant,
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    pub finished_at: tokio::time::Instant,
    pub loaded_serial: domain::base::Serial,
    pub signed_serial: domain::base::Serial,
}

impl FinishedStatus {
    fn new(in_progress_status: InProgressStatus) -> Self {
        Self {
            requested_at: in_progress_status.requested_at,
            loaded_serial: in_progress_status.loaded_serial,
            signed_serial: in_progress_status.signed_serial,
            started_at: in_progress_status.started_at,
            finished_at: Instant::now(),
        }
    }
}
