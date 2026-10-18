use std::time::SystemTime;

use cascade_api::{
    HistoricalEvent, ResigningTrigger, SigningTrigger, ZoneHistoryError, ZoneName, ZoneReviewStatus,
};

use crate::{client::CascadeApiClient, println};

#[derive(Clone, Debug, clap::Args)]
pub struct ZoneHistory {
    /// The zone to report the history of.
    pub zone: ZoneName,
}

impl ZoneHistory {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        let Self { zone } = self;

        let url = format!("zone/{}/history", zone);
        let response: Result<cascade_api::ZoneHistory, ZoneHistoryError> =
            client.get_json(&url).await?;

        match response {
            Ok(response) => {
                println!("{:25} {:10} Event", "Timestamp", "Serial");
                println!("{:25} {:10} -----", "---------", "------");
                for history_item in response.history {
                    let when = to_rfc3339(history_item.when);
                    let serial = match history_item.serial {
                        Some(serial) => serial.to_string(),
                        None => "-".to_string(),
                    };
                    let what = match &history_item.event {
                        HistoricalEvent::StartedLoad => "Started load".to_string(),
                        HistoricalEvent::StartedResign => "Started resign".to_string(),
                        HistoricalEvent::Added => "Zone added".to_string(),
                        HistoricalEvent::Removed => "Zone removed".to_string(),
                        HistoricalEvent::PolicyChanged => "Policy changed".to_string(),
                        HistoricalEvent::SourceChanged => "Source changed".to_string(),
                        HistoricalEvent::NewVersionReceived => "New version received".to_string(),
                        HistoricalEvent::SigningSucceeded { trigger } => {
                            format!(
                                "Signing succeeded (triggered by {})",
                                match trigger {
                                    SigningTrigger::Load => "loading a new instance",
                                    SigningTrigger::Resign(ResigningTrigger {
                                        keys_changed: true,
                                        sigs_need_refresh: false,
                                    }) => "a change in signing keys",
                                    SigningTrigger::Resign(ResigningTrigger {
                                        keys_changed: false,
                                        sigs_need_refresh: true,
                                    }) => "signatures needing refresh",
                                    SigningTrigger::Resign(ResigningTrigger {
                                        keys_changed: true,
                                        sigs_need_refresh: true,
                                    }) => "a change in signing keys and signatures needing refresh",
                                    SigningTrigger::Resign(ResigningTrigger {
                                        keys_changed: false,
                                        sigs_need_refresh: false,
                                    }) => "<unknown>",
                                }
                            )
                        }
                        HistoricalEvent::SigningFailed { trigger, reason } => {
                            format!(
                                "Signing failed (triggered by {}): {reason}",
                                match trigger {
                                    SigningTrigger::Load => "loading a new instance",
                                    SigningTrigger::Resign(ResigningTrigger {
                                        keys_changed: true,
                                        sigs_need_refresh: false,
                                    }) => "a change in signing keys",
                                    SigningTrigger::Resign(ResigningTrigger {
                                        keys_changed: false,
                                        sigs_need_refresh: true,
                                    }) => "signatures nearing expiration",
                                    SigningTrigger::Resign(ResigningTrigger {
                                        keys_changed: true,
                                        sigs_need_refresh: true,
                                    }) =>
                                        "a change in signing keys and signatures nearing expiration",
                                    SigningTrigger::Resign(ResigningTrigger {
                                        keys_changed: false,
                                        sigs_need_refresh: false,
                                    }) => "<unknown>",
                                }
                            )
                        }
                        HistoricalEvent::UnsignedZoneReview { status, .. } => format!(
                            "Unsigned zone review {}",
                            match status {
                                ZoneReviewStatus::Pending => "pending",
                                ZoneReviewStatus::Approved => "approved",
                                ZoneReviewStatus::Rejected => "rejected",
                            }
                        ),
                        HistoricalEvent::SignedZoneReview { status, .. } => format!(
                            "Signed zone review {}",
                            match status {
                                ZoneReviewStatus::Pending => "pending",
                                ZoneReviewStatus::Approved => "approved",
                                ZoneReviewStatus::Rejected => "rejected",
                            }
                        ),
                        HistoricalEvent::UnsignedHookFailed { err, .. } => {
                            format!("Could not execute loaded review hook: {err}",)
                        }
                        HistoricalEvent::SignedHookFailed { err, .. } => {
                            format!("Could not execute signed review hook: {err}",)
                        }
                        HistoricalEvent::KeySetCommand {
                            cmd,
                            elapsed,
                            warning: None,
                        } => {
                            format!("Keyset command '{cmd}' succeeded in {}s", elapsed.as_secs())
                        }
                        HistoricalEvent::KeySetCommand {
                            cmd,
                            elapsed,
                            warning: Some(warning),
                        } => {
                            format!(
                                "Keyset command '{cmd}' succeeded in {}s with warning: {warning}",
                                elapsed.as_secs()
                            )
                        }
                        HistoricalEvent::KeySetError { cmd, err, elapsed } => {
                            format!(
                                "Keyset command '{cmd}' failed in {}s with error: {err}",
                                elapsed.as_secs()
                            )
                        }
                        HistoricalEvent::LoadingFailed { reason } => reason.clone(),
                    };
                    println!("{when} {serial:10} {what}");
                }
                Ok(())
            }
            Err(ZoneHistoryError::ZoneDoesNotExist) => Err(format!("zone `{zone}` does not exist")),
        }
    }
}

fn to_rfc3339(v: SystemTime) -> String {
    jiff::Timestamp::try_from(v)
        .unwrap()
        .round(jiff::Unit::Second)
        .unwrap()
        .to_string()
}
