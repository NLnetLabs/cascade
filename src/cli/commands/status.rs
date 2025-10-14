use chrono::{DateTime, Utc};
use futures::TryFutureExt;

use crate::api::ServerStatusResult;
use crate::cli::client::{format_http_error, CascadeApiClient};
use crate::common::ansi;
use crate::zonemaintenance::types::SigningStageReport;

#[derive(Clone, Debug, clap::Args)]
pub struct Status {
    #[command(subcommand)]
    command: Option<StatusCommand>,
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum StatusCommand {
    /// Show status of DNSSEC keys
    #[command(name = "keys")]
    Keys,
}

// From discussion in August 2025
// - get status (what zones are there, what are things doing)
// - get dnssec status on zone
//   - maybe have it both on server level status command (so here) and in the zone command?

impl Status {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            Some(_) => todo!(),
            None => {
                let response: ServerStatusResult = client
                    .get("/status")
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(format_http_error)?;

                if !response.hard_halted_zones.is_empty() {
                    eprintln!("The following zones are hard-halted due to a serious problem:");
                    for (zone_name, err) in response.hard_halted_zones {
                        eprintln!("  - {zone_name}: {err}");
                    }
                    eprintln!();
                }

                if !response.soft_halted_zones.is_empty() {
                    eprintln!("The following zones are soft-halted:");
                    for (zone_name, err) in response.soft_halted_zones {
                        eprintln!("  - {zone_name}: {err}");
                    }
                }

                println!("Signing queue:");
                if response.signing_queue.is_empty() {
                    println!("  The signing queue is currently empty.");
                } else {
                    println!(
                        "  Key: {}In Progress{}, {}Pending{}, {}Finished{}",
                        ansi::GREEN,
                        ansi::RESET,
                        ansi::CYAN,
                        ansi::RESET,
                        ansi::GRAY,
                        ansi::RESET
                    );
                    println!("  [{:>2}]: {:<25} {:<16} Action", "#", "When", "Zone");
                    for (i, report) in response.signing_queue.iter().enumerate() {
                        let zone_name = report.zone_name.to_string();
                        let action = &report.signing_report.current_action;
                        let (colour, when) = match &report.signing_report.stage_report {
                            SigningStageReport::Requested(r) => (ansi::CYAN, r.requested_at),
                            SigningStageReport::InProgress(r) => (ansi::GREEN, r.started_at),
                            SigningStageReport::Finished(r) => (ansi::GRAY, r.finished_at),
                        };
                        let when = DateTime::<Utc>::from(when)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
                        println!(
                            "{colour}  [{i:>2}]: {when:<25} {zone_name:<16} {action}{}",
                            ansi::RESET
                        );
                    }
                }
            }
        }
        Ok(())
    }
}
