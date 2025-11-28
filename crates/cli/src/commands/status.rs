use futures_util::TryFutureExt;

use crate::ansi;
use crate::api::{KeyMsg, KeyStatusResult, KeysPerZone, ServerStatusResult, SigningStageReport};
use crate::client::{format_http_error, CascadeApiClient};
use crate::{eprintln, println};

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
            Some(StatusCommand::Keys) => {
                let response: KeyStatusResult = client
                    .get("/status/keys")
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(format_http_error)?;

                println!("First to expire (max 5):");
                if response.expirations.is_empty() {
                    println!("   No keys will expire");
                }

                for e in response.expirations.iter().take(5) {
                    println!(" - {}", e.zone);
                    println!("   {}", e.key);
                    match e.time_left {
                        Some(dur) => println!(
                            "   Time left: {:#}",
                            jiff::SignedDuration::try_from(dur)
                                .unwrap()
                                .round(jiff::Unit::Second)
                                .unwrap()
                        ),
                        None => println!("   {}EXPIRED{}", ansi::RED, ansi::RESET),
                    };
                }

                println!();
                println!("Keys per zone:");
                for KeysPerZone { zone, keys } in &response.zones {
                    println!(" - {zone}");
                    for KeyMsg { name, msg } in keys {
                        println!("   - {name}: {msg}");
                    }
                }
            }
            None => {
                let response: ServerStatusResult = client
                    .get("/status")
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(format_http_error)?;

                if !response.hard_halted_zones.is_empty() {
                    eprintln!("The following zones are hard halted due to a serious problem:");
                    for (zone_name, err) in response.hard_halted_zones {
                        eprintln!("   {}\u{78}{} {zone_name}: {err}", ansi::RED, ansi::RESET);
                    }
                    eprintln!();
                }

                if !response.soft_halted_zones.is_empty() {
                    eprintln!("The following zones are halted due to resolvable issues:");
                    for (zone_name, err) in response.soft_halted_zones {
                        eprintln!("   {}\u{78}{} {zone_name}: {err}", ansi::RED, ansi::RESET);
                    }
                    eprintln!();
                }

                println!("Signing queue:");
                if response.signing_queue.is_empty() {
                    println!("  The signing queue is currently empty.");
                } else {
                    println!(
                        "  Key: {}In Progress (\u{23F5}){}, {}Pending (\u{23F8}){}, {}Finished (\u{2714}){}",
                        ansi::YELLOW,
                        ansi::RESET,
                        ansi::GRAY,
                        ansi::RESET,
                        ansi::GREEN,
                        ansi::RESET
                    );
                    println!("  {:>2}:   {:<25} {:<16} Action", "#", "When", "Zone");
                    for (i, report) in response.signing_queue.iter().enumerate() {
                        let zone_name = report.zone_name.to_string();
                        let action = &report.signing_report.current_action;
                        let (colour, state, when) = match &report.signing_report.stage_report {
                            SigningStageReport::Requested(r) => {
                                (ansi::GRAY, "\u{23F8}", r.requested_at)
                            }
                            SigningStageReport::InProgress(r) => {
                                (ansi::YELLOW, "\u{23F5}", r.started_at)
                            }
                            SigningStageReport::Finished(r) => {
                                (ansi::GREEN, "\u{2714}", r.finished_at)
                            }
                        };
                        let when = jiff::Timestamp::try_from(when)
                            .unwrap()
                            .round(jiff::Unit::Second)
                            .unwrap();
                        println!(
                            "  {i:>2}: {colour}{state}{} {when:<25} {zone_name:<16} {action}",
                            ansi::RESET
                        );
                    }
                }
            }
        }
        Ok(())
    }
}
