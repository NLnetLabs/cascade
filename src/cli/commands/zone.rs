use std::ops::ControlFlow;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use domain::base::{Name, Serial};
use futures::TryFutureExt;
use humantime::FormattedDuration;

use crate::api::{
    KeyType, PolicyInfo, PolicyInfoError, TimestampedZoneReviewStatus, ZoneAdd, ZoneAddError,
    ZoneAddResult, ZoneReviewStatus, ZoneSource, ZoneStage, ZoneStatus, ZoneStatusError,
    ZonesListResult,
};
use crate::cli::client::CascadeApiClient;
use crate::cli::commands::policy::ansi;
use crate::zone::PipelineMode;
use crate::zonemaintenance::types::SigningReport;

#[derive(Clone, Debug, clap::Args)]
pub struct Zone {
    #[command(subcommand)]
    command: ZoneCommand,
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum ZoneCommand {
    /// Register a new zone
    #[command(name = "add")]
    Add {
        name: Name<Bytes>,
        /// The zone source can be an IP address (with or without port,
        /// defaults to port 53) or a file path.
        // TODO: allow supplying different tcp and/or udp port?
        #[arg(long = "source")]
        source: ZoneSource,

        /// Policy to use for this zone
        #[arg(long = "policy")]
        policy: String,
    },

    /// Remove a zone
    #[command(name = "remove")]
    Remove { name: Name<Bytes> },

    /// List registered zones
    #[command(name = "list")]
    List,

    /// Reload a zone
    #[command(name = "reload")]
    Reload { zone: Name<Bytes> },

    /// Get the status of a single zone
    #[command(name = "status")]
    Status {
        /// Whether or not to show additional details.
        #[arg(long = "detailed")]
        detailed: bool,

        /// The zone to report the status of.
        zone: Name<Bytes>,
    },
}

// From brainstorm in beginning of April 2025
// - Command: reload a zone immediately
// - Command: register a new zone
// - Command: de-register a zone
// - Command: reconfigure a zone

// From discussion in August 2025
// At least:
// - register zone
// - list zones
// - get status (what zones are there, what are things doing)
// - get dnssec status on zone
// - reload zone (i.e. from file)

impl Zone {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            ZoneCommand::Add {
                name,
                source,
                policy,
            } => {
                let res: Result<ZoneAddResult, ZoneAddError> = client
                    .post("zone/add")
                    .json(&ZoneAdd {
                        name,
                        source,
                        policy,
                    })
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(|e| format!("HTTP request failed: {e:?}"))?;

                match res {
                    Ok(res) => {
                        println!("Added zone {}", res.name);
                        Ok(())
                    }
                    Err(e) => Err(format!("Failed to add zone: {e}")),
                }
            }
            ZoneCommand::Remove { name } => {
                let res: ZoneAddResult = client
                    .post(&format!("zone/{name}/remove"))
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(|e| format!("HTTP request failed: {e:?}"))?;

                println!("Removed zone {}", res.name);
                Ok(())
            }
            ZoneCommand::List => {
                let response: ZonesListResult = client
                    .get("zones/list")
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(|e| format!("HTTP request failed: {e:?}"))?;

                for zone_name in response.zones {
                    println!("{}", zone_name);
                }
                Ok(())
            }
            ZoneCommand::Reload { zone } => {
                let url = format!("zone/{zone}/reload");
                client
                    .post(&url)
                    .send()
                    .and_then(|r| async { r.error_for_status() })
                    .await
                    .map_err(|e| format!("HTTP request failed: {e:?}"))?;

                println!("Success: Sent zone reload command for {}", zone);
                Ok(())
            }
            ZoneCommand::Status { zone, detailed } => Self::status(client, zone, detailed).await,
        }
    }

    async fn status(
        client: CascadeApiClient,
        zone: Name<Bytes>,
        detailed: bool,
    ) -> Result<(), String> {
        // TODO: move to function that can be called by the general
        // status command with a zone arg?
        let url = format!("zone/{}/status", zone);
        let response: Result<ZoneStatus, ZoneStatusError> = client
            .get(&url)
            .send()
            .and_then(|r| { log::error!("Decoding..."); r.json() })
            .await
            .map_err(|e| format!("HTTP request failed: {e:?}"))?;

        match response {
            Ok(status) => Self::print_zone_status(client, status, detailed).await,
            Err(ZoneStatusError::ZoneDoesNotExist) => Err(format!("zone `{zone}` does not exist")),
        }
    }

    async fn print_zone_status(
        client: CascadeApiClient,
        zone: ZoneStatus,
        detailed: bool,
    ) -> Result<(), String> {
        // Fetch the policy for the zone.
        let url = format!("policy/{}", zone.policy);
        let response: Result<PolicyInfo, PolicyInfoError> = client
            .get(&url)
            .send()
            .and_then(|r| r.json())
            .await
            .map_err(|e| format!("HTTP request failed: {e:?}"))?;

        let policy = response.map_err(|_| {
            format!(
                "policy `{}` used by zone `{}` does not exist",
                zone.policy, zone.name
            )
        })?;

        // Determine progress
        let progress = determine_progress(&zone, &policy);

        // Output information per step progressed until the first still
        // in-progress/aborted step or show all steps if all have completed.
        progress.print(&zone, &policy);

        // If the pipeline is halted, show that.
        match zone.pipeline_mode {
            PipelineMode::Running => { /* Nothing to do */ }
            PipelineMode::SoftHalt(err) => {
                println!("{}\u{78} An error occurred that prevents further processing of this zone version:{}", ansi::RED, ansi::RESET);
                println!("{}\u{78} {err}{}", ansi::RED, ansi::RESET);
            }
            PipelineMode::HardHalt(err) => {
                println!(
                    "{}\u{78} The pipeline for this zone is halted due to a serious error:{}",
                    ansi::RED,
                    ansi::RESET
                );
                println!("{}\u{78} {err}{}", ansi::RED, ansi::RESET);
            }
        }

        if detailed {
            println!("DNSSEC keys:");
            for key in zone.keys {
                match key.key_type {
                    KeyType::Ksk => print!("  KSK"),
                    KeyType::Zsk => print!("  ZSK"),
                    KeyType::Csk => print!("  CSK"),
                }
                println!(" tagged {}:", key.key_tag);
                println!("    Reference: {}", key.pubref);
                if key.signer {
                    println!("    Actively used for signing");
                }
            }
            if let Some(key_status) = zone.key_status {
                println!("  Details:");
                for line in key_status.lines() {
                    println!("    {line}");
                }
            }
        }

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Progress {
    WaitingForChanges,
    ChangesReceived,
    AtUnsignedReview,
    WaitingToSign,
    Signing,
    Signed,
    AtSignedReview,
    Published,
}

fn determine_progress(zone: &ZoneStatus, policy: &PolicyInfo) -> Progress {
    match zone.stage {
        ZoneStage::Unsigned => match (&zone.receipt_report, zone.unsigned_review_status) {
            (None, _) => Progress::WaitingForChanges,
            (Some(_), None) => Progress::ChangesReceived,
            (Some(_), Some(TimestampedZoneReviewStatus { status, .. })) => {
                match status {
                    ZoneReviewStatus::Pending | ZoneReviewStatus::Rejected => {
                        Progress::AtUnsignedReview
                    }
                    ZoneReviewStatus::Approved => {
                        // After reviewing comes signing, and if we're not stuck at
                        // reviewing then we must be somewhere in signing.
                        match &zone.signing_report {
                            None | Some(SigningReport::Requested(_)) => Progress::WaitingToSign,
                            Some(SigningReport::InProgress(_)) => Progress::Signing,
                            Some(SigningReport::Finished(_)) => Progress::Signed,
                        }
                    }
                }
            }
        },
        ZoneStage::Signed => {
            if !policy.signer.review.required {
                match &zone.signing_report {
                    None | Some(SigningReport::Requested(_)) => Progress::WaitingToSign,
                    Some(SigningReport::InProgress(_)) => Progress::Signing,
                    Some(SigningReport::Finished(_)) => Progress::Signed,
                }
            } else {
                // After reviewing comes publication, and if we're not at the
                // published stage then with review enabled we must still be
                // at the review stage.
                Progress::AtSignedReview
            }
        }
        ZoneStage::Published => Progress::Published,
    }
}

impl std::fmt::Display for Progress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Progress::WaitingForChanges => f.write_str("Waiting for changes"),
            Progress::ChangesReceived => f.write_str("Changes received"),
            Progress::AtUnsignedReview => f.write_str("At unsigned review"),
            Progress::WaitingToSign => f.write_str("Waiting to sign"),
            Progress::Signing => f.write_str("Signing"),
            Progress::Signed => f.write_str("Signed"),
            Progress::AtSignedReview => f.write_str("At signed review"),
            Progress::Published => f.write_str("Published"),
        }
    }
}

impl Progress {
    pub fn print(&self, zone: &ZoneStatus, policy: &PolicyInfo) {
        println!(
            "Status report for zone '{}' using policy '{}'",
            zone.name, policy.name
        );

        let mut p = Progress::WaitingForChanges;
        loop {
            match p {
                Progress::WaitingForChanges => self.print_waiting_for_changes(zone),
                Progress::ChangesReceived => self.print_zone_received(zone),
                Progress::AtUnsignedReview => self.print_pending_unsigned_review(zone, policy),
                Progress::WaitingToSign => self.print_waiting_to_sign(zone),
                Progress::Signing => self.print_signing(zone),
                Progress::Signed => self.print_signed(zone),
                Progress::AtSignedReview => self.print_pending_signed_review(zone, policy),
                Progress::Published => self.print_published(zone),
            }
            match p.next(*self) {
                ControlFlow::Continue(next_p) => p = next_p,
                ControlFlow::Break(()) => break,
            }
        }
    }

    fn next(&self, max: Progress) -> ControlFlow<(), Progress> {
        let next = match self {
            Progress::WaitingForChanges => Progress::ChangesReceived,
            Progress::ChangesReceived => Progress::AtUnsignedReview,
            Progress::AtUnsignedReview => Progress::WaitingToSign,
            Progress::WaitingToSign => Progress::Signing,
            Progress::Signing => Progress::Signed,
            Progress::Signed => Progress::AtSignedReview,
            Progress::AtSignedReview => Progress::Published,
            Progress::Published => return ControlFlow::Break(()),
        };

        if next > max {
            return ControlFlow::Break(());
        }

        ControlFlow::Continue(next)
    }

    fn print_waiting_for_changes(&self, zone: &ZoneStatus) {
        let done = *self > Progress::WaitingForChanges;
        let waiting_waited = match done {
            true => "Waited",
            false => "Waiting",
        };
        println!(
            "{} {} for a new version of the {} zone",
            status_icon(done),
            waiting_waited,
            zone.name
        );
        // TODO: When complete, show how long we waited.
    }

    fn print_zone_received(&self, zone: &ZoneStatus) {
        // TODO: we have no indication of whether a zone is currently being
        // received or not, we can only say if it was received after the fact.
        println!(
            "{} Loaded {}",
            status_icon(true),
            serial_to_string(zone.unsigned_serial),
        );

        // Print how receival of the zone went.
        let Some(report) = &zone.receipt_report else {
            unreachable!();
        };
        let (loaded_fetched, filesystem_network) = match zone.source {
            ZoneSource::None => unreachable!(),
            ZoneSource::Zonefile { .. } => ("Loaded", "filesystem"),
            ZoneSource::Server { .. } => ("Fetched", "network"),
        };
        println!("  Loaded at {}", to_rfc3339(report.finished_at));
        println!(
            "  {loaded_fetched} {} from the {filesystem_network} in {} seconds",
            format_size(report.byte_count, " ", "iB"),
            report
                .finished_at
                .duration_since(report.started_at)
                .unwrap()
                .as_secs()
        );
    }

    fn print_pending_unsigned_review(&self, zone: &ZoneStatus, policy: &PolicyInfo) {
        if !policy.loader.review.required {
            println!(
                "{} Auto approving signing of {}, no checks enabled in policy.",
                status_icon(true),
                serial_to_string(zone.unsigned_serial),
            );
        } else {
            let done = *self > Progress::AtUnsignedReview;
            let waiting_waited = match done {
                true => "Waited",
                false => "Waiting",
            };
            println!(
                "{} {} for approval to sign {}",
                status_icon(done),
                waiting_waited,
                serial_to_string(zone.unsigned_serial),
            );
            Self::print_review_hook(&policy.loader.review.cmd_hook);
            // TODO: When complete, show how long we waited.
        }
    }

    fn print_waiting_to_sign(&self, zone: &ZoneStatus) {
        println!(
            "{} Approval received to sign {}, signing requested",
            status_icon(*self > Progress::WaitingToSign),
            serial_to_string(zone.unsigned_serial)
        );
    }

    fn print_signing(&self, zone: &ZoneStatus) {
        if *self >= Progress::Signed {
            return;
        }

        println!(
            "{} Signing {}",
            status_icon(*self > Progress::Signing),
            serial_to_string(zone.unsigned_serial)
        );
        Self::print_signing_progress(zone);
    }

    fn print_signed(&self, zone: &ZoneStatus) {
        println!(
            "{} Signed {} as {}",
            status_icon(*self > Progress::Signed),
            serial_to_string(zone.unsigned_serial),
            serial_to_string(zone.signed_serial)
        );

        Self::print_signing_progress(zone);

        if *self == Progress::Signed {
            if let Some(addr) = zone.signed_review_addr {
                println!("  Signed zone available on {addr}");
            }
        }
    }

    fn print_pending_signed_review(&self, zone: &ZoneStatus, policy: &PolicyInfo) {
        if !policy.signer.review.required {
            println!(
                "{} Auto approving publication of {}, no checks enabled in policy.",
                status_icon(true),
                serial_to_string(zone.signed_serial)
            );
        } else {
            let done = *self > Progress::AtSignedReview;
            let waiting_waited = match done {
                true => "Waited",
                false => "Waiting",
            };
            println!(
                "{} {} for approval to publish {}",
                status_icon(*self > Progress::AtSignedReview),
                waiting_waited,
                serial_to_string(zone.signed_serial),
            );
            Self::print_review_hook(&policy.signer.review.cmd_hook);
        }
    }

    fn print_published(&self, zone: &ZoneStatus) {
        println!(
            "{} Published {}",
            status_icon(*self == Progress::Published),
            serial_to_string(zone.published_serial),
        );
        if *self == Progress::Published {
            println!("  Published zone available on {}", zone.publish_addr);
        }
    }

    fn print_review_hook(cmd_hook: &Option<String>) {
        match cmd_hook {
            Some(path) => println!("  Configured to invoke {path}"),
            None => println!("\u{0021} Zone will be held until manually approved"),
        }
    }

    fn print_signing_progress(zone: &ZoneStatus) {
        if let Some(report) = &zone.signing_report {
            match report {
                SigningReport::Requested(r) => {
                    println!("  Signing requested at {}", to_rfc3339(r.requested_at));
                }
                SigningReport::InProgress(r) => {
                    println!("  Signing started at {}", to_rfc3339(r.started_at));
                    if let (Some(unsigned_rr_count), Some(total_time)) =
                        (r.unsigned_rr_count, r.total_time)
                    {
                        println!(
                            "  Signed {} in {}",
                            format_size(unsigned_rr_count, "", " records"),
                            format_duration(total_time)
                        );
                    }
                }
                SigningReport::Finished(r) => {
                    println!("  Signed at {}", to_rfc3339(r.finished_at));
                    println!(
                        "  Signed {} in {}",
                        format_size(r.unsigned_rr_count, "", " records"),
                        format_duration(r.total_time)
                    );
                }
            }
        }
    }
}

fn status_icon(done: bool) -> String {
    match done {
        true => format!("{}\u{2714}{}", ansi::GREEN, ansi::RESET), // tick ✔
        false => format!("{}\u{2022}{}", ansi::YELLOW, ansi::RESET), // bullet •
    }
}

fn format_size(v: usize, spacer: &str, suffix: &str) -> String {
    match v {
        n if n > 1_000_000 => format!("{}{spacer}M{suffix}", n / 1_000_000),
        n if n > 1_000 => format!("{}{spacer}K{suffix}", n / 1_000),
        n => format!("{n}{spacer}{suffix}"),
    }
}

fn serial_to_string(serial: Option<Serial>) -> String {
    match serial {
        Some(serial) => format!("version {serial}"),
        None => "<serial number not yet known>".to_string(),
    }
}

fn to_rfc3339(v: SystemTime) -> String {
    let now = SystemTime::now();
    let diff = now.duration_since(v).unwrap();
    let rfc3339 = DateTime::<Utc>::from(v).to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    format!("{rfc3339} ({} ago)", format_duration(diff))
}

fn format_duration(duration: Duration) -> FormattedDuration {
    // See: https://github.com/chronotope/humantime/issues/35
    humantime::format_duration(Duration::from_secs(duration.as_secs()))
}
