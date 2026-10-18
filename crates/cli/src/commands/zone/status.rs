use std::{
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use cascade_api::{
    KeyType, PolicyInfo, PolicyInfoError, Progress, ReviewPolicyMode, Serial, SigningReport,
    SigningStageReport, ZoneLoaderReport, ZoneName, ZoneStatusError,
};

use crate::{ansi, client::CascadeApiClient, println};

#[derive(Clone, Debug, clap::Args)]
pub struct ZoneStatus {
    /// Whether or not to show additional details.
    #[arg(long = "detailed")]
    pub detailed: bool,

    /// The zone to report the status of.
    pub zone: ZoneName,
}

impl ZoneStatus {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        let Self { detailed, zone } = self;

        let url = format!("zone/{}/status", zone);
        let response: Result<cascade_api::ZoneStatus, ZoneStatusError> =
            client.get_json(&url).await?;

        match response {
            Ok(status) => Self::print_zone_status(client, status, detailed).await,
            Err(ZoneStatusError::ZoneDoesNotExist) => Err(format!("zone `{zone}` does not exist")),
        }
    }

    async fn print_zone_status(
        client: CascadeApiClient,
        zone: cascade_api::ZoneStatus,
        detailed: bool,
    ) -> Result<(), String> {
        // Fetch the policy for the zone.
        let url = format!("policy/{}", zone.policy);
        let response: Result<PolicyInfo, PolicyInfoError> = client.get_json(&url).await?;

        let policy = response.map_err(|_| {
            format!(
                "policy `{}` used by zone `{}` does not exist",
                zone.policy, zone.name
            )
        })?;

        println!("zone:   {}", zone.name);
        println!("policy: {}", zone.policy);
        println!("source: {}", zone.source);

        let loader_review = match &policy.loader.review.mode {
            ReviewPolicyMode::Off => "off",
            ReviewPolicyMode::Script { hook } => &format!("script `{hook}`"),
            ReviewPolicyMode::Manual => "manual",
        };

        let signer_review = match &policy.signer.review.mode {
            ReviewPolicyMode::Off => "off",
            ReviewPolicyMode::Script { hook } => &format!("script `{hook}`"),
            ReviewPolicyMode::Manual => "manual",
        };

        println!("");
        println!("review");
        println!("  loaded: {loader_review}");
        println!("  signed: {signer_review}");
        println!("");

        println!("last published");
        if let Some(last) = &zone.last_published {
            println!("  loaded serial: {}", last.loaded_serial);
            println!("  signed serial: {}", last.signed_serial);
            println!(
                "  timestamp:     {}",
                jiff::Timestamp::try_from(last.timestamp).unwrap()
            );
            println!("  size:          {} records", last.num_records);
        } else {
            println!("  <no versions published yet>");
        }

        // Output information per step progressed until the first still
        // in-progress/aborted step or show all steps if all have completed.
        println!("");
        print_status(&zone, &policy);

        if zone.last_published.is_some() {
            println!("");
            println!("Published zone available at:");
            for addr in zone.publish_addr {
                println!("  - {addr}")
            }
        }

        if let Some(error) = zone.error {
            println!("");
            println!("An error occurred during the last operation:");
            println!("  {}ERROR: {error}{}", ansi::RED, ansi::RESET);
            println!(
                "  Run {}`cascade zone history {}`{} for more information.",
                ansi::BLUE,
                zone.name,
                ansi::RESET
            );
        }

        if zone.maintenance_mode {
            println!("");
            println!(
                "{}WARNING: This zone is in maintenance mode{}",
                ansi::YELLOW,
                ansi::RESET
            );
            println!("  Cascade will not automatically start new loading and signing operations");
            println!(
                "  Run {}`cascade zone maintenance disable {}`{} to resume normal operation",
                ansi::BLUE,
                zone.name,
                ansi::RESET
            );
        }

        if detailed {
            println!("");
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
            println!("  Details:");
            for line in zone.key_status.lines() {
                println!("    {line}");
            }
        }

        Ok(())
    }
}

pub fn print_status(zone: &cascade_api::ZoneStatus, policy: &PolicyInfo) {
    let current = zone.progress;

    let progress = match current {
        Progress::Restoring => "restoring",
        Progress::Waiting => "idle",
        Progress::Loading => "loading",
        Progress::LoadedReview => "waiting for loaded review",
        Progress::HaltLoaded => "halted after loaded review",
        Progress::PersistingLoaded => "persisting loaded zone",
        Progress::Signing => "signing",
        Progress::SigningFailed => "signing failed",
        Progress::SignedReview => "waiting for signed review",
        Progress::HaltSigned => "halted after signed review",
        Progress::PersistingSigned => "persisting signed zone",
    };

    println!("status: {}{progress}{}", ansi::BLUE, ansi::RESET);

    if matches!(current, Progress::Waiting | Progress::Restoring) {
        return;
    }

    print_load_phase(current, zone.unsigned_serial, &zone.receipt_report);
    print_loaded_review_phase(
        &zone.name,
        zone.unsigned_serial,
        policy,
        current,
        &zone.unsigned_review_addr,
    );
    print_persist_loaded_phase(current);
    print_sign_phase(
        current,
        zone.unsigned_serial,
        zone.signed_serial,
        &zone.signing_report,
    );
    print_signed_review_phase(
        &zone.name,
        zone.signed_serial,
        policy,
        current,
        &zone.signed_review_addr,
    );
    print_persist_signed_phase(current);
    print_publish_phase();
}

fn print_load_phase(
    current: Progress,
    unsigned_serial: Option<Serial>,
    receipt_report: &Option<ZoneLoaderReport>,
) {
    if current < Progress::Loading {
        println!("  {Pending} load");
    } else if current > Progress::Loading {
        let unsigned_serial = serial_to_string(unsigned_serial);
        println!("  {Done} load (serial: {unsigned_serial})");
    } else {
        let short_serial = if let Some(unsigned_serial) = unsigned_serial {
            format!(" (serial: {unsigned_serial})")
        } else {
            "".into()
        };
        let unsigned_serial = serial_to_string(unsigned_serial);
        let start_time = to_rfc3339_ago(
            receipt_report.as_ref().map(|r| r.started_at),
            "<not started yet>",
        );

        let v = receipt_report.as_ref().map_or(0, |r| r.byte_count);
        let bytes = format_size(v, " ", "B");

        let total_size = receipt_report
            .as_ref()
            .and_then(|r| r.total_byte_count)
            .filter(|r| *r > 0)
            .map_or("".into(), |bytes| {
                let total_size = format_size(bytes, " ", "B");
                format!(" / {total_size}")
            });

        let percentage = if let Some(r) = receipt_report
            && let Some(t) = r.total_byte_count
            && t > 0
        {
            let b = r.byte_count as f64;
            let t = t as f64;
            let n = 100.0 * b / t;
            format!(" ({n:.0}%)")
        } else {
            "".into()
        };

        println!("  {Ongoing} load{short_serial}");
        println!("  |   serial: {unsigned_serial}");
        println!("  |   start time: {start_time}");
        println!("  |   progress: {bytes}{total_size}{percentage}");
        println!("  |");
    }
}

fn print_loaded_review_phase(
    zone: &ZoneName,
    serial: Option<Serial>,
    policy: &PolicyInfo,
    current: Progress,
    addrs: &[SocketAddr],
) {
    use ansi::{BLUE, DIM, RED, RESET, YELLOW};

    if let ReviewPolicyMode::Off = policy.loader.review.mode {
        println!("  {Pending} {DIM}review loaded zone (disabled){RESET}");
        return;
    }

    if current < Progress::LoadedReview {
        println!("  {Pending} review loaded zone");
    } else if current == Progress::LoadedReview {
        if let ReviewPolicyMode::Script { hook } = &policy.loader.review.mode {
            println!("  {Ongoing} review loaded zone");
            println!("  |   {BLUE}automatic zone review in progress{RESET}");
            println!("  |   review hook: \"{hook}\"",);
            println!("  |");
        } else {
            let serial = serial.map_or_else(|| "<SERIAL>".into(), |s| s.to_string());
            println!("  {Stopped} review loaded zone");
            println!("  |   {YELLOW}zone must be reviewed manually{RESET}");
            if addrs.is_empty() {
                println!("  |   {RED}no loaded review addresses were specified{RESET}");
            } else {
                println!("  |   loaded zone is available at:");
                for addr in addrs {
                    println!("  |     - {addr}");
                }
            }
            println!("  |   possible actions:");
            println!("  |     {BLUE}cascade zone approve --unsigned {zone} {serial}{RESET}");
            println!("  |     {BLUE}cascade zone reject --unsigned {zone} {serial}{RESET}");
            println!("  |");
        }
    } else if current == Progress::HaltLoaded {
        println!("  {Error} review loaded zone");
        println!("  |   {RED}ERROR: zone was rejected{RESET}");
        println!("  |   possible actions:");
        println!("  |     {BLUE}cascade zone override {zone}{RESET}",);
        println!("  |     {BLUE}cascade zone reset {zone}{RESET}",);
        println!("  |");
    } else {
        println!("  {Done} review loaded zone");
    }
}

fn print_persist_loaded_phase(current: Progress) {
    if current < Progress::PersistingLoaded {
        println!("  {Pending} persist loaded zone");
    } else if current > Progress::PersistingLoaded {
        println!("  {Done} persist loaded zone");
    } else {
        println!("  {Ongoing} persist loaded zone");
        println!("  |");
    }
}

fn print_sign_phase(
    current: Progress,
    unsigned_serial: Option<Serial>,
    signed_serial: Option<Serial>,
    signing_report: &Option<SigningReport>,
) {
    if current < Progress::Signing {
        println!("  {Pending} sign");
    } else if current > Progress::Signing {
        let signed_serial = serial_to_string(signed_serial);
        println!("  {Done} sign (serial: {signed_serial})");
    } else {
        let start_time = match &signing_report.as_ref().map(|r| &r.stage_report) {
            None => None,
            Some(SigningStageReport::InProgress(r)) => Some(r.started_at),
            Some(SigningStageReport::Requested(_)) => None,
            Some(SigningStageReport::Finished(r)) => Some(r.started_at),
        };
        let unsigned_serial = serial_to_string(unsigned_serial);

        let short_signed_serial = if let Some(signed_serial) = signed_serial {
            format!(" (serial: {signed_serial})")
        } else {
            "".into()
        };
        let signed_serial = serial_to_string(signed_serial);
        println!("  {Ongoing} sign{short_signed_serial}");
        println!("  |   loaded serial: {unsigned_serial}");
        println!("  |   signed serial: {signed_serial}");
        println!(
            "  |   start time: {}",
            to_rfc3339_ago(start_time, "<not started yet>")
        );
        println!("  |");
    }
}

fn print_signed_review_phase(
    zone: &ZoneName,
    signed_serial: Option<Serial>,
    policy: &PolicyInfo,
    current: Progress,
    addrs: &[SocketAddr],
) {
    use ansi::{BLUE, DIM, RED, RESET, YELLOW};

    if let ReviewPolicyMode::Off = policy.signer.review.mode {
        println!("  {Pending} {DIM}review signed zone (disabled){RESET}");
        return;
    }

    if current < Progress::SignedReview {
        println!("  {Pending} review signed zone");
    } else if current == Progress::SignedReview {
        if let ReviewPolicyMode::Script { hook } = &policy.signer.review.mode {
            println!("  {Ongoing} review signed zone");
            println!("  |   {YELLOW}automatic zone review in progress{RESET}");
            println!("  |   review hook: \"{hook}\"",);
        } else {
            let serial = signed_serial.map_or_else(|| "<SERIAL>".into(), |s| s.to_string());
            println!("  {Stopped} review signed zone");
            println!("  |   {YELLOW}zone must be reviewed manually{RESET}");
            if addrs.is_empty() {
                println!("  |   {RED}no signed review addresses were specified{RESET}");
            } else {
                println!("  |   signed zone is available at:");
                for addr in addrs {
                    println!("  |     - {addr}");
                }
            }
            println!("  |   possible actions:");
            println!("  |     {BLUE}cascade zone approve --signed {zone} {serial}{RESET}");
            println!("  |     {BLUE}cascade zone reject --signed {zone} {serial}{RESET}");
            println!("  |");
        }
    } else if current == Progress::HaltSigned {
        println!("  {Error} review signed zone");
        println!("  |   {RED}ERROR: zone was rejected{RESET}");
        println!("  |   possible actions:");
        println!("  |     {BLUE}cascade zone override {zone}{RESET}");
        println!("  |     {BLUE}cascade zone reset {zone}{RESET}");
        println!("  |");
    } else {
        println!("  {Done} review signed zone");
    }
}

fn print_persist_signed_phase(current: Progress) {
    if current < Progress::PersistingSigned {
        println!("  {Pending} persist signed zone");
    } else if current > Progress::PersistingSigned {
        println!("  {Done} persist signed zone");
    } else {
        println!("  {Ongoing} persist signed zone");
        println!("  |");
    }
}

fn print_publish_phase() {
    println!("  {Pending} publish");
}

enum Icon {
    /// Operation had not yet been started
    Pending,
    /// Operation is ongoing
    Ongoing,
    /// Operation is waiting for user input
    Stopped,
    /// Operation has succeeded
    Done,
    /// Operation has errored
    Error,
}

use Icon::{Done, Error, Ongoing, Pending, Stopped};

impl std::fmt::Display for Icon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ansi::{BLUE, DIM, GREEN, RED, RESET, YELLOW};
        let (color, character) = match self {
            Self::Done => (GREEN, '\u{2714}'),     // tick ✔
            Self::Ongoing => (BLUE, '\u{25CF}'),   // black circle ●
            Self::Stopped => (YELLOW, '\u{25A0}'), // black square ■
            Self::Pending => (DIM, '\u{25CB}'),    // white circle ○
            Self::Error => (RED, '\u{2A2F}'),      // cross ⨯
        };
        let s = format!("{color}{character}{RESET}");
        f.write_str(&s)
    }
}

/// Format a size in a human-readable way
///
/// Shows one decimal point if the size is small enough for that to make sense
/// (e.g. below 10KB).
fn format_size(v: usize, spacer: &str, suffix: &str) -> String {
    let v = v as f64;

    const M: f64 = 1_000_000.0;
    const K: f64 = 1_000.0;

    match v {
        n if n > 10.0 * M => format!("{:.0}{spacer}M{suffix}", n / M),
        n if n > M => format!("{:.1}{spacer}M{suffix}", n / M),
        n if n > 10.0 * K => format!("{:.0}{spacer}K{suffix}", n / K),
        n if n > K => format!("{:.1}{spacer}K{suffix}", n / K),
        n => format!("{n}{spacer}{suffix}"),
    }
}

fn serial_to_string(serial: Option<Serial>) -> String {
    match serial {
        Some(serial) => format!("{serial}"),
        None => "<not yet known>".to_string(),
    }
}

fn to_rfc3339_ago(v: Option<SystemTime>, default: &str) -> String {
    match v {
        Some(v) => {
            let now = jiff::Zoned::now().round(jiff::Unit::Second).unwrap();
            let v = jiff::Timestamp::try_from(v).unwrap();
            let span = v
                .until(now.clone())
                .unwrap()
                .round(
                    jiff::SpanRound::new()
                        .relative(&now)
                        .largest(jiff::Unit::Year)
                        .smallest(jiff::Unit::Second),
                )
                .unwrap();
            format!("{} ({span:#} ago)", now.datetime())
        }
        None => default.to_string(),
    }
}

#[expect(dead_code)]
fn format_duration(duration: Duration) -> String {
    format!(
        "{:#}",
        jiff::Span::try_from(duration)
            .unwrap()
            .round(
                jiff::SpanRound::new()
                    .smallest(jiff::Unit::Second)
                    .largest(jiff::Unit::Hour)
            )
            .unwrap()
    )
}

#[cfg(test)]
mod tests {
    use super::format_size;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(945, " ", "B"), "945 B");
        assert_eq!(format_size(9450, " ", "B"), "9.4 KB");
        assert_eq!(format_size(94500, " ", "B"), "94 KB");
        assert_eq!(format_size(945000, " ", "B"), "945 KB");
        assert_eq!(format_size(9450000, " ", "B"), "9.4 MB");
        assert_eq!(format_size(94500000, " ", "B"), "94 MB");
        assert_eq!(format_size(945000000, " ", "B"), "945 MB");
    }
}
