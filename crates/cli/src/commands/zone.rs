use std::time::{Duration, SystemTime};

use camino::Utf8PathBuf;

use crate::ansi;
use crate::api::*;
use crate::client::CascadeApiClient;
use crate::println;

#[derive(Clone, Debug, clap::Args)]
pub struct Zone {
    #[command(subcommand)]
    command: ZoneCommand,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, clap::Subcommand)]
pub enum ZoneCommand {
    /// Register a new zone
    #[command(name = "add")]
    Add {
        name: ZoneName,

        /// The zone source can be an IP address (with or without port,
        /// defaults to port 53) or a file path.
        // TODO: allow supplying different tcp and/or udp port?
        #[arg(long = "source")]
        source: ZoneSource,

        /// Policy to use for this zone
        #[arg(long = "policy")]
        policy: String,

        #[arg(long = "import-public-key")]
        import_public_key: Vec<Utf8PathBuf>,

        #[arg(long = "import-ksk-file")]
        import_ksk_file: Vec<Utf8PathBuf>,

        #[arg(long = "import-zsk-file")]
        import_zsk_file: Vec<Utf8PathBuf>,

        #[arg(long = "import-csk-file")]
        import_csk_file: Vec<Utf8PathBuf>,

        #[arg(long = "import-ksk-kmip", value_names = ["server", "public_id", "private_id", "algorithm", "flags"])]
        import_ksk_kmip: Vec<String>,

        #[arg(long = "import-zsk-kmip", value_names = ["server", "public_id", "private_id", "algorithm", "flags"])]
        import_zsk_kmip: Vec<String>,

        #[arg(long = "import-csk-kmip", value_names = ["server", "public_id", "private_id", "algorithm", "flags"])]
        import_csk_kmip: Vec<String>,
    },

    /// Remove a zone
    #[command(name = "remove")]
    Remove { name: ZoneName },

    /// List registered zones
    #[command(name = "list")]
    List,

    /// Reload a zone
    #[command(name = "reload")]
    Reload { zone: ZoneName },

    /// Approve a zone being reviewed.
    #[command(name = "approve")]
    Approve {
        /// Whether to approve an unsigned or signed version of the zone.
        #[command(flatten)]
        review_stage: ZoneReviewStage,

        /// The name of the zone.
        name: ZoneName,

        /// The serial number of the zone.
        serial: u32,
    },

    /// Override a previous rejection
    #[command(name = "override")]
    Override {
        /// Whether to approve an unsigned or signed version of the zone.
        #[command(flatten)]
        review_stage: ZoneReviewStage,

        /// The name of the zone.
        name: ZoneName,
    },

    /// Reset the pipeline for a halted zone
    #[command(name = "reset")]
    Reset {
        /// The name  of the zone
        zone: ZoneName,
    },

    /// Reject a zone being reviewed.
    #[command(name = "reject")]
    Reject {
        /// Whether to reject an unsigned or signed version of the zone.
        #[command(flatten)]
        review_stage: ZoneReviewStage,

        /// The name of the zone.
        name: ZoneName,

        /// The serial number of the zone.
        serial: u32,
    },

    /// Get the status of a single zone
    #[command(name = "status")]
    Status {
        /// Whether or not to show additional details.
        #[arg(long = "detailed")]
        detailed: bool,

        /// The zone to report the status of.
        zone: ZoneName,
    },

    /// Get the history of a single zone
    #[command(name = "history")]
    History {
        /// The zone to report the history of.
        zone: ZoneName,
    },
}

/// The stage to review a zone at.
#[derive(Clone, Debug, clap::Args)]
#[group(required = true, multiple = false)]
pub struct ZoneReviewStage {
    /// Review the zone before it is signed.
    #[arg(long = "unsigned")]
    unsigned: bool,

    /// Review the zone after it is signed.
    #[arg(long = "signed")]
    signed: bool,
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
                mut source,
                policy,
                import_public_key,
                import_ksk_file,
                import_zsk_file,
                import_csk_file,
                import_ksk_kmip,
                import_zsk_kmip,
                import_csk_kmip,
            } => {
                let import_public_key = import_public_key.into_iter().map(KeyImport::PublicKey);
                let import_ksk_file = import_ksk_file.into_iter().map(|p| {
                    KeyImport::File(FileKeyImport {
                        key_type: KeyType::Ksk,
                        path: p,
                    })
                });
                let import_csk_file = import_csk_file.into_iter().map(|p| {
                    KeyImport::File(FileKeyImport {
                        key_type: KeyType::Csk,
                        path: p,
                    })
                });
                let import_zsk_file = import_zsk_file.into_iter().map(|p| {
                    KeyImport::File(FileKeyImport {
                        key_type: KeyType::Zsk,
                        path: p,
                    })
                });
                let import_ksk_kmip = kmip_imports(KeyType::Ksk, &import_ksk_kmip);
                let import_csk_kmip = kmip_imports(KeyType::Csk, &import_csk_kmip);
                let import_zsk_kmip = kmip_imports(KeyType::Zsk, &import_zsk_kmip);

                let key_imports = import_public_key
                    .chain(import_ksk_file)
                    .chain(import_csk_file)
                    .chain(import_zsk_file)
                    .chain(import_ksk_kmip)
                    .chain(import_csk_kmip)
                    .chain(import_zsk_kmip)
                    .collect();

                if let ZoneSource::Zonefile { path } = &mut source {
                    let canonicalized_path = path.canonicalize().map_err(|err| {
                        format!("Failed to canonicalize zonefile path '{}': {err}", path)
                    })?;
                    let path_str = canonicalized_path.to_str().ok_or_else(|| {
                        format!("Failed to convert path '{}'", canonicalized_path.display())
                    })?;
                    *path = Utf8PathBuf::from(path_str).into_boxed_path();
                }

                let res: Result<ZoneAddResult, ZoneAddError> = client
                    .post_json_with(
                        "zone/add",
                        &ZoneAdd {
                            name,
                            source,
                            policy,
                            key_imports,
                        },
                    )
                    .await?;

                match res {
                    Ok(res) => {
                        println!(
                            "Zone {} scheduled for loading, use 'cascade zone status {}' to see the status.",
                            res.name, res.name
                        );
                        Ok(())
                    }
                    Err(e) => Err(format!("Failed to add zone: {e}")),
                }
            }
            ZoneCommand::Remove { name } => {
                let res: Result<ZoneRemoveResult, ZoneRemoveError> =
                    client.post_json(&format!("zone/{name}/remove")).await?;

                match res {
                    Ok(res) => {
                        println!("Removed zone {}", res.name);
                        Ok(())
                    }
                    Err(e) => Err(format!("Failed to remove zone: {e}")),
                }
            }
            ZoneCommand::List => {
                let response: ZonesListResult = client.get_json("zone/").await?;

                for zone_name in response.zones {
                    println!("{}", zone_name);
                }
                Ok(())
            }
            ZoneCommand::Reload { zone } => {
                let url = format!("zone/{zone}/reload");
                let res: Result<ZoneReloadResult, ZoneReloadError> = client.post_json(&url).await?;

                match res {
                    Ok(res) => {
                        println!("Success: Sent zone reload command for {}", res.name);
                        Ok(())
                    }
                    Err(e) => Err(format!("Failed to reload zone: {e}")),
                }
            }
            ZoneCommand::Reset { zone } => {
                let url = format!("zone/{zone}/reset");
                let result: ZoneResetResult = client.post_json(&url).await?;

                match result {
                    Ok(ZoneResetOutput { zone }) => {
                        println!("Reset the pipeline for zone '{zone}'");
                        Ok(())
                    }
                    Err(err) => Err(format!("Could not reset zone '{zone}': {err}")),
                }
            }
            ZoneCommand::Override { name, review_stage } => {
                let stage = match review_stage {
                    ZoneReviewStage {
                        unsigned: true,
                        signed: false,
                    } => "unsigned",
                    ZoneReviewStage {
                        unsigned: false,
                        signed: true,
                    } => "signed",
                    _ => unreachable!(),
                };

                let url = format!("zone/{name}/{stage}/override");
                let result: ZoneOverrideResult = client.post_json(&url).await?;

                match result {
                    Ok(ZoneOverrideOutput {
                        zone,
                        review_stage: _,
                    }) => {
                        println!("Overridden {stage} review for '{zone}'");
                        Ok(())
                    }
                    Err(err) => Err(format!(
                        "Could not override review for zone '{name}': {err}"
                    )),
                }
            }
            ZoneCommand::Approve {
                review_stage,
                name,
                serial,
            } => {
                let stage = match review_stage {
                    ZoneReviewStage {
                        unsigned: true,
                        signed: false,
                    } => "unsigned",
                    ZoneReviewStage {
                        unsigned: false,
                        signed: true,
                    } => "signed",
                    _ => unreachable!(),
                };

                let url = format!("/zone/{name}/{stage}/{serial}/approve");
                let result: ZoneReviewResult = client.post_json(&url).await?;

                match result {
                    Ok(ZoneReviewOutput {}) => {
                        println!("Approved {stage} zone '{name}' with serial number {serial}");
                        Ok(())
                    }
                    Err(ZoneReviewError::NoSuchZone) => {
                        Err(format!("Zone '{name}' could not be found"))
                    }
                    Err(ZoneReviewError::NotUnderReview) => Err(format!(
                        "The {stage} zone '{name}' with serial number {serial} is not being reviewed right now"
                    )),
                }
            }
            ZoneCommand::Reject {
                review_stage,
                name,
                serial,
            } => {
                let stage = match review_stage {
                    ZoneReviewStage {
                        unsigned: true,
                        signed: false,
                    } => "unsigned",
                    ZoneReviewStage {
                        unsigned: false,
                        signed: true,
                    } => "signed",
                    _ => unreachable!(),
                };

                let url = format!("/zone/{name}/{stage}/{serial}/reject");
                let result: ZoneReviewResult = client.post_json(&url).await?;

                match result {
                    Ok(ZoneReviewOutput {}) => {
                        println!("Rejected {stage} zone '{name}' with serial number {serial}");
                        Ok(())
                    }
                    Err(ZoneReviewError::NoSuchZone) => {
                        Err(format!("Zone '{name}' could not be found"))
                    }
                    Err(ZoneReviewError::NotUnderReview) => Err(format!(
                        "The {stage} zone '{name}' with serial number {serial} is not being reviewed right now"
                    )),
                }
            }
            ZoneCommand::Status { zone, detailed } => {
                let url = format!("zone/{}/status", zone);
                let response: Result<ZoneStatus, ZoneStatusError> = client.get_json(&url).await?;

                match response {
                    Ok(status) => Self::print_zone_status(client, status, detailed).await,
                    Err(ZoneStatusError::ZoneDoesNotExist) => {
                        Err(format!("zone `{zone}` does not exist"))
                    }
                }
            }
            ZoneCommand::History { zone } => {
                let url = format!("zone/{}/history", zone);
                let response: Result<ZoneHistory, ZoneHistoryError> = client.get_json(&url).await?;

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
                                HistoricalEvent::NewVersionReceived => {
                                    "New version received".to_string()
                                }
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
                                HistoricalEvent::KeySetCommand {
                                    cmd,
                                    elapsed,
                                    warning: None,
                                } => {
                                    format!(
                                        "Keyset command '{cmd}' succeeded in {}s",
                                        elapsed.as_secs()
                                    )
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
                                HistoricalEvent::Error(s) => s.clone(),
                            };
                            println!("{when} {serial:10} {what}");
                        }
                        Ok(())
                    }
                    Err(ZoneHistoryError::ZoneDoesNotExist) => {
                        Err(format!("zone `{zone}` does not exist"))
                    }
                }
            }
        }
    }

    async fn print_zone_status(
        client: CascadeApiClient,
        zone: ZoneStatus,
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

        let loader_review = if !policy.loader.review.required {
            "none"
        } else if let Some(hook) = &policy.loader.review.cmd_hook {
            hook
        } else {
            "manual"
        };

        let signer_review = if !policy.signer.review.required {
            "none"
        } else if let Some(hook) = &policy.signer.review.cmd_hook {
            hook
        } else {
            "manual"
        };

        println!("");
        println!("review hooks");
        println!("  loaded: {loader_review}");
        println!("  signed: {signer_review}");
        println!("");

        println!("last published");
        if let Some(last) = &zone.last_published {
            println!("  loaded serial: {}", last.loaded_serial);
            println!("  signed serial: {}", last.signed_serial);
            println!("  timestamp:     <TODO>");
            println!("  size:          <TODO> records (<TODO>B)");
        } else {
            println!("  <no versions published yet>");
        }

        // Output information per step progressed until the first still
        // in-progress/aborted step or show all steps if all have completed.
        println!("");
        print_status(zone.progress, &zone, &policy);

        if zone.last_published.is_some() {
            println!("");
            println!("Published zone available at {}", zone.publish_addr);
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

pub fn print_status(current: Progress, zone: &ZoneStatus, policy: &PolicyInfo) {
    let progress = match zone.progress {
        Progress::Waiting => "idle",
        Progress::Loading => "loading",
        Progress::LoadedReview => "waiting for loaded review",
        Progress::HaltLoaded => "halted after loaded review",
        Progress::Signing => "signing",
        Progress::SigningFailed => "signing failed",
        Progress::SignedReview => "waiting for siged review",
        Progress::HaltSigned => "halted after signed review",
    };

    println!("status: {}{progress}{}", ansi::BLUE, ansi::RESET);

    if current == Progress::Waiting {
        return;
    }

    print_load_phase(current, zone.unsigned_serial, &zone.receipt_report);
    print_loaded_review_phase(&zone.name, zone.unsigned_serial, policy, current);
    print_sign_phase(
        current,
        zone.unsigned_serial,
        zone.signed_serial,
        &zone.signing_report,
    );
    print_signed_review_phase(&zone.name, zone.signed_serial, policy, current);
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
        println!("  {Ongoing} load{short_serial}");
        println!("  |   serial: {unsigned_serial}");
        println!("  |   start time: {start_time}");
        println!("  |");
    }
}

fn print_loaded_review_phase(
    zone: &ZoneName,
    serial: Option<Serial>,
    policy: &PolicyInfo,
    current: Progress,
) {
    use ansi::{BLUE, RED, RESET, YELLOW};
    if current < Progress::LoadedReview {
        println!("  {Pending} review loaded zone");
    } else if current == Progress::LoadedReview {
        if let Some(hook) = &policy.loader.review.cmd_hook {
            println!("  {Ongoing} review loaded zone");
            println!("  |   {BLUE}automatic zone review in progress{RESET}");
            println!("  |   review hook: \"{hook}\"",);
            println!("  |");
        } else {
            let serial = serial.map_or_else(|| "<SERIAL>".into(), |s| s.to_string());
            println!("  {Stopped} review loaded zone");
            println!("  |   {YELLOW}zone must be reviewed manually{RESET}");
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
) {
    use ansi::{BLUE, RED, RESET, YELLOW};
    if current < Progress::SignedReview {
        println!("  {Pending} review signed zone");
    } else if current == Progress::SignedReview {
        if let Some(hook) = &policy.signer.review.cmd_hook {
            println!("  {Ongoing} review signed zone");
            println!("  |   {YELLOW}automatic zone review in progress{RESET}");
            println!("  |   review hook: \"{hook}\"",);
        } else {
            let serial = signed_serial.map_or_else(|| "<SERIAL>".into(), |s| s.to_string());
            println!("  {Stopped} review signed zone");
            println!("  |   {YELLOW}zone must be reviewed manually{RESET}");
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
        use ansi::{BLUE, GRAY, GREEN, RED, RESET, YELLOW};
        let (color, character) = match self {
            Self::Done => (GREEN, '\u{2714}'),     // tick ✔
            Self::Ongoing => (BLUE, '\u{25CF}'),   // black circle ●
            Self::Stopped => (YELLOW, '\u{25A0}'), // black square ■
            Self::Pending => (GRAY, '\u{25CB}'),   // white circle ○
            Self::Error => (RED, '\u{2A2F}'),      // cross ⨯
        };
        let s = format!("{color}{character}{RESET}");
        f.write_str(&s)
    }
}

#[expect(dead_code)]
fn format_size(v: usize, spacer: &str, suffix: &str) -> String {
    match v {
        n if n > 1_000_000 => format!("{}{spacer}M{suffix}", n / 1_000_000),
        n if n > 1_000 => format!("{}{spacer}K{suffix}", n / 1_000),
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

fn to_rfc3339(v: SystemTime) -> String {
    jiff::Timestamp::try_from(v)
        .unwrap()
        .round(jiff::Unit::Second)
        .unwrap()
        .to_string()
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

fn kmip_imports(key_type: KeyType, x: &[String]) -> Vec<KeyImport> {
    let chunks = x.chunks_exact(5);

    // If this fails then clap is not doing what we expect.
    assert!(chunks.remainder().is_empty());

    chunks
        .into_iter()
        .map(|chunk| {
            let [server, public_id, private_id, algorithm, flags] = chunk else {
                unreachable!()
            };
            KeyImport::Kmip(KmipKeyImport {
                key_type,
                server: server.clone(),
                public_id: public_id.clone(),
                private_id: private_id.clone(),
                algorithm: algorithm.clone(),
                flags: flags.clone(),
            })
        })
        .collect()
}
