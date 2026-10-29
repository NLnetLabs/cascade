use std::fmt;
use std::net::{IpAddr, SocketAddr};

use camino::{Utf8Path, Utf8PathBuf};
use clap::builder::{StringValueParser, TypedValueParser, ValueParserFactory};

use crate::ansi;
use crate::api::*;
use crate::client::CascadeApiClient;
use crate::{eprintln, println};

pub mod add;
pub mod edit;
pub mod history;
pub mod status;

#[derive(Clone, Debug, clap::Args)]
pub struct Zone {
    #[command(subcommand)]
    command: ZoneCommand,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, clap::Subcommand)]
pub enum ZoneCommand {
    /// Add a new zone
    #[command(name = "add")]
    Add(self::add::ZoneAdd),

    /// Edit the configuration for a zone
    #[command(name = "edit")]
    Edit(self::edit::ZoneEdit),

    /// Remove a zone
    ///
    /// The zone must be in maintenance mode.
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
    Status(self::status::ZoneStatus),

    /// Get the history of a single zone
    #[command(name = "history")]
    History(self::history::ZoneHistory),

    /// Resume a paused zone pipeline
    #[command(name = "maintenance")]
    Maintenance {
        /// Enable or disable maintenance mode.
        #[command(subcommand)]
        maintenance: Maintenance,
    },

    /// Set the variable "last-signed-serial". This affects the next serial
    /// directly (in case of the counter policy) or affects whether the
    /// next serial is considered larger than the previous serial.
    #[command(name = "set-last-signed-serial")]
    SetLastSignedSerial {
        /// The name of the zone.
        name: ZoneName,

        /// The serial number of the zone.
        serial: u32,
    },
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Maintenance {
    /// Enable maintenance mode; preventing new loading and signing operations.
    Enable { zone: ZoneName },
    /// Disable maintenance mode and resume normal operation.
    Disable { zone: ZoneName },
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
            ZoneCommand::Add(cmd) => cmd.execute(client).await,
            ZoneCommand::Edit(cmd) => cmd.execute(client).await,
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

                if response.zones.is_empty() {
                    eprintln!("No zones to show");
                }

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
            ZoneCommand::Status(cmd) => cmd.execute(client).await,
            ZoneCommand::History(cmd) => cmd.execute(client).await,
            ZoneCommand::Maintenance { maintenance } => {
                let (name, state) = match &maintenance {
                    Maintenance::Enable { zone } => (zone, "enable"),
                    Maintenance::Disable { zone } => (zone, "disable"),
                };
                let url = format!("/zone/{name}/maintenance/{state}");
                let result: ZoneMaintenanceModeResult = client.post_json(&url).await?;

                match result {
                    Ok(_) => {
                        if let Maintenance::Enable { .. } = maintenance {
                            println!(
                                "Maintenance mode for zone `{name}` is now {}enabled{}",
                                ansi::BOLD,
                                ansi::RESET
                            );
                            println!("");
                            println!(
                                "Cascade will no longer automatically start new loading and signing operations"
                            );
                            println!(
                                "Run {}`cascade zone maintenance stop {name}`{} to resume automatic operation",
                                ansi::BLUE,
                                ansi::RESET,
                            );
                        } else {
                            println!(
                                "Maintenance mode for zone `{name}` is now {}disabled{}",
                                ansi::BOLD,
                                ansi::RESET
                            );
                            println!("");
                            println!(
                                "Cascade will automatically start new loading and signing operations when appropriate."
                            );
                        }
                        Ok(())
                    }
                    Err(err) => match err {
                        ZoneMaintenanceModeError::NoSuchZone => {
                            Err(format!("zone `{name}` does not exist"))
                        }
                        ZoneMaintenanceModeError::AlreadyInThatState => Err(format!(
                            "maintenance mode for zone `{name}` was already {state}d"
                        )),
                    },
                }
            }
            ZoneCommand::SetLastSignedSerial { name, serial } => {
                let url = format!("/zone/{name}/{serial}/set-last-signed-serial");
                let result: SetLastSignedSerialResult = client.post_json(&url).await?;

                match result {
                    Ok(()) => {
                        println!("Set last signed serial of zone '{name}' to {serial}");
                        Ok(())
                    }
                    Err(SetLastSignedSerialError::NoSuchZone) => {
                        Err(format!("Zone '{name}' could not be found"))
                    }
                }
            }
        }
    }
}

//------------ ZoneSource ----------------------------------------------------

const DEFAULT_NS_PORT: u16 = 53;

/// How to load the contents of a zone.
#[derive(Debug, Clone)]
pub enum ZoneSource {
    /// Don't load the zone at all.
    None,

    /// From a zonefile on disk.
    Zonefile {
        /// The path to the zonefile.
        path: Box<Utf8Path>,
    },

    /// From a DNS server via XFR.
    Server {
        /// The address of the server.
        addr: SocketAddr,

        /// The name of a TSIG key, if any.
        tsig_key: Option<Box<TsigKeyName>>,
    },
}

impl ValueParserFactory for ZoneSource {
    type Parser = ZoneSourceParser;

    fn value_parser() -> Self::Parser {
        ZoneSourceParser
    }
}

#[derive(Clone)]
pub struct ZoneSourceParser;

/// Support parsing of `-source` command line arguments.
///
/// Supported forms:
///   - `<IP>[:<PORT>][^<TSIG_KEY_NAME>]`
///   - `<PATH/TO/ZONE/FILE/TO/LOAD>`
impl TypedValueParser for ZoneSourceParser {
    type Value = ZoneSource;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let Some(s) = value.to_str() else {
            // Use `clap`'s built-in parser to format a nice error message.
            return Err(StringValueParser::new()
                .parse_ref(cmd, arg, value)
                .unwrap_err());
        };

        // Split out any provided TSIG key from the rest of the
        // source argument.
        let (addr, tsig_key) = s.split_once('^').unwrap_or((s, ""));

        let tsig_key = if !tsig_key.is_empty() {
            Some(Box::new(tsig_key.parse().map_err(|err| {
                clap::Error::raw(clap::error::ErrorKind::InvalidValue, err).with_cmd(cmd)
            })?))
        } else {
            None
        };

        if let Ok(addr) = addr.parse::<SocketAddr>() {
            Ok(ZoneSource::Server { addr, tsig_key })
        } else if let Ok(addr) = addr.parse::<IpAddr>() {
            Ok(ZoneSource::Server {
                addr: SocketAddr::new(addr, DEFAULT_NS_PORT),
                tsig_key,
            })
        } else {
            Ok(ZoneSource::Zonefile {
                path: Utf8PathBuf::from(s).into_boxed_path(),
            })
        }
    }
}

impl fmt::Display for ZoneSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZoneSource::None => f.write_str("none"),
            ZoneSource::Zonefile { path } => write!(f, "zonefile '{path}'"),
            ZoneSource::Server {
                addr,
                tsig_key: None,
            } => write!(f, "server {addr}"),
            ZoneSource::Server {
                addr,
                tsig_key: Some(tsig_key),
            } => write!(f, "server {addr} with TSIG key '{tsig_key}'"),
        }
    }
}

impl From<ZoneSource> for cascade_api::ZoneSource {
    fn from(source: ZoneSource) -> Self {
        match source {
            ZoneSource::None => Self::None,
            ZoneSource::Zonefile { path } => Self::Zonefile { path },
            ZoneSource::Server { addr, tsig_key } => Self::Server { addr, tsig_key },
        }
    }
}

impl From<cascade_api::ZoneSource> for ZoneSource {
    fn from(source: cascade_api::ZoneSource) -> Self {
        match source {
            cascade_api::ZoneSource::None => Self::None,
            cascade_api::ZoneSource::Zonefile { path } => Self::Zonefile { path },
            cascade_api::ZoneSource::Server { addr, tsig_key } => Self::Server { addr, tsig_key },
        }
    }
}
