use std::fmt::{Display, Write};

use cascade_api::{ZoneName, ZoneStatusError, ZoneXfrStatus};

use crate::{
    api::{self, ChangeLogging, ChangeLoggingResult, TraceTarget},
    client::CascadeApiClient,
    commands::zone::to_rfc3339,
};

#[derive(Clone, Debug, clap::Args)]
pub struct Debug {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Command {
    /// Change how Cascade logs information.
    ///
    /// Note that these changes are not persisted across restarts.
    ///
    /// At least one option of 'level' or 'trace-targets' is required.
    #[command(name = "change-logging")]
    ChangeLogging {
        /// The new log level to use.
        #[arg(short = 'l', long = "level", required_unless_present_any = ["trace_targets"])]
        level: Option<LogLevel>,

        /// The new trace targets to use.
        ///
        /// These are names of Cascade modules for which trace-level logging
        /// will be enabled, even if the overall log level is lower.
        #[arg(long = "trace-targets", value_delimiter = ',')]
        trace_targets: Option<Vec<String>>,
    },

    /// Inspect internal XFR status information.
    #[command(name = "xfr-status")]
    XfrStatus { zone: ZoneName },
}

impl Debug {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            Command::ChangeLogging {
                level,
                trace_targets,
            } => {
                let mut msg = String::new();

                if let Some(level) = &level {
                    writeln!(msg, "Changed log-level to: {level}").unwrap();
                }

                if let Some(targets) = &trace_targets {
                    let targets = targets.join(", ");
                    writeln!(msg, "Changed trace targets to: {targets}").unwrap();
                }

                let level = level.map(Into::into);
                let trace_targets = trace_targets.map(|t| t.into_iter().map(TraceTarget).collect());

                let (): ChangeLoggingResult = client
                    .post_json_with(
                        "debug/change-logging",
                        &ChangeLogging {
                            level,
                            trace_targets,
                        },
                    )
                    .await?;

                print!("{msg}");
                Ok(())
            }

            Command::XfrStatus { zone } => {
                let url = format!("zone/{}/xfr-status", zone);
                let response: Result<ZoneXfrStatus, ZoneStatusError> =
                    client.get_json(&url).await?;
                match response {
                    Ok(report) => {
                        println!("zone: {}", report.name);
                        print!("refresh status: ");
                        match report.refresh_timer_state {
                            cascade_api::RefreshTimerState::Disabled => println!("disabled"),
                            cascade_api::RefreshTimerState::Refresh {
                                previous,
                                scheduled,
                            } => {
                                let previous = to_rfc3339(previous);
                                let scheduled = to_rfc3339(scheduled);
                                println!("refreshing: last={previous}, next={scheduled}");
                            }
                            cascade_api::RefreshTimerState::Retry {
                                previous,
                                scheduled,
                            } => {
                                let previous = to_rfc3339(previous);
                                let scheduled = to_rfc3339(scheduled);
                                println!("retrying: last={previous}, next={scheduled}");
                            }
                        }
                        Ok(())
                    }
                    Err(ZoneStatusError::ZoneDoesNotExist) => {
                        Err(format!("zone `{zone}` does not exist"))
                    }
                }
            }
        }
    }
}

//------------------------------------------------------------------------------

/// A logging level.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum LogLevel {
    /// A function or variable was interacted with, for debugging.
    Trace,

    /// Something occurred that may be relevant to debugging.
    Debug,

    /// Things are proceeding as expected.
    Info,

    /// Something does not appear to be correct.
    Warning,

    /// Something is wrong (but Cascade can recover).
    Error,

    /// Something is wrong and Cascade can't function at all.
    Critical,
}

impl From<LogLevel> for api::LogLevel {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => Self::Trace,
            LogLevel::Debug => Self::Debug,
            LogLevel::Info => Self::Info,
            LogLevel::Warning => Self::Warning,
            LogLevel::Error => Self::Error,
            LogLevel::Critical => Self::Critical,
        }
    }
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                LogLevel::Trace => "trace",
                LogLevel::Debug => "debug",
                LogLevel::Info => "info",
                LogLevel::Warning => "warning",
                LogLevel::Error => "error",
                LogLevel::Critical => "critical",
            }
        )
    }
}
