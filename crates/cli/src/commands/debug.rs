use futures_util::TryFutureExt;

use crate::{
    api::{self, ChangeLogging, ChangeLoggingResult, TraceTarget},
    client::{CascadeApiClient, format_http_error},
    println,
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
    #[command(name = "change-logging")]
    ChangeLogging {
        // The new log level to use.
        #[arg(short = 'l', long = "level")]
        level: Option<LogLevel>,

        /// The new trace targets to use.
        ///
        /// These are names of Cascade modules for which trace-level logging
        /// will be enabled, even if the overall log level is lower.
        #[arg(long = "trace-targets")]
        trace_targets: Option<Vec<String>>,
    },
}

impl Debug {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            Command::ChangeLogging {
                level,
                trace_targets,
            } => {
                let level = level.map(Into::into);
                let trace_targets = trace_targets.map(|t| t.into_iter().map(TraceTarget).collect());
                let (): ChangeLoggingResult = client
                    .post("debug/change-logging")
                    .json(&ChangeLogging {
                        level,
                        trace_targets,
                    })
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(format_http_error)?;

                println!("Updated logging behavior");
                Ok(())
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
