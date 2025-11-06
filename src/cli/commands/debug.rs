use std::{convert::Infallible, str::FromStr};

use clap::{builder::PossibleValue, ValueEnum};
use futures::TryFutureExt;

use crate::{
    api::{ChangeLogging, ChangeLoggingResult, LogLevel, TraceTarget},
    cli::client::{format_http_error, CascadeApiClient},
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
        /// will be enabled, even the overall log level is lower.
        #[arg(long = "trace-targets")]
        trace_targets: Option<Vec<TraceTarget>>,
    },
}

impl Debug {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            Command::ChangeLogging {
                level,
                trace_targets,
            } => {
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

impl ValueEnum for LogLevel {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warning,
            LogLevel::Error,
            LogLevel::Critical,
        ]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(PossibleValue::new(match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
            LogLevel::Critical => "critical",
        }))
    }
}

impl FromStr for TraceTarget {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: Validate the trace target syntax?
        Ok(Self(s.into()))
    }
}
