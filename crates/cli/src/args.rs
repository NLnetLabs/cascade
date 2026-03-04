use std::fmt;
use std::net::SocketAddr;

use clap::Parser;
use clap::builder::PossibleValue;
use tracing::level_filters::LevelFilter;

use super::client::CascadeApiClient;
use super::commands::Command;

#[derive(Clone, Debug, Parser)]
#[command(version = env!("CASCADE_BUILD_VERSION"), disable_help_subcommand = true)]
pub struct Args {
    /// The cascade server instance to connect to
    #[arg(
        short = 's',
        long = "server",
        value_name = "IP:PORT",
        default_value = "127.0.0.1:4539",
        global = true
    )]
    pub server: SocketAddr,

    /// The minimum severity of messages to log
    #[arg(
        long = "log-level",
        value_name = "LEVEL",
        default_value = "warning",
        global = true
    )]
    pub log_level: LogLevel,

    #[command(subcommand)]
    pub command: Command,
}

impl Args {
    pub async fn execute(self) -> Result<(), String> {
        let client = CascadeApiClient::new(format!("http://{}", self.server));
        self.command.execute(client).await
    }
}

//----------- LogLevel ---------------------------------------------------------

/// A severity level for logging.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl LogLevel {
    /// Represent a [`LogLevel`] as a string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
            LogLevel::Critical => "critical",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl clap::ValueEnum for LogLevel {
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
        Some(PossibleValue::new(self.as_str()))
    }
}

impl From<LogLevel> for LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Warning => LevelFilter::WARN,
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Critical => LevelFilter::ERROR,
        }
    }
}
