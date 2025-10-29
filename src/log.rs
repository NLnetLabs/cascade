//! Logging from Cascade.

use std::fmt;

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::Layer as FmtLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload::Handle;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{reload, EnvFilter, Registry};

use crate::config::{LogLevel, LogTarget, LoggingConfig};

//----------- Logger -----------------------------------------------------------

/// The state of the Cascade logger.
pub struct Logger {
    filter: Handle<EnvFilter, Registry>,
}

impl std::fmt::Debug for Logger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Logger")
            .field("filter", &self.filter)
            .finish()
    }
}

impl Logger {
    /// Launch the Cascade logger.
    ///
    /// ## Panics
    ///
    /// Panics if a [`log`] logger has been set already.
    pub fn launch(config: &LoggingConfig) -> Result<&'static Logger, String> {
        let mut filter = EnvFilter::from_env("CASCADE_LOG");
        filter = filter.add_directive(LevelFilter::from(*config.level.value()).into());
        for target in config.trace_targets.value().iter() {
            filter = filter.add_directive(
                target
                    .parse()
                    .map_err(|_| format!("invalid trace target: \'{}\'", target))?,
            );
        }
        let (filter, filter_handle) = reload::Layer::new(filter);

        let target = PrimaryLogger::new(config.target.value()).map_err(|e| e.to_string())?;

        match target {
            #[cfg(unix)]
            PrimaryLogger::Syslog => {
                if let Ok(tcp) = tracing_rfc_5424::transport::TcpTransport::try_default() {
                    let layer = tracing_rfc_5424::layer::Layer::with_transport(tcp);
                    tracing_subscriber::registry()
                        .with(filter)
                        .with(layer)
                        .init()
                } else {
                    let udp = tracing_rfc_5424::transport::UdpTransport::local().unwrap();
                    let layer = tracing_rfc_5424::layer::Layer::with_transport(udp);
                    tracing_subscriber::registry()
                        .with(filter)
                        .with(layer)
                        .init()
                }
            }
            PrimaryLogger::File { file } => {
                let layer = FmtLayer::new().with_ansi(false).with_writer(file);
                tracing_subscriber::registry()
                    .with(filter)
                    .with(layer)
                    .init()
            }
            PrimaryLogger::Stdout => {
                let layer = FmtLayer::new()
                    .with_ansi(supports_color::on(supports_color::Stream::Stdout).is_some())
                    .with_writer(std::io::stdout);
                tracing_subscriber::registry()
                    .with(filter)
                    .with(layer)
                    .init()
            }
            PrimaryLogger::Stderr => {
                let layer = FmtLayer::new()
                    .with_ansi(supports_color::on(supports_color::Stream::Stderr).is_some())
                    .with_writer(std::io::stderr);
                tracing_subscriber::registry()
                    .with(filter)
                    .with(layer)
                    .init()
            }
        };

        Ok(Box::leak(Box::new(Self {
            filter: filter_handle,
        })))
    }

    pub fn apply(&self, config: &LoggingConfig) -> Result<(), String> {
        self.filter
            .reload(make_env_filter(config)?)
            .map_err(|_| "could not reload filter".into())
    }
}

fn make_env_filter(config: &LoggingConfig) -> Result<EnvFilter, String> {
    let mut filter = EnvFilter::from_env("CASCADE_LOG");
    filter = filter.add_directive(LevelFilter::from(*config.level.value()).into());
    for target in config.trace_targets.value().iter() {
        filter = filter.add_directive(
            target
                .parse()
                .map_err(|_| format!("invalid trace target: \'{}\'", target))?,
        );
    }
    Ok(filter)
}

/// A primary logger.
enum PrimaryLogger {
    /// A file logger.
    //
    // TODO: Attach a per-thread buffer here.
    File {
        /// The actual file.
        file: std::fs::File,
    },

    /// A syslog logger.
    #[cfg(unix)]
    Syslog,

    /// A logger to stdout.
    Stdout,

    /// A logger to stderr.
    Stderr,
}

impl PrimaryLogger {
    /// Initialize a new [`PrimaryLogger`].
    pub fn new(config: &LogTarget) -> Result<Self, std::io::Error> {
        match config {
            LogTarget::File(path) => {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&**path)?;

                Ok(Self::File { file })
            }
            LogTarget::Syslog => Ok(Self::Syslog),
            LogTarget::Stdout => Ok(Self::Stdout),
            LogTarget::Stderr => Ok(Self::Stderr),
        }
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
            LogLevel::Critical => LevelFilter::ERROR, // TODO
        }
    }
}
