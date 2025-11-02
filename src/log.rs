//! Logging from Cascade.

use std::ffi::OsString;
use std::fmt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

use tracing::field::{self, Field};
use tracing::{Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::Layer as FmtLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload::Handle;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{reload, EnvFilter, Layer, Registry};

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
    /// Panics if a global [`tracing`] logger has been set already.
    pub fn launch(config: &LoggingConfig) -> Result<&'static Logger, String> {
        let filter = make_env_filter(config)?;

        // A reload layer is tracing's way of making it possible to change
        // values at runtime. It gives us a handle we can use to update the
        // EnvFilter when the config changes.
        let (filter, filter_handle) = reload::Layer::new(filter);

        let target = PrimaryLogger::new(config.target.value()).map_err(|e| e.to_string())?;

        match target {
            #[cfg(unix)]
            PrimaryLogger::Syslog => {
                use std::net::{Ipv4Addr, SocketAddr};

                // We try the following protocols and addresses to reach syslog:
                //  - unix sockets:
                //      - /dev/log
                //      - /var/run/syslog
                //      - /var/run/log
                //  - tcp: localhost:601
                //  - udp: localhost:514

                let paths = ["/dev/log", "/var/run/syslog", "/var/run/log"];

                let transport = if let Some(unix) = paths.iter().find_map(|p| connect_unix(p).ok())
                {
                    Transport::Unix(unix)
                } else if let Ok(tcp) = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, 601)) {
                    Transport::Tcp(tcp)
                } else if let Ok(udp) = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
                    Transport::Udp {
                        local: udp,
                        server: SocketAddr::from((Ipv4Addr::LOCALHOST, 514)),
                    }
                } else {
                    panic!("Can't connect to syslog");
                };

                let (app_name, proc_id) = get_process_info();

                // We have our own layer for sending messages to syslog. It is
                // possible in the future to use this in addition to printing to
                // stdout or a file if we wanted to (especially to a file might
                // be useful).
                let layer = Syslog {
                    facility: 1, // User level
                    hostname: hostname::get().unwrap(),
                    app_name,
                    proc_id,
                    transport,
                };

                tracing_subscriber::registry()
                    .with(filter)
                    .with(layer)
                    .init()
            }
            PrimaryLogger::File { file } => {
                // We never emit colors to files, otherwise we use the normal
                // tracing-subscriber.
                let layer = FmtLayer::new().with_ansi(false).with_writer(file);
                tracing_subscriber::registry()
                    .with(filter)
                    .with(layer)
                    .init()
            }
            PrimaryLogger::Stdout => {
                // We try to determine whether to use colors in a bit more fancy
                // way than tracing does automatically (it only does `NO_COLOR`).
                let layer = FmtLayer::new()
                    .with_ansi(supports_color::on(supports_color::Stream::Stdout).is_some())
                    .with_writer(std::io::stdout);
                tracing_subscriber::registry()
                    .with(filter)
                    .with(layer)
                    .init()
            }
            PrimaryLogger::Stderr => {
                // We try to determine whether to use colors in a bit more fancy
                // way than tracing does automatically (it only does `NO_COLOR`).
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

/// Make a new [`EnvFilter`] based on the config
///
/// Every time we load the config, we have to create a new [`EnvFilter`] based
/// on the new config settings.
fn make_env_filter(config: &LoggingConfig) -> Result<EnvFilter, String> {
    // Create an EnvFilter which won't read any env vars and only print ERROR
    // by default, which we then immediately override by adding another filter
    // on top.
    let mut filter = EnvFilter::default();
    filter = filter.add_directive(LevelFilter::from(*config.level.value()).into());

    // Add all of our trace targets to the filter.
    for target in config.trace_targets.value().iter() {
        filter = filter.add_directive(
            target
                .parse()
                .map_err(|_| format!("invalid trace target: \'{}\'", target))?,
        );
    }

    Ok(filter)
}

/// Get the name of the current executable and the process id
fn get_process_info() -> (OsString, u32) {
    let name = std::env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(|os_name| os_name.to_owned()))
        .unwrap_or_default();

    (name, std::process::id())
}

/// Connect to a unix socket
fn connect_unix(path: impl AsRef<Path>) -> std::io::Result<UnixDatagram> {
    let sock = UnixDatagram::unbound()?;
    sock.connect(path.as_ref())?;
    Ok(sock)
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

/// Implements the BSD syslog protocol as a [`tracing`] layer
///
/// The syslog format is defined by [RFC 3164].
//
/// [RFC 3164]: https://www.rfc-editor.org/rfc/rfc3164
struct Syslog {
    facility: u8,
    hostname: OsString,
    app_name: OsString,
    proc_id: u32,
    transport: Transport,
}

/// Transports for the syslog logger
#[derive(Debug)]
enum Transport {
    Unix(std::os::unix::net::UnixDatagram),
    Udp {
        local: std::net::UdpSocket,
        server: std::net::SocketAddr,
    },
    Tcp(std::net::TcpStream),
}

impl Transport {
    fn send(&self, buf: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        match self {
            Transport::Unix(unix_stream) => {
                unix_stream.send(buf)?;
            }
            Transport::Udp { local, server } => {
                local.send_to(buf, server)?;
            }
            Transport::Tcp(tcp_stream) => {
                let mut s: &std::net::TcpStream = tcp_stream;
                s.write_all(buf)?;
                s.flush()?;
            }
        }
        Ok(())
    }
}

// We implement a Layer instead of a subscriber for Syslog simply because
// it is simpler, since we only care about `on_event`.
impl<S> Layer<S> for Syslog
where
    S: Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        use std::io::Write;

        let meta = event.metadata();

        // Map tracing levels to syslog levels
        let severity = match *meta.level() {
            Level::ERROR => 3,
            Level::WARN => 4,
            Level::INFO => 6,
            Level::DEBUG | Level::TRACE => 7,
        };

        // RFC 3164 says that the priority value is calculated by first
        // multiplying the Facility number by 8 and then adding the numerical
        // value of the severity.
        let prival = self.facility << 3 | severity;

        // The timestamp must be in "Mmm dd hh:mm:ss" format in local time.
        // Important is also that the day part must be padded to 2 characters
        // with a space.
        let timestamp = jiff::Zoned::now().strftime("%b %e %T");

        let hostname = self.hostname.to_string_lossy();

        let app_name = self.app_name.to_string_lossy();

        let proc_id = &self.proc_id;

        let mut buf = Vec::new();

        // This is the format defined by RFC 3164.
        // Writing to buf won't fail because it's just a Vec.
        let _ = write!(
            buf,
            "<{prival}>{timestamp} {hostname} {app_name}[{proc_id}]: "
        );

        // We use a custom visitor to extract the message from tracing, which
        // (because it's fully structured) they hide in the structured data.
        let mut visitor = Visitor {
            writer: &mut buf,
            result: Ok(()),
        };

        event.record(&mut visitor);

        let _ = buf.write(b"\n");

        self.transport
            .send(&buf)
            .expect("Our logger broke, we might as well crash");
    }
}

struct Visitor<'a> {
    writer: &'a mut Vec<u8>,
    result: std::io::Result<()>,
}

impl field::Visit for Visitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if self.result.is_err() {
            return;
        }

        if field.name() == "message" {
            self.record_debug(field, &format_args!("{}", value))
        } else {
            self.record_debug(field, &value)
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        use std::io::Write;

        if self.result.is_err() {
            return;
        }

        if field.name() == "message" {
            self.result = write!(self.writer, "{value:?}");
        }
    }
}
