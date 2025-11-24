//! Logging from Cascade.
//!
//! Cascade using [`tracing`] to collect and produce log messages.  Unlike the
//! more traditional [`log`] crate, [`tracing`] can record _spans_ (ranges of
//! time over which actions occur) and follow asynchronous code coherently.
//!
//! [`log`]: https://docs.rs/log
//!
//! Cascade supports logging to standard output, standard error, to a file, or
//! (on UNIX systems) to syslog.  It uses [`tracing_subscriber::fmt`] to achieve
//! this for the most part, and manually implements syslog output.  It supports
//! colorized output and (limited) dynamic reconfiguration.

use camino::Utf8Path;
use tracing::Subscriber;
use tracing_subscriber::{layer::SubscriberExt, reload, util::SubscriberInitExt, Registry};

use crate::config::{LogLevel, LogTarget, LoggingConfig, RuntimeConfig};

//----------- Logger -----------------------------------------------------------

/// Cascade's logger.
///
/// This is implemented with [`tracing_subscriber`].  The constructed logger is
/// set as the global default.  The subscriber is structured thusly:
///
/// - A [`Filter`] that decides whether something should be logged.  It is
///   wrapped in [`reload::Layer`] so it can be reloaded dynamically.
///
/// - For standard output/error and file targets: a [`fmt::Layer`] that
///   prettifies log messages appropriately (including conditional colorization)
///   and writes text to the appropriate I/O sink.
///
/// - For syslog: a [`Syslog`] layer formats log lines as per RFC 3164 and
///   writes them to a UNIX socket.
///
/// - A [`tracing_subscriber::Registry`] wraps the whole thing together and
///   handles [`tracing`]-specific bookkeeping (e.g. tracking spans).
#[derive(Debug)]
pub struct Logger {
    /// A handle for dynamically changing what is logged.
    handle: reload::Handle<Filter, Registry>,
}

impl Logger {
    /// Launch the Cascade logger.
    ///
    /// The logger will be configured as per the provided [`LoggingConfig`]
    /// (which does not include dynamic runtime changes, since this should be
    /// called during initialization).
    ///
    /// ## Panics
    ///
    /// Panics if a global [`tracing`] logger has been set already.
    pub fn launch(config: &LoggingConfig) -> Result<Self, LaunchError> {
        // Construct the filter that decides how data will be logged.
        let (filter, handle) = reload::Layer::new(Filter::new(config));

        // Construct the writer layer.
        //
        // Different targets produce different writer types here, so code can't
        // be shared after this split.
        match config.target.value() {
            LogTarget::File(path) => tracing_subscriber::registry()
                .with(filter)
                .with(new_file_writer(path)?)
                .init(),

            LogTarget::Stdout => tracing_subscriber::registry()
                .with(filter)
                .with(new_stdout_writer())
                .init(),

            LogTarget::Stderr => tracing_subscriber::registry()
                .with(filter)
                .with(new_stderr_writer())
                .init(),

            #[cfg(unix)]
            LogTarget::Syslog => tracing_subscriber::registry()
                .with(filter)
                .with(new_syslog_writer()?)
                .init(),
        }

        Ok(Self { handle })
    }

    /// Apply a runtime change to the logging configuration.
    pub fn apply(&self, rt_config: &RuntimeConfig) {
        self.handle
            .modify(|filter| filter.update(rt_config))
            .unwrap_or_else(|err| panic!("the logger panicked: {err}"));
    }
}

//----------- Filter -----------------------------------------------------------

/// A [`tracing_subscriber`] layer that decides which logs to output.
#[derive(Debug)]
struct Filter {
    /// The currently set log level.
    level: tracing::Level,

    /// Targets for which to enable trace logging.
    trace_targets: foldhash::HashSet<Box<str>>,
}

impl Filter {
    /// Construct a new [`Filter`].
    pub fn new(config: &LoggingConfig) -> Self {
        Self {
            level: (*config.level.value()).into(),
            trace_targets: config.trace_targets.value().clone(),
        }
    }

    /// Update this [`Filter`] based on runtime configuration.
    pub fn update(&mut self, rt_config: &RuntimeConfig) {
        if let Some(level) = rt_config.log_level {
            self.level = level.into();
        }
        if let Some(trace_targets) = &rt_config.log_trace_targets {
            self.trace_targets = trace_targets.clone();
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Filter {
    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        self.level >= *metadata.level() || self.trace_targets.contains(metadata.target())
    }
}

//----------- Writer initialization --------------------------------------------

/// Construct a writer layer for targeting a file.
fn new_file_writer<S>(path: &Utf8Path) -> Result<impl tracing_subscriber::Layer<S>, LaunchError>
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let file = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)
        .map_err(|error| LaunchError::Open {
            path: path.into(),
            error,
        })?;

    let layer = tracing_subscriber::fmt::Layer::new()
        .with_ansi(false)
        .with_writer(file);

    Ok(layer)
}

/// Construct a writer layer for targeting standard output.
fn new_stdout_writer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    // Override 'tracing_subscriber's simple colorization detector with
    // 'supports_color', which is far more thorough.
    tracing_subscriber::fmt::Layer::new()
        .with_ansi(supports_color::on(supports_color::Stream::Stdout).is_some())
        .with_writer(std::io::stdout)
}

/// Construct a writer layer for targeting a file.
fn new_stderr_writer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    // Override 'tracing_subscriber's simple colorization detector with
    // 'supports_color', which is far more thorough.
    tracing_subscriber::fmt::Layer::new()
        .with_ansi(supports_color::on(supports_color::Stream::Stdout).is_some())
        .with_writer(std::io::stdout)
}

/// Construct a new writer layer for targeting UNIX syslog.
#[cfg(unix)]
fn new_syslog_writer<S: Subscriber>() -> Result<impl tracing_subscriber::Layer<S>, LaunchError> {
    self::unix::Syslog::init().map_err(LaunchError::Syslog)
}

//----------- unix -------------------------------------------------------------

#[cfg(unix)]
mod unix {
    use std::{
        ffi::OsStr,
        fmt,
        io::{self, Write},
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket},
        os::unix::{ffi::OsStrExt, net::UnixDatagram},
        path::Path,
        time::Duration,
    };

    use tracing::{field::Field, Subscriber};

    use crate::eprintln;

    //------- Syslog -----------------------------------------------------------

    /// A [`tracing_subscriber`] writer layer for syslog.
    ///
    /// This will format syslog messages as per [RFC 3164].
    //
    /// [RFC 3164]: https://www.rfc-editor.org/rfc/rfc3164
    #[derive(Debug)]
    pub struct Syslog {
        /// What type of program is logging the message.
        pub facility: u8,

        /// The hostname of the system.
        pub hostname: Box<OsStr>,

        /// The name of the application.
        pub app_name: Box<OsStr>,

        /// The process ID.
        pub pid: u32,

        /// How to communicate with the syslog daemon.
        pub transport: Transport,
    }

    impl Syslog {
        /// Initialize a [`Syslog`] writer.
        pub fn init() -> Result<Self, InitError> {
            // 1 = LOG_USER; "generic user-level messages"
            //
            // TODO: Use 'LOG_DAEMON' since Cascade is a daemon?
            let facility = 1;

            // Determine the system hostname.
            let hostname = hostname::get()
                .map_err(InitError::HostName)?
                .into_boxed_os_str();

            // Determine a "name" for the current application.
            //
            // Use the file name of the current executable, in case the user
            // has named it something relevant to themselves.  If the path we
            // find doesn't have a file name (for some weird reason), just use
            // the whole path.
            let app_name = std::env::current_exe().map_err(InitError::AppName)?;
            let app_name = app_name
                .file_name()
                .map(|name| name.into())
                .unwrap_or_else(|| app_name.into_os_string().into_boxed_os_str());

            let pid = std::process::id();

            // Connect to some transport.
            let transport = Transport::connect().map_err(InitError::Connect)?;

            Ok(Self {
                facility,
                hostname,
                app_name,
                pid,
                transport,
            })
        }
    }

    impl<S: Subscriber> tracing_subscriber::Layer<S> for Syslog {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            // Map tracing levels to syslog levels.
            let severity = match *event.metadata().level() {
                tracing::Level::ERROR => 3,
                tracing::Level::WARN => 4,
                tracing::Level::INFO => 6,
                tracing::Level::DEBUG | tracing::Level::TRACE => 7,
            };

            // RFC 3164 says that the priority value is calculated by first
            // multiplying the Facility number by 8 and then adding the
            // numerical value of the severity.
            let prival = self.facility * 8 + severity;

            // The timestamp must be in "Mmm dd hh:mm:ss" format in local
            // time. Important is also that the day part must be padded to 2
            // characters with a space.
            let timestamp = jiff::Zoned::now().strftime("%b %e %T");

            // TODO: Use a thread-local buffer?
            let mut buf = Vec::new();

            // This is the format defined by RFC 3164.
            write!(buf, "<{prival}>{timestamp} ").expect("'Vec::write()' never fails");
            buf.extend_from_slice(self.hostname.as_bytes());
            buf.push(b' ');
            buf.extend_from_slice(self.app_name.as_bytes());
            write!(buf, "[{}]: ", self.pid).expect("'Vec::write()' never fails");

            // Extract the primary message within the event.
            //
            // TODO: The interface 'tracing' gives us is quite frustrating, it
            // would be nice to help them with alternatives.
            let mut visitor = Visitor(&mut buf);
            event.record(&mut visitor);
            buf.push(b'\n');

            match self.transport.send(&buf) {
                Ok(()) => {}
                Err(error) => {
                    // TODO: Report into a proper fallback logger.
                    eprintln!("Logging failed: {error:?}");
                }
            }
        }
    }

    struct Visitor<'a>(&'a mut Vec<u8>);

    impl tracing::field::Visit for Visitor<'_> {
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() != "message" {
                return;
            }

            self.0.extend_from_slice(value.as_bytes());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            if field.name() != "message" {
                return;
            }

            write!(self.0, "{value:?}").expect("'Vec::write()' never fails");
        }
    }

    //------- Transport --------------------------------------------------------

    /// How to communicate with a syslog daemon.
    #[derive(Debug)]
    pub enum Transport {
        Unix(UnixDatagram),
        Tcp(TcpStream),
        Udp(UdpSocket),
    }

    /// A method by which to communicate with a syslog daemon.
    #[derive(Clone, Debug)]
    pub enum Port<P: AsRef<Path>> {
        Unix(P),
        Udp(SocketAddr),
        Tcp(SocketAddr),
    }

    impl Transport {
        /// Connect to the syslog daemon.
        pub fn connect() -> Result<Self, ConnectError> {
            // Standard ports where we expect to find the daemon.
            let ports = [
                Port::Unix("/dev/log"),
                Port::Unix("/var/run/syslog"),
                Port::Unix("/var/run/log"),
                Port::Tcp((Ipv6Addr::LOCALHOST, 601).into()),
                Port::Tcp((Ipv4Addr::LOCALHOST, 601).into()),
                Port::Udp((Ipv6Addr::LOCALHOST, 514).into()),
                Port::Udp((Ipv4Addr::LOCALHOST, 514).into()),
            ];

            // Keep track of how every attempt fails.
            let mut attempts = Vec::new();
            for port in ports {
                match Self::connect_to(&port) {
                    Ok(this) => return Ok(this),
                    Err(error) => attempts.push((port, error)),
                }
            }

            // We couldn't find a single way to connect to the syslog daemon.
            // Report the error we encountered with each of our attempts.
            Err(ConnectError {
                attempts: attempts.into_boxed_slice(),
            })
        }

        /// Connect to a syslog daemon via a particular port.
        pub fn connect_to<P: AsRef<Path>>(port: &Port<P>) -> io::Result<Self> {
            match port {
                Port::Unix(path) => {
                    let socket = UnixDatagram::unbound()?;
                    socket.connect(path)?;
                    Ok(Self::Unix(socket))
                }
                Port::Tcp(addr) => {
                    let socket = TcpStream::connect_timeout(addr, Duration::from_secs(1))?;
                    socket.set_nodelay(true)?;
                    Ok(Self::Tcp(socket))
                }
                Port::Udp(SocketAddr::V4(addr)) => {
                    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
                    socket.connect(addr)?;
                    Ok(Self::Udp(socket))
                }
                Port::Udp(SocketAddr::V6(addr)) => {
                    let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?;
                    socket.connect(addr)?;
                    Ok(Self::Udp(socket))
                }
            }
        }

        /// Send a packet to the syslog daemon.
        fn send(&self, buf: &[u8]) -> io::Result<()> {
            match self {
                Transport::Unix(s) => {
                    s.send(buf)?;
                }
                Transport::Tcp(s) => {
                    // NOTE: We used 'TcpStream::set_nodelay()'.
                    let mut s = s;
                    s.write_all(buf)?;
                }
                Transport::Udp(s) => {
                    s.send(buf)?;
                }
            }
            Ok(())
        }
    }

    //======== Errors ==========================================================

    /// An error in [`Syslog::init()`].
    #[derive(Debug)]
    pub enum InitError {
        AppName(io::Error),
        HostName(io::Error),
        Connect(ConnectError),
    }

    /// An error in connecting to a syslog daemon.
    #[derive(Debug)]
    pub struct ConnectError<P: AsRef<Path> = &'static str> {
        /// Attempts to connect to different ports.
        pub attempts: Box<[(Port<P>, io::Error)]>,
    }
}

//----------- LaunchError ------------------------------------------------------

/// An error in [`Logger::launch()`].
#[derive(Debug)]
pub enum LaunchError {
    /// The target file could not be opened.
    Open {
        /// The path to the file.
        path: Box<Utf8Path>,

        /// The underlying I/O error.
        error: std::io::Error,
    },

    /// The syslog writer could not be initialized.
    #[cfg(unix)]
    Syslog(unix::InitError),
}

//------------------------------------------------------------------------------

impl From<LogLevel> for tracing::Level {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warning => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
            LogLevel::Critical => tracing::Level::ERROR,
        }
    }
}
