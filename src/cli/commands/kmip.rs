use std::{
    io::{self, Read},
    path::PathBuf,
    time::Duration,
};

use clap::Subcommand;
use futures::TryFutureExt;
use jiff::{Span, SpanRelativeTo};

use crate::{
    api::{KmipServerAdd, KmipServerAddResult},
    cli::client::CascadeApiClient,
};

/// The default TCP port on which to connect to a KMIP server as defined by
/// IANA.
// TODO: Move this to the `kmip-protocol` crate?
const DEF_KMIP_PORT: u16 = 5696;

const ONE_MEGABYTE: u64 = 1024 * 1024;

#[derive(Clone, Debug, clap::Args)]
pub struct Kmip {
    #[command(subcommand)]
    command: KmipCommand,
}

impl Kmip {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            KmipCommand::AddServer {
                server_id,
                ip_host_or_fqdn,
                port,
                username,
                password,
                client_cert_path,
                client_key_path,
                insecure,
                server_cert_path,
                ca_cert_path,
                connect_timeout,
                read_timeout,
                write_timeout,
                max_response_bytes,
                key_label_prefix,
                key_label_max_bytes,
            } => {
                // Read files into memory.
                let client_cert =
                    read_binary_file(client_cert_path.as_ref()).map_err(|e| e.to_string())?;
                let client_key =
                    read_binary_file(client_key_path.as_ref()).map_err(|e| e.to_string())?;
                let server_cert =
                    read_binary_file(server_cert_path.as_ref()).map_err(|e| e.to_string())?;
                let ca_cert = read_binary_file(ca_cert_path.as_ref()).map_err(|e| e.to_string())?;

                let _res: KmipServerAddResult = client
                    .post("kmip")
                    .json(&KmipServerAdd {
                        server_id,
                        ip_host_or_fqdn,
                        port,
                        username,
                        password,
                        client_cert,
                        client_key,
                        insecure,
                        server_cert,
                        ca_cert,
                        connect_timeout,
                        read_timeout,
                        write_timeout,
                        max_response_bytes,
                        key_label_prefix,
                        key_label_max_bytes,
                    })
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(|e| format!("HTTP request failed: {e}"))?;

                println!("Success: Sent add KMIP server command");
            }
        }
        Ok(())
    }
}

fn read_binary_file(p: Option<&PathBuf>) -> std::io::Result<Option<Vec<u8>>> {
    let Some(p) = p else {
        return Ok(None);
    };
    let mut f = std::fs::File::open(p)?;
    let len = f.metadata()?.len();
    if len > ONE_MEGABYTE {
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    let mut buf = Vec::with_capacity(len as usize);
    f.read_to_end(&mut buf)?;
    Ok(Some(buf))
}

//------------ KmipCommands --------------------------------------------------

/// Commands for configuring the use of KMIP compatible HSMs.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Subcommand)]
pub enum KmipCommand {
    /// Disable use of KMIP for generating new keys.
    ///
    /// Existing KMIP keys will still work as normal, but any new keys will
    /// be generated using Ring/OpenSSL whether or not KMIP servers are
    /// configured.
    ///
    /// To re-enable KMIP use: kmip set-default-server.
    // Disable,

    /// Add a KMIP server to use for key generation & signing.
    ///
    /// If this is the first KMIP server to be configured it will be set
    /// as the default KMIP server which will be used to generate new keys
    /// instead of using Ring/OpenSSL based key generation.
    ///
    /// If this is NOT the first KMIP server to be configured, the default
    /// KMIP server will be left as-is, either unset or set to an existing
    /// KMIP server.
    ///
    /// Use 'kmip set-default-server' to change the default KMIP server.
    AddServer {
        /// An identifier to refer to the KMIP server by.
        ///
        /// This identifier is used in KMIP key URLs. The identifier serves
        /// several purposes:
        ///
        /// 1. To make it easy at a glance to recognize which KMIP server a
        ///    given key was created on, by allowing operators to assign a
        ///    meaningful name to the server instead of whatever identity
        ///    strings the server associates with itself or by using hostnames
        ///    or IP addresses as identifiers.
        ///
        /// 2. To refer to additional configuration elsewhere to avoid
        ///    including sensitive and/or verbose KMIP server credential or
        ///    TLS client certificate/key authentication data in the URL,
        ///    and which would be repeated in every key created on the same
        ///    server.
        ///
        /// 3. To allow the actual location of the server and/or its access
        ///    credentials to be rotated without affecting the key URLs, e.g.
        ///    if a server is assigned a new IP address or if access
        ///    credentials change.
        ///
        /// The downside of this is that consumers of the key URL must also
        /// possess the additional configuration settings and be able to fetch
        /// them based on the same server identifier.
        server_id: String,

        /// The hostname or IP address of the KMIP server.
        ip_host_or_fqdn: String,

        /// TCP port to connect to the KMIP server on.
        #[arg(help_heading = "Server", long = "port", default_value_t = DEF_KMIP_PORT)]
        port: u16,

        /// Optional username to authenticate to the KMIP server as.
        ///
        /// TODO: Also support taking the username in via STDIN or environment
        /// variable or file or other source?
        #[arg(help_heading = "Client Credentials", long = "username")]
        username: Option<String>,

        /// Optional password to authenticate to the KMIP server with.
        ///
        /// TODO: Also support taking the password in via STDIN or environment
        /// variable or file or other source?
        #[arg(
            help_heading = "Client Credentials",
            long = "password",
            requires = "username"
        )]
        password: Option<String>,

        /// Optional path to a TLS certificate to authenticate to the KMIP
        /// server with. The file will be read and sent to the server.
        #[arg(
            help_heading = "Client Certificate Authentication",
            long = "client-cert",
            requires = "client_key_path"
        )]
        client_cert_path: Option<PathBuf>,

        /// Optional path to a private key for client certificate
        /// authentication. THe file will be read and sent to the server.
        ///
        /// The private key is needed to be able to prove to the KMIP server
        /// that you are the owner of the provided TLS client certificate.
        #[arg(
            help_heading = "Client Certificate Authentication",
            long = "client-key",
            requires = "client_cert_path"
        )]
        client_key_path: Option<PathBuf>,

        /// Whether or not to accept the KMIP server TLS certificate without
        /// verifying it.
        ///
        /// Set to false if using a self-signed TLS certificate, e.g. in a
        /// test environment.
        #[arg(help_heading = "Server Certificate Verification", long = "insecure", default_value_t = false, action = clap::ArgAction::SetTrue)]
        insecure: bool,

        /// Optional path to a TLS PEM certificate for the server.
        #[arg(help_heading = "Server Certificate Verification", long = "server-cert")]
        server_cert_path: Option<PathBuf>,

        /// Optional path to a TLS PEM certificate for a Certificate Authority.
        #[arg(help_heading = "Server Certificate Verification", long = "ca-cert")]
        ca_cert_path: Option<PathBuf>,

        /// TCP connect timeout.
        // Note: This should be low otherwise the CLI user experience when
        // running a command that interacts with a KMIP server, like `dnst
        // init`, is that the command hangs if the KMIP server is not running
        // or not reachable, until the timeout expires, and one would expect
        // that under normal circumstances establishing a TCP connection to
        // the KMIP server should be quite quick.
        // Note: Does this also include time for TLS setup?
        #[arg(help_heading = "Client Limits", long = "connect-timeout", value_parser = parse_duration, default_value = "3s")]
        connect_timeout: Duration,

        /// TCP response read timeout.
        // Note: This should be high otherwise for HSMs that are slow to
        // respond, like the YubiHSM, we time out the connection while waiting
        // for the response when generating keys.
        #[arg(help_heading = "Client Limits", long = "read-timeout", value_parser = parse_duration, default_value = "30s")]
        read_timeout: Duration,

        /// TCP request write timeout.
        #[arg(help_heading = "Client Limits", long = "write-timeout", value_parser = parse_duration, default_value = "3s")]
        write_timeout: Duration,

        /// Maximum KMIP response size to accept (in bytes).
        #[arg(
            help_heading = "Client Limits",
            long = "max-response-bytes",
            default_value_t = 8192
        )]
        max_response_bytes: u32,

        /// Optional user supplied key label prefix.
        ///
        /// Can be used to denote the s/w that created the key, and/or to
        /// indicate which installation/environment it belongs to, e.g. dev,
        /// test, prod, etc.
        #[arg(help_heading = "Key Labels", long = "key-label-prefix")]
        key_label_prefix: Option<String>,

        /// Maximum label length (in bytes) permitted by the HSM.
        #[arg(
            help_heading = "Key Labels",
            long = "key-label-max-bytes",
            default_value_t = 32
        )]
        key_label_max_bytes: u8,
    },
    // /// Modify an existing KMIP server configuration.
    // ModifyServer {
    //     /// The identifier of the KMIP server.
    //     server_id: String,

    //     /// Modify the hostname or IP address of the KMIP server.
    //     #[arg(help_heading = "Server", long = "address")]
    //     ip_host_or_fqdn: Option<String>,

    //     /// Modify the TCP port to connect to the KMIP server on.
    //     #[arg(help_heading = "Server", long = "port")]
    //     port: Option<u16>,

    //     /// Disable use of username / password authentication.
    //     ///
    //     /// Note: This will remove any credentials from the credential-store
    //     /// for this server id.
    //     #[arg(help_heading = "Client Credentials", long = "no-credentials", action = clap::ArgAction::SetTrue)]
    //     no_credentials: bool,

    //     /// Modify the path to a JSON file to read/write username/password
    //     /// credentials from/to.
    //     #[arg(help_heading = "Client Credentials", long = "credential-store")]
    //     credentials_store_path: Option<PathBuf>,

    //     /// Modifyt the username to authenticate to the KMIP server as.
    //     #[arg(help_heading = "Client Credentials", long = "username")]
    //     username: Option<String>,

    //     /// Modify the password to authenticate to the KMIP server with.
    //     #[arg(help_heading = "Client Credentials", long = "password")]
    //     password: Option<String>,

    //     /// Disable use of TLS client certificate authentication.
    //     #[arg(help_heading = "Client Certificate Authentication", long = "no-client-auth", action = clap::ArgAction::SetTrue)]
    //     no_client_auth: bool,

    //     /// Modify the path to the TLS certificate to authenticate to the KMIP
    //     /// server with.
    //     #[arg(
    //         help_heading = "Client Certificate Authentication",
    //         long = "client-cert"
    //     )]
    //     client_cert_path: Option<PathBuf>,

    //     /// Modify the path to the private key for client certificate
    //     /// authentication.
    //     #[arg(
    //         help_heading = "Client Certificate Authentication",
    //         long = "client-key"
    //     )]
    //     client_key_path: Option<PathBuf>,

    //     /// Modify whether or not to accept the KMIP server TLS certificate
    //     /// without verifying it.
    //     #[arg(help_heading = "Server Certificate Verification", long = "insecure")]
    //     insecure: Option<bool>,

    //     /// Modify the path to a TLS PEM certificate for the server.
    //     #[arg(help_heading = "Server Certificate Verification", long = "server-cert")]
    //     server_cert_path: Option<PathBuf>,

    //     /// Optional path to a TLS PEM certificate for a Certificate Authority.
    //     #[arg(help_heading = "Server Certificate Verification", long = "ca-cert")]
    //     ca_cert_path: Option<PathBuf>,

    //     /// Modify the TCP connect timeout.
    //     #[arg(help_heading = "Client Limits", long = "connect-timeout", value_parser = parse_duration)]
    //     connect_timeout: Option<Duration>,

    //     /// Modify the TCP response read timeout.
    //     #[arg(help_heading = "Client Limits", long = "read-timeout", value_parser = parse_duration)]
    //     read_timeout: Option<Duration>,

    //     /// Modify the TCP request write timeout.
    //     #[arg(help_heading = "Client Limits", long = "write-timeout", value_parser = parse_duration)]
    //     write_timeout: Option<Duration>,

    //     /// Modify the maximum KMIP response size to accept (in bytes).
    //     #[arg(help_heading = "Client Limits", long = "max-response-bytes")]
    //     max_response_bytes: Option<u32>,

    //     /// Optional user supplied key label prefix.
    //     ///
    //     /// Can be used to denote the s/w that created the key, and/or to
    //     /// indicate which installation/environment it belongs to, e.g. dev,
    //     /// test, prod, etc.
    //     #[arg(help_heading = "Key Labels", long = "key-label-prefix")]
    //     key_label_prefix: Option<String>,

    //     /// Maximum label length (in bytes) permitted by the HSM.
    //     #[arg(help_heading = "Key Labels", long = "key-label-max-bytes")]
    //     key_label_max_bytes: Option<u8>,
    // },

    // /// Remove an existing non-default KMIP server.
    // ///
    // /// To remove the default KMIP server use `kmip disable` first.
    // RemoveServer {
    //     /// The identifier of the KMIP server to remove.
    //     server_id: String,
    // },

    // /// Set the default KMIP server to use for key generation.
    // SetDefaultServer {
    //     /// The identifier of the KMIP server to use as the default.
    //     server_id: String,
    // },

    // /// Get the details of an existing KMIP server.
    // GetServer {
    //     /// The identifier of the KMIP server to get.
    //     server_id: String,
    // },

    // /// List all configured KMIP servers.
    // ListServers,
}

/// Parse a duration from a string with suffixes like 'm', 'h', 'w', etc.
pub fn parse_duration(value: &str) -> Result<Duration, Error> {
    let span: Span = value
        .parse()
        .map_err::<Error, _>(|e| format!("unable to parse {value} as lifetime: {e}\n").into())?;
    let signeddur = span
        .to_duration(SpanRelativeTo::days_are_24_hours())
        .map_err::<Error, _>(|e| format!("unable to convert duration: {e}\n").into())?;
    Duration::try_from(signeddur).map_err(|e| format!("unable to convert duration: {e}\n").into())
}

/// Parse an optional duration from a string but also allow 'off' to signal
/// no duration.
fn parse_opt_duration(value: &str) -> Result<Option<Duration>, Error> {
    if value == "off" {
        return Ok(None);
    }
    let duration = parse_duration(value)?;
    Ok(Some(duration))
}

#[derive(Clone, Debug)]
pub struct Error(String);

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error(err.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}
