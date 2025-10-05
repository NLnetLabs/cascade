/// Commands to manage HSM (KMIP) servers used by Cascade.
///
/// Uses HSM as the user facing term rather than KMIP as most users likely
/// know the term HSM better than the term KMIP.
///
/// We offer subcommands to manage HSM servers because configuring HSMs via
/// configuration instead would require Cascade to be restarted to change
/// HSM settings and it is unclear how Cascade should then proceed if the
/// HSM cannot be connected to or is not usable, and fixing the issue might
/// require yet more restarts.
use std::{
    io::{self, Read},
    path::PathBuf,
    time::Duration,
};

use clap::Subcommand;
use futures::TryFutureExt;
use jiff::{Span, SpanRelativeTo};

use crate::{
    api::{
        HsmServerAdd, HsmServerAddError, HsmServerAddResult, HsmServerGetResult,
        HsmServerListResult, PolicyInfo, PolicyInfoError, PolicyListResult,
    },
    cli::client::{format_http_error, CascadeApiClient},
    units::http_server::KmipServerState,
};

/// The default TCP port on which to connect to a KMIP server as defined by
/// IANA.
// TODO: Move this to the `kmip-protocol` crate?
const DEF_KMIP_PORT: u16 = 5696;

const ONE_MEGABYTE: u64 = 1024 * 1024;

#[derive(Clone, Debug, clap::Args)]
pub struct Hsm {
    #[command(subcommand)]
    command: HsmCommand,
}

impl Hsm {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            HsmCommand::AddServer {
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

                let res: Result<HsmServerAddResult, HsmServerAddError> = client
                    .post("kmip")
                    .json(&HsmServerAdd {
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
                    .map_err(format_http_error)?;

                match res {
                    Ok(HsmServerAddResult { vendor_id }) => {
                        println!("Added KMIP server '{vendor_id}'.")
                    }
                    Err(err) => return Err(format!("Add KMIP server command failed: {err}")),
                }
            }

            HsmCommand::ListServers => {
                let res: HsmServerListResult = client
                    .get("kmip")
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(format_http_error)?;

                for server in res.servers {
                    println!("{server}");
                }
            }

            HsmCommand::GetServer { server_id } => {
                let res: Result<HsmServerGetResult, ()> = client
                    .get(&format!("kmip/{server_id}"))
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(format_http_error)?;

                match res {
                    Ok(res) => {
                        print_server(&res.server);
                        print!("Policies using this HSM:");
                        let policies = get_policy_names_using_hsm(client, &server_id).await?;

                        if policies.is_empty() {
                            println!(" None");
                        } else {
                            println!();
                            for policy_name in policies {
                                println!("  - {policy_name}");
                            }
                        }
                    }
                    Err(()) => return Err(format!("HSM '{server_id}' not known.")),
                }
            } // HsmCommand::RemoveServer { server_id } => {
              //     // To remove a server we need to know that it is not in
              //     // use. To know that we have to enumerate the policies
              //     // looking for those that use this server id, and
              //     // check if the policy is itself in use by any zones.
              //     todo!();
              // }
        }
        Ok(())
    }
}

async fn get_policy_names_using_hsm(
    client: CascadeApiClient,
    server_id: &String,
) -> Result<Vec<String>, String> {
    let mut policies_using_hsm = vec![];
    let res: PolicyListResult = client
        .get("policy/")
        .send()
        .and_then(|r| r.json())
        .await
        .map_err(format_http_error)?;
    for policy_name in res.policies {
        let res: Result<PolicyInfo, PolicyInfoError> = client
            .get(&format!("policy/{policy_name}"))
            .send()
            .and_then(|r| r.json())
            .await
            .map_err(format_http_error)?;

        let p = match res {
            Ok(p) => p,
            Err(e) => {
                return Err(format!("Unable to inspect policy '{policy_name}': {e:?}"));
            }
        };

        if let Some(hsm_server_id) = &p.key_manager.hsm_server_id {
            if hsm_server_id == server_id {
                policies_using_hsm.push(policy_name);
            }
        }
    }
    Ok(policies_using_hsm)
}

fn print_server(
    KmipServerState {
        server_id,
        ip_host_or_fqdn,
        port,
        insecure,
        connect_timeout,
        read_timeout,
        write_timeout,
        max_response_bytes,
        key_label_prefix,
        key_label_max_bytes,
        has_credentials,
    }: &KmipServerState,
) {
    let none = "<none>".to_string();
    println!("{server_id}:");
    println!("  address: {ip_host_or_fqdn}");
    println!("  port: {port}");
    println!("  insecure: {}", if *insecure { "yes" } else { "no" });
    println!("  limits:");
    println!("    connect timeout: {}s", connect_timeout.as_secs());
    println!("    read timeout: {}s", read_timeout.as_secs());
    println!("    write timeout: {}s", write_timeout.as_secs());
    println!("    max response size: {max_response_bytes} bytes");
    println!("  key label:");
    println!("    prefix: {}", key_label_prefix.as_ref().unwrap_or(&none));
    println!("    max size: {key_label_max_bytes} bytes");
    println!(
        "  has credentials: {}",
        if *has_credentials { "yes" } else { "no " }
    );
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

//------------ HsmCommand ----------------------------------------------------

/// Commands for configuring the use of KMIP compatible HSMs.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Subcommand)]
pub enum HsmCommand {
    /// Add a KMIP server to use for key generation & signing.
    ///
    /// If this is the first KMIP server to be configured it will be set
    /// as the default KMIP server which will be used to generate new keys
    /// instead of using Ring/OpenSSL based key generation.
    ///
    /// If this is NOT the first KMIP server to be configured, the default
    /// KMIP server will be left as-is, either unset or set to an existing
    /// KMIP server.
    #[command(name = "add")]
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

    /// Get the details of an existing KMIP server.
    #[command(name = "show")]
    GetServer {
        /// The identifier of the KMIP server to get.
        server_id: String,
    },

    /// List all configured KMIP servers.
    #[command(name = "list")]
    ListServers,
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
