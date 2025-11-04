use std::fmt::{self, Display};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use camino::{Utf8Path, Utf8PathBuf};
use domain::base::{Name, Serial};
use domain::zonetree::StoredName;
use serde::{Deserialize, Serialize};

use crate::center;
use crate::units::http_server::KmipServerState;
use crate::units::zone_loader::ZoneLoaderReport;
use crate::zone::{HistoryItem, PipelineMode};
use crate::zonemaintenance::types::{SigningQueueReport, SigningReport, ZoneRefreshStatus};

const DEFAULT_AXFR_PORT: u16 = 53;

//----------- ZoneReview -------------------------------------------------------

/// Review a version of a zone.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneReview {}

/// A stage for reviewing a zone.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneReviewStage {
    /// Before signing.
    Unsigned,

    /// After signing.
    Signed,
}

/// A decision upon reviewing a zone.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneReviewDecision {
    /// Approve the zone.
    Approve,

    /// Reject the zone.
    Reject,
}

/// The result of a [`ZoneReview`] command.
pub type ZoneReviewResult = Result<ZoneReviewOutput, ZoneReviewError>;

/// The output of a [`ZoneReview`] command.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneReviewOutput {}

/// An error from a [`ZoneReview`] command.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneReviewError {
    /// The specified zone could not be found.
    NoSuchZone,

    /// The specified version of the zone was not being reviewed.
    NotUnderReview,
}

impl std::fmt::Display for ZoneReviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZoneReviewError::NoSuchZone => f.write_str("No such zone"),
            ZoneReviewError::NotUnderReview => f.write_str("Zone not under review"),
        }
    }
}

//------------------------------------------------------------------------------

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum KeyImport {
    PublicKey(Utf8PathBuf),
    Kmip(KmipKeyImport),
    File(FileKeyImport),
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct FileKeyImport {
    pub key_type: KeyType,
    pub path: Utf8PathBuf,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct KmipKeyImport {
    pub key_type: KeyType,
    pub server: String,
    pub public_id: String,
    pub private_id: String,
    pub algorithm: String,
    pub flags: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneAdd {
    pub name: Name<Bytes>,
    pub source: ZoneSource,
    pub policy: String,
    pub key_imports: Vec<KeyImport>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneAddResult {
    pub name: Name<Bytes>,
    pub status: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneAddError {
    AlreadyExists,
    NoSuchPolicy,
    PolicyMidDeletion,
    Other(String),
}

impl fmt::Display for ZoneAddError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AlreadyExists => "a zone of this name already exists",
            Self::NoSuchPolicy => "no policy with that name exists",
            Self::PolicyMidDeletion => "the specified policy is being deleted",
            Self::Other(reason) => reason,
        })
    }
}

impl From<center::ZoneAddError> for ZoneAddError {
    fn from(value: center::ZoneAddError) -> Self {
        match value {
            center::ZoneAddError::AlreadyExists => Self::AlreadyExists,
            center::ZoneAddError::NoSuchPolicy => Self::NoSuchPolicy,
            center::ZoneAddError::PolicyMidDeletion => Self::PolicyMidDeletion,
            center::ZoneAddError::Other(reason) => Self::Other(reason),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneRemoveResult {
    pub name: Name<Bytes>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneRemoveError {
    NotFound,
}

impl fmt::Display for ZoneRemoveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no such zone was found",
        })
    }
}

impl From<center::ZoneRemoveError> for ZoneRemoveError {
    fn from(value: center::ZoneRemoveError) -> Self {
        match value {
            center::ZoneRemoveError::NotFound => Self::NotFound,
        }
    }
}

/// How to load the contents of a zone.
#[derive(Deserialize, Serialize, Debug, Clone)]
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
        tsig_key: Option<String>,

        /// The XFR status of the zone.
        xfr_status: ZoneRefreshStatus,
    },
}

impl Display for ZoneSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZoneSource::None => f.write_str("<none>"),
            ZoneSource::Zonefile { path } => path.fmt(f),
            ZoneSource::Server { addr, .. } => addr.fmt(f),
        }
    }
}

impl From<&str> for ZoneSource {
    fn from(s: &str) -> Self {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            ZoneSource::Server {
                addr,
                tsig_key: None,
                xfr_status: Default::default(),
            }
        } else if let Ok(addr) = s.parse::<IpAddr>() {
            ZoneSource::Server {
                addr: SocketAddr::new(addr, DEFAULT_AXFR_PORT),
                tsig_key: None,
                xfr_status: Default::default(),
            }
        } else {
            ZoneSource::Zonefile {
                path: Utf8PathBuf::from(s).into_boxed_path(),
            }
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZonesListResult {
    pub zones: Vec<StoredName>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZoneStage {
    Unsigned,
    // TODO: Signed is not strictly correct as it is currently set based on
    // the presence of a zone in the signed zones collection, but that happens
    // at the start of the signing process, not only once a zone has finished
    // being signed.
    Signed,
    Published,
}

impl Display for ZoneStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ZoneStage::Unsigned => "loader",
            ZoneStage::Signed => "signer",
            ZoneStage::Published => "publication server",
        };
        f.write_str(str)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneStatusError {
    ZoneDoesNotExist,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneStatus {
    pub name: Name<Bytes>,
    pub source: ZoneSource,
    pub policy: String,
    pub stage: ZoneStage,
    pub keys: Vec<KeyInfo>,
    pub key_status: String,
    pub receipt_report: Option<ZoneLoaderReport>,
    pub unsigned_serial: Option<Serial>,
    pub unsigned_review_status: Option<TimestampedZoneReviewStatus>,
    pub unsigned_review_addr: Option<SocketAddr>,
    pub signed_serial: Option<Serial>,
    pub signed_review_status: Option<TimestampedZoneReviewStatus>,
    pub signed_review_addr: Option<SocketAddr>,
    pub signing_report: Option<SigningReport>,
    pub published_serial: Option<Serial>,
    pub publish_addr: SocketAddr,
    pub pipeline_mode: PipelineMode,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct TimestampedZoneReviewStatus {
    pub status: ZoneReviewStatus,
    pub when: SystemTime,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum ZoneReviewStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyInfo {
    pub pubref: String,
    pub key_type: KeyType,
    pub key_tag: u16,
    pub signer: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum KeyType {
    Ksk,
    Zsk,
    Csk,
}

impl Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Ksk => "ksk",
            KeyType::Csk => "csk",
            KeyType::Zsk => "zsk",
        }
        .fmt(f)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneHistory {
    pub history: Vec<HistoryItem>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneHistoryError {
    ZoneDoesNotExist,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneReloadResult {
    pub name: Name<Bytes>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneReloadError {
    ZoneDoesNotExist,
    ZoneWithoutSource,
    ZoneHalted(String),
}

impl fmt::Display for ZoneReloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZoneDoesNotExist => "no zone with this name exist",
            Self::ZoneWithoutSource => "the specified zone has no source configured",
            Self::ZoneHalted(reason) => {
                return write!(f, "the zone has been halted (reason: {reason})")
            }
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ServerStatusResult {
    pub soft_halted_zones: Vec<(StoredName, String)>,
    pub hard_halted_zones: Vec<(StoredName, String)>,
    pub signing_queue: Vec<SigningQueueReport>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct KeyStatusResult {
    pub expirations: Vec<KeyExpiration>,
    pub zones: Vec<KeysPerZone>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct KeyExpiration {
    pub zone: String,
    pub key: String,
    pub time_left: Option<Duration>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct KeysPerZone {
    pub zone: String,
    pub keys: Vec<KeyMsg>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct KeyMsg {
    pub name: String,
    pub msg: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum PolicyReloadError {
    Io(Utf8PathBuf, String),
}

impl Display for PolicyReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let PolicyReloadError::Io(p, e) = self;
        format!("{p}: {e}").fmt(f)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PolicyChanges {
    pub changes: Vec<(String, PolicyChange)>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PolicyListResult {
    pub policies: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PolicyInfo {
    pub name: Box<str>,
    pub zones: Vec<Name<Bytes>>,
    pub loader: LoaderPolicyInfo,
    pub key_manager: KeyManagerPolicyInfo,
    pub signer: SignerPolicyInfo,
    pub server: ServerPolicyInfo,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct LoaderPolicyInfo {
    pub review: ReviewPolicyInfo,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct KeyManagerPolicyInfo {
    pub hsm_server_id: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ReviewPolicyInfo {
    pub required: bool,
    pub cmd_hook: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SignerPolicyInfo {
    pub serial_policy: SignerSerialPolicyInfo,
    // TODO: These fields should have a type that explains that they represent durations.
    pub sig_inception_offset: u32,
    pub sig_validity_offset: u32,
    pub denial: SignerDenialPolicyInfo,
    pub review: ReviewPolicyInfo,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum SignerSerialPolicyInfo {
    Keep,
    Counter,
    UnixTime,
    DateCounter,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum SignerDenialPolicyInfo {
    NSec,
    NSec3 { opt_out: bool },
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum Nsec3OptOutPolicyInfo {
    Disabled,
    FlagOnly,
    Enabled,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ServerPolicyInfo {
    pub outbound: OutboundPolicyInfo,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct OutboundPolicyInfo {
    pub accept_xfr_requests_from: Vec<NameserverCommsPolicyInfo>,
    pub send_notify_to: Vec<NameserverCommsPolicyInfo>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NameserverCommsPolicyInfo {
    pub addr: SocketAddr,
}

impl std::fmt::Display for NameserverCommsPolicyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum PolicyInfoError {
    PolicyDoesNotExist,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum PolicyChange {
    Added,
    Removed,
    Updated,
    Unchanged,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct HsmServerAdd {
    pub server_id: String,
    pub ip_host_or_fqdn: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub client_cert: Option<Vec<u8>>,
    pub client_key: Option<Vec<u8>>,
    pub insecure: bool,
    pub server_cert: Option<Vec<u8>>,
    pub ca_cert: Option<Vec<u8>>,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub max_response_bytes: u32,
    pub key_label_prefix: Option<String>,
    pub key_label_max_bytes: u8,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct HsmServerAddResult {
    pub vendor_id: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum HsmServerAddError {
    UnableToConnect {
        server_id: String,
        host: String,
        port: u16,
        err: String,
    },
    UnableToQuery {
        server_id: String,
        host: String,
        port: u16,
        err: String,
    },
    CredentialsFileCouldNotBeOpenedForWriting {
        // Path is not needed as the error already contains it.
        err: String,
    },
    CredentialsFileCouldNotBeSaved {
        // Path is not needed as the error already contains it.
        err: String,
    },
    KmipServerStateFileCouldNotBeCreated {
        path: String,
        err: String,
    },
    KmipServerStateFileCouldNotBeSaved {
        path: String,
        err: String,
    },
}

impl std::fmt::Display for HsmServerAddError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HsmServerAddError::UnableToConnect {
                server_id,
                host,
                port,
                err,
            } => write!(
                f,
                "Unable to connect to HSM '{server_id}' at {host}:{port}: {err}"
            ),
            HsmServerAddError::UnableToQuery {
                server_id,
                host,
                port,
                err,
            } => write!(
                f,
                "Unable to query HSM '{server_id}' at {host}:{port}: {err}"
            ),
            HsmServerAddError::CredentialsFileCouldNotBeOpenedForWriting { err } => {
                // The error already contains everything we want to say so
                // don't duplicate it.
                f.write_str(err)
            }
            HsmServerAddError::CredentialsFileCouldNotBeSaved { err } => {
                // The error already contains everything we want to say so
                // don't duplicate it.
                f.write_str(err)
            }
            HsmServerAddError::KmipServerStateFileCouldNotBeCreated { path, err } => {
                write!(f, "Unable to create KMIP server state file '{path}': {err}")
            }
            HsmServerAddError::KmipServerStateFileCouldNotBeSaved { path, err } => {
                write!(f, "Unable to save KMIP server state file '{path}': {err}")
            }
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct HsmServerListResult {
    pub servers: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct HsmServerGetResult {
    pub server: KmipServerState,
}

//------------ KeySet API Types ----------------------------------------------

pub mod keyset {
    use super::*;

    #[derive(Deserialize, Serialize, Debug, Clone)]
    pub struct KeyRoll {
        pub variant: KeyRollVariant,
        pub cmd: KeyRollCommand,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    pub struct KeyRemove {
        pub key: String,
        pub force: bool,
        pub continue_flag: bool,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    pub enum KeyRollVariant {
        /// Apply the subcommand to a KSK roll.
        Ksk,
        /// Apply the subcommand to a ZSK roll.
        Zsk,
        /// Apply the subcommand to a CSK roll.
        Csk,
        /// Apply the subcommand to an algorithm roll.
        Algorithm,
    }

    #[derive(Deserialize, Serialize, Clone, Debug, clap::Subcommand)]
    pub enum KeyRollCommand {
        /// Start a key roll.
        StartRoll,
        /// Report that the first propagation step has completed.
        Propagation1Complete {
            /// The TTL that is required to be reported by the Report actions.
            ttl: u32,
        },
        /// Cached information from before Propagation1Complete should have
        /// expired by now.
        CacheExpired1,
        /// Report that the second propagation step has completed.
        Propagation2Complete {
            /// The TTL that is required to be reported by the Report actions.
            ttl: u32,
        },
        /// Cached information from before Propagation2Complete should have
        /// expired by now.
        CacheExpired2,
        /// Report that the final changes have propagated and the the roll is done.
        RollDone,
    }
}
