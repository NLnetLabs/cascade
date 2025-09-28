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
use crate::zone::PipelineMode;
use crate::zonemaintenance::types::{SigningReport, ZoneRefreshStatus};

const DEFAULT_AXFR_PORT: u16 = 53;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneAdd {
    pub name: Name<Bytes>,
    pub source: ZoneSource,
    pub policy: String,
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
}

impl fmt::Display for ZoneAddError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AlreadyExists => "a zone of this name already exists",
            Self::NoSuchPolicy => "no policy with that name exists",
            Self::PolicyMidDeletion => "the specified policy is being deleted",
        })
    }
}

impl From<center::ZoneAddError> for ZoneAddError {
    fn from(value: center::ZoneAddError) -> Self {
        match value {
            center::ZoneAddError::AlreadyExists => Self::AlreadyExists,
            center::ZoneAddError::NoSuchPolicy => Self::NoSuchPolicy,
            center::ZoneAddError::PolicyMidDeletion => Self::PolicyMidDeletion,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneRemoveResult {}

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
    pub key_status: Option<String>,
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
    // pub name: Name<Bytes>,
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
    pub sig_inception_offset: Duration,
    pub sig_validity_offset: Duration,
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
pub struct ServerPolicyInfo {}

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
    UnableToConnect,
    UnableToQuery,
    CredentialsFileCouldNotBeOpenedForWriting,
    CredentialsFileCouldNotBeSaved,
    KmipServerStateFileCouldNotBeCreated,
    KmipServerStateFileCouldNotBeSaved,
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
    pub struct KeyRollResult {
        pub zone: Name<Bytes>,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    pub enum KeyRollError {
        DnstCommandError(String),
        RxError,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    pub struct KeyRemove {
        pub key: String,
        pub force: bool,
        pub continue_flag: bool,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    pub struct KeyRemoveResult {
        pub zone: Name<Bytes>,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    pub enum KeyRemoveError {
        DnstCommandError(String),
        RxError,
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
