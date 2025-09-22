use std::fmt::{self, Display};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use camino::{Utf8Path, Utf8PathBuf};
use domain::base::Name;
use serde::{Deserialize, Serialize};

use crate::center;

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
    },
}

impl Display for ZoneSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZoneSource::None => f.write_str("<none>"),
            ZoneSource::Zonefile { path } => path.fmt(f),
            ZoneSource::Server { addr, tsig_key: _ } => addr.fmt(f),
        }
    }
}

impl From<&str> for ZoneSource {
    fn from(s: &str) -> Self {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            ZoneSource::Server {
                addr,
                tsig_key: None,
            }
        } else if let Ok(addr) = s.parse::<IpAddr>() {
            ZoneSource::Server {
                addr: SocketAddr::new(addr, DEFAULT_AXFR_PORT),
                tsig_key: None,
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
    pub zones: Vec<ZoneStatus>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneStage {
    Unsigned,
    Signed,
    Published,
}

impl Display for ZoneStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ZoneStage::Unsigned => "unsigned",
            ZoneStage::Signed => "signed",
            ZoneStage::Published => "published",
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
    pub key_status: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneReloadResult {
    pub name: Name<Bytes>,
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
pub struct KeyManagerPolicyInfo {}

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
        DnstCommandError {
            status: String,
            stdout: String,
            stderr: String,
        },
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
        DnstCommandError {
            status: String,
            stdout: String,
            stderr: String,
        },
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
