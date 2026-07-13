use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

pub use domain::base::Serial;

pub mod dep;

//----------- ZoneName ---------------------------------------------------------

/// The name of a zone.
pub type ZoneName = domain::base::Name<bytes::Bytes>;

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

//----------- ZoneReset --------------------------------------------------------

/// The result of a `zone reset` command.
pub type ZoneResetResult = Result<ZoneResetOutput, ZoneResetError>;

/// The output of a `zone reset` command.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneResetOutput {
    pub zone: ZoneName,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneResetError {
    NoSuchZone,
    NotHalted,
}

impl std::fmt::Display for ZoneResetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchZone => f.write_str("No such zone"),
            Self::NotHalted => f.write_str("Zone is not halted"),
        }
    }
}

//----------- ZoneOverride -----------------------------------------------------

/// The result of a `zone override` command.
pub type ZoneOverrideResult = Result<ZoneOverrideOutput, ZoneOverrideError>;

/// The output of a `zone override` command.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneOverrideOutput {
    pub zone: ZoneName,
    pub review_stage: ZoneReviewStage,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneOverrideError {
    NoSuchZone,
    NotRejected,
}

impl std::fmt::Display for ZoneOverrideError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchZone => f.write_str("No such zone"),
            Self::NotRejected => f.write_str("Zone has not been rejected"),
        }
    }
}

//----------- ZoneOverride -----------------------------------------------------

/// The result of a `zone maintenance start/stop` command.
pub type ZoneMaintenanceModeResult = Result<ZoneMaintenanceModeOutput, ZoneMaintenanceModeError>;

/// The output of a `zone maintenance start/stop` command.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneMaintenanceModeOutput {
    pub zone: ZoneName,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneMaintenanceModeError {
    NoSuchZone,
    AlreadyInThatState,
}

//----------- ChangeLogging ----------------------------------------------------

/// Change how Cascade logs information.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ChangeLogging {
    /// The new log level to use, if any.
    pub level: Option<LogLevel>,

    /// The new trace targets to use, if any.
    pub trace_targets: Option<Vec<TraceTarget>>,
}

/// A logging level.
#[derive(Deserialize, Serialize, Debug, Clone)]
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

/// A trace target.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TraceTarget(pub String);

/// The result of a [`ChangeLogging`] command.
pub type ChangeLoggingResult = ();

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
    pub public_key_path: Utf8PathBuf,
    pub private_key_path: Utf8PathBuf,
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

//----------- TsigKeyName -----------------------------------------------------

/// The name of a TSIG key.
pub type TsigKeyName = domain::base::Name<domain::dep::octseq::Array<255>>;

//----------- TsigAdd ---------------------------------------------------------

/// Add a TSIG key to Cascade.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TsigAdd {
    /// The name of the TSIG key to add.
    pub name: TsigKeyName,

    /// The algorithm of the TSIG key.
    pub alg: TsigAlgorithm,

    /// The base64 encoded key material bytes.
    pub secret: String,
}

/// The successful result of adding a TSIG key to Cascade.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TsigAddResult;

/// An error result indicating why an attempt to add a TSIG key to Cascade
/// failed.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum TsigAddError {
    /// A TSIG key by the given name already exists in Cascade.
    AlreadyExists,

    /// The provided TSIG key secret was not correctly base64 encoded.
    InvalidBase64Secret,
}

impl Display for TsigAddError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TsigAddError::AlreadyExists => write!(f, "TSIG key already exists"),
            TsigAddError::InvalidBase64Secret => write!(f, "invalid TSIG base64 encoded secret"),
        }
    }
}

//------------ TsigRemove ----------------------------------------------------

/// The successful result of removing a TSIG key from Cascade.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TsigRemoveResult;

/// An error result indicating why an attempt to remove a TSIG key from
/// Cascade failed.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum TsigRemoveError {
    /// The specified TSIG key name was not found in Cascade.
    NotFound,

    /// The specified TSIG key cannot be removed as it is in use.
    InUse(Vec<TsigKeyUsageReference>),
}

/// Supporting details for TsigRemoveError::InUse.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum TsigKeyUsageReference {
    /// The TSIG key is referenced by the source of the named zone.
    ZoneSource(ZoneName),

    /// The TSIG key is in use by the named zone for some other reason.
    ZoneOther(ZoneName),

    /// The TSIG key is referenced by one or more settings in the named
    /// policy.
    Policy(Box<str>),
}

impl fmt::Display for TsigKeyUsageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TsigKeyUsageReference::ZoneSource(name) => write!(f, "the source of the '{name}' zone"),
            TsigKeyUsageReference::ZoneOther(name) => write!(f, "zone '{name}'"),
            TsigKeyUsageReference::Policy(name) => write!(f, "policy '{name}"),
        }
    }
}

//------------ TsigListResult ------------------------------------------------

/// The successful result of listing TSIG Cascade keys known to Cascade.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TsigListResult {
    /// The set of TSIG keys known to Cascade plus information about each key.
    pub tsig_key_info: HashMap<TsigKeyName, TsigKeyInfo>,
}

/// Information about a single listed TSIG key.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TsigKeyInfo {
    /// The set of zones with which this TSIG key is used.
    pub zone_names: HashSet<ZoneName>,

    /// The set of policies with which this TSIG key is used.
    pub policy_names: HashSet<String>,
}

//----------- ZoneAdd --------------------------------------------------------

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneAdd {
    pub name: ZoneName,
    pub source: ZoneSource,
    pub policy: String,
    pub key_imports: Vec<KeyImport>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneAddResult {
    pub name: ZoneName,
    pub status: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneAddError {
    AlreadyExists,
    NoSuchPolicy,
    PolicyMidDeletion,
    NoSuchTsigKey,
    Other(String),
}

impl fmt::Display for ZoneAddError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AlreadyExists => "a zone of this name already exists",
            Self::NoSuchPolicy => "no policy with that name exists",
            Self::PolicyMidDeletion => "the specified policy is being deleted",
            Self::NoSuchTsigKey => "no TSIG key with that name exists",
            Self::Other(reason) => reason,
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneRemoveResult {
    pub name: ZoneName,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneRemoveError {
    NotFound,
    MidRestoration,
}

impl fmt::Display for ZoneRemoveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no such zone was found",
            Self::MidRestoration => "the zone is being restored from disk",
        })
    }
}

/// How to load the contents of a zone.
#[derive(Deserialize, Serialize, Debug, Clone)]
// Allow the large enum variant caused by TsigKeyName using Name<Array<255>>
// to avoid the conversions that would be needed if Name<Bytes> were to be
// used instead.
#[allow(clippy::large_enum_variant)]
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
        tsig_key: Option<TsigKeyName>,
    },
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub enum ZoneRefreshStatus {
    /// Refreshing according to the SOA REFRESH interval.
    #[default]
    RefreshPending,

    RefreshInProgress(usize),

    /// Periodically retrying according to the SOA RETRY interval.
    RetryPending,

    RetryInProgress,

    /// Refresh triggered by NOTIFY currently in progress.
    NotifyInProgress,
}

impl Display for ZoneSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZoneSource::None => f.write_str("<none>"),
            ZoneSource::Zonefile { path } => path.fmt(f),
            ZoneSource::Server { addr, tsig_key } => {
                write!(f, "{addr}")?;
                if let Some(tsig_key) = &tsig_key {
                    write!(f, " with TSIG key '{tsig_key}'")?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZonesListResult {
    pub zones: Vec<ZoneName>,
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
    pub name: ZoneName,
    pub source: ZoneSource,
    pub policy: String,
    pub last_published: Option<LastPublishedZone>,
    pub progress: Progress,
    pub maintenance_mode: bool,
    pub keys: Vec<KeyInfo>,
    pub key_status: String,
    pub error: Option<String>,
    pub receipt_report: Option<ZoneLoaderReport>,
    pub unsigned_serial: Option<Serial>,
    pub unsigned_review_status: Option<TimestampedZoneReviewStatus>,
    pub unsigned_review_addr: Vec<SocketAddr>,
    pub signed_serial: Option<Serial>,
    pub signed_review_status: Option<TimestampedZoneReviewStatus>,
    pub signed_review_addr: Vec<SocketAddr>,
    pub signing_report: Option<SigningReport>,
    pub published_serial: Option<Serial>,
    pub publish_addr: Vec<SocketAddr>,
    pub halted_reason: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct LastPublishedZone {
    pub loaded_serial: Serial,
    pub signed_serial: Serial,
    pub timestamp: SystemTime,
    pub num_records: usize,
    // TODO: size in bytes
}

#[derive(Deserialize, Serialize, Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Progress {
    Waiting,
    Restoring,
    Loading,
    LoadedReview,
    HaltLoaded,
    Signing,
    SigningFailed,
    SignedReview,
    HaltSigned,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZoneLoaderReport {
    pub started_at: SystemTime,
    pub finished_at: Option<SystemTime>,
    pub byte_count: usize,
    pub total_byte_count: Option<usize>,
    pub record_count: usize,
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

//----------- SigningReport ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningReport {
    pub current_action: String,
    pub stage_report: SigningStageReport,
}

//------------ SigningQueueReport -------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningQueueReport {
    pub zone_name: ZoneName,
    pub signing_report: SigningReport,
}

//------------ SigningStageReport -------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SigningStageReport {
    Requested(SigningRequestedReport),
    InProgress(SigningInProgressReport),
    Finished(SigningFinishedReport),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningRequestedReport {
    pub requested_at: SystemTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningInProgressReport {
    pub requested_at: SystemTime,
    pub zone_serial: Serial,
    pub started_at: SystemTime,
    pub unsigned_rr_count: Option<usize>,
    pub walk_time: Option<Duration>,
    pub sort_time: Option<Duration>,
    pub denial_rr_count: Option<usize>,
    pub denial_time: Option<Duration>,
    pub rrsig_count: Option<usize>,
    pub rrsig_reused_count: Option<usize>,
    pub rrsig_time: Option<Duration>,
    pub total_time: Option<Duration>,
    pub threads_used: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningFinishedReport {
    pub requested_at: SystemTime,
    pub zone_serial: Serial,
    pub started_at: SystemTime,
    pub unsigned_rr_count: usize,
    pub walk_time: Duration,
    pub sort_time: Duration,
    pub denial_rr_count: usize,
    pub denial_time: Duration,
    pub rrsig_count: usize,
    pub rrsig_reused_count: usize,
    pub rrsig_time: Duration,
    pub total_time: Duration,
    pub threads_used: usize,
    pub finished_at: SystemTime,
    pub succeeded: bool,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum TsigAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl Display for TsigAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TsigAlgorithm::HmacSha1 => "hmac-sha1",
            TsigAlgorithm::HmacSha256 => "hmac-sha256",
            TsigAlgorithm::HmacSha384 => "hmac-sha384",
            TsigAlgorithm::HmacSha512 => "hmac-sha512",
        }
        .fmt(f)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneHistory {
    pub history: Vec<HistoryItem>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum PipelineMode {
    /// Newly received zone data will flow through the pipeline.
    #[default]
    Running,

    /// The current zone data could not be fully processed through the
    /// pipeline. When new zone data is received it will flow through the
    /// pipeline as normal.
    SoftHalt(String),

    /// The current zone data could not be fully processed through the
    /// pipeline. The pipeline for this zone will remain halted until manually
    /// restarted.
    HardHalt(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryItem {
    pub when: SystemTime,
    pub serial: Option<Serial>,
    pub event: HistoricalEvent,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HistoricalEventType {
    StartedLoad,
    StartedResign,
    Added,
    Removed,
    PolicyChanged,
    SourceChanged,
    NewVersionReceived,
    SigningSucceeded,
    SigningFailed,
    UnsignedZoneReview,
    SignedZoneReview,
    UnsignedHookFailed,
    SignedHookFailed,
    KeySetCommand,
    KeySetError,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum HistoricalEvent {
    StartedLoad,
    StartedResign,
    Added,
    Removed,
    PolicyChanged,
    SourceChanged,
    NewVersionReceived,
    SigningSucceeded {
        trigger: SigningTrigger,
    },
    SigningFailed {
        trigger: SigningTrigger,
        reason: String,
    },
    UnsignedZoneReview {
        status: ZoneReviewStatus,
    },
    SignedZoneReview {
        status: ZoneReviewStatus,
    },
    UnsignedHookFailed {
        err: String,
    },
    SignedHookFailed {
        err: String,
    },
    KeySetCommand {
        cmd: String,
        warning: Option<String>,
        elapsed: Duration,
    },
    KeySetError {
        cmd: String,
        err: String,
        elapsed: Duration,
    },
    LoadingFailed {
        reason: String,
    },
}

/// The trigger for a (re-)signing operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningTrigger {
    /// A new instance of a zone has been loaded.
    Load,

    /// A trigger for re-signing.
    Resign(ResigningTrigger),
}

/// The trigger for a re-signing operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResigningTrigger {
    /// Whether zone signing keys have changed.
    pub keys_changed: bool,

    /// Whether signatures need to be refreshed.
    pub sigs_need_refresh: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ZoneHistoryError {
    ZoneDoesNotExist,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ZoneReloadResult {
    pub name: ZoneName,
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
                return write!(f, "the zone has been halted (reason: {reason})");
            }
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Health {
    pub healthy: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Info {
    pub version: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ServerStatusResult {
    pub halted_zones: Vec<(ZoneName, String)>,
    pub signing_queue: Vec<SigningQueueReport>,
    pub loaded_review_addrs: Vec<SocketAddr>,
    pub signed_review_addrs: Vec<SocketAddr>,
    pub server_addrs: Vec<SocketAddr>,
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
// Allow the large enum variant caused by TsigKeyName using Name<Array<255>>
// to avoid the conversions that would be needed if Name<Bytes> were to be
// used instead.
#[allow(clippy::large_enum_variant)]
pub enum PolicyReloadError {
    Io(Utf8PathBuf, String),
    NoSuchTsigKey(TsigKeyName),
    BadValue(String),
}

impl Display for PolicyReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyReloadError::Io(p, e) => write!(f, "{p}: {e}"),
            PolicyReloadError::NoSuchTsigKey(k) => write!(f, "no TSIG key with name '{k}' exists"),
            PolicyReloadError::BadValue(e) => write!(f, "bad value in policy variable: {e}"),
        }
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
    pub zones: Vec<ZoneName>,
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
    pub use_csk: bool,
    pub algorithm: String,
    pub ksk_validity: Option<u32>,
    pub zsk_validity: Option<u32>,
    pub csk_validity: Option<u32>,
    pub auto_ksk: AutoConfigPolicyInfo,
    pub auto_zsk: AutoConfigPolicyInfo,
    pub auto_csk: AutoConfigPolicyInfo,
    pub auto_algorithm: AutoConfigPolicyInfo,
    pub dnskey_inception_offset: u32,
    pub dnskey_signature_lifetime: u32,
    pub dnskey_remain_time: u32,
    pub cds_inception_offset: u32,
    pub cds_signature_lifetime: u32,
    pub cds_remain_time: u32,
    pub ds_algorithm: String,
    pub default_ttl: u32,
    pub auto_remove: bool,
    pub auto_remove_delay: Duration,
    pub publication_nameservers: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AutoConfigPolicyInfo {
    pub start: bool,
    pub report: bool,
    pub expire: bool,
    pub done: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ReviewPolicyInfo {
    pub mode: ReviewPolicyMode,
    pub on_reject: ReviewPolicyOnReject,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ReviewPolicyMode {
    Off,
    Manual,
    Script { hook: String },
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ReviewPolicyOnReject {
    Discard,
    Halt,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SignerPolicyInfo {
    pub serial_policy: SignerSerialPolicyInfo,
    // TODO: These fields should have a type that explains that they represent durations.
    pub sig_inception_offset: u32,
    pub sig_validity_offset: u32,
    pub sig_remain_time: u32,
    pub signature_refresh_interval: u32,
    pub key_roll_time: u32,
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
    pub provide_xfr_to: Vec<NameserverCommsPolicyInfo>,
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

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct KmipServerState {
    pub server_id: String,
    pub ip_host_or_fqdn: String,
    pub port: u16,
    pub insecure: bool,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub max_response_bytes: u32,
    pub key_label_prefix: Option<String>,
    pub key_label_max_bytes: u8,
    pub has_credentials: bool,
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
    pub struct KeyGet {
        pub key_type: KeyGetType,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    pub enum KeyGetType {
        DS,
        DNSKEY,
        CDS,
    }

    impl std::fmt::Display for KeyGetType {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(match self {
                Self::DS => "ds",
                Self::DNSKEY => "dnskey",
                Self::CDS => "cds",
            })
        }
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

    #[derive(Deserialize, Serialize, Clone, Debug)]
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
