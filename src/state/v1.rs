//! Version 1 of the state file.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use domain::base::Name;
use domain::base::Ttl;
use domain::tsig::KeyName;
use serde::{Deserialize, Serialize};

use crate::hsm::KmipServerState;
use crate::policy::KeyValidity;
use crate::policy::NameserverCommsPolicy;
use crate::policy::OutboundPolicy;
use crate::{
    center::State,
    policy::{
        AutoConfig, DsAlgorithm, KeyManagerPolicy, KeyParameters, LoaderPolicy, Policy,
        PolicyVersion, ReviewPolicy, ServerPolicy, SignerDenialPolicy, SignerPolicy,
        SignerSerialPolicy,
    },
};

//----------- Spec -------------------------------------------------------------

/// A state file.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Spec {
    /// Known zones.
    ///
    /// Only the names of the zones are stored here.  The state of each zone is
    /// stored in a dedicated state file.
    pub zones: foldhash::HashSet<Name<Bytes>>,

    /// Policies.
    pub policies: foldhash::HashMap<Box<str>, PolicySpec>,

    /// HSMs.
    pub hsms: foldhash::HashMap<Box<str>, HsmSpec>,
}

//--- Conversion

impl Spec {
    /// Parse from this specification.
    ///
    /// [`Self::zones`], [`Self::policies`], and [`Self::hsms`] are ignored;
    /// these should be extracted from `self` before calling this function.
    pub fn parse(self) -> State {
        let Self {
            // Fields extracted by the caller beforehand:
            zones: _,
            policies: _,
            hsms: _,
            // Other fields:
        };

        State::default()
    }

    /// Build this state specification.
    pub fn build(state: &State) -> Self {
        Self {
            zones: state.zones.iter().map(|zone| zone.0.name.clone()).collect(),
            policies: state
                .policies
                .iter()
                .map(|(name, policy)| (name.clone(), PolicySpec::build(policy)))
                .collect(),
            hsms: state
                .hsms
                .map
                .iter()
                .map(|(name, hsm)| {
                    let kmip = &hsm.state.lock().unwrap().kmip;
                    (name.clone(), HsmSpec::build(kmip))
                })
                .collect(),
        }
    }
}

//----------- PolicySpec -------------------------------------------------------

/// A policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PolicySpec {
    /// The latest version of the policy.
    pub latest: PolicyVersionSpec,

    /// Whether the policy is being deleted.
    pub mid_deletion: bool,
}

//--- Conversion

impl PolicySpec {
    /// Parse from this specification.
    pub fn parse(self, name: &str) -> Policy {
        Policy {
            latest: Arc::new(self.latest.parse(name)),
            mid_deletion: self.mid_deletion,
            zones: Default::default(),
        }
    }

    /// Merge from this specification.
    pub fn parse_into(self, policy: &mut Policy) {
        let name = &policy.latest.name;
        let latest = self.latest.parse(name);
        if *policy.latest != latest {
            policy.latest = Arc::new(latest);
        }
        // TODO: How does this affect zones using the policy?
        policy.mid_deletion |= self.mid_deletion;
    }

    /// Build into this specification.
    pub fn build(policy: &Policy) -> Self {
        Self {
            latest: PolicyVersionSpec::build(&policy.latest),
            mid_deletion: policy.mid_deletion,
        }
    }
}

//----------- PolicyVersionSpec ------------------------------------------------

/// A particular version of a policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PolicyVersionSpec {
    /// How zones are loaded.
    pub loader: LoaderPolicySpec,

    /// Zone key management.
    pub key_manager: KeyManagerPolicySpec,

    /// How zones are signed.
    pub signer: SignerPolicySpec,

    /// How zones are served.
    pub server: ServerPolicySpec,
}

//--- Conversion

impl PolicyVersionSpec {
    /// Parse from this specification.
    pub fn parse(self, name: &str) -> PolicyVersion {
        PolicyVersion {
            name: name.into(),
            loader: self.loader.parse(),
            key_manager: self.key_manager.parse(),
            signer: self.signer.parse(),
            server: self.server.parse(),
        }
    }

    /// Build into this specification.
    pub fn build(policy: &PolicyVersion) -> Self {
        Self {
            loader: LoaderPolicySpec::build(&policy.loader),
            key_manager: KeyManagerPolicySpec::build(&policy.key_manager),
            signer: SignerPolicySpec::build(&policy.signer),
            server: ServerPolicySpec::build(&policy.server),
        }
    }
}

//----------- LoaderPolicySpec -------------------------------------------------

/// Policy for loading zones.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct LoaderPolicySpec {
    /// Reviewing loaded zones.
    pub review: ReviewPolicySpec,
}

//--- Conversion

impl LoaderPolicySpec {
    /// Parse from this specification.
    pub fn parse(self) -> LoaderPolicy {
        LoaderPolicy {
            review: self.review.parse(),
        }
    }

    /// Build into this specification.
    pub fn build(policy: &LoaderPolicy) -> Self {
        Self {
            review: ReviewPolicySpec::build(&policy.review),
        }
    }
}

//----------- KeyManagerSpec ---------------------------------------------------

/// Policy for zone key management.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct KeyManagerPolicySpec {
    /// Whether and which HSM server is being used.
    pub hsm_server_id: Option<String>,

    /// Whether to use a CSK (if true) or a KSK and a ZSK.
    use_csk: bool,

    /// Algorithm and other parameters for key generation.
    algorithm: KeyParameters,

    /// Validity of KSKs.
    ksk_validity: KeyValiditySpec,
    /// Validity of ZSKs.
    zsk_validity: KeyValiditySpec,
    /// Validity of CSKs.
    csk_validity: KeyValiditySpec,

    /// Configuration variable for automatic KSK rolls.
    auto_ksk: AutoConfig,
    /// Configuration variable for automatic ZSK rolls.
    auto_zsk: AutoConfig,
    /// Configuration variable for automatic CSK rolls.
    auto_csk: AutoConfig,
    /// Configuration variable for automatic algorithm rolls.
    auto_algorithm: AutoConfig,

    /// DNSKEY signature inception offset (positive values are subtracted
    ///from the current time).
    dnskey_inception_offset: u32,

    /// DNSKEY signature lifetime
    dnskey_signature_lifetime: u32,

    /// The required remaining signature lifetime.
    dnskey_remain_time: u32,

    /// CDS/CDNSKEY signature inception offset
    cds_inception_offset: u32,

    /// CDS/CDNSKEY signature lifetime
    cds_signature_lifetime: u32,

    /// The required remaining signature lifetime.
    cds_remain_time: u32,

    /// The DS hash algorithm.
    ds_algorithm: DsAlgorithmSpec,

    /// The TTL to use when creating DNSKEY/CDS/CDNSKEY records.
    default_ttl: Ttl,

    /// Automatically remove keys that are no longer in use.
    auto_remove: bool,

    /// Remove old keys after this amount of time.
    auto_remove_delay: u64,

    /// Nameservers to check for RRSIG propagation during a key roll.
    publication_nameservers: Vec<NameserverCommsSpec>,
}

//--- Conversion

impl KeyManagerPolicySpec {
    /// Parse from this specification.
    pub fn parse(self) -> KeyManagerPolicy {
        KeyManagerPolicy {
            hsm_server_id: self.hsm_server_id,
            use_csk: self.use_csk,
            algorithm: self.algorithm,
            ksk_validity: self.ksk_validity.into(),
            zsk_validity: self.zsk_validity.into(),
            csk_validity: self.csk_validity.into(),
            auto_ksk: self.auto_ksk,
            auto_zsk: self.auto_zsk,
            auto_csk: self.auto_csk,
            auto_algorithm: self.auto_algorithm,
            dnskey_inception_offset: self.dnskey_inception_offset,
            dnskey_signature_lifetime: self.dnskey_signature_lifetime,
            dnskey_remain_time: self.dnskey_remain_time,
            cds_inception_offset: self.cds_inception_offset,
            cds_signature_lifetime: self.cds_signature_lifetime,
            cds_remain_time: self.cds_remain_time,
            ds_algorithm: self.ds_algorithm.into(),
            default_ttl: self.default_ttl,
            auto_remove: self.auto_remove,
            auto_remove_delay: Duration::from_secs(self.auto_remove_delay),
            publication_nameservers: self
                .publication_nameservers
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }

    /// Build into this specification.
    pub fn build(policy: &KeyManagerPolicy) -> Self {
        Self {
            hsm_server_id: policy.hsm_server_id.clone(),
            use_csk: policy.use_csk,
            algorithm: policy.algorithm.clone(),
            ksk_validity: policy.ksk_validity.clone().into(),
            zsk_validity: policy.zsk_validity.clone().into(),
            csk_validity: policy.csk_validity.clone().into(),
            auto_ksk: policy.auto_ksk.clone(),
            auto_zsk: policy.auto_zsk.clone(),
            auto_csk: policy.auto_csk.clone(),
            auto_algorithm: policy.auto_algorithm.clone(),
            dnskey_inception_offset: policy.dnskey_inception_offset,
            dnskey_signature_lifetime: policy.dnskey_signature_lifetime,
            dnskey_remain_time: policy.dnskey_remain_time,
            cds_inception_offset: policy.cds_inception_offset,
            cds_signature_lifetime: policy.cds_signature_lifetime,
            cds_remain_time: policy.cds_remain_time,
            ds_algorithm: policy.ds_algorithm.clone().into(),
            default_ttl: policy.default_ttl,
            auto_remove: policy.auto_remove,
            auto_remove_delay: policy.auto_remove_delay.as_secs(),
            publication_nameservers: policy
                .publication_nameservers
                .iter()
                .cloned()
                .map(Into::into)
                .collect(),
        }
    }
}

//----------- KeyValiditySpec --------------------------------------------------

/// The validity of a key.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum KeyValiditySpec {
    /// The key is valid for a finite duration.
    Finite(u32),

    /// The key is valid forever.
    Forever,
}

impl From<KeyValiditySpec> for KeyValidity {
    fn from(value: KeyValiditySpec) -> Self {
        match value {
            KeyValiditySpec::Finite(span) => Self::Finite(span),
            KeyValiditySpec::Forever => Self::Forever,
        }
    }
}

impl From<KeyValidity> for KeyValiditySpec {
    fn from(value: KeyValidity) -> Self {
        match value {
            KeyValidity::Finite(span) => Self::Finite(span),
            KeyValidity::Forever => Self::Forever,
        }
    }
}

//----------- DsAlgorithmSpec --------------------------------------------------

/// The hash algorithm to use for DS records.
///
/// Note the RFC 8624 has (for DNSSEC delegation use) a MUST for SHA-256,
/// a MAY for SHA-384 and a MUST NOT for SHA-1 and GOST R 34.11-94.
/// Therefore, we only support SHA-256 and SHA-384 and the default is
/// SHA-256.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DsAlgorithmSpec {
    /// Hash the public key using SHA-256.
    Sha256,

    /// Hash the public key using SHA-384.
    Sha384,
}

impl From<DsAlgorithmSpec> for DsAlgorithm {
    fn from(value: DsAlgorithmSpec) -> Self {
        match value {
            DsAlgorithmSpec::Sha256 => Self::Sha256,
            DsAlgorithmSpec::Sha384 => Self::Sha384,
        }
    }
}

impl From<DsAlgorithm> for DsAlgorithmSpec {
    fn from(value: DsAlgorithm) -> Self {
        match value {
            DsAlgorithm::Sha256 => Self::Sha256,
            DsAlgorithm::Sha384 => Self::Sha384,
        }
    }
}

//----------- SignerPolicySpec -------------------------------------------------

/// Policy for signing zones.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SignerPolicySpec {
    /// The serial number generation policy.
    pub serial_policy: SignerSerialPolicySpec,

    /// The offset for record signature inceptions, in seconds.
    pub sig_inception_offset: u32,

    /// How long record signatures will be valid for, in seconds.
    pub sig_validity_time: u32,

    /// How long before expiration a new signature has to be generated, in seconds.
    pub sig_remain_time: u32,

    /// How often to refresh some amount of signatures to make resigning
    /// smoother.
    pub signature_refresh_interval: u32,

    /// How long should it take to resign a zone during a ZSK or CSK roll.
    pub key_roll_time: u32,

    /// How denial-of-existence records are generated.
    pub denial: SignerDenialPolicySpec,

    /// Reviewing signed zones.
    pub review: ReviewPolicySpec,
}

//--- Conversion

impl SignerPolicySpec {
    /// Parse from this specification.
    pub fn parse(self) -> SignerPolicy {
        SignerPolicy {
            serial_policy: self.serial_policy.parse(),
            sig_inception_offset: self.sig_inception_offset,
            sig_validity_time: self.sig_validity_time,
            sig_remain_time: self.sig_remain_time,
            signature_refresh_interval: self.signature_refresh_interval,
            key_roll_time: self.key_roll_time,
            denial: self.denial.parse(),
            review: self.review.parse(),
        }
    }

    /// Build into this specification.
    pub fn build(policy: &SignerPolicy) -> Self {
        Self {
            serial_policy: SignerSerialPolicySpec::build(policy.serial_policy),
            sig_inception_offset: policy.sig_inception_offset,
            sig_validity_time: policy.sig_validity_time,
            sig_remain_time: policy.sig_remain_time,
            signature_refresh_interval: policy.signature_refresh_interval,
            key_roll_time: policy.key_roll_time,
            denial: SignerDenialPolicySpec::build(&policy.denial),
            review: ReviewPolicySpec::build(&policy.review),
        }
    }
}

//----------- SignerSerialPolicySpec -------------------------------------------

/// Policy for generating serial numbers.
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum SignerSerialPolicySpec {
    /// Use the same serial number as the unsigned zone.
    Keep,

    /// Increment the serial number on every change.
    Counter,

    /// Use the current Unix time, in seconds.
    ///
    /// New versions of the zone cannot be generated in the same second.
    UnixTime,

    /// Set the serial number to `<YYYY><MM><DD><xx>`.
    DateCounter,
}

//--- Conversion

impl SignerSerialPolicySpec {
    /// Parse from this specification.
    pub fn parse(self) -> SignerSerialPolicy {
        match self {
            Self::Keep => SignerSerialPolicy::Keep,
            Self::Counter => SignerSerialPolicy::Counter,
            Self::UnixTime => SignerSerialPolicy::UnixTime,
            Self::DateCounter => SignerSerialPolicy::DateCounter,
        }
    }

    /// Build into this specification.
    pub fn build(policy: SignerSerialPolicy) -> Self {
        match policy {
            SignerSerialPolicy::Keep => Self::Keep,
            SignerSerialPolicy::Counter => Self::Counter,
            SignerSerialPolicy::UnixTime => Self::UnixTime,
            SignerSerialPolicy::DateCounter => Self::DateCounter,
        }
    }
}

//----------- SignerDenialPolicySpec -------------------------------------------

/// Spec for generating denial-of-existence records.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, tag = "type")]
pub enum SignerDenialPolicySpec {
    /// Generate NSEC records.
    NSec,

    /// Generate NSEC3 records.
    NSec3 {
        /// Whether and how to enable NSEC3 Opt-Out.
        opt_out: bool,
    },
}

//--- Conversion

impl SignerDenialPolicySpec {
    /// Parse from this specification.
    pub fn parse(self) -> SignerDenialPolicy {
        match self {
            SignerDenialPolicySpec::NSec => SignerDenialPolicy::NSec,
            SignerDenialPolicySpec::NSec3 { opt_out } => SignerDenialPolicy::NSec3 { opt_out },
        }
    }

    /// Build into this specification.
    pub fn build(policy: &SignerDenialPolicy) -> Self {
        match *policy {
            SignerDenialPolicy::NSec => SignerDenialPolicySpec::NSec,
            SignerDenialPolicy::NSec3 { opt_out } => SignerDenialPolicySpec::NSec3 { opt_out },
        }
    }
}

//--- Default

impl Default for SignerDenialPolicySpec {
    fn default() -> Self {
        Self::NSec3 { opt_out: false }
    }
}

//----------- ReviewPolicySpec -------------------------------------------------

/// Policy for reviewing loaded/signed zones.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ReviewPolicySpec {
    /// Whether review is required.
    pub mode: ReviewPolicyMode,

    /// A command hook for reviewing a new version of the zone.
    pub on_reject: ReviewPolicyOnReject,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ReviewPolicyMode {
    Off,
    Manual,
    Script { hook: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ReviewPolicyOnReject {
    Discard,
    Halt,
}

//--- Conversion

impl ReviewPolicySpec {
    /// Parse from this specification.
    pub fn parse(self) -> ReviewPolicy {
        ReviewPolicy {
            mode: match self.mode {
                ReviewPolicyMode::Off => crate::policy::ReviewMode::Off,
                ReviewPolicyMode::Manual => crate::policy::ReviewMode::Manual,
                ReviewPolicyMode::Script { hook } => crate::policy::ReviewMode::Script { hook },
            },
            on_reject: match self.on_reject {
                ReviewPolicyOnReject::Discard => crate::policy::RejectionPolicy::Discard,
                ReviewPolicyOnReject::Halt => crate::policy::RejectionPolicy::Halt,
            },
        }
    }

    /// Build into this specification.
    pub fn build(policy: &ReviewPolicy) -> Self {
        Self {
            mode: match policy.mode.clone() {
                crate::policy::ReviewMode::Off => ReviewPolicyMode::Off,
                crate::policy::ReviewMode::Manual => ReviewPolicyMode::Manual,
                crate::policy::ReviewMode::Script { hook } => ReviewPolicyMode::Script { hook },
            },
            on_reject: match policy.on_reject {
                crate::policy::RejectionPolicy::Discard => ReviewPolicyOnReject::Discard,
                crate::policy::RejectionPolicy::Halt => ReviewPolicyOnReject::Halt,
            },
        }
    }
}

//----------- ServerPolicySpec -------------------------------------------------

/// Policy for serving zones.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ServerPolicySpec {
    pub outbound: OutboundSpec,
}

//--- Conversion

impl ServerPolicySpec {
    /// Parse from this specification.
    pub fn parse(self) -> ServerPolicy {
        ServerPolicy {
            outbound: self.outbound.into(),
        }
    }

    /// Build into this specification.
    pub fn build(policy: &ServerPolicy) -> Self {
        Self {
            outbound: policy.outbound.clone().into(),
        }
    }
}

//----------- OutboundSpec ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct OutboundSpec {
    /// The set of nameservers to which zone transfers may be provided.
    pub provide_xfr_to: Vec<NameserverCommsSpec>,

    /// The set of nameservers to which NOTIFY messages should be sent.
    pub send_notify_to: Vec<NameserverCommsSpec>,

    /// The maximum number of IXFR diffs to keep.
    pub max_diffs: usize,

    /// The maximum percentage of change allowed for a single IXFR diff.
    pub max_diffs_size: usize,
}

impl From<OutboundSpec> for OutboundPolicy {
    fn from(
        OutboundSpec {
            provide_xfr_to,
            send_notify_to,
            max_diffs,
            max_diffs_size,
        }: OutboundSpec,
    ) -> Self {
        Self {
            provide_xfr_to: provide_xfr_to.into_iter().map(Into::into).collect(),
            send_notify_to: send_notify_to.into_iter().map(Into::into).collect(),
            max_diffs,
            max_diffs_size,
        }
    }
}

impl From<OutboundPolicy> for OutboundSpec {
    fn from(
        OutboundPolicy {
            provide_xfr_to,
            send_notify_to,
            max_diffs,
            max_diffs_size,
        }: OutboundPolicy,
    ) -> Self {
        Self {
            provide_xfr_to: provide_xfr_to.into_iter().map(Into::into).collect(),
            send_notify_to: send_notify_to.into_iter().map(Into::into).collect(),
            max_diffs,
            max_diffs_size,
        }
    }
}

//----------- NameserverCommsSpec --------------------------------------------

/// Policy for communicating with another namesever.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NameserverCommsSpec {
    /// The address to send NOTIFYs to or allow XFRs from.
    pub addr: SocketAddr,

    /// An optional TSIG key to sign and authenticate messages with.
    pub tsig_key_name: Option<KeyName>,
}

impl From<NameserverCommsSpec> for NameserverCommsPolicy {
    fn from(
        NameserverCommsSpec {
            addr,
            tsig_key_name,
        }: NameserverCommsSpec,
    ) -> Self {
        Self {
            addr,
            tsig_key_name,
        }
    }
}

impl From<NameserverCommsPolicy> for NameserverCommsSpec {
    fn from(
        NameserverCommsPolicy {
            addr,
            tsig_key_name,
        }: NameserverCommsPolicy,
    ) -> Self {
        Self {
            addr,
            tsig_key_name,
        }
    }
}

//----------- HsmSpec ----------------------------------------------------------

/// A known HSM.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HsmSpec {
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

//--- Conversion

impl HsmSpec {
    /// Parse from this specification.
    pub fn parse(self, name: &str) -> KmipServerState {
        let Self {
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
        } = self;

        KmipServerState {
            server_id: name.into(),
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
        }
    }

    /// Build into this specification.
    pub fn build(kmip: &KmipServerState) -> Self {
        let KmipServerState {
            server_id: _,
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
        } = kmip.clone();

        Self {
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
        }
    }
}
