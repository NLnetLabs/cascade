//! Version 1 of the policy file.

use std::time::Duration;

use domain::base::Ttl;
use serde::{Deserialize, Serialize};

use crate::policy::{
    KeyManagerPolicy, LoaderPolicy, Nsec3OptOutPolicy, PolicyVersion, ReviewPolicy, ServerPolicy,
    SignerDenialPolicy, SignerPolicy, SignerSerialPolicy,
};

use super::super::{AutoConfig, DsAlgorithm, KeyParameters};

//----------- Spec -------------------------------------------------------------

/// A policy file.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct Spec {
    /// How zones are loaded.
    pub loader: LoaderSpec,

    /// Zone key management.
    pub key_manager: KeyManagerSpec,

    /// How zones are signed.
    pub signer: SignerSpec,

    /// How zones are served.
    pub server: ServerSpec,
}

//--- Conversion

impl Spec {
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
            loader: LoaderSpec::build(&policy.loader),
            key_manager: KeyManagerSpec::build(&policy.key_manager),
            signer: SignerSpec::build(&policy.signer),
            server: ServerSpec::build(&policy.server),
        }
    }
}

//----------- LoaderSpec -------------------------------------------------------

/// Policy for loading zones.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct LoaderSpec {
    /// Reviewing loaded zones.
    pub review: ReviewSpec,
}

//--- Conversion

impl LoaderSpec {
    /// Parse from this specification.
    pub fn parse(self) -> LoaderPolicy {
        LoaderPolicy {
            review: self.review.parse(),
        }
    }

    /// Build into this specification.
    pub fn build(policy: &LoaderPolicy) -> Self {
        Self {
            review: ReviewSpec::build(&policy.review),
        }
    }
}

//----------- KeyManagerSpec ---------------------------------------------------

/// Policy for zone key management.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct KeyManagerSpec {
    /// Whether and which HSM server is benig used.
    pub hsm_server_id: Option<String>,

    /// Whether to use a CSK (if true) or a KSK and a ZSK.
    use_csk: bool,

    /// Algorithm and other parameters for key generation.
    algorithm: KeyParameters,

    /// Validity of KSKs in seconds.
    ksk_validity: Option<u64>,
    /// Validity of ZSKs in seconds.
    zsk_validity: Option<u64>,
    /// Validity of CSKs in seconds.
    csk_validity: Option<u64>,

    /// Configuration variable for automatic KSK rolls.
    auto_ksk: AutoConfig,
    /// Configuration variable for automatic ZSK rolls.
    auto_zsk: AutoConfig,
    /// Configuration variable for automatic CSK rolls.
    auto_csk: AutoConfig,
    /// Configuration variable for automatic algorithm rolls.
    auto_algorithm: AutoConfig,

    /// DNSKEY signature inception offset in seconds (positive values are
    /// subtracted from the current time).
    dnskey_inception_offset: u64,

    /// DNSKEY signature lifetime in seconds.
    dnskey_signature_lifetime: u64,

    /// The required remaining signature time in seconds.
    dnskey_remain_time: u64,

    /// CDS/CDNSKEY signature inception offset in seconds.
    cds_inception_offset: u64,

    /// CDS/CDNSKEY signature lifetime in seconds.
    cds_signature_lifetime: u64,

    /// The required remaining signature time in seconds.
    cds_remain_time: u64,

    /// The DS hash algorithm.
    ds_algorithm: DsAlgorithm,

    /// The TTL to use when creating DNSKEY/CDS/CDNSKEY records.
    default_ttl: Ttl,

    /// Automatically remove keys that are no long in use.
    auto_remove: bool,
}

//--- Conversion

impl KeyManagerSpec {
    /// Parse from this specification.
    pub fn parse(self) -> KeyManagerPolicy {
        KeyManagerPolicy {
            hsm_server_id: self.hsm_server_id,
            use_csk: self.use_csk,
            algorithm: self.algorithm,
            ksk_validity: self.ksk_validity,
            zsk_validity: self.zsk_validity,
            csk_validity: self.csk_validity,
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
            ds_algorithm: self.ds_algorithm,
            default_ttl: self.default_ttl,
            auto_remove: self.auto_remove,
        }
    }

    /// Build into this specification.
    pub fn build(policy: &KeyManagerPolicy) -> Self {
        Self {
            hsm_server_id: policy.hsm_server_id.clone(),
            use_csk: policy.use_csk,
            algorithm: policy.algorithm.clone(),
            ksk_validity: policy.ksk_validity,
            zsk_validity: policy.zsk_validity,
            csk_validity: policy.csk_validity,
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
            ds_algorithm: policy.ds_algorithm.clone(),
            default_ttl: policy.default_ttl,
            auto_remove: policy.auto_remove,
        }
    }
}

impl Default for KeyManagerSpec {
    fn default() -> Self {
        const ONE_DAY: u64 = 86400;
        const FOUR_WEEKS: u64 = 2419200;
        Self {
            hsm_server_id: Default::default(),
            use_csk: false,
            algorithm: Default::default(),
            ksk_validity: None, // Is this correct?
            zsk_validity: None,
            csk_validity: None,
            auto_ksk: Default::default(),
            auto_zsk: Default::default(),
            auto_csk: Default::default(),
            auto_algorithm: Default::default(),

            // Do we have a reference for this following durations?
            dnskey_inception_offset: ONE_DAY,
            dnskey_signature_lifetime: FOUR_WEEKS,
            dnskey_remain_time: FOUR_WEEKS / 2,
            cds_inception_offset: ONE_DAY,
            cds_signature_lifetime: FOUR_WEEKS,
            cds_remain_time: FOUR_WEEKS / 2,

            ds_algorithm: Default::default(),
            default_ttl: Ttl::from_secs(3600), // Reference?
            auto_remove: true,                 // Note, no auto_remove_delay at the moment.
        }
    }
}

//----------- SignerSpec -------------------------------------------------------

/// Policy for signing zones.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct SignerSpec {
    /// The serial number generation policy.
    pub serial_policy: SignerSerialPolicySpec,

    /// The offset for record signature inceptions, in seconds.
    pub sig_inception_offset: u64,

    /// How long record signatures will be valid for, in seconds.
    pub sig_validity_time: u64,

    /// How denial-of-existence records are generated.
    pub denial: SignerDenialSpec,

    /// Reviewing signed zones.
    pub review: ReviewSpec,
    //
    // TODO:
    // - Signing policy (disabled, pass-through?, enabled)
}

//--- Conversion

impl SignerSpec {
    /// Parse from this specification.
    pub fn parse(self) -> SignerPolicy {
        SignerPolicy {
            serial_policy: self.serial_policy.parse(),
            sig_inception_offset: Duration::from_secs(self.sig_inception_offset),
            sig_validity_time: Duration::from_secs(self.sig_validity_time),
            denial: self.denial.parse(),
            review: self.review.parse(),
        }
    }

    /// Build into this specification.
    pub fn build(policy: &SignerPolicy) -> Self {
        Self {
            serial_policy: SignerSerialPolicySpec::build(policy.serial_policy),
            sig_inception_offset: policy.sig_inception_offset.as_secs(),
            sig_validity_time: policy.sig_validity_time.as_secs(),
            denial: SignerDenialSpec::build(&policy.denial),
            review: ReviewSpec::build(&policy.review),
        }
    }
}

//----------- SignerSerialPolicySpec -------------------------------------------

/// Policy for generating serial numbers.
#[derive(Copy, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum SignerSerialPolicySpec {
    /// Use the same serial number as the unsigned zone.
    Keep,

    /// Increment the serial number on every change.
    #[default]
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

//----------- SignerDenialSpec -------------------------------------------------

/// Spec for generating denial-of-existence records.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, tag = "type")]
pub enum SignerDenialSpec {
    /// Generate NSEC records.
    NSec,

    /// Generate NSEC3 records.
    NSec3 {
        /// Whether and how to enable NSEC3 Opt-Out.
        opt_out: Nsec3OptOutSpec,
    },
}

//--- Conversion

impl SignerDenialSpec {
    /// Parse from this specification.
    pub fn parse(self) -> SignerDenialPolicy {
        match self {
            SignerDenialSpec::NSec => SignerDenialPolicy::NSec,
            SignerDenialSpec::NSec3 { opt_out } => SignerDenialPolicy::NSec3 {
                opt_out: opt_out.parse(),
            },
        }
    }

    /// Build into this specification.
    pub fn build(policy: &SignerDenialPolicy) -> Self {
        match *policy {
            SignerDenialPolicy::NSec => SignerDenialSpec::NSec,
            SignerDenialPolicy::NSec3 { opt_out } => SignerDenialSpec::NSec3 {
                opt_out: Nsec3OptOutSpec::build(opt_out),
            },
        }
    }
}

//--- Default

impl Default for SignerDenialSpec {
    fn default() -> Self {
        Self::NSec3 {
            opt_out: Nsec3OptOutSpec::Disabled,
        }
    }
}

//----------- Nsec3OptOutSpec --------------------------------------------------

/// Spec for the NSEC3 Opt-Out mechanism.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, tag = "type")]
pub enum Nsec3OptOutSpec {
    /// Do not enable Opt-Out.
    #[default]
    Disabled,

    /// Only set the Opt-Out flag.
    FlagOnly,

    /// Enable Opt-Out and omit the corresponding NSEC3 records.
    Enabled,
}

//--- Conversion

impl Nsec3OptOutSpec {
    /// Parse from this specification.
    pub fn parse(self) -> Nsec3OptOutPolicy {
        match self {
            Nsec3OptOutSpec::Disabled => Nsec3OptOutPolicy::Disabled,
            Nsec3OptOutSpec::FlagOnly => Nsec3OptOutPolicy::FlagOnly,
            Nsec3OptOutSpec::Enabled => Nsec3OptOutPolicy::Enabled,
        }
    }

    /// Build into this specification.
    pub fn build(policy: Nsec3OptOutPolicy) -> Self {
        match policy {
            Nsec3OptOutPolicy::Disabled => Nsec3OptOutSpec::Disabled,
            Nsec3OptOutPolicy::FlagOnly => Nsec3OptOutSpec::FlagOnly,
            Nsec3OptOutPolicy::Enabled => Nsec3OptOutSpec::Enabled,
        }
    }
}

//----------- ReviewSpec -------------------------------------------------------

/// Policy for reviewing loaded/signed zones.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ReviewSpec {
    /// Whether review is required.
    pub required: bool,

    /// A command hook for reviewing a new version of the zone.
    pub cmd_hook: Option<String>,
}

//--- Conversion

impl ReviewSpec {
    /// Parse from this specification.
    pub fn parse(self) -> ReviewPolicy {
        ReviewPolicy {
            required: self.required,
            cmd_hook: self.cmd_hook,
        }
    }

    /// Build into this specification.
    pub fn build(policy: &ReviewPolicy) -> Self {
        Self {
            required: policy.required,
            cmd_hook: policy.cmd_hook.clone(),
        }
    }
}

//----------- ServerSpec -------------------------------------------------------

/// Policy for serving zones.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ServerSpec {}

//--- Conversion

impl ServerSpec {
    /// Parse from this specification.
    pub fn parse(self) -> ServerPolicy {
        ServerPolicy {}
    }

    /// Build into this specification.
    pub fn build(policy: &ServerPolicy) -> Self {
        let ServerPolicy {} = policy;
        Self {}
    }
}
