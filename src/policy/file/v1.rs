//! Version 1 of the policy file.

use std::time::Duration;

use domain::base::Ttl;
use serde::{Deserialize, Serialize};

use crate::policy::{
    KeyManagerPolicy, LoaderPolicy, PolicyVersion, ReviewPolicy, ServerPolicy, SignerDenialPolicy,
    SignerPolicy, SignerSerialPolicy,
};

use super::super::{AutoConfig, DsAlgorithm, KeyParameters};

// Defaults for signatures.
//
// Signature lifetimes for a few TLDs:
// .com SOA: 7 days
// .nl SOA: 14 days
// .net SOA: 7 days
// .org SOA: 21 days
// No official reference.
const SIGNATURE_VALIDITY_TIME: u64 = 14 * 24 * 3600;

// Set the remain time to half of the validity time. Note that the maximum
// TTL should be taken into account. Assume that the maximum TTL is small
// compared to the remain time and can be ignored. No official reference.
const SIGNATURE_REMAIN_TIME: u64 = SIGNATURE_VALIDITY_TIME / 2;

// There is small risk that either the signer or a validator
// has the wrong time zone settings. Back dating signatures by
// one day should solve that problem and not introduce any
// security risks. No official reference.
const SIGNATURE_INCEPTION_OFFSET: u64 = 24 * 3600;

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
        Self {
            hsm_server_id: Default::default(),

            // Default to KSK plus ZSK. CSK key rolls are more complex.
            // No official reference.
            use_csk: false,

            algorithm: Default::default(),

            // Roll a KSK once a year. No official reference.
            ksk_validity: Some(365 * 24 * 3600),

            // Roll a ZSK once a month. No official reference.
            zsk_validity: Some(30 * 24 * 3600),

            // Roll a CSK once a year just like a KSK. Assume that the DS
            // record may need to be updated by hand.
            csk_validity: Some(365 * 24 * 3600),

            auto_ksk: Default::default(),
            auto_zsk: Default::default(),
            auto_csk: Default::default(),
            auto_algorithm: Default::default(),

            // The following have the same defaults as used for
            // signing the zone.
            dnskey_inception_offset: SIGNATURE_INCEPTION_OFFSET,
            dnskey_signature_lifetime: SIGNATURE_VALIDITY_TIME,
            dnskey_remain_time: SIGNATURE_REMAIN_TIME,
            cds_inception_offset: SIGNATURE_INCEPTION_OFFSET,
            cds_signature_lifetime: SIGNATURE_VALIDITY_TIME,
            cds_remain_time: SIGNATURE_REMAIN_TIME,

            ds_algorithm: Default::default(),

            // It would be best to default to the SOA minimum. However,
            // keyset doesn't have access to that. No official reference.
            default_ttl: Ttl::from_secs(3600), // Reference?

            auto_remove: true, // Note, no auto_remove_delay at the moment.
        }
    }
}

//----------- SignerSpec -------------------------------------------------------

/// Policy for signing zones.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct SignerSpec {
    /// The serial number generation policy.
    pub serial_policy: SignerSerialPolicySpec,

    /// The offset for record signature inceptions, in seconds.
    pub sig_inception_offset: u64,

    /// How long record signatures will be valid for, in seconds.
    pub sig_validity_time: u64,

    /// How long before expiration a new signature has to be
    /// generated, in seconds.
    pub sig_remain_time: u64,

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
            sig_remain_time: Duration::from_secs(self.sig_remain_time),
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
            sig_remain_time: policy.sig_remain_time.as_secs(),
            denial: SignerDenialSpec::build(&policy.denial),
            review: ReviewSpec::build(&policy.review),
        }
    }
}

impl Default for SignerSpec {
    fn default() -> Self {
        Self {
            serial_policy: Default::default(),

            sig_inception_offset: SIGNATURE_INCEPTION_OFFSET,
            sig_validity_time: SIGNATURE_VALIDITY_TIME,
            sig_remain_time: SIGNATURE_REMAIN_TIME,

            denial: Default::default(),

            review: Default::default(),
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
    Counter,

    /// Use the current Unix time, in seconds.
    ///
    /// New versions of the zone cannot be generated in the same second.
    UnixTime,

    /// Set the serial number to `<YYYY><MM><DD><xx>`.
    ///
    /// Set the default to a human readable serial number. Counter would be
    /// a good default for zone recevied through XFR. For zones that are
    /// received we may not have a usable serial number.
    #[default]
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

// Missing here is the TTL of the NSEC/NSEC3/NSEC3PARAMS records.
// Make the ttl Option<u64>. None means use the SOA minimum.
// Turn SignerDenialSpec into a struct.

/// Spec for generating denial-of-existence records.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, tag = "type")]
pub enum SignerDenialSpec {
    /// Generate NSEC records.
    ///
    /// RFC 9276 Section 3.1 recommends NSEC. Therefore it is the default.
    #[default]
    NSec,

    /// Generate NSEC3 records.
    NSec3 {
        /// Whether and how to enable NSEC3 Opt-Out.
        // From RFC 9276:
        // In general, NSEC3 with the Opt-Out flag enabled should only be
        // used in large, highly dynamic zones with a small percentage of
        // signed delegations. Operationally, this allows for fewer signature
        // creations when new delegations are inserted into a zone. This is
        // typically only necessary for extremely large registration points
        // providing zone updates faster than real-time signing allows or
        // when using memory-constrained hardware. Operators considering
        // the use of NSEC3 are advised to carefully weigh the costs and
        // benefits of choosing NSEC3 over NSEC. Smaller zones, or large
        // but relatively static zones, are encouraged to not use the
        // opt-opt flag and to take advantage of DNSSEC's authenticated
        // denial of existence.
        opt_out: bool,
        // Missing fields:
        // - salt
        // - iterations
        // RFC 9276 Section 3.1 recommends an iteration count of 0.
        // RFC 9276 Section 3.1 recommends an empty salt.
    },
}

//--- Conversion

impl SignerDenialSpec {
    /// Parse from this specification.
    pub fn parse(self) -> SignerDenialPolicy {
        match self {
            SignerDenialSpec::NSec => SignerDenialPolicy::NSec,
            SignerDenialSpec::NSec3 { opt_out } => SignerDenialPolicy::NSec3 { opt_out },
        }
    }

    /// Build into this specification.
    pub fn build(policy: &SignerDenialPolicy) -> Self {
        match *policy {
            SignerDenialPolicy::NSec => SignerDenialSpec::NSec,
            SignerDenialPolicy::NSec3 { opt_out } => SignerDenialSpec::NSec3 { opt_out },
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
