//! Version 1 of the policy file.

use std::{
    fmt::{self, Display},
    net::{AddrParseError, SocketAddr},
    str::FromStr,
    time::Duration,
};

use domain::base::Ttl;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::policy::{
    KeyManagerPolicy, LoaderPolicy, NameserverCommsPolicy, OutboundPolicy, PolicyVersion,
    ReviewPolicy, ServerPolicy, SignerDenialPolicy, SignerPolicy, SignerSerialPolicy,
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
    /// Policy for KSKs.
    pub ksk: KeyKindSpec,

    /// Policy for ZSKs.
    pub zsk: KeyKindSpec,

    /// Policy for CSKs.
    pub csk: KeyKindSpec,

    /// Policy for algorithm rollovers.
    pub alg: RolloverSpec,

    /// The DS hash algorithm.
    pub ds_algorithm: DsAlgorithm,

    /// Automatically remove keys that are no long in use.
    pub auto_remove: bool,

    /// How special DNS records are managed.
    pub records: KeyManagerRecordsSpec,

    /// How keys are generated.
    pub generation: KeyManagerGenerationSpec,
}

//--- Conversion

impl KeyManagerSpec {
    /// Parse from this specification.
    pub fn parse(self) -> KeyManagerPolicy {
        KeyManagerPolicy {
            hsm_server_id: self.generation.hsm_server_id,
            use_csk: self.generation.use_csk,
            algorithm: match self.generation.parameters {
                KeyGenerationParametersSpec::RsaSha256(bits) => {
                    KeyParameters::RsaSha256(bits.into())
                }
                KeyGenerationParametersSpec::RsaSha512(bits) => {
                    KeyParameters::RsaSha512(bits.into())
                }
                KeyGenerationParametersSpec::EcdsaP256Sha256 => KeyParameters::EcdsaP256Sha256,
                KeyGenerationParametersSpec::EcdsaP384Sha384 => KeyParameters::EcdsaP384Sha384,
                KeyGenerationParametersSpec::Ed25519 => KeyParameters::Ed25519,
                KeyGenerationParametersSpec::Ed448 => KeyParameters::Ed448,
            },

            ksk_validity: self
                .ksk
                .validity
                .map(|v| match v {
                    KeyValiditySpec::Finite(duration) => Some(duration.as_secs()),
                    KeyValiditySpec::Forever => None,
                })
                // Roll a KSK once a year. No official reference.
                .unwrap_or(Some(365 * 24 * 3600)),

            zsk_validity: self
                .zsk
                .validity
                .map(|v| match v {
                    KeyValiditySpec::Finite(duration) => Some(duration.as_secs()),
                    KeyValiditySpec::Forever => None,
                })
                // Roll a ZSK once a month. No official reference.
                .unwrap_or(Some(30 * 24 * 3600)),

            csk_validity: self
                .csk
                .validity
                .map(|v| match v {
                    KeyValiditySpec::Finite(duration) => Some(duration.as_secs()),
                    KeyValiditySpec::Forever => None,
                })
                // Roll a CSK once a year just like a KSK. Assume that the DS
                // record may need to be updated by hand.
                .unwrap_or(Some(365 * 24 * 3600)),

            auto_ksk: self.ksk.rollover.parse(),
            auto_zsk: self.zsk.rollover.parse(),
            auto_csk: self.csk.rollover.parse(),
            auto_algorithm: self.alg.parse(),

            // The following have the same defaults as used for
            // signing the zone.
            dnskey_inception_offset: self
                .records
                .dnskey
                .signature_inception_offset
                .unwrap_or(SIGNATURE_INCEPTION_OFFSET),
            dnskey_signature_lifetime: self
                .records
                .dnskey
                .signature_lifetime
                .unwrap_or(SIGNATURE_VALIDITY_TIME),
            dnskey_remain_time: self
                .records
                .dnskey
                .signature_remain_time
                .unwrap_or(SIGNATURE_REMAIN_TIME),
            cds_inception_offset: self
                .records
                .cds
                .signature_inception_offset
                .unwrap_or(SIGNATURE_INCEPTION_OFFSET),
            cds_signature_lifetime: self
                .records
                .cds
                .signature_lifetime
                .unwrap_or(SIGNATURE_VALIDITY_TIME),
            cds_remain_time: self
                .records
                .cds
                .signature_remain_time
                .unwrap_or(SIGNATURE_REMAIN_TIME),

            default_ttl: self.records.ttl,
            ds_algorithm: self.ds_algorithm,
            auto_remove: self.auto_remove,
        }
    }

    /// Build into this specification.
    pub fn build(policy: &KeyManagerPolicy) -> Self {
        Self {
            ksk: KeyKindSpec {
                validity: Some(match policy.ksk_validity {
                    Some(secs) => KeyValiditySpec::Finite(Duration::from_secs(secs)),
                    None => KeyValiditySpec::Forever,
                }),
                rollover: RolloverSpec::build(&policy.auto_ksk),
            },
            zsk: KeyKindSpec {
                validity: Some(match policy.zsk_validity {
                    Some(secs) => KeyValiditySpec::Finite(Duration::from_secs(secs)),
                    None => KeyValiditySpec::Forever,
                }),
                rollover: RolloverSpec::build(&policy.auto_zsk),
            },
            csk: KeyKindSpec {
                validity: Some(match policy.csk_validity {
                    Some(secs) => KeyValiditySpec::Finite(Duration::from_secs(secs)),
                    None => KeyValiditySpec::Forever,
                }),
                rollover: RolloverSpec::build(&policy.auto_csk),
            },
            alg: RolloverSpec::build(&policy.auto_algorithm),

            ds_algorithm: policy.ds_algorithm.clone(),
            auto_remove: policy.auto_remove,

            records: KeyManagerRecordsSpec {
                ttl: policy.default_ttl,
                dnskey: RecordSigningSpec {
                    signature_inception_offset: Some(policy.dnskey_inception_offset),
                    signature_lifetime: Some(policy.dnskey_signature_lifetime),
                    signature_remain_time: Some(policy.dnskey_remain_time),
                },
                cds: RecordSigningSpec {
                    signature_inception_offset: Some(policy.cds_inception_offset),
                    signature_lifetime: Some(policy.cds_signature_lifetime),
                    signature_remain_time: Some(policy.cds_remain_time),
                },
            },

            generation: KeyManagerGenerationSpec {
                hsm_server_id: policy.hsm_server_id.clone(),
                use_csk: policy.use_csk,
                parameters: match policy.algorithm {
                    KeyParameters::RsaSha256(bits) => {
                        KeyGenerationParametersSpec::RsaSha256(bits as u16)
                    }
                    KeyParameters::RsaSha512(bits) => {
                        KeyGenerationParametersSpec::RsaSha512(bits as u16)
                    }
                    KeyParameters::EcdsaP256Sha256 => KeyGenerationParametersSpec::EcdsaP256Sha256,
                    KeyParameters::EcdsaP384Sha384 => KeyGenerationParametersSpec::EcdsaP384Sha384,
                    KeyParameters::Ed25519 => KeyGenerationParametersSpec::Ed25519,
                    KeyParameters::Ed448 => KeyGenerationParametersSpec::Ed448,
                },
            },
        }
    }
}

impl Default for KeyManagerSpec {
    fn default() -> Self {
        Self {
            ksk: Default::default(),
            zsk: Default::default(),
            csk: Default::default(),
            alg: Default::default(),
            ds_algorithm: DsAlgorithm::Sha256,
            auto_remove: true,
            records: Default::default(),
            generation: Default::default(),
        }
    }
}

//----------- KeyKindRolloverSpec ----------------------------------------------

/// Rollover policy for a particular kind of key.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct KeyKindSpec {
    /// How long keys are considered valid for.
    pub validity: Option<KeyValiditySpec>,

    /// The rollover policy for the key.
    #[serde(flatten)]
    pub rollover: RolloverSpec,
}

/// The validity of a key.
#[derive(Clone, Debug, SerializeDisplay, DeserializeFromStr)]
pub enum KeyValiditySpec {
    /// The key is valid for a finite duration.
    Finite(Duration),

    /// The key is valid forever.
    Forever,
}

impl fmt::Display for KeyValiditySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Finite(duration) => write!(f, "{}", duration.as_secs()),
            Self::Forever => f.write_str("forever"),
        }
    }
}

impl FromStr for KeyValiditySpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "forever" => Ok(Self::Forever),
            _ => match s.parse::<u64>() {
                Ok(secs) => Ok(Self::Finite(Duration::from_secs(secs))),
                Err(_err) => Err(format!("{s:?} is not 'forever' or an integer")),
            },
        }
    }
}

//----------- RolloverSpec -----------------------------------------------------

/// Policy for rolling over (certain kinds of) keys.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct RolloverSpec {
    /// Whether to automatically start rollovers.
    pub auto_start: bool,

    // TODO: Document.
    pub auto_report: bool,
    pub auto_expire: bool,
    pub auto_done: bool,
}

impl Default for RolloverSpec {
    fn default() -> Self {
        Self {
            auto_start: true,
            auto_report: true,
            auto_expire: true,
            auto_done: true,
        }
    }
}

//--- Conversion

impl RolloverSpec {
    pub fn parse(self) -> AutoConfig {
        AutoConfig {
            start: self.auto_start,
            report: self.auto_report,
            expire: self.auto_expire,
            done: self.auto_done,
        }
    }

    pub fn build(policy: &AutoConfig) -> Self {
        Self {
            auto_start: policy.start,
            auto_report: policy.report,
            auto_expire: policy.expire,
            auto_done: policy.done,
        }
    }
}

//----------- KeyManagerRecordsSpec --------------------------------------------

/// Policy for managing special DNS records.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct KeyManagerRecordsSpec {
    /// The TTL to use when creating special records.
    pub ttl: Ttl,

    /// Signing parameters for DNSKEY records.
    pub dnskey: RecordSigningSpec,

    /// Signing parameters for CDS records.
    pub cds: RecordSigningSpec,
    //
    // TODO: CDNSKEY?
}

impl Default for KeyManagerRecordsSpec {
    fn default() -> Self {
        Self {
            // It would be best to default to the SOA minimum. However,
            // keyset doesn't have access to that. No official reference.
            ttl: Ttl::from_secs(3600), // Reference?

            dnskey: Default::default(),
            cds: Default::default(),
        }
    }
}

//----------- KeyManagerGenerationSpec -----------------------------------------

/// Policy for generating DNSSEC keys.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct KeyManagerGenerationSpec {
    /// Whether and which HSM server is being used.
    pub hsm_server_id: Option<String>,

    /// Whether to generate CSKs, instead of separate ZSKs and KSKs.
    pub use_csk: bool,

    /// Parameters for the cryptographic key material.
    pub parameters: KeyGenerationParametersSpec,
}

impl Default for KeyManagerGenerationSpec {
    fn default() -> Self {
        Self {
            hsm_server_id: None,

            // Default to KSK plus ZSK. CSK key rolls are more complex.
            // No official reference.
            use_csk: false,

            parameters: KeyGenerationParametersSpec::EcdsaP256Sha256,
        }
    }
}

/// Policy for generating cryptographic keys.
#[derive(Clone, Debug, DeserializeFromStr, SerializeDisplay)]
pub enum KeyGenerationParametersSpec {
    RsaSha256(u16),
    RsaSha512(u16),
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
    Ed448,
}

impl Display for KeyGenerationParametersSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RsaSha256(2048) => "rsa-sha256",
            Self::RsaSha512(2048) => "rsa-sha512",
            Self::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            Self::EcdsaP384Sha384 => "ecdsa-p384-sha384",
            Self::Ed25519 => "ed25519",
            Self::Ed448 => "ed448",

            Self::RsaSha256(bits) => return write!(f, "rsa-sha256:{bits}"),
            Self::RsaSha512(bits) => return write!(f, "rsa-sha512:{bits}"),
        })
    }
}

impl FromStr for KeyGenerationParametersSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(bits) = s.strip_prefix("rsa-sha256:") {
            match bits.parse::<u16>() {
                Ok(bits) => Ok(Self::RsaSha256(bits)),
                Err(err) => Err(format!("Could not parse key size {bits:?}: {err}")),
            }
        } else if let Some(bits) = s.strip_prefix("rsa-sha512:") {
            match bits.parse::<u16>() {
                Ok(bits) => Ok(Self::RsaSha512(bits)),
                Err(err) => Err(format!("Could not parse key size {bits:?}: {err}")),
            }
        } else {
            Ok(match s {
                "rsa-sha256" => Self::RsaSha256(2048),
                "rsa-sha512" => Self::RsaSha512(2048),
                "ecdsa-p256-sha256" => Self::EcdsaP256Sha256,
                "ecdsa-p384-sha384" => Self::EcdsaP384Sha384,
                "ed25519" => Self::Ed25519,
                "ed448" => Self::Ed448,
                _ => return Err(format!("Unrecognized algorithm {s:?}")),
            })
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
    pub signature_inception_offset: u64,

    /// How long record signatures will be valid for, in seconds.
    pub signature_lifetime: u64,

    /// How long before expiration a new signature has to be
    /// generated, in seconds.
    pub signature_remain_time: u64,

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
            sig_inception_offset: Duration::from_secs(self.signature_inception_offset),
            sig_validity_time: Duration::from_secs(self.signature_lifetime),
            sig_remain_time: Duration::from_secs(self.signature_remain_time),
            denial: self.denial.parse(),
            review: self.review.parse(),
        }
    }

    /// Build into this specification.
    pub fn build(policy: &SignerPolicy) -> Self {
        Self {
            serial_policy: SignerSerialPolicySpec::build(policy.serial_policy),
            signature_inception_offset: policy.sig_inception_offset.as_secs(),
            signature_lifetime: policy.sig_validity_time.as_secs(),
            signature_remain_time: policy.sig_remain_time.as_secs(),
            denial: SignerDenialSpec::build(&policy.denial),
            review: ReviewSpec::build(&policy.review),
        }
    }
}

impl Default for SignerSpec {
    fn default() -> Self {
        Self {
            serial_policy: Default::default(),

            signature_inception_offset: SIGNATURE_INCEPTION_OFFSET,
            signature_lifetime: SIGNATURE_VALIDITY_TIME,
            signature_remain_time: SIGNATURE_REMAIN_TIME,

            denial: Default::default(),

            review: Default::default(),
        }
    }
}

//----------- RecordSigningSpec ------------------------------------------------

/// Policy for signing DNS records.
#[derive(Copy, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RecordSigningSpec {
    /// The offset for generated signature inceptions.
    pub signature_inception_offset: Option<u64>,

    /// The lifetime of generated signatures.
    pub signature_lifetime: Option<u64>,

    /// The amount of time remaining before expiry when signatures will be
    /// regenerated.
    pub signature_remain_time: Option<u64>,
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
    #[serde(rename = "nsec")]
    #[default]
    NSec,

    /// Generate NSEC3 records.
    #[serde(rename = "nsec3")]
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
pub struct ServerSpec {
    outbound: OutboundSpec,
}

//--- Conversion

impl ServerSpec {
    /// Parse from this specification.
    pub fn parse(self) -> ServerPolicy {
        ServerPolicy {
            outbound: self.outbound.parse(),
        }
    }

    /// Build into this specification.
    pub fn build(policy: &ServerPolicy) -> Self {
        Self {
            outbound: OutboundSpec::build(&policy.outbound),
        }
    }
}

//----------- OutboundSpec ---------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct OutboundSpec {
    /// The set of nameservers from which SOA and XFR requests may be received.
    ///
    /// If empty, any nameserver may request XFR from us.
    #[serde(default = "empty_list")]
    pub accept_xfr_requests_from: Vec<NameserverCommsSpec>,

    /// The set of nameservers to which NOTIFY messages should be sent.
    ///
    /// If empty, no NOTIFY messages will be sent.
    ///
    /// TODO: support the RFC 1996 "Notify Set"?
    #[serde(default = "empty_list")]
    pub send_notify_to: Vec<NameserverCommsSpec>,
}

fn empty_list() -> Vec<NameserverCommsSpec> {
    vec![]
}

//--- Conversion

impl OutboundSpec {
    /// Parse from this specification.
    pub fn parse(self) -> OutboundPolicy {
        OutboundPolicy {
            accept_xfr_requests_from: self
                .accept_xfr_requests_from
                .into_iter()
                .map(|v| v.parse())
                .collect(),
            send_notify_to: self.send_notify_to.into_iter().map(|v| v.parse()).collect(),
        }
    }

    /// Build into this specification.
    pub fn build(policy: &OutboundPolicy) -> Self {
        Self {
            accept_xfr_requests_from: policy
                .accept_xfr_requests_from
                .iter()
                .map(NameserverCommsSpec::build)
                .collect(),
            send_notify_to: policy
                .send_notify_to
                .iter()
                .map(NameserverCommsSpec::build)
                .collect(),
        }
    }
}

//----------- NameserverCommsSpec --------------------------------------------

/// Policy for communicating with another namesever.
#[derive(Clone, Debug, DeserializeFromStr, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct NameserverCommsSpec {
    /// The address to send to/receive from.
    ///
    /// For sending the port MUST NOT be zero.
    ///
    /// TODO: Support IP prefixes?
    pub addr: SocketAddr,
    // TODO: Support TSIG key names?
}

//--- Conversion

impl NameserverCommsSpec {
    /// Parse from this specification.
    pub fn parse(self) -> NameserverCommsPolicy {
        NameserverCommsPolicy { addr: self.addr }
    }

    /// Build into this specification.
    pub fn build(policy: &NameserverCommsPolicy) -> Self {
        Self { addr: policy.addr }
    }
}

impl FromStr for NameserverCommsSpec {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(NameserverCommsSpec {
            addr: SocketAddr::from_str(s)?,
        })
    }
}
