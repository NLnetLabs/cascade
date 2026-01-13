//! Version 1 of the zone state file.

use std::net::SocketAddr;

use bytes::Bytes;
use camino::Utf8Path;
use domain::base::Ttl;
use domain::{base::Name, rdata::dnssec::Timestamp};
use serde::{Deserialize, Serialize};

use crate::policy::file::v1::OutboundSpec;
use crate::policy::{AutoConfig, DsAlgorithm, KeyParameters};
use crate::zone::HistoryItem;
use crate::zone::loader::Source;
use crate::{
    policy::{
        KeyManagerPolicy, LoaderPolicy, PolicyVersion, ReviewPolicy, ServerPolicy,
        SignerDenialPolicy, SignerPolicy, SignerSerialPolicy,
    },
    zone::ZoneState,
};

//----------- Spec -------------------------------------------------------------

/// A zone state file.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Spec {
    /// The current policy.
    ///
    /// The full details of the policy are stored here, as there may be a newer
    /// version of the policy that is not yet in use.
    pub policy: Option<PolicySpec>,

    /// The source of the zone.
    pub source: ZoneLoadSourceSpec,

    /// The minimum expiration time in the signed zone we are serving from
    /// the publication server.
    pub min_expiration: Option<Timestamp>,

    /// The minimum expiration time in the most recently signed zone. This
    /// value should be move to min_expiration after the signed zone is
    /// approved.
    pub next_min_expiration: Option<Timestamp>,

    /// History of interesting events that occurred for this zone.
    pub history: Vec<HistoryItem>,
}

//--- Conversion

impl Spec {
    /// Build into this specification.
    pub fn build(zone: &ZoneState) -> Self {
        Self {
            policy: zone.policy.as_ref().map(|p| PolicySpec::build(p)),
            source: ZoneLoadSourceSpec::build(&zone.loader.source),
            min_expiration: zone.min_expiration,
            next_min_expiration: zone.next_min_expiration,
            history: zone.history.clone(),
        }
    }
}

//----------- PolicySpec -------------------------------------------------------

/// The policy details for a zone.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PolicySpec {
    /// The name of the policy.
    pub name: Box<str>,

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

impl PolicySpec {
    /// Parse from this specification.
    pub fn parse(self) -> PolicyVersion {
        PolicyVersion {
            name: self.name,
            loader: self.loader.parse(),
            key_manager: self.key_manager.parse(),
            signer: self.signer.parse(),
            server: self.server.parse(),
        }
    }

    /// Build into this specification.
    pub fn build(policy: &PolicyVersion) -> Self {
        Self {
            name: policy.name.clone(),
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
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct KeyManagerPolicySpec {
    /// Whether and which HSM server is being used.
    pub hsm_server_id: Option<String>,

    /// Whether to use a CSK (if true) or a KSK and a ZSK.
    use_csk: bool,

    /// Algorithm and other parameters for key generation.
    algorithm: KeyParameters,

    /// Validity of KSKs.
    ksk_validity: Option<u32>,
    /// Validity of ZSKs.
    zsk_validity: Option<u32>,
    /// Validity of CSKs.
    csk_validity: Option<u32>,

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
    ds_algorithm: DsAlgorithm,

    /// The TTL to use when creating DNSKEY/CDS/CDNSKEY records.
    default_ttl: Ttl,

    /// Automatically remove keys that are no long in use.
    auto_remove: bool,
}

//--- Conversion

impl KeyManagerPolicySpec {
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
    pub required: bool,

    /// A command hook for reviewing a new version of the zone.
    pub cmd_hook: Option<String>,
}

//--- Conversion

impl ReviewPolicySpec {
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

//----------- ZoneLoadSourceSpec -----------------------------------------------

/// Where to load a zone from.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum ZoneLoadSourceSpec {
    /// Don't load the zone at all.
    None,

    /// Load from a zonefile on a disk.
    Zonefile {
        /// The path to the zonefile.
        path: Box<Utf8Path>,
    },

    /// Load from a DNS server via XFR.
    Server {
        /// The TCP/UDP address of the server.
        addr: SocketAddr,

        /// The TSIG key to use, if any.
        tsig_key: Option<Name<Bytes>>,
    },
}

//--- Conversion

impl ZoneLoadSourceSpec {
    /// Parse from this specification.
    pub fn parse(self) -> Source {
        match self {
            Self::None => Source::None,
            Self::Zonefile { path } => Source::Zonefile { path },
            // TODO: Look up the TSIG key in the key store.
            Self::Server { addr, tsig_key: _ } => Source::Server {
                addr,
                tsig_key: None,
            },
        }
    }

    /// Build into this specification.
    pub fn build(source: &Source) -> Self {
        match source.clone() {
            Source::None => Self::None,
            Source::Zonefile { path } => Self::Zonefile { path },
            Source::Server { addr, tsig_key } => Self::Server {
                addr,
                tsig_key: tsig_key.map(|key| {
                    let bytes = key.name().as_slice();
                    let bytes = Bytes::copy_from_slice(bytes);
                    Name::from_octets(bytes).unwrap()
                }),
            },
        }
    }
}
