//! Version 1 of the policy file.

use std::{
    fmt::{self, Display},
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use domain::tsig::KeyName;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

pub use crate::datetime::TimeSpan;

//--- Defaults for signatures

/// Signature lifetimes for a few TLDs:
///
/// - .com SOA: 7 days
/// - .nl SOA: 14 days
/// - .net SOA: 7 days
/// - .org SOA: 21 days
///
/// No official reference.
const SIGNATURE_VALIDITY_TIME: u32 = 14 * 24 * 3600;

/// Set the remain time to half of the validity time. Note that the maximum TTL
/// should be taken into account. Assume that the maximum TTL is small compared
/// to the remain time and can be ignored. No official reference.
const SIGNATURE_REMAIN_TIME: u32 = SIGNATURE_VALIDITY_TIME / 2;

/// There is small risk that either the signer or a validator has the wrong time
/// zone settings. Back dating signatures by one day should solve that problem
/// and not introduce any security risks. No official reference.
const SIGNATURE_INCEPTION_OFFSET: u32 = 24 * 3600;

/// Try to find the right comprise between zones that hardly ever changes and
/// zones that are changed frequently. This should be a safe default, though big
/// zones that change frequently may set it to around 15 minutes to avoid jitter
/// in signing performance.
const SIGNATURE_REFRESH_INTERVAL: u32 = 12 * 3600;

/// Assume it is fine if resigning a zone takes one day. This could be a lot
/// lower for small zones. For big zones it is balance between the time the
/// DNSKEY RRset contains an extra KSK and how disruptive it is to sign more
/// records.
const KEY_ROLL_TIME: u32 = 24 * 3600;

/// When auto remove is enabled, remove old keys after one week.
const AUTO_REMOVE_DELAY: u32 = 7 * 24 * 3600;

//--- Defaults for diff purging

/// The maximum number of diffs to keep per zone.
///
/// Based on the NSD default of ixfr-number: 5.
const MAX_DIFFS: usize = 5;

/// The maximum size that in-memory diffs may reach as a percentage of the
/// published zone.
///
/// IXFR diffs that describe larger changes (compared to the last published
/// version of the zone) than this limit will be kept in-memory to to serve to
/// IXFR clients.
///
/// Based on <https://github.com/NLnetLabs/cascade/issues/830#issuecomment-4752275415>.
const MAX_DIFFS_SIZE: usize = 20;

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

//----------- LoaderSpec -------------------------------------------------------

/// Policy for loading zones.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct LoaderSpec {
    /// Reviewing loaded zones.
    pub review: Option<ReviewSpec>,
}

//----------- KeyManagerSpec ---------------------------------------------------

/// Policy for zone key management.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct KeyManagerSpec {
    /// Policy for KSKs.
    pub ksk: KskManagementSpec,

    /// Policy for ZSKs.
    pub zsk: ZskManagementSpec,

    /// Policy for CSKs.
    pub csk: CskManagementSpec,

    /// Policy for algorithm rollovers.
    pub algorithm: RolloverSpec,

    /// The DS hash algorithm.
    pub ds_algorithm: DsAlgorithmSpec,

    /// Automatically remove keys that are no longer in use.
    pub auto_remove: bool,

    /// How long to wait before removing old keys.
    pub auto_remove_delay: TimeSpan,

    /// How special DNS records are managed.
    pub records: KeyManagerRecordsSpec,

    /// How keys are generated.
    pub generation: KeyManagerGenerationSpec,

    /// The upstream nameservers to use when checking for RRSIG propagation
    /// during a key roll. The value is a list of strings. Each string has the following
    /// syntax: `<IP-address>:<port>[^<tsig-key-name>].`
    /// The port is mandatory. The TSIG key name is optional and the name
    /// of the key is preceded by a caret character (`^`).
    pub publication_nameservers: Vec<NameserverCommsSpec>,
}

impl Default for KeyManagerSpec {
    fn default() -> Self {
        Self {
            ksk: Default::default(),
            zsk: Default::default(),
            csk: Default::default(),
            algorithm: Default::default(),
            ds_algorithm: DsAlgorithmSpec::Sha256,
            auto_remove: true,
            auto_remove_delay: TimeSpan::from_secs(AUTO_REMOVE_DELAY),
            publication_nameservers: Default::default(),
            records: Default::default(),
            generation: Default::default(),
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
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum DsAlgorithmSpec {
    /// Hash the public key using SHA-256.
    #[serde(rename = "SHA-256")]
    #[default]
    Sha256,

    /// Hash the public key using SHA-384.
    #[serde(rename = "SHA-384")]
    Sha384,
}

//----------- {Ksk,Zsk,Csk}RolloverSpec ----------------------------------------

/// Rollover policy for a particular kind of key.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct KskManagementSpec {
    /// How long keys are considered valid for.
    pub validity: KeyValiditySpec,

    /// The rollover policy for the key.
    #[serde(flatten)]
    pub rollover: RolloverSpec,
}

impl Default for KskManagementSpec {
    fn default() -> Self {
        Self {
            // Roll a KSK once a year. No official reference.
            validity: KeyValiditySpec::Finite(TimeSpan::from_secs(365 * 24 * 3600)),
            rollover: RolloverSpec::default(),
        }
    }
}

/// Rollover policy for a particular kind of key.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ZskManagementSpec {
    /// How long keys are considered valid for.
    pub validity: KeyValiditySpec,

    /// The rollover policy for the key.
    #[serde(flatten)]
    pub rollover: RolloverSpec,
}

impl Default for ZskManagementSpec {
    fn default() -> Self {
        Self {
            // Roll a ZSK once a month. No official reference.
            validity: KeyValiditySpec::Finite(TimeSpan::from_secs(30 * 24 * 3600)),
            rollover: RolloverSpec::default(),
        }
    }
}

/// Rollover policy for a particular kind of key.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct CskManagementSpec {
    /// How long keys are considered valid for.
    pub validity: KeyValiditySpec,

    /// The rollover policy for the key.
    #[serde(flatten)]
    pub rollover: RolloverSpec,
}

impl Default for CskManagementSpec {
    fn default() -> Self {
        Self {
            // Roll a CSK once a year just like a KSK. Assume that the DS
            // record may need to be updated by hand.
            validity: KeyValiditySpec::Finite(TimeSpan::from_secs(365 * 24 * 3600)),
            rollover: RolloverSpec::default(),
        }
    }
}

//----------- KeyValiditySpec --------------------------------------------------

/// The validity of a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyValiditySpec {
    /// The key is valid for a finite duration.
    Finite(TimeSpan),

    /// The key is valid forever.
    Forever,
}

struct ValidityVisitor;

impl<'de> serde::de::Visitor<'de> for ValidityVisitor {
    type Value = KeyValiditySpec;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("string, int, or \"forever\"")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value == "forever" {
            return Ok(KeyValiditySpec::Forever);
        }
        let span = value.parse().map_err(E::custom)?;
        Ok(KeyValiditySpec::Finite(span))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(KeyValiditySpec::Finite(TimeSpan::from_secs(
            value
                .try_into()
                .map_err(|_| E::custom("timespan must be non-negative"))?,
        )))
    }
}

impl<'de> Deserialize<'de> for KeyValiditySpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(ValidityVisitor)
    }
}

impl Serialize for KeyValiditySpec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            KeyValiditySpec::Finite(time_span) => time_span.serialize(serializer),
            KeyValiditySpec::Forever => "forever".serialize(serializer),
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

//----------- KeyManagerRecordsSpec --------------------------------------------

/// Policy for managing special DNS records.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct KeyManagerRecordsSpec {
    /// The TTL to use when creating special records.
    pub ttl: TimeSpan,

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
            ttl: TimeSpan::from_secs(3600), // Reference?

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
    pub algorithm: KeyGenerationParametersSpec,
}

impl Default for KeyManagerGenerationSpec {
    fn default() -> Self {
        Self {
            hsm_server_id: None,

            // Default to KSK plus ZSK. CSK key rolls are more complex.
            // No official reference.
            use_csk: false,

            algorithm: KeyGenerationParametersSpec::EcdsaP256Sha256,
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
            Self::RsaSha256(2048) => "RSASHA256",
            Self::RsaSha512(2048) => "RSASHA512",
            Self::EcdsaP256Sha256 => "ECDSAP256SHA256",
            Self::EcdsaP384Sha384 => "ECDSAP384SHA384",
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "ED448",

            Self::RsaSha256(bits) => return write!(f, "RSASHA256:{bits}"),
            Self::RsaSha512(bits) => return write!(f, "RSASHA512:{bits}"),
        })
    }
}

impl FromStr for KeyGenerationParametersSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(bits) = s.strip_prefix("RSASHA256:") {
            match bits.parse::<u16>() {
                Ok(bits) => Ok(Self::RsaSha256(bits)),
                Err(err) => Err(format!("Could not parse key size {bits:?}: {err}")),
            }
        } else if let Some(bits) = s.strip_prefix("RSASHA512:") {
            match bits.parse::<u16>() {
                Ok(bits) => Ok(Self::RsaSha512(bits)),
                Err(err) => Err(format!("Could not parse key size {bits:?}: {err}")),
            }
        } else {
            Ok(match s {
                "RSASHA256" => Self::RsaSha256(2048),
                "RSASHA512" => Self::RsaSha512(2048),
                "ECDSAP256SHA256" => Self::EcdsaP256Sha256,
                "ECDSAP384SHA384" => Self::EcdsaP384Sha384,
                "ED25519" => Self::Ed25519,
                "ED448" => Self::Ed448,
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
    pub signature_inception_offset: TimeSpan,

    /// How long record signatures will be valid for, in seconds.
    pub signature_lifetime: TimeSpan,

    /// How long before expiration a new signature has to be
    /// generated, in seconds.
    pub signature_remain_time: TimeSpan,

    /// How often should the signatures in the zone be checked and
    /// updated. This generates a new version of the signed zone.
    pub signature_refresh_interval: TimeSpan,

    /// How long should it take to resign a zone during a ZSK or CSK roll.
    pub key_roll_time: TimeSpan,

    /// How denial-of-existence records are generated.
    pub denial: SignerDenialSpec,

    /// Reviewing signed zones.
    pub review: ReviewSpec,
    //
    // TODO:
    // - Signing policy (disabled, pass-through?, enabled)
}

impl Default for SignerSpec {
    fn default() -> Self {
        Self {
            serial_policy: Default::default(),

            signature_inception_offset: TimeSpan::from_secs(SIGNATURE_INCEPTION_OFFSET),
            signature_lifetime: TimeSpan::from_secs(SIGNATURE_VALIDITY_TIME),
            signature_remain_time: TimeSpan::from_secs(SIGNATURE_REMAIN_TIME),
            signature_refresh_interval: TimeSpan::from_secs(SIGNATURE_REFRESH_INTERVAL),
            key_roll_time: TimeSpan::from_secs(KEY_ROLL_TIME),

            denial: Default::default(),

            review: Default::default(),
        }
    }
}

//----------- RecordSigningSpec ------------------------------------------------

/// Policy for signing DNS records.
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct RecordSigningSpec {
    /// The offset for generated signature inceptions.
    pub signature_inception_offset: TimeSpan,

    /// The lifetime of generated signatures.
    pub signature_lifetime: TimeSpan,

    /// The amount of time remaining before expiry when signatures will be
    /// regenerated.
    pub signature_remain_time: TimeSpan,
}

impl Default for RecordSigningSpec {
    fn default() -> Self {
        Self {
            signature_inception_offset: TimeSpan::from_secs(SIGNATURE_INCEPTION_OFFSET),
            signature_lifetime: TimeSpan::from_secs(SIGNATURE_VALIDITY_TIME),
            signature_remain_time: TimeSpan::from_secs(SIGNATURE_REMAIN_TIME),
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

//----------- SignerDenialSpec -------------------------------------------------

// Missing here is the TTL of the NSEC/NSEC3/NSEC3PARAMS records.
// Make the ttl Option<u64>. None means use the SOA minimum.
// Turn SignerDenialSpec into a struct.

/// Spec for generating denial-of-existence records.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "type")]
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
        #[serde(rename = "opt-out")]
        opt_out: bool,
        // Missing fields:
        // - salt
        // - iterations
        // RFC 9276 Section 3.1 recommends an iteration count of 0.
        // RFC 9276 Section 3.1 recommends an empty salt.
    },
}

//----------- ReviewSpec -------------------------------------------------------

/// Policy for reviewing loaded/signed zones.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ReviewSpec {
    /// Do not review
    #[default]
    Off,

    /// Reset the pipeline on reject
    #[serde(rename_all = "kebab-case")]
    Manual {
        #[serde(default)]
        on_reject: RejectionSpec,
    },

    /// Halt the pipeline on reject
    #[serde(rename_all = "kebab-case")]
    Script {
        hook: String,
        #[serde(default)]
        on_reject: RejectionSpec,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RejectionSpec {
    /// Reset the pipeline on reject
    #[default]
    Discard,

    /// Halt the pipeline on reject
    Halt,
}

//----------- ServerSpec -------------------------------------------------------

/// Policy for serving zones.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ServerSpec {
    pub outbound: OutboundSpec,
}

//----------- OutboundSpec ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct OutboundSpec {
    /// The set of nameservers to which zone transfers may be provided.
    ///
    /// If empty, zone transfers will be provided to any nameserver.
    pub provide_xfr_to: Vec<NameserverCommsSpec>,

    /// The set of nameservers to which NOTIFY messages should be sent.
    ///
    /// If empty, no NOTIFY messages will be sent.
    ///
    /// TODO: support the RFC 1996 "Notify Set"?
    pub send_notify_to: Vec<NameserverCommsSpec>,

    /// The maximum number of IXFR diffs to keep.
    ///
    /// Excess diffs will be discarded.
    pub max_diffs: usize,

    /// The maximum percentage of change allowed for a single IXFR diff.
    ///
    /// Only diffs that desribe smaller changes (compared to the last
    /// published version of the zone) than this limit will be stored and
    /// served to clients.
    pub max_diffs_size: usize,
}

impl Default for OutboundSpec {
    fn default() -> Self {
        Self {
            provide_xfr_to: vec![],
            send_notify_to: vec![],
            max_diffs: MAX_DIFFS,
            max_diffs_size: MAX_DIFFS_SIZE,
        }
    }
}

//----------- NameserverCommsSpec --------------------------------------------

/// Policy for communicating with another namesever.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    untagged,
    expecting = "a string ('<IP>[:<PORT>][^<TSIG_KEY_NAME>]') or an inline table"
)]
pub enum NameserverCommsSpec {
    /// A simple notify specification.
    Simple(SimpleNameserverCommsSpec),

    /// A complex notify specification.
    Complex(ComplexNameserverCommsSpec),
}

/// Policy for communicating with another namesever.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ComplexNameserverCommsSpec {
    /// The address to send NOTIFYs to or allow XFRs from.
    pub addr: SocketAddr,

    /// An optional TSIG key to sign and authenticate messages with.
    pub tsig_key_name: Option<KeyName>,
}

/// Policy for communicating with another namesever.
#[derive(Clone, Debug, DeserializeFromStr, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SimpleNameserverCommsSpec {
    /// The address to send NOTIFYs to or allow XFRs from.
    pub addr: SocketAddr,

    /// An optional TSIG key to sign and authenticate messages with.
    pub tsig_key_name: Option<KeyName>,
}

/// Parse`<IP_ADDRESS>[:<PORT>][^<TSIG_KEY_NAME>]`
impl FromStr for SimpleNameserverCommsSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (s, tsig_key_name) = s.split_once('^').unwrap_or((s, ""));

        let tsig_key_name = if !tsig_key_name.is_empty() {
            Some(
                KeyName::from_str(tsig_key_name)
                    .map_err(|err| format!("Invalid TSIG key name '{tsig_key_name}': {err}"))?,
            )
        } else {
            None
        };

        let addr = IpAddr::from_str(s)
            .map(|ip| SocketAddr::new(ip, 53))
            .or_else(|_| {
                SocketAddr::from_str(s)
                    .map_err(|err| format!("Invalid socket address '{s}': {err}"))
            })?;
        Ok(SimpleNameserverCommsSpec {
            addr,
            tsig_key_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::datetime::TimeSpan;

    use super::KeyValiditySpec;

    #[test]
    fn parse_key_validity_spec() {
        #[derive(Deserialize)]
        struct Foo {
            val: Vec<KeyValiditySpec>,
        }

        let foo: Foo = toml::from_str(
            r#"
            val = [
              10,
              "10",
              "10s",
              "10m",
              "10h",
              "10d",
              "365d",
              "10w",
              "forever",
            ]
            "#,
        )
        .unwrap();
        assert_eq!(
            foo.val,
            vec![
                KeyValiditySpec::Finite(TimeSpan::from_secs(10)),
                KeyValiditySpec::Finite(TimeSpan::from_secs(10)),
                KeyValiditySpec::Finite(TimeSpan::from_secs(10)),
                KeyValiditySpec::Finite(TimeSpan::from_secs(10 * 60)),
                KeyValiditySpec::Finite(TimeSpan::from_secs(10 * 60 * 60)),
                KeyValiditySpec::Finite(TimeSpan::from_secs(10 * 60 * 60 * 24)),
                KeyValiditySpec::Finite(TimeSpan::from_secs(365 * 60 * 60 * 24)),
                KeyValiditySpec::Finite(TimeSpan::from_secs(10 * 60 * 60 * 24 * 7)),
                KeyValiditySpec::Forever,
            ]
        )
    }
}
