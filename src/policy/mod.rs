//! Zone policy.

use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::{fs, io, sync::Arc, time::Duration};

use bytes::Bytes;
use camino::Utf8PathBuf;
use domain::base::Name;
use domain::base::Ttl;
use serde::{Deserialize, Serialize};

use crate::center::Change;
use crate::zone::ZoneByName;
use crate::{api::PolicyReloadError, config::Config};

pub mod file;

//----------- Policy -----------------------------------------------------------

/// A policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The latest version of the policy.
    pub latest: Arc<PolicyVersion>,

    /// Whether the policy is being deleted.
    ///
    /// This is an intermediate state used to prevent race conditions while the
    /// policy is being removed.  In this state, new zones cannot be attached to
    /// this policy.
    pub mid_deletion: bool,

    /// The zones using this policy.
    pub zones: foldhash::HashSet<Name<Bytes>>,
}

//--- Loading / Saving

impl Policy {
    /// Reload this policy.
    #[allow(clippy::mutable_key_type)]
    pub fn reload(
        &mut self,
        config: &Config,
        zones: &foldhash::HashSet<ZoneByName>,
        on_change: impl FnMut(Change),
    ) -> io::Result<()> {
        // TODO: Carefully consider how 'config.policy_dir' and the path last
        // loaded from are synchronized.

        let path = config.policy_dir.join(format!("{}.toml", self.latest.name));
        file::Spec::load(&path)?.parse_into(self, zones, on_change);
        Ok(())
    }
}

/// Reload all policies.
#[allow(clippy::mutable_key_type)]
pub fn reload_all(
    policies: &mut foldhash::HashMap<Box<str>, Policy>,
    zones: &foldhash::HashSet<ZoneByName>,
    config: &Config,
    mut on_change: impl FnMut(Change),
) -> Result<(), PolicyReloadError> {
    // TODO: This function is not atomic: it may have effects even if it fails.

    // Write the loaded policies to a new hashmap, so policies that no longer
    // exist can be detected easily.
    let mut new_policies = foldhash::HashMap::<_, _>::default();

    // Traverse all objects in the policy directory.
    for entry in fs::read_dir(&*config.policy_dir)
        .map_err(|e| PolicyReloadError::Io(config.policy_dir.clone().into(), e.to_string()))?
    {
        let entry = entry
            .map_err(|e| PolicyReloadError::Io(config.policy_dir.clone().into(), e.to_string()))?;

        // Filter for UTF-8 paths.
        let Ok(path) = Utf8PathBuf::from_path_buf(entry.path()) else {
            log::warn!(
                "Ignoring potential policy '{}' as the path is non-UTF-8",
                entry.path().display()
            );
            continue;
        };

        // Filter hidden files.
        if path
            .file_name()
            .expect("this path has a known parent directory")
            .starts_with('.')
        {
            log::debug!("Ignoring hidden file '{path}' among policies");
            continue;
        }

        // Filter for '.toml' files.
        if path
            .extension()
            .is_none_or(|e| !e.eq_ignore_ascii_case("toml"))
        {
            log::warn!("Ignoring potential policy '{path}'; policies must end in '.toml'");
            continue;
        }

        // Try loading the file; ignore a failure if it's a directory.
        //
        // NOTE: Checking that the object is a file, and then opening it, would
        // be vulnerable to TOCTOU.
        let spec = match file::Spec::load(&path) {
            Ok(spec) => spec,
            // Ignore a directory ending in '.toml'.
            Err(err) if err.kind() == io::ErrorKind::IsADirectory => {
                log::warn!("Ignoring potential policy '{path}'; policies must be files");
                continue;
            }
            Err(err) => return Err(PolicyReloadError::Io(path, err.to_string())),
        };

        // Build a new policy or merge an existing one.
        let name = path
            .file_stem()
            .expect("this path points to a readable file, so it must have a file name");
        let policy = if let Some(mut policy) = policies.remove(name) {
            spec.parse_into(&mut policy, zones, &mut on_change);
            policy
        } else {
            log::info!("Loaded new policy '{name}'");
            let policy = spec.parse(name);
            (on_change)(Change::PolicyAdded(policy.latest.clone()));
            policy
        };

        // Record the new policy.
        let prev = new_policies.insert(name.into(), policy);
        assert!(prev.is_none(), "there is at most one policy per path");
    }

    // Traverse policies whose files were not found.
    for (name, policy) in policies.drain() {
        // If any zones are using this policy, keep it.
        if !policy.zones.is_empty() {
            log::error!("The file backing policy '{name}' has been removed, but some zones are still using it; Cascade will preserve its internal copy");
            let prev = new_policies.insert(name, policy);
            assert!(
                prev.is_none(),
                "'new_policies' and 'policies' are disjoint sets"
            );
        } else {
            log::info!("Forgetting now-removed policy '{name}'");
            (on_change)(Change::PolicyRemoved(policy.latest));
        }
    }

    // Update the set of policies.
    *policies = new_policies;

    Ok(())
}

//----------- PolicyVersion ----------------------------------------------------

/// A particular version of a policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyVersion {
    /// The name of the policy.
    pub name: Box<str>,

    /// How zones are loaded.
    pub loader: LoaderPolicy,

    /// Zone key management.
    pub key_manager: KeyManagerPolicy,

    /// How zones are signed.
    pub signer: SignerPolicy,

    /// How zones are served.
    pub server: ServerPolicy,
}

//----------- LoaderPolicy -----------------------------------------------------

/// Policy for loading zones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoaderPolicy {
    /// Reviewing loaded zones.
    pub review: ReviewPolicy,
}

//----------- KeyManagerPolicy -------------------------------------------------

/// Policy for zone key management.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyManagerPolicy {
    /// Whether and which HSM is being used by the key manager.
    pub hsm_server_id: Option<String>,

    /// Whether to use a CSK (if true) or a KSK and a ZSK.
    pub use_csk: bool,

    /// Algorithm and other parameters for key generation.
    pub algorithm: KeyParameters,

    /// Validity of KSKs.
    pub ksk_validity: Option<u64>,
    /// Validity of ZSKs.
    pub zsk_validity: Option<u64>,
    /// Validity of CSKs.
    pub csk_validity: Option<u64>,

    /// Configuration variable for automatic KSK rolls.
    pub auto_ksk: AutoConfig,
    /// Configuration variable for automatic ZSK rolls.
    pub auto_zsk: AutoConfig,
    /// Configuration variable for automatic CSK rolls.
    pub auto_csk: AutoConfig,
    /// Configuration variable for automatic algorithm rolls.
    pub auto_algorithm: AutoConfig,

    /// DNSKEY signature inception offset (positive values are subtracted
    ///from the current time).
    pub dnskey_inception_offset: u64,

    /// DNSKEY signature lifetime
    pub dnskey_signature_lifetime: u64,

    /// The required remaining signature lifetime.
    pub dnskey_remain_time: u64,

    /// CDS/CDNSKEY signature inception offset
    pub cds_inception_offset: u64,

    /// CDS/CDNSKEY signature lifetime
    pub cds_signature_lifetime: u64,

    /// The required remaining signature lifetime.
    pub cds_remain_time: u64,

    /// The DS hash algorithm.
    pub ds_algorithm: DsAlgorithm,

    /// The TTL to use when creating DNSKEY/CDS/CDNSKEY records.
    pub default_ttl: Ttl,

    /// Automatically remove keys that are no long in use.
    pub auto_remove: bool,
}

//----------- SignerPolicy -----------------------------------------------------

/// Policy for signing zones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerPolicy {
    /// The serial number generation policy.
    ///
    /// This is used to generate new SOA serial numbers, inserted into zones
    /// being (re)signed.
    pub serial_policy: SignerSerialPolicy,

    /// The offset for record signature inceptions.
    ///
    /// When DNS records are signed, the `RRSIG` signature records will record
    /// that the signature was made this far in the past.  This can help DNSSEC
    /// validation pass in case the signer and validator disagree on the current
    /// time (by a small amount).
    pub sig_inception_offset: Duration,

    /// How long record signatures will be valid for.
    pub sig_validity_time: Duration,

    /// How long before expiration a new signature has to be generated.
    pub sig_remain_time: Duration,

    /// How denial-of-existence records are generated.
    pub denial: SignerDenialPolicy,

    /// Reviewing signed zones.
    pub review: ReviewPolicy,
    //
    // TODO:
    // - Signing policy (disabled, pass-through?, enabled)
    // - Support keeping unsigned vs. signed zone serials distinct
}

//----------- SignerSerialPolicy -----------------------------------------------

/// Policy for generating serial numbers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SignerSerialPolicy {
    /// Use the same serial number as the unsigned zone.
    ///
    /// The zone cannot be resigned, not without a change in the underlying
    /// unsigned contents.
    Keep,

    /// Increment the serial number on every change.
    Counter,

    /// Use the current Unix time, in seconds.
    ///
    /// New versions of the zone cannot be generated in the same second.
    UnixTime,

    /// Set the serial number to `<YYYY><MM><DD><xx>`.
    ///
    /// The serial number, when formatted in decimal, contains the calendar
    /// date (in the UTC timezone).  The `<xx>` component is a simple counter;
    /// at most 100 versions of the zone can be used per day.
    //
    // TODO: How to handle "emergency" situations where the zone will expire?
    DateCounter,
}

impl std::fmt::Display for SignerSerialPolicy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerSerialPolicy::Keep => f.write_str("keep"),
            SignerSerialPolicy::Counter => f.write_str("counter"),
            SignerSerialPolicy::UnixTime => f.write_str("unix time"),
            SignerSerialPolicy::DateCounter => f.write_str("date counter"),
        }
    }
}

//----------- SignerDenialPolicy -----------------------------------------------

/// Policy for generating denial-of-existence records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerDenialPolicy {
    /// Generate NSEC records.
    NSec,

    /// Generate NSEC3 records.
    NSec3 {
        /// Whether to enable NSEC3 Opt-Out.
        opt_out: bool,
    },
}

//----------- ReviewPolicy -----------------------------------------------------

/// Policy for reviewing loaded/signed zones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewPolicy {
    /// Whether review is required.
    ///
    /// If this is `false`, zones under this policy will not wait for external
    /// approval of new versions when they are loaded / signed.
    pub required: bool,

    /// A command hook for reviewing a new version of the zone.
    ///
    /// When a new loaded / signed version of the zone is prepared, this hook
    /// (if [`Some`]) will be spawned to verify the zone.  If review is required
    /// and the hook fails, the zone will not be propagated.
    pub cmd_hook: Option<String>,
}

//----------- ServerPolicy -----------------------------------------------------

/// Policy for serving zones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerPolicy {
    /// Outbound policy.
    pub outbound: OutboundPolicy,
}

//----------- OutboundPolicy --------------------------------------------------

/// Policy for restricting to whom data may be sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutboundPolicy {
    /// The set of nameservers from which SOA and XFR requests may be received.
    ///
    /// If empty, any nameserver may request XFR from us.
    pub accept_xfr_requests_from: Vec<NameserverCommsPolicy>,

    /// The set of nameservers to which NOTIFY messages should be sent.
    ///
    /// If empty, no NOTIFY messages will be sent.
    ///
    /// TODO: support the RFC 1996 "Notify Set"?
    pub send_notify_to: Vec<NameserverCommsPolicy>,
}

//----------- InboundPolicy ---------------------------------------------------

/// Policy for restricting from whom data may be received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundPolicy {
    /// The set of nameservers to which SOA and XFR requests should be sent.
    ///
    /// If empty, the nameserver from which the zone was received will be
    /// contacted.
    pub send_xfr_requests_to: Vec<NameserverCommsPolicy>,

    /// The set of nameservers from which may NOTIFY messages may be received.
    ///
    /// If empty, the nameserver from which the zone was received will be
    /// allowed to send us NOTIFY messages.
    pub accept_notify_messages_from: Vec<NameserverCommsPolicy>,
}

//----------- NameserverCommsPolicy -------------------------------------------

/// Policy for communicating with another namesever.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameserverCommsPolicy {
    /// The address to send to/receive from.
    ///
    /// For sending the port MUST NOT be zero.
    ///
    /// TODO: Support IP prefixes?
    pub addr: SocketAddr,
    // TODO: Support TSIG key names?
}

//----------- KeyParameters ---------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyParameters {
    /// The RSASHA256 algorithm with the key length in bits.
    RsaSha256(usize),
    /// The RSASHA512 w algorithmith the key length in bits.
    RsaSha512(usize),
    /// The ECDSAP256SHA256 algorithm.
    ///
    /// Note that RFC 8624 Section 3.2 recommends the use of ECDSAP256SHA256
    /// for new deployments and that other users SHOULD upgrade. So it is
    /// the default.
    #[default]
    EcdsaP256Sha256,
    /// The ECDSAP384SHA384 algorithm.
    EcdsaP384Sha384,
    /// The ED25519 algorithm.
    Ed25519,
    /// The ED448 algorithm.
    Ed448,
}

impl Display for KeyParameters {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            KeyParameters::RsaSha256(bits) => write!(fmt, "RSASHA256 {bits} bits"),
            KeyParameters::RsaSha512(bits) => write!(fmt, "RSASHA512 {bits} bits"),
            KeyParameters::EcdsaP256Sha256 => write!(fmt, "ECDSAP256SHA256"),
            KeyParameters::EcdsaP384Sha384 => write!(fmt, "ECDSAP384SHA384"),
            KeyParameters::Ed25519 => write!(fmt, "ED25519"),
            KeyParameters::Ed448 => write!(fmt, "ED448"),
        }
    }
}

//----------- AutoConfig ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AutoConfig {
    /// Whether to start a key roll automatically.
    pub start: bool,
    /// Whether to handle the Report actions automatically.
    pub report: bool,
    /// Whether to handle the cache expire step automatically.
    pub expire: bool,
    /// Whether to handle the done step automatically.
    pub done: bool,
}

// Turn key roll automation on by default. This should be safe except when
// the zone is served by an anycast cluster and propagation is slow.
// It also requires network access to the zone's nameservers and the
// nameservers of the parent zone to check propagation.
impl Default for AutoConfig {
    fn default() -> Self {
        AutoConfig {
            start: true,
            report: true,
            expire: true,
            done: true,
        }
    }
}

//----------- DsAlgorithm -----------------------------------------------------

/// The hash algorithm to use for DS records.
///
/// Note the RFC 8624 has (for DNSSEC delegation use) a MUST for SHA-256,
/// a MAY for SHA-384 and a MUST NOT for SHA-1 and GOST R 34.11-94.
/// Therefore, we only support SHA-256 and SHA-384 and the default is
/// SHA-256.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum DsAlgorithm {
    /// Hash the public key using SHA-256.
    #[serde(rename = "SHA-256")]
    #[default]
    Sha256,
    /// Hash the public key using SHA-384.
    #[serde(rename = "SHA-384")]
    Sha384,
}

impl Display for DsAlgorithm {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            DsAlgorithm::Sha256 => write!(fmt, "SHA-256"),
            DsAlgorithm::Sha384 => write!(fmt, "SHA-384"),
        }
    }
}
