//! Zone policy.

use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::time::Duration;
use std::{fs, io, sync::Arc};

use bytes::Bytes;
use camino::Utf8PathBuf;
use domain::base::Name;
use domain::base::Ttl;
use domain::tsig::KeyName;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::tsig::TsigStore;
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

pub enum PolicyChange {
    #[expect(dead_code)]
    Removed(Arc<PolicyVersion>),
    Updated {
        old: Arc<PolicyVersion>,
        new: Arc<PolicyVersion>,
    },
    Added(Arc<PolicyVersion>),
}

/// Reload all policies.
///
/// Any changes are reported via the `on_change` callback.
// Allow the large enum variant caused by TsigKeyName using Name<Array<255>>
// to avoid the conversions that would be needed if Name<Bytes> were to be
// used instead.
#[allow(clippy::result_large_err)]
pub fn reload_all(
    policies: &mut foldhash::HashMap<Box<str>, Policy>,
    config: &Config,
    tsig_store: &TsigStore,
    mut on_change: impl FnMut(&Box<str>, PolicyChange),
) -> Result<(), PolicyReloadError> {
    let new_versions = load_all(policies, config, tsig_store)?;

    let mut new_policies = foldhash::HashMap::default();

    for (name, new_version) in new_versions {
        if let Some(mut pol) = policies.remove(&name) {
            if *pol.latest == new_version {
                new_policies.insert(name, pol);
            } else {
                let new = Arc::new(new_version);
                let old = std::mem::replace(&mut pol.latest, new.clone());
                (on_change)(&name, PolicyChange::Updated { old, new });

                new_policies.insert(name, pol);
            }
        } else {
            let new = Arc::new(new_version);
            (on_change)(&name, PolicyChange::Added(new.clone()));

            new_policies.insert(
                name,
                Policy {
                    latest: new,
                    mid_deletion: false,
                    zones: Default::default(),
                },
            );
        }
    }

    // Traverse policies whose files were not found.
    for (name, policy) in policies.drain() {
        // If any zones are using this policy, keep it.
        if !policy.zones.is_empty() {
            error!(
                "The file backing policy '{name}' has been removed, but some zones are still using it; Cascade will preserve its internal copy"
            );
            let prev = new_policies.insert(name, policy);
            assert!(
                prev.is_none(),
                "'new_policies' and 'policies' are disjoint sets"
            );
        } else {
            info!("Forgetting now-removed policy '{name}'");
            (on_change)(
                &policy.latest.name,
                PolicyChange::Removed(policy.latest.clone()),
            );
        }
    }

    // Update the set of policies.
    *policies = new_policies;

    Ok(())
}

/// Load all the policies based on the path to the config
///
/// The current policies are used for logging purposes so we can log whether
/// a policy is new, updated, unchanged or removed.
// Allow the large enum variant caused by TsigKeyName using Name<Array<255>>
// to avoid the conversions that would be needed if Name<Bytes> were to be
// used instead.
#[allow(clippy::result_large_err)]
pub fn load_all(
    policies: &foldhash::HashMap<Box<str>, Policy>,
    config: &Config,
    tsig_store: &TsigStore,
) -> Result<foldhash::HashMap<Box<str>, PolicyVersion>, PolicyReloadError> {
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
            warn!(
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
            debug!("Ignoring hidden file '{path}' among policies");
            continue;
        }

        // Filter for '.toml' files.
        if path
            .extension()
            .is_none_or(|e| !e.eq_ignore_ascii_case("toml"))
        {
            warn!("Ignoring potential policy '{path}'; policies must end in '.toml'");
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
                warn!("Ignoring potential policy '{path}'; policies must be files");
                continue;
            }
            Err(err) => return Err(PolicyReloadError::Io(path, err.to_string())),
        };

        // Build a new policy or merge an existing one.
        let name = path
            .file_stem()
            .expect("this path points to a readable file, so it must have a file name");

        let policy = spec.parse(name);

        check_policy(&policy, tsig_store)?;
        if policies.contains_key(name) {
            info!("Reloaded policy '{name}'");
        } else {
            info!("Loaded new policy '{name}'");
        }

        // Record the new policy.
        let prev = new_policies.insert(name.into(), policy);
        assert!(prev.is_none(), "there is at most one policy per path");
    }

    Ok(new_policies)
}

/// Perform a semantic check on the loaded policy.
// Allow the large enum variant caused by TsigKeyName using Name<Array<255>>
// to avoid the conversions that would be needed if Name<Bytes> were to be
// used instead.
#[allow(clippy::result_large_err)]
fn check_policy(policy: &PolicyVersion, tsig_store: &TsigStore) -> Result<(), PolicyReloadError> {
    // Check the publication nameservers for the key manager. Any TSIG key
    // that is part of those nameservers has to exist in the TSIG key store.
    let tsig_names = policy
        .key_manager
        .publication_nameservers
        .iter()
        .chain(policy.server.outbound.provide_xfr_to.iter())
        .chain(policy.server.outbound.send_notify_to.iter())
        .filter_map(|ns| ns.tsig_key_name.as_ref());

    for tsig_name in tsig_names {
        tsig_store
            .get(tsig_name)
            .ok_or(PolicyReloadError::NoSuchTsigKey(tsig_name.clone()))?;
    }

    // Check signer policy.

    // sig_validity_time
    //
    // The maximum sig_validity_time is determined by what we can put in
    // the expiration time. Expiration time is effectively a 32-bit signed
    // value. So sig_validity_time has to be less then 0x8000_0000. To
    // give ourselves some headroom, set the limit to 0x4000_0000.
    if policy.signer.sig_validity_time >= 0x4000_0000 {
        return Err(PolicyReloadError::BadValue(format!(
            "signature-lifetime {} too big (>= 0x4000_0000)",
            policy.signer.sig_validity_time
        )));
    }

    // The minimum value of sig_validity_time is bounded by sig_remain_time
    // and signature_refresh_interval. We get to this later.

    // sig_remain_time
    //
    // The effective lifetime of a signature is
    // sig_validity_time - sig_remain_time. This needs to be greater than
    // zero. So the maximum value of sig_remain_time is bounded by
    // sig_validity_time. We will check this later.
    //
    // Ideally, sig_remain_time should be larger than the maximum TTL
    // to make sure that old signatures are removed from caches before
    // they expire. We don't have a maximum TTL value. So what the signer
    // does is add the TTL of an RRset to sig_remain_time to determine
    // if a signature needs to be refreshed. For this reason, the lower bound
    // of sig_remain_time is zero. However, this does not leave any margin
    // for error.

    // signature_refresh_interval
    //
    // The maximum is again bounded by sig_validity_time.
    //
    // Each signature_refresh_interval seconds, the signer will generate a
    // new version of the zone with some refreshed signatures. For this reason,
    // signature_refresh_interval should not be too low. Enforce a lower
    // bound of 60 seconds to avoid accidentally generating new zone versions
    // at a high rate.
    if policy.signer.signature_refresh_interval < 60 {
        return Err(PolicyReloadError::BadValue(format!(
            "signature-refresh-interval {} too small (< 60)",
            policy.signer.signature_refresh_interval
        )));
    }

    // Check if everything fits together. The effective lifetime of a
    // signature is sig_validity_time - sig_remain_time. This needs to be
    // greater than zero. We need to take TTL into account. Assume a reasonable
    // TTL of one hour (3600 seconds). So now we have
    // sig_validity_time - sig_remain_time - 3600 > 0.
    // We sign every signature_refresh_interval so we need to take that into
    // account. Which gives:
    // sig_validity_time - sig_remain_time - 3600 - signature_refresh_interval > 0
    // Which can be written as:
    // sig_validity_time > sig_remain_time + 3600 + signature_refresh_interval
    //
    // If an RRset has a high TTL such that
    // sig_remain_time + TTL + signature_refresh_interval >= sig_validity_time
    // then the signature will be refreshed every signature_refresh_interval
    // and an error will be logged. In extreme cases, i.e. when
    // TTL + signature_refresh_interval > sig_validity_time
    // then validation errors may happen due to caching. However, this only
    // affects RRsets with too high TTLs. The rest of the zone will be
    // unaffected.
    if policy.signer.sig_validity_time
        <= policy.signer.sig_remain_time + 3600 + policy.signer.signature_refresh_interval
    {
        return Err(PolicyReloadError::BadValue(format!(
            "signature-lifetime ({}) too small (<= signature-remain-time ({}) + room for TTL (3600) + signature-refresh-interval ({}))",
            policy.signer.sig_validity_time,
            policy.signer.sig_remain_time,
            policy.signer.signature_refresh_interval
        )));
    }

    // key_roll_time
    //
    // If the value is too high then the key roll never completes. It is not
    // clear if there is a sensible upper bound.
    //
    // It is fine to set this value to zero, the key roll will just complete
    // the next time the refresh timer expires.
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
    pub ksk_validity: Option<u32>,
    /// Validity of ZSKs.
    pub zsk_validity: Option<u32>,
    /// Validity of CSKs.
    pub csk_validity: Option<u32>,

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
    pub dnskey_inception_offset: u32,

    /// DNSKEY signature lifetime
    pub dnskey_signature_lifetime: u32,

    /// The required remaining signature lifetime.
    pub dnskey_remain_time: u32,

    /// CDS/CDNSKEY signature inception offset
    pub cds_inception_offset: u32,

    /// CDS/CDNSKEY signature lifetime
    pub cds_signature_lifetime: u32,

    /// The required remaining signature lifetime.
    pub cds_remain_time: u32,

    /// The DS hash algorithm.
    pub ds_algorithm: DsAlgorithm,

    /// The TTL to use when creating DNSKEY/CDS/CDNSKEY records.
    pub default_ttl: Ttl,

    /// Automatically remove keys that are no longer in use.
    pub auto_remove: bool,

    /// Remove keys after this amount of time.
    pub auto_remove_delay: Duration,

    /// Nameservers to check for RRSIG propagation during a key roll.
    pub publication_nameservers: Vec<NameserverCommsPolicy>,
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
    pub sig_inception_offset: u32,

    /// How long record signatures will be valid for.
    pub sig_validity_time: u32,

    /// How long before expiration a new signature has to be generated.
    pub sig_remain_time: u32,

    /// How often to refresh some amount of signatures to make resigning
    /// smoother.
    pub signature_refresh_interval: u32,

    /// How long should it take to resign a zone during a ZSK or CSK roll.
    pub key_roll_time: u32,

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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReviewPolicy {
    pub mode: ReviewMode,

    pub on_reject: OnReject,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ReviewMode {
    #[default]
    Off,
    Manual,
    Script {
        hook: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum OnReject {
    #[default]
    Discard,
    Halt,
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
    /// The set of nameservers to which zone transfers may be provided.
    ///
    /// If empty, zone transfers will be provided to any nameserver.
    pub provide_xfr_to: Vec<NameserverCommsPolicy>,

    /// The set of nameservers to which NOTIFY messages should be sent.
    ///
    /// If empty, no NOTIFY messages will be sent.
    ///
    /// TODO: support the RFC 1996 "Notify Set"?
    pub send_notify_to: Vec<NameserverCommsPolicy>,

    /// The maximum number of IXFR diffs to keep.
    ///
    /// Excess diffs will be discarded.
    pub max_diffs: usize,

    /// The maximum size that in-memory diffs may reach as a percentage
    /// of the published zone.
    ///
    /// IXFR diffs that describe larger changes (compared to the last
    /// published version of the zone) than this limit will be kept in-memory
    /// to to serve to IXFR clients.
    pub max_diffs_size: usize,
}

//----------- NameserverCommsPolicy -------------------------------------------

/// Policy for communicating with another namesever.
///
/// This type serves a dual purpose:
///   - For outbound communication it specifies the address and port of the
///     nameserver to contact, and optionally a TSIG key that should be used
///     to sign outbound requests. When used for this purpose the address and
///     port are mandatory.
///   - For inbound communication this type is intended to support the access
///     control use case, acting as a white list entry. When used for this
///     purpose typically a port is not specified as the sending port that
///     will be used by the client cannot be known in advance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameserverCommsPolicy {
    /// The address to send to/receive from.
    ///
    /// TODO: Support IP prefixes?
    pub addr: SocketAddr,

    /// An optional TSIG key to sign and authenticate messages with.
    pub tsig_key_name: Option<KeyName>,
}

impl Display for NameserverCommsPolicy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)?;
        if let Some(tsig_key_name) = &self.tsig_key_name {
            write!(f, "^{tsig_key_name}")?;
        }
        Ok(())
    }
}

//----------- KeyParameters ---------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyParameters {
    /// The RSASHA256 algorithm with the key length in bits.
    RsaSha256(usize),
    /// The RSASHA512 algorithm with the key length in bits.
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
