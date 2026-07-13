//! Version 1 of the zone state file.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use camino::Utf8Path;
use cascade_zonedata::SoaRecord;
use domain::base::{Rtype, Serial, Ttl};
use domain::dep::octseq::Array;
use domain::dnssec::sign::keys::keyset::UnixTime;
use domain::new::base::Record;
use domain::new::base::name::{NameBuf, RevNameBuf};
use domain::new::base::wire::{BuildBytes, ParseBytes};
use domain::new::rdata::Soa;
use domain::utils::dst::UnsizedCopy;
use domain::{base::Name, rdata::dnssec::Timestamp};
use serde::{Deserialize, Serialize};

use crate::loader::Source;
use crate::persistence::zone::{
    PersistedDiffFileInfo, PersistedDiffManager, PersistedDiffRecordSource,
};
use crate::policy::file::v1::{NameserverCommsSpec, OutboundSpec};
use crate::policy::{AutoConfig, DsAlgorithm, KeyParameters};
use crate::tsig::TsigStore;
use crate::zone::instance::PersistedInstance;
use crate::zone::{HistoryItem, Instances, LastPublished, LoadedInstance, SignedInstance};
use crate::{
    policy::{
        KeyManagerPolicy, LoaderPolicy, PolicyVersion, ReviewPolicy, ServerPolicy,
        SignerDenialPolicy, SignerPolicy, SignerSerialPolicy,
    },
    zone::ZoneState,
};

use super::MissingTsigKeyError;

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

    /// Metadata related to the last published zone version.
    pub last_published: Option<LastPublished>,

    /// Instances of the zone.
    pub instances: InstancesSpec,

    /// The source of the zone.
    pub source: ZoneLoadSourceSpec,

    /// The minimum expiration time in the signed zone we are serving from
    /// the publication server.
    pub min_expiration: Option<Timestamp>,

    /// The minimum expiration time in the most recently signed zone. This
    /// value should be move to min_expiration after the signed zone is
    /// approved.
    pub next_min_expiration: Option<Timestamp>,

    /// We expect this from the key manager. These are the types that
    /// the key manager takes control over in the apex. Use this to
    /// determine if the zone needs resigning. If what is stored here is
    /// different from what we get from the key manager, then update this
    /// field and resign the zone. Maybe this should be associated with
    /// a signed instance of a zone to avoid problems when a signed zone
    /// gets rejected.
    pub apex_remove: HashSet<Rtype>,

    /// Same comment as for apex_remove. But this is about the records
    /// that should be added to the apex after removing the apex_remove
    /// types.
    pub apex_extra: Vec<String>,

    /// This field is set based on the key tags of the keys that need to
    /// sign the zone. It doesn't say anything about how the zone is
    /// currently signed, just what the goal is. This field is used to
    /// detiermine when a ZSK or CSK key roll has started and the zone
    /// needs to be resigned with a new key.
    pub key_tags: HashSet<u16>,

    /// Record when key_tags has changed. We take this as the start of a key
    /// roll. This start time is used to compute which percentage of
    /// RRsets that should have signatures from the new key.
    pub key_roll: Option<UnixTime>,

    /// Record when the last time signtures were refreshed. This is used
    /// together with the signature_refresh_interval value in policy to
    /// determine when to refresh signatures next. Maybe this should be
    /// associated with a signed instance of a zone to avoid problems when
    /// a signed zone gets rejected.
    pub last_signature_refresh: UnixTime,

    /// Record the SOA serial of the last signed version of the zone.
    /// We use a serial only once, even if the signed zone gets rejected.
    /// It would be good to have a command where the user can set the
    /// serial for the Increment serial policy.
    pub previous_serial: Option<Serial>,

    /// History of interesting events that occurred for this zone.
    pub history: Vec<HistoryItem>,

    /// Locations of persisted unsigned zone diffs to enable IXFR from
    /// the upstream to resume on restart, and to enable a complete latest
    /// unsigned version of the zone to be reconstituted.
    pub persisted_loaded_diffs: PersistedDiffsSpec,

    /// Locations of persisted signed zone diffs to ensure IXFR out toward
    /// downstreams is still possible after restart, and to enable a complete
    /// latest signed version of the zone to be reconsituted.
    pub persisted_signed_diffs: PersistedDiffsSpec,
}

//--- Conversion

impl Spec {
    /// Build into this specification.
    pub fn build(zone: &ZoneState) -> Self {
        Self {
            policy: zone.policy.as_ref().map(|p| PolicySpec::build(p)),
            last_published: zone.last_published.clone(),
            instances: InstancesSpec::build(&zone.instances),
            source: ZoneLoadSourceSpec::build(&zone.loader.source),
            min_expiration: zone.min_expiration,
            next_min_expiration: zone.next_min_expiration,
            apex_remove: zone.apex_remove.clone(),
            apex_extra: zone.apex_extra.clone(),
            key_tags: zone.key_tags.clone(),
            key_roll: zone.key_roll.clone(),
            last_signature_refresh: zone.last_signature_refresh.clone(),
            previous_serial: zone.previous_serial,
            history: zone.history.clone(),
            persisted_loaded_diffs: PersistedDiffsSpec::build_loaded(
                &zone.persistence.loaded_diffs,
            ),
            persisted_signed_diffs: PersistedDiffsSpec::build_signed(
                &zone.persistence.signed_diffs,
            ),
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
            auto_remove_delay: Duration::from_secs(self.auto_remove_delay),
            publication_nameservers: self
                .publication_nameservers
                .into_iter()
                .map(|v| v.parse())
                .collect(),
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
            auto_remove_delay: policy.auto_remove_delay.as_secs(),
            publication_nameservers: policy
                .publication_nameservers
                .iter()
                .map(NameserverCommsSpec::build)
                .collect(),
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
                ReviewPolicyOnReject::Discard => crate::policy::OnReject::Discard,
                ReviewPolicyOnReject::Halt => crate::policy::OnReject::Halt,
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
                crate::policy::OnReject::Discard => ReviewPolicyOnReject::Discard,
                crate::policy::OnReject::Halt => ReviewPolicyOnReject::Halt,
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

//----------- InstancesSpec ----------------------------------------------------

/// Known instances of a zone.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct InstancesSpec {
    /// The persisted instance of the zone.
    pub persisted: Option<PersistedInstanceSpec>,
    //
    // TODO:
    // - The next usable loaded/signed instance IDs.
    // - Obsolete instances.
    // - Abandoned instances.
}

// TODO: It's frustrating that the `current`->`persisted` switch happens here,
// rather than at some higher level. It feels like a good place for it could
// be a version-independent persistence format, but that would introduce even
// more boilerplate.

impl InstancesSpec {
    /// Parse from this specification.
    pub fn parse(self) -> Instances {
        let Self { persisted } = self;

        Instances {
            upcoming: None,
            current: None,
            persisted: persisted.map(|p| p.parse()),
        }
    }

    /// Build into this specification.
    pub fn build(instances: &Instances) -> Self {
        let Instances {
            upcoming: _,
            current,
            persisted: _,
        } = instances;

        Self {
            persisted: current
                .as_ref()
                .map(|i| PersistedInstanceSpec::build(&i.to_persisted())),
        }
    }
}

//----------- PersistedInstanceSpec --------------------------------------------

/// The persisted instance of a zone.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PersistedInstanceSpec {
    /// The loaded instance.
    pub loaded: LoadedInstanceSpec,

    /// The signed instance.
    pub signed: SignedInstanceSpec,

    /// When the instance was published.
    pub pub_time: SystemTime,
}

impl PersistedInstanceSpec {
    /// Parse from this specification.
    pub fn parse(self) -> PersistedInstance {
        let Self {
            loaded,
            signed,
            pub_time,
        } = self;

        PersistedInstance {
            loaded: loaded.parse(),
            signed: signed.parse(),
            pub_time,
        }
    }

    /// Build into this specification.
    pub fn build(instance: &PersistedInstance) -> Self {
        let PersistedInstance {
            ref loaded,
            ref signed,
            pub_time,
        } = *instance;

        Self {
            loaded: LoadedInstanceSpec::build(loaded),
            signed: SignedInstanceSpec::build(signed),
            pub_time,
        }
    }
}

//----------- LoadedInstanceSpec -----------------------------------------------

/// A loaded instance of a zone.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct LoadedInstanceSpec {
    /// The SOA record of this instance.
    ///
    /// The record is serialized to the DNS wire format.
    pub soa: Box<[u8]>,

    /// The number of loaded records.
    pub num_records: NonZeroU64,
}

impl LoadedInstanceSpec {
    /// Parse from this specification.
    pub fn parse(self) -> LoadedInstance {
        let Self { soa, num_records } = self;

        // TODO: Don't panic on failure; move this into Serde.
        let soa = SoaRecord(Record::parse_bytes(&soa).unwrap().transform(
            |name: RevNameBuf| name.unsized_copy_into(),
            |data: Soa<NameBuf>| data.map_names(|n| n.unsized_copy_into()),
        ));

        LoadedInstance { soa, num_records }
    }

    /// Build into this specification.
    pub fn build(instance: &LoadedInstance) -> Self {
        let LoadedInstance {
            ref soa,
            num_records,
        } = *instance;

        let mut buffer = vec![0u8; soa.0.built_bytes_size()];
        assert!(soa.0.build_bytes(&mut buffer).unwrap().is_empty());
        let soa = buffer.into_boxed_slice();

        Self { soa, num_records }
    }
}

//----------- SignedInstanceSpec -----------------------------------------------

/// A signed instance of a zone.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SignedInstanceSpec {
    /// The SOA record of this instance.
    ///
    /// The record is serialized to the DNS wire format.
    pub soa: Box<[u8]>,

    /// The number of generated records.
    pub num_generated_records: NonZeroU64,

    /// The number of records included from the loaded instance.
    pub num_loaded_records: u64,
}

impl SignedInstanceSpec {
    /// Parse from this specification.
    pub fn parse(self) -> SignedInstance {
        let Self {
            soa,
            num_generated_records,
            num_loaded_records,
        } = self;

        // TODO: Don't panic on failure; move this into Serde.
        let soa = SoaRecord(Record::parse_bytes(&soa).unwrap().transform(
            |name: RevNameBuf| name.unsized_copy_into(),
            |data: Soa<NameBuf>| data.map_names(|n| n.unsized_copy_into()),
        ));

        SignedInstance {
            soa,
            num_generated_records,
            num_loaded_records,
        }
    }

    /// Build into this specification.
    pub fn build(instance: &SignedInstance) -> Self {
        let SignedInstance {
            ref soa,
            num_generated_records,
            num_loaded_records,
        } = *instance;

        let mut buffer = vec![0u8; soa.0.built_bytes_size()];
        assert!(soa.0.build_bytes(&mut buffer).unwrap().is_empty());
        let soa = buffer.into_boxed_slice();

        Self {
            soa,
            num_generated_records,
            num_loaded_records,
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
        tsig_key: Option<Box<Name<Array<255>>>>,
    },
}

//--- Conversion

impl ZoneLoadSourceSpec {
    /// Parse from this specification.
    pub fn parse(self, tsig_store: &TsigStore) -> Result<Source, MissingTsigKeyError> {
        match self {
            Self::None => Ok(Source::None),
            Self::Zonefile { path } => Ok(Source::Zonefile { path }),
            Self::Server { addr, tsig_key } => {
                // Look up the TSIG key from the key store.
                let tsig_key = tsig_key
                    .map(|name| {
                        tsig_store
                            .get(&name)
                            .map(|key| key.inner.clone())
                            .ok_or(MissingTsigKeyError { name })
                    })
                    .transpose()?;

                Ok(Source::Server { addr, tsig_key })
            }
        }
    }

    /// Build into this specification.
    pub fn build(source: &Source) -> Self {
        match source.clone() {
            Source::None => Self::None,
            Source::Zonefile { path } => Self::Zonefile { path },
            Source::Server { addr, tsig_key } => Self::Server {
                addr,
                tsig_key: tsig_key.map(|key| key.name().clone().into()),
            },
        }
    }
}

//------------ PersistedDiffsSpec --------------------------------------------

/// Information about a collection of persisted diffs.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PersistedDiffsSpec {
    pub is_signed: bool,
    pub next_idx: usize,
    pub restore_base_idx: usize,
    pub diff_infos: Vec<PersistedDiffFileInfoSpec>,
}

impl PersistedDiffsSpec {
    /// Parse from this specification.
    pub fn parse(self) -> PersistedDiffManager {
        let diff_infos = self
            .diff_infos
            .into_iter()
            .map(PersistedDiffFileInfoSpec::parse)
            .collect();
        let is_signed = match self.is_signed {
            true => PersistedDiffRecordSource::Signed,
            false => PersistedDiffRecordSource::Loaded,
        };
        PersistedDiffManager::from_parts(
            is_signed,
            self.next_idx,
            self.restore_base_idx,
            diff_infos,
        )
    }

    /// Build into this specification.
    fn build_loaded(loaded_diffs: &PersistedDiffManager) -> Self {
        Self {
            is_signed: false,
            next_idx: loaded_diffs.next_idx(),
            restore_base_idx: loaded_diffs.restore_base_idx(),
            diff_infos: loaded_diffs
                .diffs()
                .iter()
                .map(PersistedDiffFileInfoSpec::build)
                .collect(),
        }
    }

    /// Build into this specification.
    fn build_signed(signed_diffs: &PersistedDiffManager) -> Self {
        Self {
            is_signed: true,
            next_idx: signed_diffs.next_idx(),
            restore_base_idx: signed_diffs.restore_base_idx(),
            diff_infos: signed_diffs
                .diffs()
                .iter()
                .map(PersistedDiffFileInfoSpec::build)
                .collect(),
        }
    }
}

/// Information a single persisted diff.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PersistedDiffFileInfoSpec {
    path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    loaded_serial: Option<Serial>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signed_serial: Option<Serial>,
}

impl PersistedDiffFileInfoSpec {
    /// Parse from this specification.
    fn parse(self) -> PersistedDiffFileInfo {
        PersistedDiffFileInfo::new(
            self.path,
            self.loaded_serial
                .map(|s| domain::new::base::Serial::from(s.0)),
            self.signed_serial
                .map(|s| domain::new::base::Serial::from(s.0)),
        )
    }

    /// Build into this specification.
    fn build(info: &PersistedDiffFileInfo) -> Self {
        Self {
            path: info.path().to_path_buf(),
            loaded_serial: info.loaded_serial().map(|s| Serial(s.into())),
            signed_serial: info.signed_serial().map(|s| Serial(s.into())),
        }
    }
}
