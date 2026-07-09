//! Incremental signing.

use core::ops::RangeBounds;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet, btree_map, hash_map, hash_set};
use std::hash;
use std::sync::{Arc, RwLock};
use std::time::{Duration, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use domain::base::RecordData;
use domain::base::Serial;
use domain::base::iana::{Class, ZonemdAlgorithm, ZonemdScheme};
use domain::base::name::FlattenInto;
use domain::base::rdata::ComposeRecordData;
use domain::base::wire::Composer;
use domain::base::{
    CanonicalOrd, Name, NameBuilder, Record, Rtype, Serial as DomainSerial, ToName, Ttl,
};
use domain::dep::octseq::builder::with_infallible;
use domain::dep::octseq::{OctetsFrom, Parser};
use domain::dnssec::common::nsec3_hash;
use domain::dnssec::sign::denial::nsec::{GenerateNsecConfig, generate_nsecs};
use domain::dnssec::sign::denial::nsec3::{
    GenerateNsec3Config, Nsec3ParamTtlMode, generate_nsec3s,
};
use domain::dnssec::sign::keys::keyset::{KeyType, UnixTime};
use domain::dnssec::sign::records::{DefaultSorter, RecordsIter, Rrset};
use domain::dnssec::sign::signatures::rrsigs::sign_rrset;
use domain::new::base::build::AsBytes;
use domain::new::base::compat::iana::Class as NewClass;
use domain::new::base::name::{Name as NewName, NameBuf, RevName, RevNameBuf};
use domain::new::base::parse::{ParseBytes, ParseBytesZC};
use domain::new::base::wire::SizePrefixed;
use domain::new::base::{RType as NewRtype, TTL as NewTtl};
use domain::new::rdata::{
    Nsec as NewNsec, Nsec3 as NewNsec3, Nsec3Param as NewNsec3Param, RecordData as NewRecordData,
};
use domain::rdata::dnssec::{RtypeBitmap, Timestamp};
use domain::rdata::nsec3::OwnerHash;
use domain::rdata::{Nsec, Nsec3, Nsec3param, Soa, ZoneRecordData, Zonemd};
use domain::utils::base32;
use domain::utils::dst::UnsizedCopy;
use domain::zonefile::inplace::Entry;
use jiff::tz::TimeZone;
use jiff::{Timestamp as JiffTimestamp, Zoned};
use rayon::slice::ParallelSliceMut;
use ring::digest;
use tokio::time::Instant;
use tracing::debug;
use tracing::error;

use crate::center::Center;
use crate::manager::record_zone_event;
use crate::policy::{PolicyVersion, SignerDenialPolicy, SignerSerialPolicy};
use crate::signer::SigningTrigger;
use crate::signer::keys::ZoneSigningKeys;
use crate::signer::status::SigningStatusPerZone;
use crate::units::key_manager::mk_dnst_keyset_state_file_path;
use crate::units::zone_signer::{
    KeySetState, MinTimestamp, PassThroughMode, SignerError, faketime_or_now,
};
use crate::zone::{HistoricalEvent, Zone};
use crate::zonedata::{DiffData, RegularRecord, SignedZonePatcher, SignedZoneReader, SoaRecord};

pub fn sign_incrementally(
    patch: SignedZonePatcher,
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    trigger: SigningTrigger,
    status: Arc<RwLock<SigningStatusPerZone>>,
) -> Result<(), SignerError> {
    // Check what work needs to be done. If the keyset state
    // changed then check if the apex records change or if a
    // CSK or ZSK roll require resigning the zone.
    // If enough time has passed since the last time
    // signatures have been updated, then update signatures
    // and during a key roll, sign with the new key(s).
    // Ignore signer configuration changes, they will get picked up when
    // signatures need to be updated.
    // Resign using the unsigned zonefile when load_unsigned is true.

    status.write().expect("should not fail").current_action =
        "Start incremental signing".to_string();
    let load_unsigned = patch.next_loaded().is_some();

    let origin = &zone.name;
    let state_path = mk_dnst_keyset_state_file_path(&center.config.keys_dir, origin);
    let state = std::fs::read_to_string(&state_path)
        .map_err(|_| SignerError::CannotReadStateFile(state_path.into_string()))?;
    let keyset_state: KeySetState = serde_json::from_str(&state)
        .map_err(|e| SignerError::SigningError(format!("loading keyset state failed: {e}")))?;

    let policy = zone.read().policy.clone().unwrap();

    let use_nsec3 = matches!(policy.signer.denial, SignerDenialPolicy::NSec3 { .. });

    let local_state = LocalState::new(zone)?;
    let mut ws = WorkSpace {
        keyset_state,
        use_nsec3,
        policy: policy.clone(),
        zone: zone.clone(),
        center: center.clone(),
        patch,
        zonemd: HashSet::new(),
        //zonemd: [(ZonemdScheme::SIMPLE, ZonemdAlgorithm::SHA384)].into(),
        pass_through_mode: PassThroughMode::Off,
        local_state,
    };

    let curr_last_signature_refresh = ws.local_state.last_signature_refresh.clone();
    let curr_key_roll = ws.local_state.key_roll.clone();

    let apex_changed = ws.handle_keyset_changed();

    if !matches!(ws.pass_through_mode, PassThroughMode::Off) {
        ws.sign_pass_through()?;
        return Ok(());
    }

    let mut refresh_signatures = false;
    let now = faketime_or_now();
    if now
        > curr_last_signature_refresh.clone()
            + Duration::from_secs(ws.policy.signer.signature_refresh_interval.into())
    {
        debug!(
            "refresh signatures: {now} > {curr_last_signature_refresh} + {:?}",
            ws.policy.signer.signature_refresh_interval
        );
        refresh_signatures = true;
    }

    if !load_unsigned && !apex_changed && !refresh_signatures {
        // Nothing to do.
        return Err(SignerError::NothingToDo);
    }

    let mut iss = IncrementalSigningState::new(zone, &policy, center, &ws.keyset_state, status)?;

    let start = Instant::now();
    let patch_curr = ws.patch.curr();
    iss.load_signed_zone(&patch_curr)?;
    debug!("loading signed zone took {:?}", start.elapsed());

    ws.handle_nsec_nsec3(&mut iss)?;

    if load_unsigned {
        let start = Instant::now();
        iss.load_unsigned_diffs(ws.patch.unsigned_diff().expect("should be there"))?;
        debug!("loading new unsigned diffs took {:?}", start.elapsed());
    } else {
        // Re-use the signed data.
        iss.load_signed_only();
    }

    let start = Instant::now();
    ws.load_apex_records(&mut iss)?;

    iss.initial_diffs()?;

    match policy.signer.denial {
        SignerDenialPolicy::NSec3 { .. } => iss.incremental_nsec3()?,
        SignerDenialPolicy::NSec => iss.incremental_nsec()?,
    }

    ws.new_nsec_nsec3_sigs(&mut iss)?;

    if !ws.zonemd.is_empty() {
        let start = Instant::now();
        ws.add_zonemd(&mut iss)?;
        debug!("ZONEMD took {:?}", start.elapsed());
    }

    if refresh_signatures {
        ws.refresh_some_signatures(&mut iss)?;

        if curr_key_roll.is_some() {
            ws.key_roll_signatures(&mut iss)?;
        }
    }
    debug!("incremental signing took {:?}", start.elapsed());

    let start = Instant::now();
    ws.incremental_generate_diffs(&iss)?;
    debug!("generating diffs took {:?}", start.elapsed());

    ws.patch
        .apply()
        .map_err(|e| SignerError::PatchFailed(format!("apply failed: {e}")))?;

    debug!("SIGNER: Determining min expiration time");
    let min_expiration = Arc::new(MinTimestamp::new());
    let saved_min_expiration = min_expiration.clone();
    for record in iss.rrsigs.values().flatten() {
        let NewRecordData::Rrsig(sig) = record.data() else {
            unreachable!();
        };

        // Ignore RRSIG records for DNSKEY, CDS, and CDNSKEY records; these
        // are generated by the key manager, using KSKs.
        if sig.type_covered() == NewRtype::DNSKEY
            || sig.type_covered() == NewRtype::CDS
            || sig.type_covered() == NewRtype::CDNSKEY
        {
            continue;
        }

        min_expiration.add(sig.expiration().into());
    }

    // Save as next_min_expiration. After the signed zone is approved
    // this value should be move to min_expiration.
    ws.local_state.next_min_expiration = saved_min_expiration.get();
    debug!(
        "SIGNER: Determined min expiration time: {:?}",
        ws.local_state.next_min_expiration
    );

    record_zone_event(
        center,
        zone,
        HistoricalEvent::SigningSucceeded {
            trigger: trigger.into(),
        },
        ws.local_state
            .previous_serial
            .map(|s| domain::base::Serial(s.into())),
    );

    ws.local_state.save(&ws.center, &ws.zone);

    Ok(())
}

type Zrd = RecordFullCmp<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>;
type RtypeSet = HashSet<NewRtype>;
type ChangesValue = (RtypeSet, RtypeSet); // add set followed by delete set.

struct WorkSpace<'a> {
    pub keyset_state: KeySetState,
    pub use_nsec3: bool,
    pub policy: Arc<PolicyVersion>,
    pub zone: Arc<Zone>,
    pub center: Arc<Center>,
    pub patch: SignedZonePatcher<'a>,

    // Extra fields that should go to policy.
    pub zonemd: HashSet<(ZonemdScheme, ZonemdAlgorithm)>,
    pub pass_through_mode: PassThroughMode,

    // Local copy of state variables we need.
    local_state: LocalState,
}

impl WorkSpace<'_> {
    pub fn refresh_some_signatures(
        &mut self,
        iss: &mut IncrementalSigningState,
    ) -> Result<(), SignerError> {
        // In policy we check that for a new policy the following holds:
        // sig_validity_time > sig_remain_time + signature_refresh_interval.
        // The calculation below is safe but ignores TTL. In general,
        // effective_lifetime is expected to be much larger than most TTLs.
        // If that is not true, then nothing bad will happen, but this
        // algorithm will fail to properly spread out signature refresh.
        let effective_lifetime = Duration::from_secs(
            (self.policy.signer.sig_validity_time
                - self.policy.signer.sig_remain_time
                - self.policy.signer.signature_refresh_interval) as u64,
        );
        let now = faketime_or_now();
        let now_system_time = UNIX_EPOCH + Duration::from(now.clone());

        // Note that min_expire does not take TTL into account. We will
        // correct for that later.
        let min_expire = now_system_time
            + Duration::from_secs(self.policy.signer.sig_remain_time as u64)
            + Duration::from_secs(self.policy.signer.signature_refresh_interval as u64);

        let curr_last_signature_refresh = &self.local_state.last_signature_refresh;

        let mut since_last_time: Duration = if now >= *curr_last_signature_refresh {
            <UnixTime as Into<Duration>>::into(now.clone())
                - <UnixTime as Into<Duration>>::into(curr_last_signature_refresh.clone())
        } else {
            debug!(
                "Weird current time ({now}) is less than last time signatures were refreshed ({curr_last_signature_refresh})"
            );
            // Use 60 seconds when times are weird. This should get things
            // back in sync.
            Duration::from_secs(60)
        };

        // Limit to effective_lifetime in case of weird values.
        if since_last_time > effective_lifetime {
            since_last_time = effective_lifetime;
        }

        let total_signatures = iss.rrsigs.signed_rrset_count();

        let to_sign = since_last_time.as_secs_f64() * (total_signatures as f64)
            / effective_lifetime.as_secs_f64();
        let to_sign = to_sign.ceil() as usize;

        // Check the TTL of all signatures. Just generate an error. Maybe
        // zone versions with too high TTLs should be rejected during loading.
        // A too high TTL causes the record to be signed each interval.
        // With high TTLs signatures may be cached beyond expiration. We
        // could return a failure, but that would affect the entire zone.
        for ((owner, rtype), r) in &iss.rrsigs {
            let ttl = r[0].ttl();
            if self.policy.signer.sig_validity_time
                <= self.policy.signer.sig_remain_time
                    + ttl.as_secs()
                    + self.policy.signer.signature_refresh_interval
            {
                let owner_namebuf: NameBuf = RevNameBuf::copy_from(owner).into();
                let old_rtype = new_base_rtype_to_old_base(rtype);
                error!(
                    "TTL of {}/{} too large: signature-remain-time ({}) + TTL ({}) + signature-refresh-interval ({}) >= signature-lifetime ({})",
                    owner_namebuf,
                    old_rtype,
                    self.policy.signer.sig_remain_time,
                    ttl.as_secs(),
                    self.policy.signer.signature_refresh_interval,
                    self.policy.signer.sig_validity_time,
                );
            }
        }

        // Collect expiration times, owner names, and types to figure out what
        // to sign. Subtract TTL to account for caching.
        let mut expire_sigs = vec![];
        for ((owner, rtype), r) in &iss.rrsigs {
            let min_expiration = r
                .iter()
                .map(|r| {
                    let NewRecordData::Rrsig(rrsig) = r.data() else {
                        panic!("Rrsig expected");
                    };
                    rrsig.expiration().to_system_time(now_system_time)
                        - Duration::from_secs(rrsig.original_ttl().as_secs() as u64)
                })
                .min()
                .expect("minimum should exist");
            let v = (min_expiration, owner, rtype);
            expire_sigs.push(v);
        }

        expire_sigs.sort();

        let mut new_sigs = vec![];
        for (i, (expire, owner, rtype)) in expire_sigs.iter().enumerate() {
            if *expire > min_expire && i >= to_sign {
                break;
            }

            let box_owner: Box<RevName> = (**owner).unsized_copy_into();
            let key = (box_owner, *rtype);
            if *rtype == NewRtype::NSEC {
                let record = iss
                    .nsecs
                    .get(key.0.as_ref())
                    .expect("NSEC record should exist");
                let records = [record.clone().into()];
                sign_records(
                    &iss.origin,
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else if *rtype == NewRtype::NSEC3 {
                let record = iss
                    .nsec3s
                    .get(key.0.as_ref())
                    .expect("NSEC3 record should exist");
                let record: Zrd = record.clone().into();
                let records = [record.clone()];
                sign_records(
                    &iss.origin,
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else {
                let new_origin = old_base_name_to_revnamebuf(&iss.origin);
                let records = if *key.0 == *new_origin.as_ref() {
                    iss.new_apex
                        .get(&key.1)
                        .map(|v| v.iter().map(|r| (*r).clone().into()).collect::<Vec<_>>())
                } else {
                    iss.data
                        .get(&key)
                        .map(|v| v.iter().map(|r| (*r).clone().into()).collect::<Vec<_>>())
                }
                .expect("records should exist");
                sign_records(
                    &iss.origin,
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            };
        }

        for sigs in new_sigs {
            iss.rrsigs.replace_with_new_records(sigs);
        }

        // Assume we signed at least one record. If we don't then something is
        // off, but we will eventually resign RRsets with signature that are
        // close to expiring.
        self.local_state.last_signature_refresh = now;

        Ok(())
    }

    pub fn key_roll_signatures(
        &mut self,
        iss: &mut IncrementalSigningState,
    ) -> Result<(), SignerError> {
        let key_roll_time = Duration::from_secs(self.policy.signer.key_roll_time as u64);

        let curr_key_roll = &self.local_state.key_roll;
        let key_roll_start = curr_key_roll.as_ref().expect("should be there");

        let now = faketime_or_now();

        let since_start: Duration = <UnixTime as Into<Duration>>::into(now.clone())
            - <UnixTime as Into<Duration>>::into(key_roll_start.clone());

        let curr_key_tags = &self.local_state.key_tags;

        if since_start > key_roll_time {
            // Full roll. Make sure all signatures are made using the new keys.
            // Clear key_roll when we are done.

            let mut new_sigs = vec![];
            for ((owner, rtype), r) in &iss.rrsigs {
                let key_tags: HashSet<u16> = r
                    .iter()
                    .map(|r| {
                        let NewRecordData::Rrsig(rrsig) = r.data() else {
                            panic!("Rrsig expected");
                        };
                        rrsig.key_tag()
                    })
                    .collect();
                if key_tags == *curr_key_tags {
                    // Nothing to do.
                    continue;
                }

                let box_owner: Box<RevName> = owner.unsized_copy_into();
                let key = (box_owner, rtype);
                if rtype == NewRtype::NSEC {
                    let record = iss
                        .nsecs
                        .get(key.0.as_ref())
                        .expect("NSEC record should exist");
                    let records = [record.clone().into()];
                    sign_records(
                        &iss.origin,
                        &records,
                        &iss.keys,
                        iss.inception,
                        iss.expiration,
                        &mut new_sigs,
                    )?;
                } else if rtype == NewRtype::NSEC3 {
                    let record = iss
                        .nsec3s
                        .get(key.0.as_ref())
                        .expect("NSEC3 record should exist");
                    let record: Zrd = record.clone().into();
                    let records = [record.clone()];
                    sign_records(
                        &iss.origin,
                        &records,
                        &iss.keys,
                        iss.inception,
                        iss.expiration,
                        &mut new_sigs,
                    )?;
                } else {
                    let new_origin = old_base_name_to_revnamebuf(&iss.origin);
                    let records: Vec<Zrd> = if *key.0 == *new_origin.as_ref() {
                        iss.new_apex
                            .get(&key.1)
                            .map(|v| v.iter().map(|r| (*r).clone().into()).collect::<Vec<_>>())
                    } else {
                        iss.data
                            .get(&key)
                            .map(|v| v.iter().map(|r| (*r).clone().into()).collect::<Vec<_>>())
                    }
                    .expect("records should exist");
                    sign_records(
                        &iss.origin,
                        &records,
                        &iss.keys,
                        iss.inception,
                        iss.expiration,
                        &mut new_sigs,
                    )?;
                };
            }

            for sigs in new_sigs {
                iss.rrsigs.replace_with_new_records(sigs);
            }

            // Clear key_roll.
            self.local_state.key_roll = None;
            return Ok(());
        }

        let total_signatures = iss.rrsigs.signed_rrset_count();

        let to_sign =
            since_start.as_secs_f64() * (total_signatures as f64) / key_roll_time.as_secs_f64();
        let to_sign = to_sign.ceil() as usize;

        // owner names, types, and key tags to figure out what to sign.
        let mut sigs_key_tags = vec![];
        for ((owner, rtype), r) in &iss.rrsigs {
            let key_tags: Vec<u16> = r
                .iter()
                .map(|r| {
                    let NewRecordData::Rrsig(rrsig) = r.data() else {
                        panic!("Rrsig expected");
                    };
                    rrsig.key_tag()
                })
                .collect();
            let v = (owner, rtype, key_tags);
            sigs_key_tags.push(v);
        }

        sigs_key_tags.sort();

        let mut new_sigs = vec![];
        for (owner, rtype, key_tags) in sigs_key_tags.iter().take(to_sign) {
            if HashSet::<u16>::from_iter(key_tags.iter().copied()) == *curr_key_tags {
                // Nothing to do.
                continue;
            }

            let box_owner: Box<RevName> = (*owner).unsized_copy_into();
            let key = (box_owner, *rtype);
            if *rtype == NewRtype::NSEC {
                let record = iss
                    .nsecs
                    .get(key.0.as_ref())
                    .expect("NSEC record should exist");
                let records = [record.clone().into()];
                sign_records(
                    &iss.origin,
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else if *rtype == NewRtype::NSEC3 {
                let record = iss
                    .nsec3s
                    .get(key.0.as_ref())
                    .expect("NSEC3 record should exist");
                let record: Zrd = record.clone().into();
                let records = [record.clone()];
                sign_records(
                    &iss.origin,
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else {
                let new_origin = old_base_name_to_revnamebuf(&iss.origin);
                let records: Vec<Zrd> = if *key.0 == *new_origin.as_ref() {
                    iss.new_apex
                        .get(&key.1)
                        .map(|v| v.iter().map(|r| (*r).clone().into()).collect::<Vec<_>>())
                } else {
                    iss.data
                        .get(&key)
                        .map(|v| v.iter().map(|r| (*r).clone().into()).collect::<Vec<_>>())
                }
                .expect("records should exist");
                sign_records(
                    &iss.origin,
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            };
        }

        for sigs in new_sigs {
            iss.rrsigs.replace_with_new_records(sigs);
        }
        Ok(())
    }

    pub fn handle_keyset_changed(&mut self) -> bool {
        let mut apex_changed = false;

        let apex_remove = self.keyset_state.apex_remove.clone();

        let curr_apex_remove = &self.local_state.apex_remove;
        if apex_remove != *curr_apex_remove {
            debug!("apex remove RRtypes changed: from {curr_apex_remove:?} to {apex_remove:?}",);
            self.local_state.apex_remove = apex_remove;
            apex_changed = true;
        }

        // Check records that need to be added to the apex.
        let mut apex_extra = self.keyset_state.apex_extra.clone();
        apex_extra.sort();

        let curr_apex_extra = &self.local_state.apex_extra;
        if apex_extra != *curr_apex_extra {
            debug!("apex extra changed: from {curr_apex_extra:?} to {apex_extra:?}",);
            self.local_state.apex_extra = apex_extra;
            apex_changed = true;
        }

        // Check if a ZSK/CSK roll has started.
        let mut key_tags = HashSet::new();
        for v in self.keyset_state.keyset.keys().values() {
            let signer = match v.keytype() {
                KeyType::Ksk(_) => false,
                KeyType::Zsk(key_state) => key_state.signer(),
                KeyType::Csk(_, key_state) => key_state.signer(),
                KeyType::Include(_) => false,
            };

            if !signer {
                continue;
            }

            key_tags.insert(v.key_tag());
        }

        let curr_key_tags = &self.local_state.key_tags;
        if key_tags != *curr_key_tags {
            debug!("key tags changed: from {curr_key_tags:?} to {key_tags:?}",);
            self.local_state.key_tags = key_tags;
            self.local_state.key_roll = Some(faketime_or_now());
            apex_changed = true;
        }
        apex_changed
    }

    pub fn incremental_generate_diffs(
        &mut self,
        iss: &IncrementalSigningState,
    ) -> Result<(), SignerError> {
        let signing_rtypes = HashSet::from([
            NewRtype::DNSKEY,
            NewRtype::CDS,
            NewRtype::CDNSKEY,
            NewRtype::NSEC3PARAM,
            NewRtype::ZONEMD,
        ]);

        // For signing_rtypes diff against old_apex_saved. For all other
        // types diff against new_apex_saved. Ignore the diff against
        // new_apex_saved; that is currently not supported in the zone store.

        // apex records that were deleted.
        for (k, old_rrs) in &iss.old_apex_saved {
            if *k == NewRtype::SOA {
                // Just remove the old SOA record. There should be only one,
                // just remove all if there is more than one.
                for r in old_rrs {
                    let r: SoaRecord = (*r).clone().into();
                    self.patch.remove(r.clone().into()).map_err(|e| {
                        SignerError::PatchFailed(format!("unable to remove soa {r:?}: {e}"))
                    })?;
                    self.patch.remove_soa(r.clone()).map_err(|e| {
                        SignerError::PatchFailed(format!("unable to remove soa {r:?}: {e}"))
                    })?;
                }
                continue;
            }

            if !signing_rtypes.contains(k) {
                // Ignore. Should diff againt new_apex_saved.
                continue;
            }

            if let Some(new_rrs) = iss.new_apex.get(k) {
                if new_rrs == old_rrs {
                    // No change.
                    continue;
                }
                // Add the new records to a hash set and then check the old
                // ones against the set to see which ones are removed.
                let new_rrs: HashSet<&RegularRecord> = HashSet::from_iter(new_rrs.iter());
                for r in old_rrs {
                    if new_rrs.contains(r) {
                        continue;
                    }
                    self.patch.remove((*r).clone()).map_err(|e| {
                        SignerError::PatchFailed(format!("unable to remove {r:?}: {e}"))
                    })?;
                }
            } else {
                for r in old_rrs {
                    self.patch.remove((*r).clone()).map_err(|e| {
                        SignerError::PatchFailed(format!("unable to remove {r:?}: {e}"))
                    })?;
                }
            }
        }

        // apex records that were added.
        for (k, new_rrs) in &iss.new_apex {
            if *k == NewRtype::SOA {
                // Just add the new SOA record. There should be only one,
                // just add all if there is more than one.
                for r in new_rrs {
                    let r: SoaRecord = r.clone().into();
                    self.patch.add(r.clone().into()).map_err(|e| {
                        SignerError::PatchFailed(format!("unable to add soa {r:?}: {e}"))
                    })?;
                    self.patch.add_soa(r.clone()).map_err(|e| {
                        SignerError::PatchFailed(format!("unable to add soa {r:?}: {e}"))
                    })?;
                }
                continue;
            }

            if !signing_rtypes.contains(k) {
                // Ignore. Should diff againt new_apex_saved.
                continue;
            }

            if let Some(old_rrs) = iss.old_apex_saved.get(k) {
                if new_rrs == old_rrs {
                    // No change.
                    continue;
                }
                // Add the old records to a hash set and then check the new
                // ones against the set to see which ones are added.
                let old_rrs: HashSet<&RegularRecord> = HashSet::from_iter(old_rrs.iter());
                for r in new_rrs {
                    if old_rrs.contains(r) {
                        continue;
                    }
                    self.patch.add(r.clone()).map_err(|e| {
                        SignerError::PatchFailed(format!("unable to add {r:?}: {e}"))
                    })?;
                }
            } else {
                for r in new_rrs {
                    self.patch.add(r.clone()).map_err(|e| {
                        SignerError::PatchFailed(format!("unable to add {r:?}: {e}"))
                    })?;
                }
            }
        }

        iss.nsecs.generate_diff(&mut self.patch)?;
        iss.nsec3s.generate_diff(&mut self.patch)?;

        for change in iss.rrsigs.changes.values() {
            match change {
                RrsigChange::Delete { old } => {
                    for r in old {
                        self.patch.remove((*r).clone()).map_err(|e| {
                            SignerError::PatchFailed(format!("unable to remove {r:?}: {e}"))
                        })?;
                    }
                }
                RrsigChange::Modified { old, new } => {
                    // It is possible that old and new are equal. In that
                    // case the following code will not add anything to the
                    // patch.

                    // First check which records are removed.
                    let new_rrsigs: HashSet<&RegularRecord> = HashSet::from_iter(new.iter());
                    for r in old {
                        if new_rrsigs.contains(r) {
                            continue;
                        }
                        self.patch.remove((*r).clone()).map_err(|e| {
                            SignerError::PatchFailed(format!("unable to remove {r:?}: {e}"))
                        })?;
                    }

                    // Add the records that are new.
                    let old_rrsigs: HashSet<&RegularRecord> =
                        HashSet::from_iter(old.iter().copied());
                    for r in new {
                        if old_rrsigs.contains(r) {
                            continue;
                        }
                        let r: RegularRecord = r.clone();
                        self.patch.add(r.clone()).map_err(|e| {
                            SignerError::PatchFailed(format!("unable to add {r:?}: {e}"))
                        })?;
                    }
                }
                RrsigChange::Insert { new } => {
                    for r in new {
                        let r: RegularRecord = r.clone();
                        self.patch.add(r.clone()).map_err(|e| {
                            SignerError::PatchFailed(format!("unable to add {r:?}: {e}"))
                        })?;
                    }
                }
            }
        }

        Ok(())
    }

    /*
        fn load_pass_through_dnskey(&mut self, iss: &mut IncrementalSigningState) -> Result<(), Error> {
            // Assume that the apex records have been copied from KeySetState to
            // SignerState. Now update the apex in new_data.

            let mut dnskey_records = vec![];
            let mut rrsig_records = vec![];

            for r in &self.state.apex_extra {
                let zonefile =
                    domain::zonefile::inplace::Zonefile::from((r.to_string() + "\n").as_ref() as &str);
                for entry in zonefile {
                    let entry = entry.map_err::<Error, _>(|e| format!("bad entry: {e}\n").into())?;

                    // We only care about records in a zonefile
                    let Entry::Record(record) = entry else {
                        continue;
                    };

                    if record.rtype() != Rtype::DNSKEY && record.rtype() != Rtype::RRSIG {
                        continue;
                    }

                    let owner = record.owner().to_name::<Bytes>();
                    let data = record.data().clone().try_flatten_into().expect("should not fail");
                    let r = Record::new(owner.clone(), record.class(), record.ttl(), data);

                    if r.rtype() == Rtype::RRSIG {
                        let ZoneRecordData::Rrsig(rrsig) = r.data() else {
                            panic!("RRSIG expected");
                        };
                        if rrsig.type_covered() != Rtype::DNSKEY {
                            continue;
                        }
                        rrsig_records.push(r);
                    } else {
                        dnskey_records.push(r);
                    }
                }
            }

            match self.config.pass_through_mode {
                PassThroughMode::Off => unreachable!(),
                PassThroughMode::CopyDnskeyRrset => {
                    let key = (
                        dnskey_records
                            .first()
                            .ok_or("at least one DNSKEY expected")?
                            .owner()
                            .clone(),
                        Rtype::DNSKEY,
                    );
                    iss.new_data.insert(key.clone(), dnskey_records);
                    iss.rrsigs.insert(key, rrsig_records);
                }
                PassThroughMode::MergeDnskeySignatures => {
                    // Make sure the old and new DNSKEY RRsets are the same.
                    let key = (iss.origin.clone(), Rtype::DNSKEY);
                    let Some(old_dnskey_records) = iss.old_data.get(&key) else {
                        return Err("A DNSKEY RRset should exist in the input zone".into());
                    };
                    let mut old_dnskey_records = old_dnskey_records.clone();
                    old_dnskey_records.sort();
                    dnskey_records.sort();
                    if *old_dnskey_records != dnskey_records {
                        return Err(
                            "DNSKEY RRset in input has to be same as the DNSKEY RRset in keyset".into(),
                        );
                    }
                    let Some(rrsigs) = iss.rrsigs.get(&key) else {
                        return Err("RRSIGs expected for DNSKEY RRset".into());
                    };
                    let mut rrsigs = rrsigs.clone();
                    rrsigs.append(&mut rrsig_records);
                    iss.rrsigs.insert(key, rrsigs);
                }
            }

            let key = (iss.origin.clone(), Rtype::ZONEMD);
            if iss.new_data.contains_key(&key) {
                return Err("Pass-through is not possible for zone input with ZONEMD".into());
            }

            Ok(())
        }
    */

    pub fn add_zonemd(&self, iss: &mut IncrementalSigningState) -> Result<(), SignerError> {
        // Get the SOA record. We need that for the Serial and for the
        // TTL.
        let soa_records = iss
            .new_apex
            .get(&NewRtype::SOA)
            .expect("SOA record should be present");

        // TODO: convert back to old base for now. Some compatibility in new
        // base is needed.
        let soa_record: Zrd = soa_records[0].clone().into();
        let ZoneRecordData::Soa(soa) = soa_record.data() else {
            panic!("SOA record expected");
        };

        let start = Instant::now();

        // Create a Vec with all records to be able to sort them in canonical
        // order. Ignore ZONEMD and RRSIGs of ZONEMD records.
        let mut all: Vec<Zrd> = vec![];

        all.extend(
            iss.new_apex
                .iter()
                .filter_map(|(t, r)| {
                    if *t != NewRtype::ZONEMD {
                        Some(r)
                    } else {
                        None
                    }
                })
                .flatten()
                .map(|r| (*r).clone().into()),
        );

        let mut all_data: Vec<Zrd> = vec![];
        let new_origin = old_base_name_to_revnamebuf(&iss.origin);
        all_data.extend(
            iss.data
                .iter_unordered()
                .filter_map(|((o, t), r)| {
                    if o.as_ref() != new_origin.as_ref() || *t != NewRtype::ZONEMD {
                        Some(r)
                    } else {
                        None
                    }
                })
                .flatten()
                .map(|r| {
                    let s: Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>> =
                        (*r).clone().into();
                    s.into()
                }),
        );
        all.extend(all_data);

        let mut all_nsecs: Vec<Zrd> = vec![];
        all_nsecs.extend(iss.nsecs.values().map(|r| {
            let s: Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>> = (*r).clone().into();
            s.into()
        }));
        all.extend(all_nsecs);

        let mut all_nsec3s: Vec<Zrd> = vec![];
        all_nsec3s.extend(iss.nsec3s.values().map(|r| {
            let s: Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>> = (*r).clone().into();
            s.into()
        }));
        all.extend(all_nsec3s);

        let mut all_rrsigs: Vec<Zrd> = vec![];
        let new_origin = old_base_name_to_revnamebuf(&iss.origin);
        all_rrsigs.extend(
            iss.rrsigs
                .iter()
                .filter_map(|((o, t), r)| {
                    if *o != *new_origin.as_ref() || t != NewRtype::ZONEMD {
                        Some(r)
                    } else {
                        None
                    }
                })
                .flatten()
                .map(|r| {
                    let s: Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>> =
                        (*r).clone().into();
                    s.into()
                }),
        );

        all.extend(all_rrsigs);

        //all.sort_by(|e1, e2| CanonicalOrd::canonical_cmp(*e1, *e2));
        all.par_sort_by(CanonicalOrd::canonical_cmp);

        debug!("ZONEMD prepare and sort took {:?}", start.elapsed());

        let start = Instant::now();

        let mut zonemd_records = vec![];
        for z in &self.zonemd {
            if z.0 != ZonemdScheme::SIMPLE {
                return Err(SignerError::SigningError(
                    "unsupported zonemd scheme (only SIMPLE is supported)".into(),
                ));
            }
            let mut buf: Vec<u8> = Vec::new();
            let mut ctx = match z.1 {
                ZonemdAlgorithm::SHA384 => digest::Context::new(&digest::SHA384),
                ZonemdAlgorithm::SHA512 => digest::Context::new(&digest::SHA512),
                _ => unreachable!(),
            };
            for r in &all {
                buf.clear();
                with_infallible(|| r.compose_canonical(&mut buf));
                ctx.update(&buf);
            }
            let digest = ctx.finish();
            let zonemd = Zonemd::new(
                soa.serial(),
                z.0,
                z.1,
                Bytes::copy_from_slice(digest.as_ref()),
            );
            let record = RecordFullCmp::new(
                iss.origin.clone(),
                soa_record.class(),
                soa_record.ttl(),
                ZoneRecordData::Zonemd(zonemd),
            );
            zonemd_records.push(record);
        }

        debug!("ZONEMD hash took {:?}", start.elapsed());

        let key = (iss.origin.clone(), NewRtype::ZONEMD);
        let mut new_sigs = vec![];
        sign_records(
            &iss.origin,
            &zonemd_records,
            &iss.keys,
            iss.inception,
            iss.expiration,
            &mut new_sigs,
        )?;
        let new_zonemd_records: Vec<RegularRecord> =
            zonemd_records.iter().map(|r| (*r).clone().into()).collect();
        iss.new_apex.insert(key.1, new_zonemd_records);
        iss.rrsigs.replace_with_new_records(new_sigs[0].clone());
        Ok(())
    }

    fn update_soa_serial(&mut self, old_soa: &Zrd) -> Result<Zrd, SignerError> {
        // Implement SOA serial policies. There are four policies:
        // 1) Keep. Copy the serial from the unsigned zone. Refuse to sign
        //    if the serial did not change.
        // 2) Increment. Copy the serial from the unsigned zone but increment
        //    the serial if the zone needs to be signed an the serial in
        //    the unsigned zone did not change.
        // 3) Unix timestamp. The current time in Unix seconds. Increment if
        //    that does not result in a higher serial.
        // 4) Broken down time (YYYYMMDDnn). The current day plus a serial
        //    number. Implies increment to generate different serial numbers
        //    over a day.

        let ZoneRecordData::Soa(zone_soa) = old_soa.data() else {
            unreachable!();
        };

        let curr_previous_serial = &self.local_state.previous_serial;
        match self.policy.signer.serial_policy {
            SignerSerialPolicy::Keep => {
                if let Some(previous_serial) = curr_previous_serial
                    && zone_soa.serial() <= *previous_serial
                {
                    return Err(SignerError::KeepSerialPolicyViolated);
                }

                // Save the new SOA serial.
                self.local_state.previous_serial = Some(zone_soa.serial());
                Ok(old_soa.clone())
            }
            SignerSerialPolicy::Counter => {
                // Always increment the serial number, ignore the serial
                // number in the unsigned zone.
                let previous_serial = if let Some(serial) = curr_previous_serial {
                    *serial
                } else {
                    DomainSerial::from(0)
                };

                let serial = previous_serial.add(1);

                // Save the new SOA serial.
                self.local_state.previous_serial = Some(serial);

                let new_soa = ZoneRecordData::Soa(Soa::new(
                    zone_soa.mname().clone(),
                    zone_soa.rname().clone(),
                    serial,
                    zone_soa.refresh(),
                    zone_soa.retry(),
                    zone_soa.expire(),
                    zone_soa.minimum(),
                ));
                let record = RecordFullCmp::new(
                    old_soa.owner().clone(),
                    old_soa.class(),
                    old_soa.ttl(),
                    new_soa,
                );

                Ok(record)
            }
            SignerSerialPolicy::UnixTime => {
                let mut serial = DomainSerial::now();
                if let Some(previous_serial) = curr_previous_serial
                    && serial <= *previous_serial
                {
                    serial = previous_serial.add(1);
                }

                // Save the new SOA serial.
                self.local_state.previous_serial = Some(serial);

                let new_soa = ZoneRecordData::Soa(Soa::new(
                    zone_soa.mname().clone(),
                    zone_soa.rname().clone(),
                    serial,
                    zone_soa.refresh(),
                    zone_soa.retry(),
                    zone_soa.expire(),
                    zone_soa.minimum(),
                ));

                let record = RecordFullCmp::new(
                    old_soa.owner().clone(),
                    old_soa.class(),
                    old_soa.ttl(),
                    new_soa,
                );

                Ok(record)
            }
            SignerSerialPolicy::DateCounter => {
                let ts = JiffTimestamp::now();
                let zone = Zoned::new(ts, TimeZone::UTC);
                let serial = ((zone.year() as u32 * 100 + zone.month() as u32) * 100
                    + zone.day() as u32)
                    * 100;
                let mut serial: DomainSerial = serial.into();

                if let Some(previous_serial) = curr_previous_serial
                    && serial <= *previous_serial
                {
                    serial = previous_serial.add(1);
                }

                // Save the new SOA serial.
                self.local_state.previous_serial = Some(serial);

                let new_soa = ZoneRecordData::Soa(Soa::new(
                    zone_soa.mname().clone(),
                    zone_soa.rname().clone(),
                    serial,
                    zone_soa.refresh(),
                    zone_soa.retry(),
                    zone_soa.expire(),
                    zone_soa.minimum(),
                ));

                let record = RecordFullCmp::new(
                    old_soa.owner().clone(),
                    old_soa.class(),
                    old_soa.ttl(),
                    new_soa,
                );

                Ok(record)
            }
        }
    }

    pub fn sign_pass_through(&mut self) -> Result<(), SignerError> {
        todo!();
        /*
                // Clear key_tags and key_roll to trigger resigning when
                // pass-through mode is turned off. Also clear keyset_state_modified
                // to trigger a reload of the keyset state when pass-through is
                // turned off.
                if !self.state.key_tags.is_empty() {
                    self.state.key_tags = HashSet::new();
                    self.state.keyset_state_modified = Timestamp::from(0).into();
                    self.state_changed = true;
                }
                if self.state.key_roll.is_some() {
                    self.state.key_roll = None;
                    self.state_changed = true;
                }

                let mut iss = IncrementalSigningState::new(self)?;

                let start = Instant::now();
                load_signed_zone(&mut iss, &self.config.zonefile_in)?;
                    debug!("loading signed zone took {:?}", start.elapsed());

                // Re-use the signed data.
                load_signed_only(&mut iss);

                self.load_pass_through_dnskey(&mut iss)?;

                self.incremental_write_output(&iss)?;
                Ok(())
        */
    }

    pub fn load_apex_records(
        &mut self,
        iss: &mut IncrementalSigningState,
    ) -> Result<(), SignerError> {
        // Assume that the apex records have been copied from KeySetState to
        // state. Now update the apex in new_data.

        // Delete all types in apex_remove.
        let curr_apex_remove = &self.local_state.apex_remove;
        for t in curr_apex_remove {
            let new_origin = old_base_name_to_revnamebuf(&iss.origin);
            let new_t = old_base_rtype_to_new_base(*t);
            let key = (new_origin.as_ref(), new_t);
            iss.new_apex.remove(&new_t);
            iss.rrsigs.remove(&key);
        }

        let curr_apex_extra = &self.local_state.apex_extra;
        for r in curr_apex_extra {
            let zonefile =
                domain::zonefile::inplace::Zonefile::from((r.to_string() + "\n").as_ref() as &str);
            for entry in zonefile {
                let entry =
                    entry.map_err(|e| SignerError::SigningError(format!("bad entry: {e}\n")))?;

                // We only care about records in a zonefile
                let Entry::Record(record) = entry else {
                    continue;
                };

                let owner = record.owner().to_name::<Bytes>();
                let data = record
                    .data()
                    .clone()
                    .try_flatten_into()
                    .expect("should not fail");
                let r = RecordFullCmp::new(owner.clone(), record.class(), record.ttl(), data);

                let r: RegularRecord = r.into_record().into();
                if r.data().rtype() == NewRtype::RRSIG {
                    iss.rrsigs.add_new_record(r);
                } else {
                    let key = r.data().rtype();
                    let mut records = vec![r];
                    iss.new_apex.entry(key).or_default().append(&mut records);
                }
            }
        }

        if self.use_nsec3 {
            // Copy the NSEC3PARAM record from the old_apex to the new_apex.
            // The reason is that the NSEC3PARAM gets lost when the unsigned
            // zone is loaded.
            let nsec3param_records = iss
                .old_apex
                .get(&NewRtype::NSEC3PARAM)
                .expect("NSEC3PARAM should be present");
            iss.new_apex
                .insert(NewRtype::NSEC3PARAM, nsec3param_records.to_vec());
        }

        if !self.zonemd.is_empty() {
            let zonemd = Zonemd::new(
                0.into(),
                ZonemdScheme::SIMPLE,
                ZonemdAlgorithm::SHA384,
                Bytes::new(),
            );
            let record = RecordFullCmp::new(
                iss.origin.clone(),
                Class::IN,
                Ttl::ZERO,
                ZoneRecordData::Zonemd(zonemd),
            );
            let record: RegularRecord = record.into();
            let records = vec![record];
            iss.new_apex.insert(NewRtype::ZONEMD, records);
        }

        // Update the SOA serial.
        let zone_soa_rr = &iss.new_apex.get(&NewRtype::SOA).expect("SOA should exist")[0];
        let old_zone_soa_rr: Zrd = (*zone_soa_rr).clone().into();
        let new_soa = self.update_soa_serial(&old_zone_soa_rr)?;
        let new_rrset: Vec<RegularRecord> = vec![new_soa.into()];
        iss.new_apex.insert(NewRtype::SOA, new_rrset);

        Ok(())
    }

    pub fn new_nsec_nsec3_sigs(
        &self,
        iss: &mut IncrementalSigningState,
    ) -> Result<(), SignerError> {
        let mut new_sigs = vec![];
        if self.use_nsec3 {
            for m in iss.nsec3s.changes_iter() {
                let Some(nsec3) = iss.nsec3s.get(m) else {
                    // Record has been removed.
                    continue;
                };

                let nsec3 = nsec3.clone().into();
                sign_records(
                    &iss.origin,
                    &[nsec3],
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            }
        } else {
            for m in iss.nsecs.changes_iter() {
                let Some(nsec) = iss.nsecs.get(m) else {
                    // Record has been removed.
                    continue;
                };

                let nsec: Zrd = nsec.clone().into();
                sign_records(
                    &iss.origin,
                    &[nsec],
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            }
        }
        for sigs in new_sigs {
            iss.rrsigs.replace_with_new_records(sigs);
        }
        Ok(())
    }

    pub fn handle_nsec_nsec3(
        &mut self,
        iss: &mut IncrementalSigningState,
    ) -> Result<(), SignerError> {
        // Note that we could try to regenerate the NSEC(3). Assume that
        // switching between NSEC, NSEC3, and NSEC3 opt-out (or other NSEC3
        // parameter changes) is rare enough that we can just resign the full
        // zone.
        let opt_nsec3param = iss.old_apex.get(&NewRtype::NSEC3PARAM);
        if let Some(nsec3param_records) = opt_nsec3param {
            // Zone was signed with NSEC3.
            if !self.use_nsec3 {
                // Zone is signed with NSEC3 but we want NSEC.
                let start = Instant::now();
                iss.remove_nsec_nsec3();
                iss.new_nsec_chain()?;
                debug!("replacing NSEC3 with NSEC took {:?}", start.elapsed());
                return Ok(());
            }
            let NewRecordData::Nsec3Param(nsec3param) = nsec3param_records[0].data() else {
                panic!("ZoneRecordData::Nsec3param expected");
            };
            if *nsec3param != *iss.nsec3param {
                // Parameters changed, resign.
                let start = Instant::now();
                iss.remove_nsec_nsec3();
                iss.new_nsec3_chain()?;
                debug!("updating NSEC3 parameters took {:?}", start.elapsed());
                return Ok(());
            }
        } else {
            // Zone was signed with NSEC, check if that is also the target.
            if self.use_nsec3 {
                // Resign the full zone with NSEC3.
                let start = Instant::now();
                iss.remove_nsec_nsec3();
                iss.new_nsec3_chain()?;
                debug!("replacing NSEC with NSEC3 took {:?}", start.elapsed());
                return Ok(());
            }
            // Stay with NSEC.
        }
        Ok(())
    }
}

struct IncrementalSigningState<'zd> {
    /// DNS name of the zone we are signing.
    origin: Name<Bytes>,

    /// Apex RRsets of the previously signed zone. With the execption of
    /// NSEC, NSEC3 and RRSIG records. Old_apex and old_data are used
    /// destructively to create a list of changes. This should be replaced
    /// by the diff that the zone store provides.
    old_apex: HashMap<NewRtype, Vec<RegularRecord>>,

    /// Saved copy of old_apex for generating diffs for the zone store.
    old_apex_saved: HashMap<NewRtype, Vec<RegularRecord>>,

    /// After incremental signing, this contains the apex RRsets (with the
    /// exception of NSEC, NSEC3, and RRSIG records) of the newly signed
    /// zone.
    new_apex: HashMap<NewRtype, Vec<RegularRecord>>,

    /// The apex of the new version of the unsigned zone.
    new_apex_saved: HashMap<NewRtype, Vec<RegularRecord>>,

    data: Data<'zd>,

    // Stores old and new NSEC records and creates diffs.
    nsecs: Nsecs<'zd>,

    // Stores old and new NSEC3 records and creates diffs.
    nsec3s: Nsecs<'zd>,

    // Stores old and new RRSIG records and creates diffs.
    rrsigs: Rrsigs<'zd>,

    /// List of RRsets that are added or deleted.
    changes: HashMap<Box<RevName>, ChangesValue>,

    /// Signing keys.
    keys: ZoneSigningKeys,

    /// Inception time to use for signatures.
    inception: Timestamp,

    /// Expiration time to use for signatures.
    expiration: Timestamp,

    // NSEC3 parameters.
    nsec3param: Box<NewNsec3Param>,
}

impl<'a> IncrementalSigningState<'a> {
    pub fn new(
        zone: &Zone,
        policy: &PolicyVersion,
        center: &Arc<Center>,
        keyset_state: &KeySetState,
        status: Arc<RwLock<SigningStatusPerZone>>,
    ) -> Result<Self, SignerError> {
        let keys = ZoneSigningKeys::load(center, zone, keyset_state, &status)?;

        let now = faketime_or_now();
        let now_u32 = Into::<Duration>::into(now.clone()).as_secs() as u32;
        let inception = (now_u32 - policy.signer.sig_inception_offset).into();
        let expiration = (now_u32 + policy.signer.sig_validity_time).into();

        // This is the only way to deal with opt-out. There is no data type
        // for flags or constant for opt-out. Creating an Nsec3param makes it
        // possible to set opt-out.
        let mut nsec3param: Nsec3param<Vec<u8>> = Nsec3param::default();
        match &policy.signer.denial {
            SignerDenialPolicy::NSec => (),
            SignerDenialPolicy::NSec3 { opt_out } => {
                if *opt_out {
                    nsec3param.set_opt_out_flag();
                }
            }
        }
        let nsec3param = old_base_nsec3param_to_new_base(&nsec3param);
        Ok(Self {
            origin: zone.name.clone(),
            old_apex: HashMap::new(),
            old_apex_saved: HashMap::new(),
            new_apex: HashMap::new(),
            new_apex_saved: HashMap::new(),
            data: Data::new(),
            nsecs: Nsecs::new(),
            nsec3s: Nsecs::new(),
            rrsigs: Rrsigs::new(),
            changes: HashMap::new(),
            keys,
            inception,
            expiration,
            nsec3param,
        })
    }

    pub fn load_signed_zone(
        &mut self,
        signed_reader: &'a SignedZoneReader,
    ) -> Result<(), SignerError> {
        // Loop over all records. Records do not have to be sorted.
        let new_origin = old_base_name_to_revnamebuf(&self.origin);
        for record in signed_reader.all_records() {
            match record.data() {
                NewRecordData::Rrsig(_rrsig) => {
                    self.rrsigs.add_existing_record(record);
                }
                NewRecordData::Nsec(_) => {
                    // Assume (at most) one NSEC record per owner name.
                    // Directly insert into the btree map.
                    self.nsecs.add_existing_record(record);
                }
                NewRecordData::Nsec3(_) => {
                    // Assume (at most) one NSEC3 record per owner name.
                    // Directly insert into the btree map.
                    self.nsec3s.add_existing_record(record);
                }
                _ => {
                    if record.owner() != new_origin.as_ref() {
                        self.data.insert_existing_record(record);
                        continue;
                    }
                    let rtype = record.data().rtype();
                    self.old_apex.entry(rtype).or_default().push(record.clone());
                }
            }
        }

        self.old_apex_saved = self.old_apex.clone();
        Ok(())
    }

    pub fn load_unsigned_diffs(&mut self, diffs: DiffData) -> Result<(), SignerError> {
        let origin_revnamebuf = old_base_name_to_revnamebuf(&self.origin);

        self.new_apex = self.old_apex.clone();

        // Add_records and removed_records can be processed in any order.
        // Processing removed_records first is slightly more efficient.
        for record in diffs.removed_records {
            if record.owner() == origin_revnamebuf.as_ref() {
                let hash_map::Entry::Occupied(mut entry) =
                    self.new_apex.entry(record.data().rtype())
                else {
                    unreachable!();
                };
                let records = entry.get_mut();
                let index = records
                    .iter()
                    .position(|r| *r == record)
                    .expect("position should exist");
                records.remove(index);
                if records.is_empty() {
                    entry.remove();
                }
            } else {
                self.data.remove_record(record);
            }
        }
        for record in diffs.added_records {
            if record.owner() == origin_revnamebuf.as_ref() {
                self.new_apex
                    .entry(record.data().rtype())
                    .or_default()
                    .push(record.clone());
            } else {
                self.data.add_record(record);
            }
        }

        // Save a copy of the loaded new_apex to create a diff later.
        for (k, v) in &self.new_apex {
            self.new_apex_saved.insert(*k, v.clone());
        }

        // Remove an NSEC3PARAM and ZONEMD that we got from the unsigned
        // zone.
        self.new_apex.remove(&NewRtype::NSEC3PARAM);
        self.new_apex.remove(&NewRtype::ZONEMD);

        Ok(())
    }

    pub fn load_signed_only(&mut self) {
        // Copy old data to new data.
        for (k, v) in &self.old_apex {
            self.new_apex.insert(*k, v.to_vec());
            self.new_apex_saved.insert(*k, v.to_vec());
        }
    }

    pub fn initial_diffs(&mut self) -> Result<(), SignerError> {
        let mut new_sigs = vec![];

        // Iterated over changes.
        let new_origin = old_base_name_to_revnamebuf(&self.origin);
        for (key, change) in self.data.changes_iter() {
            // XXX for compatibility with the full zone signer, always
            // ignore DNSKEY/CDS/CDNSKEY when not at apex.
            let rtype = key.1;
            if (rtype == NewRtype::DNSKEY || rtype == NewRtype::CDS || rtype == NewRtype::CDNSKEY)
                && key.0.as_ref() != new_origin.as_ref()
            {
                continue;
            }

            match change {
                DataChange::Removed { .. } => {
                    let tmp_key = (key.0.as_ref(), rtype);

                    self.rrsigs.remove(&tmp_key);

                    if let Some((_, removed)) = self.changes.get_mut(&key.0) {
                        removed.insert(rtype);
                    } else {
                        let added = HashSet::new();
                        let mut removed = HashSet::new();
                        removed.insert(rtype);
                        self.changes.insert(key.0.clone(), (added, removed));
                    }
                }
                DataChange::Modified { new, .. } => {
                    let key = (key.0.as_ref(), key.1);
                    if self.rrsigs.remove(&key).is_some() {
                        let new_rrset: Vec<_> = new.iter().map(|r| (*r).clone().into()).collect();
                        sign_records(
                            &self.origin,
                            &new_rrset,
                            &self.keys,
                            self.inception,
                            self.expiration,
                            &mut new_sigs,
                        )?;
                    }
                }
                DataChange::Insert { .. } => {
                    if let Some((added, _)) = self.changes.get_mut(&key.0) {
                        added.insert(rtype);
                    } else {
                        let mut added = HashSet::new();
                        let removed = HashSet::new();
                        added.insert(rtype);
                        self.changes.insert(key.0.clone(), (added, removed));
                    }
                }
            }
        }
        let new_origin = old_base_name_to_revnamebuf(&self.origin);
        for new_rrset in self.new_apex.values_mut() {
            let owner_revnamebuf = RevNameBuf::copy_from(new_rrset[0].owner());
            let owner_boxrevname = owner_revnamebuf.unsized_copy_into();
            let key = (owner_revnamebuf.as_ref(), new_rrset[0].data().rtype());
            if let Some(mut old_rrset) = self.old_apex.remove(&key.1) {
                let rtype = new_rrset[0].data().rtype();
                if (rtype == NewRtype::DNSKEY
                    || rtype == NewRtype::CDS
                    || rtype == NewRtype::CDNSKEY)
                    && new_rrset[0].owner() == new_origin.as_ref()
                {
                    // At apex, these types are signed by the key manager. No
                    // need to check for changes.
                    continue;
                }
                old_rrset.sort();
                new_rrset.sort();

                let old_base_new_rrset: Vec<_> =
                    new_rrset.iter().map(|r| (*r).clone().into()).collect();
                if old_rrset != *new_rrset && self.rrsigs.remove(&key).is_some() {
                    sign_records(
                        &self.origin,
                        &old_base_new_rrset,
                        &self.keys,
                        self.inception,
                        self.expiration,
                        &mut new_sigs,
                    )?;
                }
            } else if let Some((added, _)) = self.changes.get_mut(&owner_boxrevname) {
                added.insert(new_rrset[0].data().rtype());
            } else {
                let mut added = HashSet::new();
                let removed = HashSet::new();
                added.insert(new_rrset[0].data().rtype());
                self.changes.insert(owner_boxrevname, (added, removed));
            }
        }
        for sigs in new_sigs {
            self.rrsigs.replace_with_new_records(sigs);
        }
        for old_rrset in self.old_apex.values() {
            // What is left in old_data is removed.
            let rtype = old_rrset[0].data().rtype();
            let key = (old_rrset[0].owner(), rtype);

            self.rrsigs.remove(&key);

            let owner_boxrevname = old_rrset[0].owner().unsized_copy_into();
            if let Some((_, removed)) = self.changes.get_mut(&owner_boxrevname) {
                removed.insert(rtype);
            } else {
                let added = HashSet::new();
                let mut removed = HashSet::new();
                removed.insert(rtype);
                self.changes.insert(owner_boxrevname, (added, removed));
            }
        }
        Ok(())
    }

    pub fn incremental_nsec(&mut self) -> Result<(), SignerError> {
        // Should changes be sorted or not? If changes is sorted we will
        // process a new delegation before any glue. Which is more efficient.
        // Otherwise if glue comes first, the glue will be signed and inserted
        // in the NSEC chain only to be removed when the delegation is processed.
        // However, we removing a delegation, the situation is reversed. For now
        // assuming that sorting is not necessary.

        let new_origin = old_base_name_to_revnamebuf(&self.origin);

        let changes = self.changes.clone();
        for (key, (add, delete)) in &changes {
            let old_key_name = revname_to_old_base_name(key);

            // The intersection between add and delete is empty.
            assert!(add.intersection(delete).next().is_none());

            if let Some(record_nsec) = self.nsecs.get(key) {
                let record_nsec = record_nsec.clone();
                let NewRecordData::Nsec(nsec) = record_nsec.data() else {
                    panic!("NSEC record expected");
                };

                // Convert the existing RRtype bitmap into a hash set.
                let mut curr = HashSet::new();

                // TODO: figure out how to implement IntoIterator for
                // TypeBitmaps.
                //for rtype in nsec.types() {
                for rtype in nsec.types().types() {
                    curr.insert(rtype);
                }

                // The intersection between curr and add is empty.
                assert!(curr.intersection(add).next().is_none());

                // delete is completely contained in curr. In other words the
                // difference between delete and curr is empty.
                assert!(delete.difference(&curr).next().is_none());

                if add.contains(&NewRtype::NS) {
                    // Apex is special, but we can assume the NS RRset will not
                    // be added to apex.
                    assert!(key.as_ref() != new_origin.as_ref());

                    // Remove the signatures for the existing types.
                    for rtype in nsec.types().iter() {
                        // When NS is added, we should keep the signatures for
                        // DS and NSEC. The NSEC signature will be updated but
                        // there is no point in removing it first. Do not try to
                        // remove a signature for RRSIG because it does not exist.
                        if rtype == NewRtype::DS
                            || rtype == NewRtype::NSEC
                            || rtype == NewRtype::RRSIG
                        {
                            continue;
                        }
                        let key = (key.as_ref(), rtype);
                        self.rrsigs.remove(&key);
                    }

                    // Restrict curr and add to these types.
                    let mask: HashSet<NewRtype> =
                        [NewRtype::NS, NewRtype::DS, NewRtype::NSEC, NewRtype::RRSIG].into();

                    let curr: HashSet<NewRtype> = curr.intersection(&mask).copied().collect();
                    let add: HashSet<NewRtype> = add.intersection(&mask).copied().collect();

                    // Update the NSEC record.
                    nsec_update_bitmap(&record_nsec, nsec, &curr, &add, delete, self);

                    // Mark descendents as occluded after updating the bitmap.
                    // The reason is that nsec_update_bitmap uses the current
                    // next_name and nsec_set_occluded may change that.
                    nsec_set_occluded(key, self);

                    continue;
                }
                if delete.contains(&NewRtype::NS) {
                    // Apex is special, but we can assume the NS RRset will not
                    // be removed from apex.
                    assert!(key.as_ref() != new_origin.as_ref());

                    // Curr does not include all types at this name. Add the
                    // missing types to curr.
                    let box_revname: Box<RevName> = key.as_ref().unsized_copy_into();
                    let range_key = (box_revname, 0.into());
                    let range = self.data.range(range_key..);
                    for ((r_name, r_type), _) in range {
                        if r_name.as_ref() != key.as_ref() {
                            break;
                        }
                        if add.contains(r_type) {
                            // Skip what we are trying to add.
                            continue;
                        }
                        curr.insert(*r_type);
                    }

                    let mut new = nsec_update_bitmap(&record_nsec, nsec, &curr, add, delete, self);

                    // Sign the types at this name except for NSEC, and RRSIG.
                    new.remove(&NewRtype::NSEC);
                    new.remove(&NewRtype::RRSIG);
                    sign_rtype_set(&old_key_name, &new, self)?;

                    // Names that were previously occluded are no longer.
                    nsec_clear_occluded(&old_key_name, self)?;
                    continue;
                }
                if key.as_ref() != new_origin.as_ref() && nsec.types().contains(NewRtype::NS) {
                    // NS marks a delegation but only when the NS is not
                    // at the apex.

                    // If the add set contains DS then sign the DS RRset.
                    if add.contains(&NewRtype::DS) {
                        let ds_set: HashSet<_> = [NewRtype::DS].into();
                        sign_rtype_set(&old_key_name, &ds_set, self)?;
                    }
                    nsec_update_bitmap(&record_nsec, nsec, &curr, add, delete, self);
                    continue;
                }

                // The add types need to be signed.
                sign_rtype_set(&old_key_name, add, self)?;

                nsec_update_bitmap(&record_nsec, nsec, &curr, add, delete, self);
            } else {
                if add.is_empty() {
                    assert!(!delete.is_empty());
                    // No need to do anything.
                    continue;
                }
                assert!(delete.is_empty());
                if is_occluded(&old_key_name, self) {
                    // No need to do anything.
                    continue;
                }

                if add.contains(&NewRtype::NS) {
                    // Create a new NSEC record and sign only DS records (if any).
                    let old_add: HashSet<_> =
                        add.iter().map(|r| new_base_rtype_to_old_base(*r)).collect();
                    let rtypebitmap = nsec_rtypebitmap_from_iterator(old_add.iter());
                    nsec_insert(key, rtypebitmap, self);
                    if add.contains(&NewRtype::DS) {
                        let ds_set: HashSet<_> = [NewRtype::DS].into();
                        sign_rtype_set(&old_key_name, &ds_set, self)?;
                    }

                    // nsec_set_occluded expects the NSEC for key to exist.
                    // So call this after inserting the new NSEC record.
                    nsec_set_occluded(key, self);
                    continue;
                }
                // Create a new NSEC record and sign all records.
                let old_add: HashSet<_> =
                    add.iter().map(|r| new_base_rtype_to_old_base(*r)).collect();
                let rtypebitmap = nsec_rtypebitmap_from_iterator(old_add.iter());
                nsec_insert(key, rtypebitmap, self);
                sign_rtype_set(&old_key_name, add, self)?;
            }
        }
        Ok(())
    }

    pub fn incremental_nsec3(&mut self) -> Result<(), SignerError> {
        // Should changes be sorted or not? If changes is sorted we will
        // process a new delegation before any glue. Which is more efficient.
        // Otherwise if glue comes first, the glue will be signed and inserted
        // in the NSEC chain only to be removed when the delegation is processed.
        // However, when removing a delegation, the situation is reversed.
        // For now assume that sorting is not necessary.

        let new_origin = old_base_name_to_revnamebuf(&self.origin);

        let opt_out_flag = self.nsec3param.opt_out_flag();

        let changes = self.changes.clone();
        for (key, (add, delete)) in &changes {
            let old_key_name = revname_to_old_base_name(key);

            // The intersection between add and delete is empty.
            assert!(add.intersection(delete).next().is_none());

            let (nsec3_hash_octets, nsec3_name) = nsec3_hash_parts(&old_key_name, self);

            let new_nsec3_name = old_base_name_to_revnamebuf(&nsec3_name);
            if let Some(record_nsec3) = self.nsec3s.get(&new_nsec3_name) {
                let record_nsec3 = record_nsec3.clone();
                let NewRecordData::Nsec3(nsec3) = record_nsec3.data() else {
                    panic!("NSEC3 record expected");
                };

                // Convert the existing RRtype bitmap into a hash set.
                let mut curr = HashSet::new();
                // TODO: should implement IntoIterator for TypeBitMaps.
                //for rtype in nsec3.types() {
                for rtype in nsec3.types().iter() {
                    curr.insert(rtype);
                }

                // The intersection between curr and add is empty.
                assert!(curr.intersection(add).next().is_none());

                // delete is completely contained in curr. In other words the
                // difference between delete and curr is empty.
                assert!(delete.difference(&curr).next().is_none());

                if add.contains(&NewRtype::NS) {
                    // Apex is special, but we can assume the NS RRset will not
                    // be added to apex.
                    assert!(key.as_ref() != new_origin.as_ref());

                    // Remove the signatures for the existing types.
                    for rtype in nsec3.types().iter() {
                        // When NS is added, we should keep the signatures for
                        // DS. Do not try to remove a signature for RRSIG because
                        // it does not exist.
                        if rtype == NewRtype::DS || rtype == NewRtype::RRSIG {
                            continue;
                        }
                        let key = (key.as_ref(), rtype);
                        self.rrsigs.remove(&key);
                    }

                    // Restrict curr and add to these types.
                    let mask: HashSet<NewRtype> =
                        [NewRtype::NS, NewRtype::DS, NewRtype::RRSIG].into();

                    let curr = curr.intersection(&mask).copied().collect();
                    let add = add.intersection(&mask).copied().collect();

                    // Update the NSEC3 record.
                    nsec3_update_bitmap(
                        &old_key_name,
                        &record_nsec3,
                        &nsec3,
                        &curr,
                        &add,
                        delete,
                        self,
                    );

                    // Mark descendents as occluded after updating the bitmap.
                    // The reason is that nsec3_update_bitmap uses the current
                    // next_hash and nsec3_set_occluded may change that.
                    nsec3_set_occluded(&old_key_name, self);

                    continue;
                }
                if delete.contains(&NewRtype::NS) {
                    // Apex is special, but we can assume the NS RRset will not
                    // be removed from apex.
                    assert!(key.as_ref() != new_origin.as_ref());

                    // Curr does not include all types at this name. Add the
                    // missing types to curr.
                    let box_revname = key.as_ref().unsized_copy_into();
                    let range_key = (box_revname, 0.into());
                    let range = self.data.range(range_key..);
                    for ((r_name, r_type), _) in range {
                        if r_name.as_ref() != key.as_ref() {
                            break;
                        }
                        if add.contains(r_type) {
                            // Skip what we are trying to add.
                            continue;
                        }
                        curr.insert(*r_type);
                    }

                    let mut new = nsec3_update_bitmap(
                        &old_key_name,
                        &record_nsec3,
                        &nsec3,
                        &curr,
                        add,
                        delete,
                        self,
                    );

                    // Sign the types at this name except for NSEC, and RRSIG.
                    new.remove(&NewRtype::RRSIG);
                    sign_rtype_set(&old_key_name, &new, self)?;

                    // Names that were previously occluded are no longer.
                    nsec3_clear_occluded(&old_key_name, self)?;
                    continue;
                }
                if key.as_ref() != new_origin.as_ref() && nsec3.types().contains(NewRtype::NS) {
                    // NS marks a delegation but only when the NS is not
                    // at the apex.

                    // If the add set contains DS then sign the DS RRset.
                    if add.contains(&NewRtype::DS) {
                        let ds_set: HashSet<_> = [NewRtype::DS].into();
                        sign_rtype_set(&old_key_name, &ds_set, self)?;
                    }
                    nsec3_update_bitmap(
                        &old_key_name,
                        &record_nsec3,
                        &nsec3,
                        &curr,
                        add,
                        delete,
                        self,
                    );
                    continue;
                }

                // The add types need to be signed.
                sign_rtype_set(&old_key_name, add, self)?;

                nsec3_update_bitmap(
                    &old_key_name,
                    &record_nsec3,
                    &nsec3,
                    &curr,
                    add,
                    delete,
                    self,
                );
            } else {
                if add.is_empty() {
                    assert!(!delete.is_empty());

                    // Special magic for out-out. It is possible that an NS
                    // record got deleted. With opt-out there will not be an
                    // NSEC3 record if there is only a NS record and no DS record.
                    if opt_out_flag && delete.contains(&NewRtype::NS) {
                        if is_occluded(&old_key_name, self) {
                            // No need to do anything.
                            continue;
                        }
                        nsec3_clear_occluded(&old_key_name, self)?;
                        continue;
                    }

                    // No need to do anything.
                    continue;
                }
                assert!(delete.is_empty());
                if is_occluded(&old_key_name, self) {
                    // No need to do anything.
                    continue;
                }

                // Just copy add in case we need to change it.
                let mut add = add.clone();
                if opt_out_flag {
                    // We have a new record and no NSEC3 record exists. But in the
                    // case of opt-out there may already be an NS record.
                    // We are not at apex because apex always has an NSEC3
                    // record.
                    let key_boxrevname = key.as_ref().unsized_copy_into();
                    let tmpkey = (key_boxrevname, NewRtype::NS);
                    if self.data.contains_key(&tmpkey) {
                        // Found an NS record. It is safe to add NS to the add
                        // set.
                        add.insert(NewRtype::NS);
                    }
                }

                if add.contains(&NewRtype::NS) {
                    if opt_out_flag {
                        // Check if this is just an NS record. If so, don't
                        // create an NSEC3 record.
                        if !add.iter().any(|r| *r != NewRtype::NS) {
                            continue;
                        }
                    }
                    // Create a new NSEC3 record and sign only DS records (if any).
                    // If add contains DS then add RRSIG to add.

                    let mut add = add.clone(); // In case we need to add RRSIG.
                    if add.contains(&NewRtype::DS) {
                        let ds_set: HashSet<_> = [NewRtype::DS].into();
                        sign_rtype_set(&old_key_name, &ds_set, self)?;
                        add.insert(NewRtype::RRSIG);
                    }

                    let old_add: HashSet<_> =
                        add.iter().map(|r| new_base_rtype_to_old_base(*r)).collect();
                    let rtypebitmap = nsec3_rtypebitmap_from_iterator(old_add.iter());

                    nsec3_insert_full(
                        &old_key_name,
                        nsec3_hash_octets,
                        &new_nsec3_name,
                        rtypebitmap,
                        self,
                    );
                    nsec3_set_occluded(&old_key_name, self);
                    continue;
                }
                // The new name is not a delegation. Add RRSIG to the set of
                // Rtypes.
                let mut add_with_rrsig = add.clone();
                add_with_rrsig.insert(NewRtype::RRSIG);

                // Create a new NSEC3 record and sign all records.
                let old_add_with_rrsig: HashSet<_> = add_with_rrsig
                    .iter()
                    .map(|r| new_base_rtype_to_old_base(*r))
                    .collect();
                let rtypebitmap = nsec3_rtypebitmap_from_iterator(old_add_with_rrsig.iter());
                nsec3_insert_full(
                    &old_key_name,
                    nsec3_hash_octets,
                    &new_nsec3_name,
                    rtypebitmap,
                    self,
                );
                sign_rtype_set(&old_key_name, &add, self)?;
            }
        }
        Ok(())
    }

    fn remove_nsec_nsec3(&mut self) {
        for k in self.nsecs.keys() {
            let key = (k, NewRtype::NSEC);
            self.rrsigs.remove(&key);
        }
        self.nsecs.remove_all();

        for k in self.nsec3s.keys() {
            let key = (k, NewRtype::NSEC3);
            self.rrsigs.remove(&key);
        }
        self.nsec3s.remove_all();
    }

    fn new_nsec_chain(&mut self) -> Result<(), SignerError> {
        let records = self.get_unsigned_sorted();
        let records: Vec<_> = records.into_iter().map(|r| r.to_record().clone()).collect();
        let records_iter = RecordsIter::new_from_owned(&records);
        let config = GenerateNsecConfig::new();
        let nsec_records = generate_nsecs(&self.origin, records_iter, &config)
            .map_err(|e| SignerError::SigningError(format!("new_nsec_chain failed: {e}")))?;

        // Collect signatures here.
        let mut new_sigs = vec![];

        for r in nsec_records {
            let record = RecordFullCmp::new(
                r.owner().clone(),
                r.class(),
                r.ttl(),
                ZoneRecordData::Nsec(r.data().clone()),
            );
            let new_record: RegularRecord = record.clone().into();
            self.nsecs.insert_new_record(new_record.clone());
            sign_records(
                &self.origin,
                &[record],
                &self.keys,
                self.inception,
                self.expiration,
                &mut new_sigs,
            )?;
        }
        for sig in new_sigs {
            self.rrsigs.replace_with_new_records(sig);
        }
        Ok(())
    }

    fn new_nsec3_chain(&mut self) -> Result<(), SignerError> {
        let records = self.get_unsigned_sorted();
        let records: Vec<_> = records.into_iter().map(|r| r.to_record().clone()).collect();
        let records_iter = RecordsIter::new_from_owned(&records);
        let old_nsec3param = new_base_nsec3param_to_old_base(&self.nsec3param);
        let config = GenerateNsec3Config::<_, DefaultSorter>::new(old_nsec3param)
            .with_ttl_mode(Nsec3ParamTtlMode::SoaMinimum);
        let nsec3_records = generate_nsec3s(&self.origin, records_iter, &config)
            .map_err(|e| SignerError::SigningError(format!("generate_nsec3s failed: {e}")))?;

        // Collect signatures here.
        let mut new_sigs = vec![];

        let r = nsec3_records.nsec3param;
        let record = RecordFullCmp::new(
            r.owner().clone(),
            r.class(),
            r.ttl(),
            ZoneRecordData::Nsec3param(r.data().clone()),
        );
        let records = [record.clone()];

        // Insert in both old and new data.
        sign_records(
            &self.origin,
            &[record],
            &self.keys,
            self.inception,
            self.expiration,
            &mut new_sigs,
        )?;
        let new_records: Vec<RegularRecord> = records.iter().map(|r| (*r).clone().into()).collect();
        self.old_apex
            .insert(NewRtype::NSEC3PARAM, new_records.clone());
        self.new_apex.insert(NewRtype::NSEC3PARAM, new_records);

        for r in nsec3_records.nsec3s {
            let record = RecordFullCmp::new(
                r.owner().clone(),
                r.class(),
                r.ttl(),
                ZoneRecordData::Nsec3(r.data().clone()),
            );
            let new_record: RegularRecord = record.clone().into();
            self.nsec3s.insert_new_record(new_record.clone());
            sign_records(
                &self.origin,
                &[record],
                &self.keys,
                self.inception,
                self.expiration,
                &mut new_sigs,
            )?;
        }
        for sig in new_sigs {
            self.rrsigs.replace_with_new_records(sig);
        }
        Ok(())
    }

    fn get_unsigned_sorted(&self) -> Vec<Zrd> {
        // Create a Vec with all unsigned records to be able to sort them in
        // canonical order.

        let mut apex: Vec<Zrd> = self
            .old_apex
            .values()
            .flatten()
            .map(|r| (*r).clone().into())
            .collect();
        let mut data: Vec<_> = self
            .data
            .values_unordered()
            .flatten()
            .map(|r| (*r).clone().into())
            .collect();
        data.append(&mut apex);
        data.par_sort_by(CanonicalOrd::canonical_cmp);

        data
    }
}

type DataKey = (Box<RevName>, NewRtype);

struct Data<'a> {
    old_data: BTreeMap<DataKey, Vec<&'a RegularRecord>>,

    changes: BTreeMap<DataKey, DataChange<'a>>,
}

impl<'a> Data<'a> {
    fn new() -> Self {
        Self {
            old_data: BTreeMap::new(),
            changes: BTreeMap::new(),
        }
    }

    fn insert_existing_record(&mut self, record: &'a RegularRecord) {
        let box_owner = record.owner().unsized_copy_into();
        let key = (box_owner, record.data().rtype());
        match self.old_data.entry(key) {
            btree_map::Entry::Vacant(entry) => {
                entry.insert(vec![record]);
            }
            btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().push(record);
            }
        }
    }

    fn add_record(&mut self, record: RegularRecord) {
        let box_owner = record.owner().unsized_copy_into();
        let key = (box_owner, record.data().rtype());
        match self.changes.entry(key.clone()) {
            btree_map::Entry::Vacant(entry) => {
                if let Some(old) = self.old_data.get(&key) {
                    let mut new: Vec<_> = old.iter().map(|r| (*r).clone()).collect();
                    new.push(record);
                    entry.insert(DataChange::Modified {
                        old: old.clone(),
                        new,
                    });
                } else {
                    entry.insert(DataChange::Insert { new: vec![record] });
                }
            }
            btree_map::Entry::Occupied(ref mut entry) => {
                let change = entry.get_mut();
                match change {
                    DataChange::Removed { old } => {
                        *change = DataChange::Modified {
                            old: old.to_vec(),
                            new: vec![record],
                        };
                    }
                    DataChange::Modified { new, .. } | DataChange::Insert { new, .. } => {
                        new.push(record);
                    }
                }
            }
        }
    }

    fn remove_record(&mut self, record: RegularRecord) {
        // Assume that zonedata is internally consistent and we will not get
        // a remove for a record that is not present in the current signed
        // zone.
        // If that would happen we can do one of three things:
        // 1) panic,
        // 2) return an error,
        // 3) log an error and continue.
        // Option 3) is unattactive because it may lead to broken zones.
        // Option 2) is extra complexity for something that should not happen.
        // That leaves option 1).
        // A better solution would be to change that zonedata interface to
        // deal with RRsets instead of individual records.

        let box_owner = record.owner().unsized_copy_into();
        let key = (box_owner, record.data().rtype());
        match self.changes.entry(key.clone()) {
            btree_map::Entry::Vacant(entry) => {
                let old = self.old_data.get(&key).expect("RRset should exist");
                let mut new: Vec<_> = old.iter().map(|r| (*r).clone()).collect();
                let index = new
                    .iter()
                    .position(|r| *r == record)
                    .expect("position should exist");
                new.remove(index);
                let change = if new.is_empty() {
                    DataChange::Removed { old: old.clone() }
                } else {
                    DataChange::Modified {
                        old: old.clone(),
                        new,
                    }
                };
                entry.insert(change);
            }
            btree_map::Entry::Occupied(mut entry) => {
                match entry.get() {
                    DataChange::Removed { .. } => unreachable!(), // Cannot remove from a remove RRset.
                    DataChange::Modified { old, new } => {
                        let index = new
                            .iter()
                            .position(|r| *r == record)
                            .expect("position should exist");
                        let mut new = new.to_vec();
                        new.remove(index);
                        let change = if new.is_empty() {
                            DataChange::Removed { old: old.clone() }
                        } else {
                            DataChange::Modified {
                                old: old.clone(),
                                new,
                            }
                        };
                        entry.insert(change);
                    }
                    DataChange::Insert { .. } => unreachable!(), // There should be no remove for a record that has just been inserted.
                }
            }
        }
    }

    fn get(&self, key: &DataKey) -> Option<Vec<&RegularRecord>> {
        if let Some(change) = self.changes.get(key) {
            match change {
                DataChange::Removed { .. } => None,
                DataChange::Modified { new, .. } | DataChange::Insert { new } => {
                    Some(new.iter().collect())
                }
            }
        } else {
            self.old_data.get(key).cloned()
        }
    }

    fn contains_key(&self, key: &DataKey) -> bool {
        if let Some(change) = self.changes.get(key) {
            match change {
                DataChange::Removed { .. } => false,
                DataChange::Modified { .. } | DataChange::Insert { .. } => true,
            }
        } else {
            self.old_data.contains_key(key)
        }
    }

    // Iterator but unordered.
    fn iter_unordered(&self) -> DataIter<'_> {
        DataIter::new(self.old_data.iter(), &self.changes)
    }

    // Iterator over all values but unordered.
    fn values_unordered(&self) -> DataValuesIter<'_> {
        DataValuesIter::new(self.old_data.iter(), &self.changes)
    }

    fn changes_iter(&self) -> btree_map::Iter<'_, DataKey, DataChange<'_>> {
        self.changes.iter()
    }

    fn range<R>(&self, range: R) -> DataRange<'_>
    where
        R: Clone + RangeBounds<DataKey>,
    {
        DataRange::new(
            self.old_data.range(range.clone()),
            self.changes.range(range),
        )
    }
}

enum DataChange<'a> {
    Removed {
        old: Vec<&'a RegularRecord>,
    },
    Modified {
        old: Vec<&'a RegularRecord>,
        new: Vec<RegularRecord>,
    },
    Insert {
        new: Vec<RegularRecord>,
    },
}

// Iterator but without any defined order.
struct DataIter<'a> {
    iter: Option<btree_map::Iter<'a, DataKey, Vec<&'a RegularRecord>>>,
    changes: &'a BTreeMap<DataKey, DataChange<'a>>,
    changes_iter: Option<btree_map::Iter<'a, DataKey, DataChange<'a>>>,
}

impl<'a> DataIter<'a> {
    fn new(
        iter: btree_map::Iter<'a, DataKey, Vec<&'a RegularRecord>>,
        changes: &'a BTreeMap<DataKey, DataChange>,
    ) -> Self {
        Self {
            iter: Some(iter),
            changes,
            changes_iter: None,
        }
    }
}

type DataIterItem<'a> = (&'a DataKey, Vec<&'a RegularRecord>);
impl<'a> Iterator for DataIter<'a> {
    type Item = DataIterItem<'a>;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if let Some(iter) = &mut self.iter {
            for (key, data) in iter.by_ref() {
                // Check if changes has something.
                if self.changes.get(key).is_some() {
                    // Get it from changes if not deleted.
                    continue;
                }

                return Some((key, data.to_vec()));
            }
            self.iter = None;
            self.changes_iter = Some(self.changes.iter());
        }
        if let Some(changes_iter) = &mut self.changes_iter {
            for (key, change) in changes_iter.by_ref() {
                match change {
                    DataChange::Removed { .. } => {
                        // Nothing here.
                        continue;
                    }
                    DataChange::Modified { new, .. } | DataChange::Insert { new, .. } => {
                        let new: Vec<&RegularRecord> = new.iter().collect();
                        return Some((key, new.to_vec()));
                    }
                }
            }
            self.changes_iter = None;
        }
        None
    }
}

// Iterator over all values but without any defined order.
struct DataValuesIter<'a> {
    iter: Option<btree_map::Iter<'a, DataKey, Vec<&'a RegularRecord>>>,
    changes: &'a BTreeMap<DataKey, DataChange<'a>>,
    changes_values: Option<btree_map::Values<'a, DataKey, DataChange<'a>>>,
}

impl<'a> DataValuesIter<'a> {
    fn new(
        iter: btree_map::Iter<'a, DataKey, Vec<&'a RegularRecord>>,
        changes: &'a BTreeMap<DataKey, DataChange>,
    ) -> Self {
        Self {
            iter: Some(iter),
            changes,
            changes_values: None,
        }
    }
}

impl<'a> Iterator for DataValuesIter<'a> {
    type Item = Vec<&'a RegularRecord>;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if let Some(iter) = &mut self.iter {
            for (key, data) in iter.by_ref() {
                // Check if changes has something.
                if self.changes.get(key).is_some() {
                    // Get it from changes if not deleted.
                    continue;
                }

                return Some(data.to_vec());
            }
            self.iter = None;
            self.changes_values = Some(self.changes.values());
        }
        if let Some(changes_values) = &mut self.changes_values {
            for change in changes_values.by_ref() {
                match change {
                    DataChange::Removed { .. } => {
                        // Nothing here.
                        continue;
                    }
                    DataChange::Modified { new, .. } | DataChange::Insert { new, .. } => {
                        let new: Vec<&RegularRecord> = new.iter().collect();
                        return Some(new.to_vec());
                    }
                }
            }
            self.changes_values = None;
        }
        None
    }
}

struct DataRange<'a> {
    old_data_range: Option<btree_map::Range<'a, DataKey, Vec<&'a RegularRecord>>>,
    changes_range: Option<btree_map::Range<'a, DataKey, DataChange<'a>>>,
    old_data_item: Option<(&'a DataKey, &'a Vec<&'a RegularRecord>)>,
    change_item: Option<(&'a DataKey, &'a DataChange<'a>)>,
}

impl<'a> DataRange<'a> {
    fn new(
        old_data_range: btree_map::Range<'a, DataKey, Vec<&'a RegularRecord>>,
        changes_range: btree_map::Range<'a, DataKey, DataChange>,
    ) -> Self {
        Self {
            old_data_range: Some(old_data_range),
            changes_range: Some(changes_range),
            old_data_item: None,
            change_item: None,
        }
    }
}

impl<'a> Iterator for DataRange<'a> {
    type Item = (&'a DataKey, Vec<&'a RegularRecord>);
    fn next(&mut self) -> std::option::Option<<Self as Iterator>::Item> {
        while let Some(old_data_range) = &mut self.old_data_range
            && let Some(changes_range) = &mut self.changes_range
        {
            if self.old_data_item.is_none() {
                if let Some(item) = old_data_range.next() {
                    self.old_data_item = Some(item);
                } else {
                    self.old_data_range = None;
                    break;
                }
            }
            if self.change_item.is_none() {
                if let Some(item) = changes_range.next() {
                    self.change_item = Some(item);
                } else {
                    self.changes_range = None;
                    break;
                }
            }
            let old_data_key = self.old_data_item.expect("item should be there").0;
            let change_key = self.change_item.expect("item should be there").0;
            match old_data_key.cmp(change_key) {
                Ordering::Less => {
                    // old_data_item comes first.
                    let old_data_item = self.old_data_item.take().expect("item should be there");
                    return Some((old_data_key, old_data_item.1.to_vec()));
                }
                Ordering::Equal => {
                    // Remove the old_data_item and continue with change_item;
                    let _ = self.old_data_item.take();
                }
                Ordering::Greater => {
                    // change_item comes first.
                }
            }
            let change_item = self.change_item.take().expect("item should be there");
            match change_item.1 {
                DataChange::Removed { .. } => continue,
                DataChange::Modified { new, .. } | DataChange::Insert { new } => {
                    return Some((change_key, new.iter().collect()));
                }
            }
        }

        // One of the two iterators has exhauted, drain the other one.
        while let Some(old_data_range) = &mut self.old_data_range {
            if let Some(item) = self.old_data_item.take() {
                return Some((item.0, item.1.to_vec()));
            }
            if let Some(item) = old_data_range.next() {
                return Some((item.0, item.1.to_vec()));
            }
            self.old_data_range = None;
        }
        while let Some(changes_range) = &mut self.changes_range {
            let change_item = if let Some(item) = self.change_item.take() {
                item
            } else if let Some(item) = changes_range.next() {
                item
            } else {
                self.changes_range = None;
                continue;
            };
            match change_item.1 {
                DataChange::Removed { .. } => continue,
                DataChange::Modified { new, .. } | DataChange::Insert { new } => {
                    return Some((change_item.0, new.iter().collect()));
                }
            }
        }
        None
    }
}

struct Nsecs<'rd> {
    nsecs: BTreeMap<Box<RevName>, NsecChange<'rd>>,
    changes: HashSet<Box<RevName>>,
}

impl<'a> Nsecs<'a> {
    fn new() -> Self {
        Self {
            nsecs: BTreeMap::new(),
            changes: HashSet::new(),
        }
    }

    fn add_existing_record(&mut self, value: &'a RegularRecord) {
        let nsec_change = NsecChange::Original { old: value };
        self.nsecs
            .insert(value.owner().unsized_copy_into(), nsec_change);
    }

    fn insert_new_record(&mut self, value: RegularRecord) {
        let owner_boxrevname: Box<_> = value.owner().unsized_copy_into();
        let entry = self.nsecs.entry(owner_boxrevname.clone());
        match entry {
            btree_map::Entry::Occupied(mut entry) => {
                let change = entry.get_mut();
                match change {
                    NsecChange::Original { old }
                    | NsecChange::Modified { old, .. }
                    | NsecChange::Removed { old } => {
                        let new_change = NsecChange::Modified { old, new: value };
                        *change = new_change;

                        // No need for an insert for Modified, but it doesn't
                        // hurt.
                        self.changes.insert(owner_boxrevname);
                    }
                    NsecChange::New { .. } => {
                        let new_change = NsecChange::New { new: value };
                        *change = new_change;
                    }
                }
            }
            btree_map::Entry::Vacant(entry) => {
                let change = NsecChange::New { new: value };
                entry.insert(change);
                self.changes.insert(owner_boxrevname);
            }
        }
    }

    fn remove(&mut self, name: &RevName) {
        let entry = self.nsecs.entry(name.unsized_copy_into());
        match entry {
            btree_map::Entry::Occupied(mut entry) => {
                let change = entry.get_mut();
                match change {
                    NsecChange::Original { old } | NsecChange::Modified { old, .. } => {
                        let new_change = NsecChange::Removed { old };
                        *change = new_change;

                        // No need for an insert for Modified, but it doesn't
                        // hurt.
                        self.changes.insert(name.unsized_copy_into());
                    }
                    NsecChange::Removed { .. } => (),
                    NsecChange::New { .. } => {
                        // Remove the new entry.
                        entry.remove();
                        self.changes.remove(name);
                    }
                }
            }
            btree_map::Entry::Vacant(_) => (),
        }
    }

    fn remove_all(&mut self) {
        for (name, change) in self.nsecs.iter_mut() {
            match change {
                NsecChange::Original { old } => {
                    let new_change = NsecChange::Removed { old };
                    *change = new_change;

                    // No need for an insert for Modified, but it doesn't
                    // hurt.
                    self.changes.insert(name.clone());
                }
                NsecChange::Modified { .. }
                | NsecChange::New { .. }
                | NsecChange::Removed { .. } => {
                    // It would be very hard to remove a New entry here.
                    // However, in the current code, Remove, New and Modified
                    // should not exist when calling remove_all.
                    // Remove and Modified are easy to implement though.
                    unreachable!();
                }
            }
        }
    }

    fn get(&self, name: &RevName) -> Option<&RegularRecord> {
        if let Some(change) = self.nsecs.get(name) {
            match change {
                NsecChange::Original { old } => return Some(old),
                NsecChange::Removed { .. } => return None,
                NsecChange::Modified { new, .. } | NsecChange::New { new } => return Some(new),
            }
        }
        None
    }

    fn get_change(&self, name: &RevName) -> Option<&NsecChange<'_>> {
        self.nsecs.get(name)
    }

    fn contains_key(&self, name: &RevName) -> bool {
        if let Some(change) = self.nsecs.get(name) {
            match change {
                NsecChange::Removed { .. } => return false,
                NsecChange::Original { .. }
                | NsecChange::Modified { .. }
                | NsecChange::New { .. } => return true,
            }
        }
        false
    }

    fn keys(&self) -> NsecsKeysIter<'_> {
        NsecsKeysIter::new(self.nsecs.iter())
    }

    fn values(&self) -> NsecsValuesIter<'_> {
        NsecsValuesIter::new(self.nsecs.values())
    }

    fn range<R>(&self, range: R) -> NsecRange<'_>
    where
        R: RangeBounds<Box<RevName>>,
    {
        NsecRange::new(self.nsecs.range(range))
    }

    fn changes_iter(&self) -> hash_set::Iter<'_, Box<RevName>> {
        self.changes.iter()
    }

    /// Add changes to NSEC(3) records to the patch.
    fn generate_diff(&self, patch: &mut SignedZonePatcher) -> Result<(), SignerError> {
        for name in self.changes_iter() {
            if let Some(change) = self.get_change(name) {
                match change {
                    NsecChange::Original { .. } => unreachable!(),
                    NsecChange::Removed { old } => {
                        patch.remove((*old).clone()).map_err(|e| {
                            SignerError::PatchFailed(format!("unable to remove {old:?}: {e}"))
                        })?;
                    }
                    NsecChange::Modified { old, new } => {
                        if *old != new {
                            patch.remove((*old).clone()).map_err(|e| {
                                SignerError::PatchFailed(format!("unable to remove {old:?}: {e}"))
                            })?;
                            patch.add(new.clone()).map_err(|e| {
                                SignerError::PatchFailed(format!("unable to add {new:?}: {e}"))
                            })?;
                        }
                    }
                    NsecChange::New { new } => {
                        patch.add(new.clone()).map_err(|e| {
                            SignerError::PatchFailed(format!("unable to add {new:?}: {e}"))
                        })?;
                    }
                }
            }
        }
        Ok(())
    }
}

enum NsecChange<'zd> {
    Original {
        old: &'zd RegularRecord,
    },
    Removed {
        old: &'zd RegularRecord,
    },
    Modified {
        old: &'zd RegularRecord,
        new: RegularRecord,
    },
    New {
        new: RegularRecord,
    },
}

struct NsecsKeysIter<'a> {
    iter: btree_map::Iter<'a, Box<RevName>, NsecChange<'a>>,
}

impl<'a> NsecsKeysIter<'a> {
    fn new(iter: btree_map::Iter<'a, Box<RevName>, NsecChange>) -> Self {
        Self { iter }
    }
}

type NsecKeyItem<'a> = &'a RevName;

impl<'a> Iterator for NsecsKeysIter<'a> {
    type Item = NsecKeyItem<'a>;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        for (name, item) in self.iter.by_ref() {
            match item {
                NsecChange::Original { .. }
                | NsecChange::Modified { .. }
                | NsecChange::New { .. } => return Some(name),
                NsecChange::Removed { .. } => continue,
            }
        }
        None
    }
}

struct NsecsValuesIter<'a> {
    iter: btree_map::Values<'a, Box<RevName>, NsecChange<'a>>,
}

impl<'a> NsecsValuesIter<'a> {
    fn new(iter: btree_map::Values<'a, Box<RevName>, NsecChange>) -> Self {
        Self { iter }
    }
}

type NsecItem<'a> = &'a RegularRecord;

impl<'a> Iterator for NsecsValuesIter<'a> {
    type Item = NsecItem<'a>;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        for item in self.iter.by_ref() {
            match item {
                NsecChange::Original { old } => return Some(old),
                NsecChange::Removed { .. } => continue,
                NsecChange::Modified { new, .. } | NsecChange::New { new } => return Some(new),
            }
        }
        None
    }
}

struct NsecRange<'a> {
    range: btree_map::Range<'a, Box<RevName>, NsecChange<'a>>,
}

impl<'a> NsecRange<'a> {
    fn new(range: btree_map::Range<'a, Box<RevName>, NsecChange>) -> Self {
        Self { range }
    }
}

impl<'a> Iterator for NsecRange<'a> {
    type Item = (&'a RevName, &'a RegularRecord);
    fn next(&mut self) -> std::option::Option<<Self as Iterator>::Item> {
        for (name, item) in self.range.by_ref() {
            match item {
                NsecChange::Original { old } => return Some((name, old)),
                NsecChange::Removed { .. } => continue,
                NsecChange::Modified { new, .. } | NsecChange::New { new } => {
                    return Some((name, new));
                }
            }
        }
        None
    }
}

impl<'a> DoubleEndedIterator for NsecRange<'a> {
    fn next_back(&mut self) -> Option<<Self as Iterator>::Item> {
        while let Some((name, item)) = self.range.next_back() {
            match item {
                NsecChange::Original { old } => return Some((name, old)),
                NsecChange::Removed { .. } => continue,
                NsecChange::Modified { new, .. } | NsecChange::New { new } => {
                    return Some((name, new));
                }
            }
        }
        None
    }
}

type RrsigKey<'a> = (&'a RevName, NewRtype);
struct Rrsigs<'zd> {
    // Store the existing RRSIG records. The incremental signer doesn't
    // need them, but we need them to inform the zone store which records
    // have been removed.
    old_rrsigs: HashMap<RrsigKey<'zd>, Vec<&'zd RegularRecord>>,

    changes: HashMap<(Box<RevName>, NewRtype), RrsigChange<'zd>>,
}

impl<'zd> Rrsigs<'zd> {
    fn new() -> Rrsigs<'zd> {
        Rrsigs {
            old_rrsigs: HashMap::new(),
            changes: HashMap::new(),
        }
    }

    fn add_existing_record(&mut self, record: &'zd RegularRecord) {
        let NewRecordData::Rrsig(rrsig) = record.data() else {
            panic!("ZoneRecordData::Rrsig expected");
        };
        let key = (record.owner(), rrsig.type_covered());
        self.old_rrsigs.entry(key).or_default().push(record);
    }

    fn add_new_record(&mut self, record: RegularRecord) {
        let NewRecordData::Rrsig(rrsig) = record.data() else {
            panic!("ZoneRecordData::Rrsig expected");
        };
        let buf_key = (record.owner().unsized_copy_into(), rrsig.type_covered());

        // First check the changes map.
        match self.changes.entry(buf_key) {
            hash_map::Entry::Occupied(mut entry) => {
                let change = entry.get_mut();
                match change {
                    RrsigChange::Delete { old } => {
                        // We found Delete so old RRSIGs exit and we need
                        // to create a Modified.
                        *change = RrsigChange::Modified {
                            old: old.to_vec(),
                            new: vec![record],
                        };
                    }
                    RrsigChange::Modified { new, .. } | RrsigChange::Insert { new, .. } => {
                        new.push(record);
                    }
                }
            }
            hash_map::Entry::Vacant(entry) => {
                // Whether a new change is Modified or Insert depends on
                // whether RRSIGs already exist or not.
                let key = (record.owner(), rrsig.type_covered());
                let change = if let Some(old_sigs) = self.old_rrsigs.get(&key) {
                    RrsigChange::Modified {
                        old: old_sigs.to_vec(),
                        new: vec![record],
                    }
                } else {
                    // Nothing yet. Create an Insert.
                    RrsigChange::Insert { new: vec![record] }
                };
                entry.insert(change);
            }
        }
    }

    /// Replace the signature for an RRset with a new collection of signatures.
    /// If there were no previous signature then this is an insert.
    /// The list of RRSIG records has to have a common owner name and
    /// the same type_covered().
    fn replace_with_new_records(&mut self, records: Vec<RegularRecord>) {
        let NewRecordData::Rrsig(rrsig) = records[0].data() else {
            panic!("ZoneRecordData::Rrsig expected");
        };

        let buf_key: (Box<RevName>, _) =
            (records[0].owner().unsized_copy_into(), rrsig.type_covered());

        // Check that all records have the same owner name and the same
        // type_covered().
        debug_assert!(records.iter().all(|r| r.owner() == buf_key.0.as_ref() && matches!(r.data(), NewRecordData::Rrsig(rrsig) if rrsig.type_covered() == buf_key.1)));

        // First check the changes map.
        match self.changes.entry(buf_key) {
            hash_map::Entry::Occupied(mut entry) => {
                let change = entry.get_mut();
                match change {
                    RrsigChange::Delete { old } => {
                        // Old RRSIGs existed but were deleted. Create a
                        // Modify.
                        *change = RrsigChange::Modified {
                            old: old.to_vec(),
                            new: records,
                        };
                    }
                    RrsigChange::Modified { new, .. } | RrsigChange::Insert { new, .. } => {
                        *new = records;
                    }
                }
            }
            hash_map::Entry::Vacant(entry) => {
                // Create a new empty change, either insert or
                // modify depending on the existing RRSIGS.
                let key = (records[0].owner(), rrsig.type_covered());
                let new_change = if let Some(rrsigs) = self.old_rrsigs.get(&key) {
                    RrsigChange::Modified {
                        old: rrsigs.to_vec(),
                        new: records,
                    }
                } else {
                    RrsigChange::Insert { new: records }
                };
                entry.insert(new_change);
            }
        }
    }

    fn values(&self) -> RrsigsValuesIter<'_> {
        RrsigsValuesIter::new(self.old_rrsigs.iter(), &self.changes)
    }

    /// Return the number of RRsets that have signatures taking inserts and
    /// deletes into account.
    fn signed_rrset_count(&self) -> usize {
        // Return the number of RRsets that have signatures.
        let len = self.old_rrsigs.len();

        let changes: isize = self
            .changes
            .values()
            .map(|v| match v {
                RrsigChange::Delete { .. } => -1,
                RrsigChange::Modified { .. } => 0,
                RrsigChange::Insert { .. } => 1,
            })
            .sum();

        len.checked_add_signed(changes).expect("len + changes >= 0")
    }

    fn remove(&mut self, key: &RrsigKey) -> Option<()> {
        // Remove normally returns the removed item, but we don't need
        // that. We should switch to a boolean.

        // Check if the old version has RRSIGs.
        let old_key = (key.0, key.1);
        let box_key = (key.0.unsized_copy_into(), key.1);
        if let Some(rrsigs) = self.old_rrsigs.get(&old_key) {
            // There are RRSIGs in the old version. Check if they have been
            // deleted before.
            let mut result = Some(());
            match self.changes.entry(box_key.clone()) {
                hash_map::Entry::Occupied(mut entry) => {
                    let change = entry.get_mut();
                    match change {
                        RrsigChange::Delete { .. } => {
                            // RRSIGs were already deleted. Report that there
                            // was nothing.
                            result = None;
                        }
                        RrsigChange::Modified { .. } => {
                            // RRSIGs were modified. Replace with a Delete
                            // entry.
                            *change = RrsigChange::Delete {
                                old: rrsigs.to_vec(),
                            };
                        }
                        RrsigChange::Insert { .. } => unreachable!(),
                    }
                }
                hash_map::Entry::Vacant(entry) => {
                    // There is no change. This means that RRSIGs exist.
                    entry.insert(RrsigChange::Delete {
                        old: rrsigs.to_vec(),
                    });
                }
            }
            result
        } else {
            // They were not present in the old version, check if they have
            // been added.
            let mut result = None;
            match self.changes.entry(box_key) {
                hash_map::Entry::Occupied(entry) => {
                    let change = entry.get();
                    match change {
                        RrsigChange::Delete { .. } => unreachable!(),
                        RrsigChange::Modified { .. } => unreachable!(),
                        RrsigChange::Insert { .. } => {
                            // RRSIGs exist. Remove this entry.
                            result = Some(());
                            entry.remove();
                        }
                    }
                }
                hash_map::Entry::Vacant(_) => {
                    // Nothing to do.
                }
            }
            result
        }
    }

    fn iter(&self) -> RrsigIter<'_> {
        RrsigIter::new(self.old_rrsigs.iter(), &self.changes)
    }
}

type RrsigIterItem<'a> = (RrsigKey<'a>, Vec<&'a RegularRecord>);
impl<'a> IntoIterator for &'a Rrsigs<'a> {
    type Item = RrsigIterItem<'a>;
    type IntoIter = RrsigIter<'a>;
    fn into_iter(self) -> <Self as IntoIterator>::IntoIter {
        RrsigIter::new(self.old_rrsigs.iter(), &self.changes)
    }
}

#[allow(clippy::type_complexity)]
struct RrsigIter<'a> {
    iter: Option<hash_map::Iter<'a, RrsigKey<'a>, Vec<&'a RegularRecord>>>,
    changes: &'a HashMap<(Box<RevName>, NewRtype), RrsigChange<'a>>,
    changes_iter: Option<hash_map::Iter<'a, (Box<RevName>, NewRtype), RrsigChange<'a>>>,
}

impl<'a> RrsigIter<'a> {
    fn new(
        iter: hash_map::Iter<'a, RrsigKey<'a>, Vec<&RegularRecord>>,
        changes: &'a HashMap<(Box<RevName>, NewRtype), RrsigChange>,
    ) -> RrsigIter<'a> {
        RrsigIter {
            iter: Some(iter),
            changes,
            changes_iter: None,
        }
    }
}

impl<'a> Iterator for RrsigIter<'a> {
    type Item = RrsigIterItem<'a>;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if let Some(iter) = &mut self.iter {
            for ((name, rtype), sigs) in iter.by_ref() {
                // Check if changes has something.
                let key = ((*name).unsized_copy_into(), *rtype);
                if self.changes.get(&key).is_some() {
                    // Get it from changes if not deleted.
                    continue;
                }

                return Some(((name, *rtype), sigs.to_vec()));
            }
            self.iter = None;
            self.changes_iter = Some(self.changes.iter());
        }
        if let Some(changes_iter) = &mut self.changes_iter {
            for ((name, rtype), change) in changes_iter.by_ref() {
                match change {
                    RrsigChange::Delete { .. } => {
                        // Nothing here.
                        continue;
                    }
                    RrsigChange::Modified { new, .. } | RrsigChange::Insert { new, .. } => {
                        let new: Vec<&RegularRecord> = new.iter().collect();
                        return Some(((name.as_ref(), *rtype), new));
                    }
                }
            }
            self.changes_iter = None;
        }
        None
    }
}

#[allow(clippy::type_complexity)]
struct RrsigsValuesIter<'a> {
    iter: Option<hash_map::Iter<'a, RrsigKey<'a>, Vec<&'a RegularRecord>>>,
    changes: &'a HashMap<(Box<RevName>, NewRtype), RrsigChange<'a>>,
    changes_values: Option<hash_map::Values<'a, (Box<RevName>, NewRtype), RrsigChange<'a>>>,
}

impl<'a> RrsigsValuesIter<'a> {
    fn new(
        iter: hash_map::Iter<'a, RrsigKey<'a>, Vec<&RegularRecord>>,
        changes: &'a HashMap<(Box<RevName>, NewRtype), RrsigChange>,
    ) -> RrsigsValuesIter<'a> {
        RrsigsValuesIter {
            iter: Some(iter),
            changes,
            changes_values: None,
        }
    }
}

impl<'a> Iterator for RrsigsValuesIter<'a> {
    type Item = Vec<&'a RegularRecord>;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if let Some(iter) = &mut self.iter {
            for ((name, rtype), sigs) in iter.by_ref() {
                // Check if changes has something.
                let key = ((*name).unsized_copy_into(), *rtype);
                if self.changes.get(&key).is_some() {
                    // Get it from changes if not deleted.
                    continue;
                }

                return Some(sigs.to_vec());
            }
            self.iter = None;
            self.changes_values = Some(self.changes.values());
        }
        if let Some(changes_values) = &mut self.changes_values {
            for change in changes_values.by_ref() {
                match change {
                    RrsigChange::Delete { .. } => {
                        // Nothing here.
                        continue;
                    }
                    RrsigChange::Modified { new, .. } | RrsigChange::Insert { new, .. } => {
                        let new: Vec<&RegularRecord> = new.iter().collect();
                        return Some(new.to_vec());
                    }
                }
            }
            self.changes_values = None;
        }
        None
    }
}

/// Changes to the signatures for an RRset. Note that the signatures
/// are not ordered.
#[derive(Debug)]
enum RrsigChange<'zd> {
    Delete {
        old: Vec<&'zd RegularRecord>,
    },
    Modified {
        old: Vec<&'zd RegularRecord>,
        new: Vec<RegularRecord>,
    },
    Insert {
        new: Vec<RegularRecord>,
    },
}

/// Load the state varibles we need at the start and then update state at the end.
pub struct LocalState {
    pub apex_remove: HashSet<Rtype>,
    pub apex_extra: Vec<String>,
    pub last_signature_refresh: UnixTime,
    pub key_tags: HashSet<u16>,
    pub key_roll: Option<UnixTime>,
    pub previous_serial: Option<Serial>,
    pub next_min_expiration: Option<Timestamp>,
}

impl LocalState {
    pub fn new(zone: &Arc<Zone>) -> Result<Self, SignerError> {
        let zone_state = zone.read();

        Ok(Self {
            apex_remove: zone_state.apex_remove.clone(),
            apex_extra: zone_state.apex_extra.clone(),
            last_signature_refresh: zone_state.last_signature_refresh.clone(),
            key_tags: zone_state.key_tags.clone(),
            key_roll: zone_state.key_roll.clone(),
            previous_serial: zone_state.previous_serial,
            next_min_expiration: zone_state.next_min_expiration,
        })
    }

    pub fn save(self, center: &Arc<Center>, zone: &Arc<Zone>) {
        // TODO: The state is always marked as dirty. We could avoid marking it
        // as dirty in case we detect a modification has not happened. We should
        // evaluate whether this is worthwhile.
        let mut zone_state = zone.write(center);

        zone_state.apex_remove = self.apex_remove;
        zone_state.apex_extra = self.apex_extra;
        zone_state.last_signature_refresh = self.last_signature_refresh;
        zone_state.key_tags = self.key_tags;
        zone_state.key_roll = self.key_roll;
        zone_state.previous_serial = self.previous_serial;
        zone_state.next_min_expiration = self.next_min_expiration;
    }
}

fn sign_records(
    origin: &Name<Bytes>,
    records: &[Zrd],
    keys: &ZoneSigningKeys,
    inception: Timestamp,
    expiration: Timestamp,
    new_sigs: &mut Vec<Vec<RegularRecord>>,
) -> Result<(), SignerError> {
    let rtype = records[0].rtype();
    if (rtype == Rtype::DNSKEY || rtype == Rtype::CDS || rtype == Rtype::CDNSKEY)
        && records[0].owner() == origin
    {
        // These records get signed with the KSK(s). Don't touch
        // the signatures.
        return Ok(());
    }

    let records: Vec<_> = records.iter().map(RecordFullCmp::to_record).collect();
    let rrset = Rrset::new_from_refs(&records)
        .map_err(|e| SignerError::SigningError(format!("Rrset::new failed: {e}")))?;
    let mut rrsig_records = vec![];
    for key in &keys.list {
        let rrsig = sign_rrset(key, &rrset, inception, expiration)
            .map_err(|e| SignerError::SigningError(format!("signing failed: {e}")))?;
        let record = Record::new(
            rrsig.owner().clone(),
            rrsig.class(),
            rrsig.ttl(),
            ZoneRecordData::Rrsig(rrsig.data().clone()),
        );
        rrsig_records.push(record.into());
    }
    new_sigs.push(rrsig_records);
    Ok(())
}

fn nsec_insert(name: &RevName, rtypebitmap: RtypeBitmap<Bytes>, iss: &mut IncrementalSigningState) {
    // Try to find the NSEC record that comes before the one we are trying
    // to insert. Assume that the apex NSEC will always exist can sort
    // before anything else.
    let name_box: Box<RevName> = name.unsized_copy_into();
    let old_name = revname_to_old_base_name(name);
    let mut range = iss.nsecs.range(..name_box);
    let (previous_name, previous_record) = range
        .next_back()
        .expect("previous NSEC record should exist");
    let previous_revnamebuf = RevNameBuf::copy_from(previous_name);
    let previous_record = previous_record.clone();
    let NewRecordData::Nsec(previous_nsec) = previous_record.data() else {
        panic!("NSEC record expected");
    };
    let next = name_to_old_base_name(previous_nsec.next_name());
    // We need the new base version of rtypebitmap to create a new base Nsec.
    let new_nsec = Nsec::new(next, rtypebitmap);
    // TODO: construct using new base.
    let new_record = Record::new(
        old_name.clone(),
        new_base_class_to_old_base(previous_record.class()),
        new_base_ttl_to_old_base(previous_record.ttl()),
        ZoneRecordData::Nsec(new_nsec),
    );
    iss.nsecs.insert_new_record(new_record.into());
    let name_revbuf = RevNameBuf::copy_from(name);
    let name_buf: NameBuf = name_revbuf.into();
    let previous_nsec = NewNsec::new(&name_buf, previous_nsec.types());
    let previous_record = RegularRecord::new(
        previous_revnamebuf.unsized_copy_into(),
        previous_record.class(),
        previous_record.ttl(),
        NewRecordData::<NameBuf>::Nsec(previous_nsec).into(),
    );
    iss.nsecs.insert_new_record(previous_record);
}

fn nsec_remove(name: &RevName, next_name: &NewName, iss: &mut IncrementalSigningState) {
    // Try to find the NSEC record that comes before the one we are trying
    // to remove. Assume that the apex NSEC will always exist can sort
    // before anything else.
    let name_box: Box<RevName> = name.unsized_copy_into();
    let mut range = iss.nsecs.range(..name_box);
    let (previous_name, previous_record) = range
        .next_back()
        .expect("previous NSEC record should exist");
    let previous_record = previous_record.clone();
    let NewRecordData::Nsec(previous_nsec) = previous_record.data() else {
        panic!("NSEC record expected");
    };
    let previous_name_revnamebuf = RevNameBuf::copy_from(previous_name);
    let previous_nsec = NewNsec::new(next_name, previous_nsec.types());
    let previous_record = RegularRecord::new(
        previous_name_revnamebuf.as_ref().unsized_copy_into(),
        previous_record.class(),
        previous_record.ttl(),
        NewRecordData::<NameBuf>::Nsec(previous_nsec).into(),
    );
    iss.nsecs.insert_new_record(previous_record);
    iss.nsecs.remove(name);
    let key = (name, NewRtype::NSEC);
    iss.rrsigs.remove(&key);
}

// Return the effective result HashSet even when the NSEC record gets deleted.
fn nsec_update_bitmap(
    record: &RegularRecord,
    nsec: NewNsec,
    curr: &HashSet<NewRtype>,
    add: &HashSet<NewRtype>,
    delete: &HashSet<NewRtype>,
    iss: &mut IncrementalSigningState,
) -> HashSet<NewRtype> {
    let set_nsec_rrsig: HashSet<_> = [NewRtype::NSEC, NewRtype::RRSIG].into();

    // Update curr.
    let curr: HashSet<_> = curr.union(add).copied().collect();
    let curr = curr.difference(delete).copied().collect();

    let owner = record.owner();
    if curr == set_nsec_rrsig {
        nsec_remove(owner, nsec.next_name(), iss);
        return curr;
    }

    let old_curr: HashSet<_> = curr
        .iter()
        .map(|r| new_base_rtype_to_old_base(*r))
        .collect();
    let rtypebitmap = nsec_rtypebitmap_from_iterator(old_curr.iter());
    let old_next_name = name_to_old_base_name(nsec.next_name());
    let nsec = Nsec::new(old_next_name, rtypebitmap);
    let old_owner = revname_to_old_base_name(owner);
    let record = RecordFullCmp::new(
        old_owner.clone(),
        new_base_class_to_old_base(record.class()),
        new_base_ttl_to_old_base(record.ttl()),
        ZoneRecordData::Nsec(nsec),
    );
    iss.nsecs.insert_new_record(record.into());

    curr
}

fn nsec_set_occluded(name: &RevName, iss: &mut IncrementalSigningState) {
    let old_name = revname_to_old_base_name(name);
    let Some(nsec_record) = iss.nsecs.get(name) else {
        panic!("NSEC for {name:?} expected to exist");
    };
    let NewRecordData::Nsec(nsec) = nsec_record.data() else {
        panic!("NSEC record expected");
    };
    let nsec = nsec.clone();
    let mut next = NameBuf::copy_from(nsec.next_name());
    let mut old_next = name_to_old_base_name(next.as_ref());
    loop {
        if !old_next.ends_with(&old_name) {
            break;
        }

        // For consistency, make sure next is not equal to name.
        if old_next == old_name {
            break;
        }
        let curr = next;
        let curr_revnamebuf: RevNameBuf = curr.clone().into();
        let Some(nsec_record) = iss.nsecs.get(&curr_revnamebuf) else {
            panic!("NSEC for {curr:?} expected to exist");
        };
        let nsec_record = nsec_record.clone();
        let NewRecordData::Nsec(nsec) = nsec_record.data() else {
            panic!("NSEC record expected");
        };
        let nsec = nsec.clone();
        next = NameBuf::copy_from(nsec.next_name());
        old_next = name_to_old_base_name(next.as_ref());

        let curr_revnamebuf: RevNameBuf = curr.clone().into();
        nsec_remove(curr_revnamebuf.as_ref(), &next, iss);

        // Remove all signatures.
        for rtype in nsec.types().iter() {
            let curr_revnamebuf: RevNameBuf = curr.clone().into();
            let key = (curr_revnamebuf.as_ref(), rtype);
            iss.rrsigs.remove(&key);
        }
    }
}

fn nsec_clear_occluded(
    name: &Name<Bytes>,
    iss: &mut IncrementalSigningState,
) -> Result<(), SignerError> {
    let name_revnamebuf = old_base_name_to_revnamebuf(name);
    let name_boxrevname = name_revnamebuf.unsized_copy_into();
    let key = (name_boxrevname, NewRtype::SOA);
    let range = iss.data.range(key..);
    let mut opt_curr_name: Option<Name<Bytes>> = None;
    let mut curr_types: HashSet<Rtype> = HashSet::new();
    let mut work = vec![];

    // Keep track of delegations. Name below a delegation remain occluded.
    let mut delegation: Option<Name<Bytes>> = None;

    for ((key_name, key_rtype), _) in range {
        // There is no easy way to avoid name showing up in the range. Just
        // filter out name.
        if key_name.as_ref() == name_revnamebuf.as_ref() {
            continue;
        }

        // Make sure curr_name is below name.
        let old_key_name = revname_to_old_base_name(key_name);
        if !old_key_name.ends_with(name) {
            break;
        }
        if let Some(d) = &delegation
            && old_key_name.ends_with(d)
            && old_key_name != d
        {
            // Skip.
            continue;
        }

        if *key_rtype == NewRtype::NS {
            // Set key_name as a delegation.
            delegation = Some(old_key_name.clone());
        }
        if let Some(curr_name) = &opt_curr_name {
            if old_key_name == curr_name {
                curr_types.insert(new_base_rtype_to_old_base(*key_rtype));
            } else {
                work.push((curr_name.clone(), curr_types));
                opt_curr_name = Some(old_key_name);
                curr_types = [new_base_rtype_to_old_base(*key_rtype)].into();
            }
        } else {
            opt_curr_name = Some(old_key_name);
            curr_types.insert(new_base_rtype_to_old_base(*key_rtype));
        }
    }
    if let Some(curr_name) = opt_curr_name {
        work.push((curr_name.clone(), curr_types));
    }
    for (curr_name, curr_types) in work {
        let mut curr_types = if curr_types.contains(&Rtype::NS) {
            let has_ds = curr_types.contains(&Rtype::DS);
            let mut curr_types: HashSet<Rtype> = [Rtype::NS].into();
            if has_ds {
                curr_types.insert(Rtype::DS);
            }
            curr_types
        } else {
            curr_types
        };
        let rtypebitmap = nsec_rtypebitmap_from_iterator(curr_types.iter());

        // Make sure NS doesn't get signed.
        curr_types.remove(&Rtype::NS);
        let new_curr_types = curr_types
            .iter()
            .map(|r| old_base_rtype_to_new_base(*r))
            .collect();
        sign_rtype_set(&curr_name, &new_curr_types, iss)?;
        let curr_revnamebuf = old_base_name_to_revnamebuf(curr_name);
        nsec_insert(&curr_revnamebuf, rtypebitmap, iss);
    }
    Ok(())
}

fn nsec_rtypebitmap_from_iterator<'a, I>(iter: I) -> RtypeBitmap<Bytes>
where
    I: Iterator<Item = &'a Rtype>,
{
    let mut rtypebitmap = RtypeBitmap::<Bytes>::builder();
    rtypebitmap.add(Rtype::NSEC).expect("should not fail");
    rtypebitmap.add(Rtype::RRSIG).expect("should not fail");
    for rtype in iter {
        rtypebitmap.add(*rtype).expect("should not fail");
    }
    rtypebitmap.finalize()
}

fn nsec3_update(
    owner: &RevName,
    nsec3_record: &RegularRecord,
    nsec3: &NewNsec3,
    rtypes: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) {
    // Just update an NSEC3 record without further logic.
    let rtypebitmap = nsec3_rtypebitmap_from_iterator(rtypes.iter());
    let old_nsec3param = new_base_nsec3param_to_old_base(&iss.nsec3param);
    let nsec3 = Nsec3::new(
        old_nsec3param.hash_algorithm(),
        old_nsec3param.flags(),
        old_nsec3param.iterations(),
        old_nsec3param.salt().clone(),
        new_base_bytes_to_old_base_ownerhash(nsec3.next_owner()),
        rtypebitmap,
    );
    let old_owner = revname_to_old_base_name(owner);
    let record = RecordFullCmp::new(
        old_owner.clone(),
        new_base_class_to_old_base(nsec3_record.class()),
        new_base_ttl_to_old_base(nsec3_record.ttl()),
        ZoneRecordData::Nsec3(nsec3),
    );
    iss.nsec3s.insert_new_record(record.into());
}

fn nsec3_remove_full(
    name: &Name<Bytes>,
    nsec3_name: &RevName,
    nsec3_next: &SizePrefixed<u8, [u8]>,
    iss: &mut IncrementalSigningState,
) {
    nsec3_remove_one(nsec3_name, nsec3_next, iss);

    // Assume that we never remove the apex. So the parent always exists.
    let name = name.parent().expect("should exist");
    nsec3_remove_et(&name, iss);
}

fn nsec3_remove_et(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Check if name is an ET. If so remove it and see if the parent is
    // also an ET.
    //
    // Take a simple approach to check if a name is an ET: first lookup
    // the NSEC3 record for name and check that the bitmap is empty. Then
    // check all descendent names and check that none of them has an
    // NSEC3 record.
    let mut name = name.clone();
    loop {
        if !name.ends_with(&iss.origin) {
            // This is weird, we should never be able to get beyond apex.
            // Just ignore this.
            return;
        }
        if name == iss.origin {
            // Never remove the NSEC3 record for apex.
            return;
        }

        let (_, nsec3_name) = nsec3_hash_parts(&name, iss);
        let nsec3_revnamebuf = old_base_name_to_revnamebuf(&nsec3_name);

        let Some(record_nsec3) = iss.nsec3s.get(&nsec3_revnamebuf) else {
            // No NSEC3 record, nothing to do.
            return;
        };
        let record_nsec3 = record_nsec3.clone();

        let NewRecordData::Nsec3(nsec3) = record_nsec3.data() else {
            panic!("NSEC3 record expected");
        };

        if !nsec3.types().is_empty() {
            // There are types here.
            return;
        }

        // Check the descendents.
        let name_revnamebuf = old_base_name_to_revnamebuf(&name);
        let name_boxrevname = name_revnamebuf.unsized_copy_into();
        let key = (name_boxrevname, NewRtype::SOA);
        let range = iss.data.range(key..);
        let mut opt_curr_name: Option<Name<Bytes>> = None;

        for ((key_name, _), _) in range {
            // There is no easy way to avoid name showing up in the range. Just
            // filter out name.
            if key_name.as_ref() == name_revnamebuf.as_ref() {
                continue;
            }

            // Make sure curr_name is below name.
            let old_key_name = revname_to_old_base_name(key_name);
            if !old_key_name.ends_with(&name) {
                break;
            }

            if let Some(curr_name) = &opt_curr_name
                && old_key_name == curr_name
            {
                // Already checked.
                continue;
            }

            opt_curr_name = Some(old_key_name.clone());

            let (_, nsec3_name) = nsec3_hash_parts(&old_key_name, iss);
            let nsec3_revnamebuf = old_base_name_to_revnamebuf(&nsec3_name);

            if iss.nsec3s.contains_key(&nsec3_revnamebuf) {
                // NSEC3 record is found. Our target is not an ET.
                return;
            };
        }

        // No descendents with NSEC3 records are found. Delete this one.
        let next_owner = nsec3.next_owner();
        nsec3_remove_one(&nsec3_revnamebuf, next_owner, iss);

        // We remove the NSEC3 record for the name. Get the parent. We should
        // be below apex, so the parent has to exist.
        name = name.parent().expect("parent should exist");
    }
}

fn nsec3_remove_one(
    nsec3_name: &RevName,
    nsec3_next: &SizePrefixed<u8, [u8]>,
    iss: &mut IncrementalSigningState,
) {
    // Try to find the NSEC3 record that comes before the one we are trying
    // to remove.
    let nsec3_boxrevname: Box<RevName> = nsec3_name.unsized_copy_into();
    let mut range = iss.nsec3s.range(..nsec3_boxrevname.clone());
    let (previous_name, previous_record) = if let Some(kv) = range.next_back() {
        kv
    } else {
        let mut range = iss.nsec3s.range(nsec3_boxrevname..);
        range
            .next_back()
            .expect("at least one element should exist")
    };

    let previous_record = previous_record.clone();
    let NewRecordData::Nsec3(previous_nsec) = previous_record.data() else {
        panic!("NSEC3 record expected");
    };
    let previous_nsec3 = NewNsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt(),
        nsec3_next,
        previous_nsec.types(),
    );
    let previous_name_revnamebuf = RevNameBuf::copy_from(previous_name);
    let previous_record = RegularRecord::new(
        previous_name_revnamebuf.unsized_copy_into(),
        previous_record.class(),
        previous_record.ttl(),
        NewRecordData::<NameBuf>::Nsec3(previous_nsec3).into(),
    );
    iss.nsec3s.insert_new_record(previous_record);
    iss.nsec3s.remove(nsec3_name);
    let key = (nsec3_name, NewRtype::NSEC3);
    iss.rrsigs.remove(&key);
}

fn nsec3_set_occluded(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Loop over all names below name, if there is an NSEC3 record then
    // delete all signatures and the NSEC3 record.

    let name_revnamebuf = old_base_name_to_revnamebuf(name);
    let name_boxrevname = name_revnamebuf.unsized_copy_into();
    let key = (name_boxrevname, NewRtype::SOA);
    let range = iss.data.range(key..);
    let mut opt_curr_name: Option<Name<Bytes>> = None;
    let mut work = vec![];

    for ((key_name, _), _) in range {
        // There is no easy way to avoid name showing up in the range. Just
        // filter out name.
        if key_name.as_ref() == name_revnamebuf.as_ref() {
            continue;
        }

        // Make sure curr_name is below name.
        let old_key_name = revname_to_old_base_name(key_name);
        if !old_key_name.ends_with(name) {
            break;
        }

        if let Some(curr_name) = &opt_curr_name
            && old_key_name == curr_name
        {
            // Looked at this name already.
            continue;
        }

        opt_curr_name = Some(old_key_name.clone());

        let (_, nsec3_name) = nsec3_hash_parts(&old_key_name, iss);
        let nsec3_revnamebuf = old_base_name_to_revnamebuf(&nsec3_name);

        let Some(record_nsec3) = iss.nsec3s.get(&nsec3_revnamebuf) else {
            // No NSEC3 record, nothing to do.
            continue;
        };

        let NewRecordData::Nsec3(nsec3) = record_nsec3.data() else {
            panic!("NSEC3 record expected");
        };

        work.push((key_name.clone(), nsec3_name));

        // Remove all signatures.
        for rtype in nsec3.types().iter() {
            let key = (key_name.as_ref(), rtype);
            iss.rrsigs.remove(&key);
        }
    }
    for (key_name, nsec3_name) in work {
        let nsec3_revnamebuf = old_base_name_to_revnamebuf(&nsec3_name);
        let record_nsec3 = iss
            .nsec3s
            .get(&nsec3_revnamebuf)
            .expect("NSEC3 should exist")
            .clone();

        let NewRecordData::Nsec3(nsec3) = record_nsec3.data() else {
            panic!("NSEC3 record expected");
        };

        let nsec3_next = nsec3.next_owner();
        let nsec3_revnamebuf = old_base_name_to_revnamebuf(&nsec3_name);
        let old_key_name = revname_to_old_base_name(key_name.as_ref());
        nsec3_remove_full(&old_key_name, &nsec3_revnamebuf, nsec3_next, iss);
    }
}

fn nsec3_clear_occluded(
    name: &Name<Bytes>,
    iss: &mut IncrementalSigningState,
) -> Result<(), SignerError> {
    let name_revnamebuf = old_base_name_to_revnamebuf(name);
    let name_boxrevname = name_revnamebuf.unsized_copy_into();
    let key = (name_boxrevname, NewRtype::SOA);
    let range = iss.data.range(key..);
    let mut opt_curr_name: Option<Name<Bytes>> = None;
    let mut curr_types: HashSet<Rtype> = HashSet::new();
    let mut work = vec![];

    // Keep track of delegations. Name below a delegation remain occluded.
    let mut delegation: Option<Name<Bytes>> = None;

    for ((key_name, key_rtype), _) in range {
        // There is no easy way to avoid name showing up in the range. Just
        // filter out name.
        if key_name.as_ref() == name_revnamebuf.as_ref() {
            continue;
        }

        // Make sure curr_name is below name.
        let old_key_name = revname_to_old_base_name(key_name);
        if !old_key_name.ends_with(name) {
            break;
        }
        if let Some(d) = &delegation
            && old_key_name.ends_with(d)
            && old_key_name != d
        {
            // Skip.
            continue;
        }

        if *key_rtype == NewRtype::NS {
            // Set key_name as a delegation.
            delegation = Some(old_key_name.clone());
        }
        if let Some(curr_name) = &opt_curr_name {
            if old_key_name == curr_name {
                curr_types.insert(new_base_rtype_to_old_base(*key_rtype));
            } else {
                work.push((curr_name.clone(), curr_types));
                opt_curr_name = Some(old_key_name);
                curr_types = [new_base_rtype_to_old_base(*key_rtype)].into();
            }
        } else {
            opt_curr_name = Some(old_key_name);
            curr_types.insert(new_base_rtype_to_old_base(*key_rtype));
        }
    }
    if let Some(curr_name) = opt_curr_name {
        work.push((curr_name.clone(), curr_types));
    }
    for (curr_name, mut curr_types) in work {
        let mut curr_types = if curr_types.contains(&Rtype::NS) {
            let has_ds = curr_types.contains(&Rtype::DS);
            let mut curr_types: HashSet<Rtype> = [Rtype::NS].into();
            if has_ds {
                curr_types.insert(Rtype::DS);
                curr_types.insert(Rtype::RRSIG);
            }
            curr_types
        } else {
            curr_types.insert(Rtype::RRSIG);
            curr_types
        };
        let rtypebitmap = nsec3_rtypebitmap_from_iterator(curr_types.iter());

        // Make sure NS doesn't get signed. And avoid signing RRSIGs.
        curr_types.remove(&Rtype::NS);
        curr_types.remove(&Rtype::RRSIG);
        let new_curr_types = curr_types
            .iter()
            .map(|r| old_base_rtype_to_new_base(*r))
            .collect();
        sign_rtype_set(&curr_name, &new_curr_types, iss)?;

        let (nsec3_hash_octets, nsec3_name) = nsec3_hash_parts(&curr_name, iss);
        let nsec3_revnamebuf = old_base_name_to_revnamebuf(&nsec3_name);
        nsec3_insert_full(
            &curr_name,
            nsec3_hash_octets,
            &nsec3_revnamebuf,
            rtypebitmap,
            iss,
        );
    }
    Ok(())
}

fn nsec3_insert_full(
    name: &Name<Bytes>,
    nsec3_hash: OwnerHash<Bytes>,
    nsec3_name: &RevName,
    rtypebitmap: RtypeBitmap<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    nsec3_insert_one(nsec3_hash, nsec3_name, rtypebitmap, iss);

    // Assume that we never insert the apex. So the parent always exists.
    let name = name.parent().expect("should exist");
    nsec3_insert_ent(&name, iss);
}

fn nsec3_insert_ent(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Check if name has an NSEC3 record. If so, we are done. Otherwise,
    // insert an ENT and continue with the parent.
    let mut name = name.clone();
    loop {
        if !name.ends_with(&iss.origin) {
            // This is weird, we should never be able to get beyond apex.
            // Just ignore this.
            return;
        }
        if name == iss.origin {
            // apex exists by definition.
            return;
        }

        let (nsec3_hash_octets, nsec3_name) = nsec3_hash_parts(&name, iss);

        let nsec3_revnamebuf = old_base_name_to_revnamebuf(&nsec3_name);
        if iss.nsec3s.contains_key(&nsec3_revnamebuf) {
            // Found something. We are done.
            return;
        }

        let rtypebitmap = RtypeBitmap::<Bytes>::builder();
        let rtypebitmap = rtypebitmap.finalize();
        nsec3_insert_one(nsec3_hash_octets, &nsec3_revnamebuf, rtypebitmap, iss);

        // Get the parent. We should be below apex, so the parent has to exist.
        name = name.parent().expect("parent should exist");
    }
}

fn nsec3_insert_one(
    nsec3_hash: OwnerHash<Bytes>,
    nsec3_name: &RevName,
    rtypebitmap: RtypeBitmap<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    // Try to find the NSEC3 record that comes before the one we are trying
    // to insert. It is possible that we try to insert before the first NSEC3
    // record. In that case, logically try to insert after the last NSEC3
    // record.
    let nsec3_boxrevname: Box<RevName> = nsec3_name.unsized_copy_into();
    let mut range = iss.nsec3s.range(..nsec3_boxrevname.clone());
    let (previous_name, previous_record) = if let Some(kv) = range.next_back() {
        kv
    } else {
        let mut range = iss.nsec3s.range(nsec3_boxrevname..);
        range
            .next_back()
            .expect("at least one element should exist")
    };
    let previous_name_revnamebuf = RevNameBuf::copy_from(previous_name);
    let previous_record = previous_record.clone();
    let NewRecordData::Nsec3(previous_nsec3) = previous_record.data() else {
        panic!("NSEC3 record expected");
    };
    let next = previous_nsec3.next_owner();
    let old_nsec3param = new_base_nsec3param_to_old_base(&iss.nsec3param);
    let new_nsec3 = Nsec3::new(
        old_nsec3param.hash_algorithm(),
        old_nsec3param.flags(),
        old_nsec3param.iterations(),
        old_nsec3param.salt().clone(),
        new_base_bytes_to_old_base_ownerhash(next),
        rtypebitmap,
    );
    let old_nsec3_name = revname_to_old_base_name(nsec3_name);
    let new_record = RecordFullCmp::new(
        old_nsec3_name.clone(),
        new_base_class_to_old_base(previous_record.class()),
        new_base_ttl_to_old_base(previous_record.ttl()),
        ZoneRecordData::Nsec3(new_nsec3),
    );
    iss.nsec3s.insert_new_record(new_record.into());
    let new_nsec3_hash = ownerhash_to_new_base_bytes(nsec3_hash);
    let previous_nsec3 = NewNsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt(),
        new_nsec3_hash.as_ref(),
        previous_nsec3.types(),
    );
    let previous_record = RegularRecord::new(
        previous_name_revnamebuf.unsized_copy_into(),
        previous_record.class(),
        previous_record.ttl(),
        NewRecordData::<NameBuf>::Nsec3(previous_nsec3).into(),
    );
    iss.nsec3s.insert_new_record(previous_record);
}

// Return the effective result HashSet even when the NSEC3 record gets deleted.
fn nsec3_update_bitmap(
    name: &Name<Bytes>,
    nsec3_record: &RegularRecord,
    nsec3: &NewNsec3,
    curr: &HashSet<NewRtype>,
    add: &HashSet<NewRtype>,
    delete: &HashSet<NewRtype>,
    iss: &mut IncrementalSigningState,
) -> HashSet<NewRtype> {
    // Update curr.
    let curr: HashSet<_> = curr.union(add).copied().collect();
    let mut curr: HashSet<_> = curr.difference(delete).copied().collect();
    let owner = nsec3_record.owner();

    // Check if we need to add or remove RRSIG. Assume that apex has a SOA
    // record.
    if curr.contains(&NewRtype::NS) && !curr.contains(&NewRtype::SOA) {
        // For an NS not at origin, there is an RRSIG if there is also a
        // DS record.
        if curr.contains(&NewRtype::DS) {
            // Yes, add RRSIG.
            curr.insert(NewRtype::RRSIG);
        } else {
            // No. Remove RRSIG.
            curr.remove(&NewRtype::RRSIG);
        }
    } else {
        // Is there anything apart from RRSIG?
        if curr.iter().any(|r| *r != NewRtype::RRSIG) {
            // Yes. Add RRSIG.
            curr.insert(NewRtype::RRSIG);
        } else {
            // No. Remove RRSIG.
            curr.remove(&NewRtype::RRSIG);
        }
    }

    let old_curr: HashSet<_> = curr
        .iter()
        .map(|r| new_base_rtype_to_old_base(*r))
        .collect();
    if curr.is_empty() {
        // The NSEC3 bitmp will be empty, but this may now have become an
        // empty non-terminal. Our only option is to update the NSEC3 record
        // and then call nsec3_remove_et to see if it is empty can can be
        // removed.
        nsec3_update(owner, nsec3_record, nsec3, &old_curr, iss);
        nsec3_remove_et(name, iss);
        return curr;
    }

    if iss.nsec3param.opt_out_flag() && !curr.iter().any(|r| *r != NewRtype::NS) {
        // The new bitmap has nothing except for NS. We would like to delete
        // the NSEC3. However there may still be descendents that need to be
        // removed with nsec3_set_occluded. Update this NSEC3 to be empty and
        // call nsec3_remove_et to remove it if there are no descendents.

        let empty_curr = HashSet::new();
        nsec3_update(owner, nsec3_record, nsec3, &empty_curr, iss);
        nsec3_remove_et(name, iss);
        return curr;
    }

    nsec3_update(owner, nsec3_record, nsec3, &old_curr, iss);
    curr
}

fn nsec3_rtypebitmap_from_iterator<'a, I>(iter: I) -> RtypeBitmap<Bytes>
where
    I: Iterator<Item = &'a Rtype>,
{
    let mut rtypebitmap = RtypeBitmap::<Bytes>::builder();
    for rtype in iter {
        rtypebitmap.add(*rtype).expect("should not fail");
    }
    rtypebitmap.finalize()
}

fn nsec3_hash_parts(
    name: &Name<Bytes>,
    iss: &IncrementalSigningState,
) -> (OwnerHash<Bytes>, Name<Bytes>) {
    let old_nsec3param = new_base_nsec3param_to_old_base(&iss.nsec3param);
    let nsec3_hash_octets = OwnerHash::<Bytes>::octets_from(
        nsec3_hash::<_, _, BytesMut>(
            name,
            old_nsec3param.hash_algorithm(),
            old_nsec3param.iterations(),
            old_nsec3param.salt(),
        )
        .expect("should not fail"),
    );
    let nsec3_hash_base32 = base32::encode_string_hex(&nsec3_hash_octets).to_ascii_lowercase();
    let mut builder = NameBuilder::<BytesMut>::new();
    builder
        .append_label(nsec3_hash_base32.as_bytes())
        .expect("should not fail");
    let nsec3_name = builder.append_origin(&iss.origin).expect("should not fail");
    (nsec3_hash_octets, nsec3_name)
}

fn is_occluded(name: &Name<Bytes>, iss: &IncrementalSigningState) -> bool {
    // We need to check if the parent of name is a delegation. Stop
    // when we reached origin.
    let mut curr = name.clone();
    loop {
        let Some(parent) = curr.parent() else {
            // We asked for the parent of the root. That is weird. Just
            // return not occluded.
            return false;
        };
        curr = parent;

        if curr == iss.origin {
            // We reached apex. The name was not occluded.
            return false;
        }
        if !curr.ends_with(&iss.origin) {
            // Something weird is going on. Return not occluded.
            return false;
        }
        let curr_revnamebuf = old_base_name_to_revnamebuf(&curr);
        let curr_boxrevname = curr_revnamebuf.unsized_copy_into();
        if iss.data.contains_key(&(curr_boxrevname, NewRtype::NS)) {
            // Name is occluded.
            return true;
        }
    }
}

fn sign_rtype_set(
    name: &Name<Bytes>,
    set: &HashSet<NewRtype>,
    iss: &mut IncrementalSigningState,
) -> Result<(), SignerError> {
    let mut new_sigs = vec![];
    for rtype in set {
        let key_revnamebuf = old_base_name_to_revnamebuf(name);
        let key_boxrevname = key_revnamebuf.unsized_copy_into();
        let key = (key_boxrevname, *rtype);
        let Some(records) = (if *name == iss.origin {
            iss.new_apex
                .get(&key.1)
                .map(|v| v.iter().map(|r| (*r).clone().into()).collect::<Vec<_>>())
        } else {
            iss.data
                .get(&key)
                .map(|v| v.iter().map(|r| (*r).clone().into()).collect::<Vec<_>>())
        }) else {
            panic!("Expected something for {name}/{rtype}");
        };
        sign_records(
            &iss.origin,
            &records,
            &iss.keys,
            iss.inception,
            iss.expiration,
            &mut new_sigs,
        )?;
    }
    for sigs in new_sigs {
        iss.rrsigs.replace_with_new_records(sigs);
    }
    Ok(())
}

//------------ RecordFullCmp -------------------------------------------------
/// A wrapper around Record where compare and equal also take the TTL into
/// account.
#[derive(Debug)]
struct RecordFullCmp<Name, Data>(Record<Name, Data>);

impl<Name, Data> RecordFullCmp<Name, Data> {
    fn new(owner: Name, class: Class, ttl: Ttl, data: Data) -> Self {
        Self(Record::new(owner, class, ttl, data))
    }

    fn class(&self) -> Class {
        self.0.class()
    }

    fn data(&self) -> &Data {
        self.0.data()
    }

    fn owner(&self) -> &Name {
        self.0.owner()
    }

    fn ttl(&self) -> Ttl {
        self.0.ttl()
    }

    fn to_record(&self) -> &Record<Name, Data> {
        &self.0
    }

    fn into_record(self) -> Record<Name, Data> {
        self.0
    }
}

impl<Name, Data> RecordFullCmp<Name, Data>
where
    Data: RecordData,
{
    fn rtype(&self) -> Rtype {
        self.0.rtype()
    }
}

//--- PartialEq and Eq

impl<N, NN, D, DD> PartialEq<RecordFullCmp<NN, DD>> for RecordFullCmp<N, D>
where
    N: PartialEq<NN>,
    D: RecordData + PartialEq<DD>,
    DD: RecordData,
{
    fn eq(&self, other: &RecordFullCmp<NN, DD>) -> bool {
        self.owner() == other.owner()
            && self.class() == other.class()
            && self.ttl() == other.ttl()
            && self.data() == other.data()
    }
}

impl<N: Eq, D: RecordData + Eq> Eq for RecordFullCmp<N, D> {}

impl<N, NN, D, DD> CanonicalOrd<RecordFullCmp<NN, DD>> for RecordFullCmp<N, D>
where
    N: ToName,
    NN: ToName,
    D: RecordData + CanonicalOrd<DD>,
    DD: RecordData,
{
    fn canonical_cmp(&self, other: &RecordFullCmp<NN, DD>) -> Ordering {
        self.0.canonical_cmp(&other.0)
    }
}

//--- Hash

impl<Name, Data> hash::Hash for RecordFullCmp<Name, Data>
where
    Name: hash::Hash,
    Data: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<N: ToName, D: RecordData + ComposeRecordData> RecordFullCmp<N, D> {
    /* Currently unused.
    pub fn compose<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
    self.0.compose(target)
    }
    */

    pub fn compose_canonical<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.0.compose_canonical(target)
    }
}

//--- AsRef

impl<N, D> AsRef<RecordFullCmp<N, D>> for RecordFullCmp<N, D> {
    fn as_ref(&self) -> &RecordFullCmp<N, D> {
        self
    }
}

impl<Name, TName, Data, TData> FlattenInto<RecordFullCmp<TName, TData>>
    for RecordFullCmp<Name, Data>
where
    Name: FlattenInto<TName>,
    Data: FlattenInto<TData, AppendError = Name::AppendError>,
{
    type AppendError = Name::AppendError;

    fn try_flatten_into(self) -> Result<RecordFullCmp<TName, TData>, Name::AppendError> {
        Ok(RecordFullCmp(self.0.try_flatten_into()?))
    }
}

impl<Name, Data> Clone for RecordFullCmp<Name, Data>
where
    Name: Clone,
    Data: Clone,
{
    fn clone(&self) -> Self {
        RecordFullCmp(self.0.clone())
    }
}

// Do not implement
// impl<Name, Data> From<RecordFullCmp<Name, Data>> for Record<Name, Data>
// this may unexpectedly change RecordFullCmp into Record. Use
// into_record instead.

impl From<RecordFullCmp<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>> for SoaRecord {
    fn from(source: RecordFullCmp<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>) -> Self {
        source.0.into()
    }
}

impl From<RecordFullCmp<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>> for RegularRecord {
    fn from(source: RecordFullCmp<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>) -> Self {
        source.0.into()
    }
}

impl<Name, Data> From<Record<Name, Data>> for RecordFullCmp<Name, Data> {
    fn from(source: Record<Name, Data>) -> Self {
        Self(source)
    }
}

impl From<RegularRecord> for RecordFullCmp<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>> {
    fn from(source: RegularRecord) -> Self {
        Self(source.into())
    }
}

impl From<SoaRecord> for RecordFullCmp<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>> {
    fn from(source: SoaRecord) -> Self {
        Self(source.into())
    }
}

/// Turn an old base Name into a RevName.
// TODO: add to domain.
fn old_base_name_to_revnamebuf(name: impl ToName) -> RevNameBuf {
    let mut buf = vec![];
    name.compose(&mut buf).expect("should not fail");
    RevNameBuf::parse_bytes(&buf).expect("RevNameBuf can parse ToName")
}

/*
/// Turn an old base Name into a Name.
// TODO: add to domain.
fn old_base_name_to_namebuf(name: impl ToName) -> NameBuf {
    let mut buf = vec![];
    name.compose(&mut buf).expect("should not fail");
    NameBuf::parse_bytes(&buf).expect("NameBuf can parse ToName")
}
*/

/// Turn a RevName into an old base Name.
// TODO: add to domain.
fn revname_to_old_base_name(revname: &RevName) -> Name<Bytes> {
    let revnamebuf = RevNameBuf::copy_from(revname);
    let namebuf: NameBuf = revnamebuf.into();
    let buf = namebuf.as_bytes().to_vec();
    Name::<Bytes>::from_octets(buf.into()).expect("Name<Bytes> should be able to accept RevName")
}

/// Turn a Name into an old base Name.
// TODO: add to domain.
fn name_to_old_base_name(name: &NewName) -> Name<Bytes> {
    let namebuf = NameBuf::copy_from(name);
    let buf = namebuf.as_bytes().to_vec();
    Name::<Bytes>::from_octets(buf.into()).expect("Name<Bytes> should be able to accept Name")
}

/// Turn an old base Rtype into a new base Rtype.
// TODO: add to domain.
fn old_base_rtype_to_new_base(rtype: Rtype) -> NewRtype {
    rtype.to_int().into()
}

/// Turn a new base Rtype into an old base Rtype.
// TODO: add to domain.
fn new_base_rtype_to_old_base(rtype: NewRtype) -> Rtype {
    let v: u16 = rtype.into();
    v.into()
}

/// Turn a new base Class into an old base Class.
// TODO: add to domain.
fn new_base_class_to_old_base(class: NewClass) -> Class {
    let v: u16 = class.code.into();
    v.into()
}

/// Turn a new base Ttl into an old base Ttl.
// TODO: add to domain.
fn new_base_ttl_to_old_base(ttl: NewTtl) -> Ttl {
    let v: u32 = ttl.into();
    Ttl::from_secs(v)
}

fn old_base_nsec3param_to_new_base<Oct>(nsec3param: &Nsec3param<Oct>) -> Box<NewNsec3Param>
where
    Oct: AsRef<[u8]>,
{
    let mut buf = vec![];
    nsec3param.compose_rdata(&mut buf).expect("should not fail");
    let new_nsec3param = NewNsec3Param::parse_bytes_by_ref(&buf)
        .expect("should be able to parse old base Nsec3Param");
    let nsec3param_box: Box<NewNsec3Param> = new_nsec3param.unsized_copy_into();
    nsec3param_box
}

fn new_base_nsec3param_to_old_base(nsec3param: &NewNsec3Param) -> Nsec3param<Bytes> {
    let bytes = nsec3param.as_bytes().to_vec();
    let mut parser = Parser::from_ref(&bytes);
    let old_nsec3param = Nsec3param::parse(&mut parser)
        .expect("old base Nsec3param should be able to parse new base Nsec3Param");
    assert!(parser.remaining() == 0);
    let old_nsec3param = Nsec3param::<Vec<u8>>::octets_from(old_nsec3param);
    Nsec3param::<Bytes>::octets_from(old_nsec3param)
}

fn new_base_bytes_to_old_base_ownerhash(owner: &SizePrefixed<u8, [u8]>) -> OwnerHash<Bytes> {
    // There is no parse for OwnerHash. Hack around it be just dropping the
    // first byte of the slice. This is the length byte.
    let bytes = &owner.as_bytes()[1..];
    let old_ownerhash =
        OwnerHash::from_octets(bytes).expect("OwnerHash should accept new base bytes");
    let old_ownerhash = OwnerHash::<Vec<u8>>::octets_from(old_ownerhash);
    OwnerHash::<Bytes>::octets_from(old_ownerhash)
}

fn ownerhash_to_new_base_bytes<Octs>(ownerhash: OwnerHash<Octs>) -> Box<SizePrefixed<u8, [u8]>>
where
    Octs: AsRef<[u8]>,
{
    let bytes = ownerhash.as_slice();

    // Assume that OwnerHash limits the length to something that fits in a u8.
    let mut vec = vec![bytes.len() as u8];
    vec.extend_from_slice(bytes);
    let sp_box = Vec::into_boxed_slice(vec);
    SizePrefixed::parse_bytes_in(sp_box).expect("Should not fail")
}
