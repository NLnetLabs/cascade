//! Incremental signing.

use core::ops::RangeBounds;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet, btree_map, hash_map, hash_set};
use std::hash;
use std::sync::{Arc, RwLock};
use std::time::{Duration, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use cascade_zonedata::{
    LoadedZoneReader, OldParsedRecord, RegularRecord, SignedZonePatcher, SignedZoneReader,
    SoaRecord,
};
use domain::base::RecordData;
use domain::base::Serial;
use domain::base::iana::{Class, ZonemdAlgorithm, ZonemdScheme};
use domain::base::name::FlattenInto;
use domain::base::rdata::ComposeRecordData;
use domain::base::wire::Composer;
use domain::base::{
    CanonicalOrd, Name, NameBuilder, Record, Rtype, Serial as DomainSerial, ToName, Ttl,
};
use domain::dep::octseq::OctetsFrom;
use domain::dep::octseq::builder::with_infallible;
use domain::dnssec::common::nsec3_hash;
use domain::dnssec::sign::denial::nsec::{GenerateNsecConfig, generate_nsecs};
use domain::dnssec::sign::denial::nsec3::{
    GenerateNsec3Config, Nsec3ParamTtlMode, generate_nsec3s,
};
use domain::dnssec::sign::keys::SigningKey;
use domain::dnssec::sign::keys::keyset::{KeyType, UnixTime};
use domain::dnssec::sign::records::{DefaultSorter, RecordsIter, Rrset};
use domain::dnssec::sign::signatures::rrsigs::sign_rrset;
use domain::new::base::RType as NewRtype;
use domain::new::base::name::{NameBuf, RevName, RevNameBuf};
use domain::new::base::parse::ParseBytes;
use domain::new::rdata::RecordData as NewRecordData;
use domain::rdata::dnssec::{RtypeBitmap, Timestamp};
use domain::rdata::nsec3::OwnerHash;
use domain::rdata::{Nsec, Nsec3, Nsec3param, Soa, ZoneRecordData, Zonemd};
use domain::utils::base32;
use domain::zonefile::inplace::Entry;
use domain::zonetree::StoredRecord;
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
use crate::signer::status::SigningStatusPerZone;
use crate::units::key_manager::mk_dnst_keyset_state_file_path;
use crate::units::zone_signer::{
    KeyPair, KeySetState, MinTimestamp, PassThroughMode, SignerError, ZoneSigner, faketime_or_now,
    load_keys,
};
use crate::zone::{HistoricalEvent, Zone};

pub fn sign_incrementally(
    zone_signer: &ZoneSigner,
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

    let mut iss = IncrementalSigningState::new(
        origin.clone(),
        &policy,
        zone_signer,
        center,
        &ws.keyset_state,
        status,
    )?;

    let start = Instant::now();
    let patch_curr = ws.patch.curr();
    iss.load_signed_zone(&patch_curr)?;
    debug!("loading signed zone took {:?}", start.elapsed());

    ws.handle_nsec_nsec3(&mut iss)?;

    if load_unsigned {
        let start = Instant::now();
        iss.load_unsigned_zone(&ws.patch.next_loaded().expect("should be there"))?;
        debug!("loading new unsigned zone took {:?}", start.elapsed());
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
type RtypeSet = HashSet<Rtype>;
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

        let total_signatures = iss.rrsigs.len();

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
                let old_rtype = new_base_rtype_to_old_base_rtype(*rtype);
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

            let key = (*owner, **rtype);
            let old_key = (
                revname_to_old_base_name(owner),
                new_base_rtype_to_old_base_rtype(**rtype),
            );
            if **rtype == NewRtype::NSEC {
                let record = iss.nsecs.get(&old_key.0).expect("NSEC record should exist");
                let records = [record.clone()];
                sign_records(
                    &iss.origin,
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else if **rtype == NewRtype::NSEC3 {
                let record = iss
                    .nsec3s
                    .get(&old_key.0)
                    .expect("NSEC3 record should exist");
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
                    iss.new_apex.get(&old_key.1)
                } else {
                    iss.new_data.get(&old_key)
                }
                .expect("records should exist");
                sign_records(
                    &iss.origin,
                    records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            };
        }

        for sigs in new_sigs {
            iss.rrsigs.insert_new_records(sigs);
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

                let key = (owner, *rtype);
                let old_key = (
                    revname_to_old_base_name(owner),
                    new_base_rtype_to_old_base_rtype(*rtype),
                );
                if *rtype == NewRtype::NSEC {
                    let record = iss.nsecs.get(&old_key.0).expect("NSEC record should exist");
                    let records = [record.clone()];
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
                        .get(&old_key.0)
                        .expect("NSEC3 record should exist");
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
                        iss.new_apex.get(&old_key.1)
                    } else {
                        iss.new_data.get(&old_key)
                    }
                    .expect("records should exist");
                    sign_records(
                        &iss.origin,
                        records,
                        &iss.keys,
                        iss.inception,
                        iss.expiration,
                        &mut new_sigs,
                    )?;
                };
            }

            for sigs in new_sigs {
                iss.rrsigs.insert_new_records(sigs);
            }

            // Clear key_roll.
            self.local_state.key_roll = None;
            return Ok(());
        }

        let total_signatures = iss.rrsigs.len();

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

            let key = (*owner, **rtype);
            let old_key = (
                revname_to_old_base_name(owner),
                new_base_rtype_to_old_base_rtype(**rtype),
            );
            if **rtype == NewRtype::NSEC {
                let record = iss.nsecs.get(&old_key.0).expect("NSEC record should exist");
                let records = [record.clone()];
                sign_records(
                    &iss.origin,
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else if **rtype == NewRtype::NSEC3 {
                let record = iss
                    .nsec3s
                    .get(&old_key.0)
                    .expect("NSEC3 record should exist");
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
                    iss.new_apex.get(&old_key.1)
                } else {
                    iss.new_data.get(&old_key)
                }
                .expect("records should exist");
                sign_records(
                    &iss.origin,
                    records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            };
        }

        for sigs in new_sigs {
            iss.rrsigs.insert_new_records(sigs);
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
            Rtype::DNSKEY,
            Rtype::CDS,
            Rtype::CDNSKEY,
            Rtype::NSEC3PARAM,
            Rtype::ZONEMD,
        ]);

        // For signing_rtypes diff against old_apex_saved. For all other
        // types diff against new_apex_saved. Ignore the diff against
        // new_apex_saved; that is currently not supported in the zone store.

        // apex records that were deleted.
        for (k, old_rrs) in &iss.old_apex_saved {
            if *k == Rtype::SOA {
                // Just remove the old SOA record. There should be only one,
                // just remove all if there is more than one.
                for r in old_rrs {
                    let r: SoaRecord = r.clone().into();
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
                let new_rrs: HashSet<&Zrd> = HashSet::from_iter(new_rrs.iter());
                for r in old_rrs {
                    if new_rrs.contains(r) {
                        continue;
                    }
                    let r: RegularRecord = r.clone().into();
                    self.patch.remove(r.clone()).map_err(|e| {
                        SignerError::PatchFailed(format!("unable to remove {r:?}: {e}"))
                    })?;
                }
            } else {
                for r in old_rrs {
                    let r: RegularRecord = r.clone().into();
                    self.patch.remove(r.clone()).map_err(|e| {
                        SignerError::PatchFailed(format!("unable to remove {r:?}: {e}"))
                    })?;
                }
            }
        }

        // apex records that were added.
        for (k, new_rrs) in &iss.new_apex {
            if *k == Rtype::SOA {
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
                let old_rrs: HashSet<&Zrd> = HashSet::from_iter(old_rrs.iter());
                for r in new_rrs {
                    if old_rrs.contains(r) {
                        continue;
                    }
                    let r: RegularRecord = r.clone().into();
                    self.patch.add(r.clone()).map_err(|e| {
                        SignerError::PatchFailed(format!("unable to add {r:?}: {e}"))
                    })?;
                }
            } else {
                for r in new_rrs {
                    let r: RegularRecord = r.clone().into();
                    self.patch.add(r.clone()).map_err(|e| {
                        SignerError::PatchFailed(format!("unable to add {r:?}: {e}"))
                    })?;
                }
            }
        }

        // Handle NSECs.
        for name in iss.nsecs.changes_iter() {
            if let Some(change) = iss.nsecs.get_change(name) {
                match change {
                    NsecChange::Original { .. } => unreachable!(),
                    NsecChange::Removed { old } => {
                        let old_nsec: RegularRecord = old.clone().into();
                        self.patch.remove(old_nsec.clone()).map_err(|e| {
                            SignerError::PatchFailed(format!("unable to remove {old_nsec:?}: {e}"))
                        })?;
                    }
                    NsecChange::Modified { old, new } => {
                        if old != new {
                            let old_nsec: RegularRecord = old.clone().into();
                            self.patch.remove(old_nsec.clone()).map_err(|e| {
                                SignerError::PatchFailed(format!(
                                    "unable to remove {old_nsec:?}: {e}"
                                ))
                            })?;
                            let new_nsec: RegularRecord = new.clone().into();
                            self.patch.add(new_nsec.clone()).map_err(|e| {
                                SignerError::PatchFailed(format!("unable to add {new_nsec:?}: {e}"))
                            })?;
                        }
                    }
                    NsecChange::New { new } => {
                        let new_nsec: RegularRecord = new.clone().into();
                        self.patch.add(new_nsec.clone()).map_err(|e| {
                            SignerError::PatchFailed(format!("unable to add {new_nsec:?}: {e}"))
                        })?;
                    }
                }
            }
        }

        // NSEC3 records that were deleted.
        for (k, old_nsec3) in &iss.old_nsec3s {
            if let Some(new_nsec3) = iss.nsec3s.get(k) {
                if new_nsec3 == old_nsec3 {
                    // No change.
                    continue;
                }
                let old_nsec3: RegularRecord = old_nsec3.clone().into();
                self.patch.remove(old_nsec3.clone()).map_err(|e| {
                    SignerError::PatchFailed(format!("unable to remove {old_nsec3:?}: {e}"))
                })?;
            } else {
                let old_nsec3: RegularRecord = old_nsec3.clone().into();
                self.patch.remove(old_nsec3.clone()).map_err(|e| {
                    SignerError::PatchFailed(format!("unable to remove {old_nsec3:?}: {e}"))
                })?;
            }
        }

        // NSEC3 records that were added.
        for (k, new_nsec3) in &iss.nsec3s {
            if let Some(old_nsec3) = iss.old_nsec3s.get(k) {
                if new_nsec3 == old_nsec3 {
                    // No change.
                    continue;
                }
                let new_nsec3: RegularRecord = new_nsec3.clone().into();
                self.patch.add(new_nsec3.clone()).map_err(|e| {
                    SignerError::PatchFailed(format!("unable to add {new_nsec3:?}: {e}"))
                })?;
            } else {
                let new_nsec3: RegularRecord = new_nsec3.clone().into();
                self.patch.add(new_nsec3.clone()).map_err(|e| {
                    SignerError::PatchFailed(format!("unable to add {new_nsec3:?}: {e}"))
                })?;
            }
        }

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
            .get(&Rtype::SOA)
            .expect("SOA record should be present");
        let ZoneRecordData::Soa(soa) = soa_records[0].data() else {
            panic!("SOA record expected");
        };

        let start = Instant::now();

        // Create a Vec with all records to be able to sort them in canonical
        // order. Ignore ZONEMD and RRSIGs of ZONEMD records.
        let mut all = vec![];

        all.extend(
            iss.new_apex
                .iter()
                .filter_map(|(t, r)| if *t != Rtype::ZONEMD { Some(r) } else { None })
                .flatten(),
        );

        all.extend(
            iss.new_data
                .iter()
                .filter_map(|((o, t), r)| {
                    if *o != iss.origin || *t != Rtype::ZONEMD {
                        Some(r)
                    } else {
                        None
                    }
                })
                .flatten(),
        );

        all.extend(iss.nsecs.values());

        all.extend(iss.nsec3s.values());

        let mut all_rrsigs: Vec<Zrd> = vec![];
        let new_origin = old_base_name_to_revnamebuf(&iss.origin);
        all_rrsigs.extend(
            iss.rrsigs
                .iter()
                .filter_map(|((o, t), r)| {
                    if *o != *new_origin.as_ref() || *t != NewRtype::ZONEMD {
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

        all.extend(all_rrsigs.iter());

        //all.sort_by(|e1, e2| CanonicalOrd::canonical_cmp(*e1, *e2));
        all.par_sort_by(|e1, e2| CanonicalOrd::canonical_cmp(*e1, *e2));

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
                soa_records[0].class(),
                soa_records[0].ttl(),
                ZoneRecordData::Zonemd(zonemd),
            );
            zonemd_records.push(record);
        }

        debug!("ZONEMD hash took {:?}", start.elapsed());

        let key = (iss.origin.clone(), Rtype::ZONEMD);
        let mut new_sigs = vec![];
        sign_records(
            &iss.origin,
            &zonemd_records,
            &iss.keys,
            iss.inception,
            iss.expiration,
            &mut new_sigs,
        )?;
        iss.new_apex.insert(key.1, zonemd_records);
        iss.rrsigs.insert_new_records(new_sigs[0].clone());
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
            let origin = old_base_name_to_revnamebuf(&iss.origin);
            let rtype = old_base_rtype_to_new_base_rtype(*t);
            let key = (origin, rtype);
            iss.new_apex.remove(t);
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

                if r.rtype() == Rtype::RRSIG {
                    let r: RegularRecord = r.into_record().into();
                    iss.rrsigs.add_new_record(r);
                } else {
                    let key = r.rtype();
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
                .get(&Rtype::NSEC3PARAM)
                .expect("NSEC3PARAM should be present");
            iss.new_apex
                .insert(Rtype::NSEC3PARAM, nsec3param_records.to_vec());
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
            let records = vec![record];
            iss.new_apex.insert(Rtype::ZONEMD, records);
        }

        // Update the SOA serial.
        let zone_soa_rr = &iss.new_apex.get(&Rtype::SOA).expect("SOA should exist")[0];
        let new_soa = self.update_soa_serial(zone_soa_rr)?;
        let new_rrset = vec![new_soa];
        iss.new_apex.insert(Rtype::SOA, new_rrset);

        Ok(())
    }

    pub fn new_nsec_nsec3_sigs(
        &self,
        iss: &mut IncrementalSigningState,
    ) -> Result<(), SignerError> {
        let mut new_sigs = vec![];
        if self.use_nsec3 {
            for m in &iss.modified_nsecs {
                let Some(nsec3) = iss.nsec3s.get(m) else {
                    panic!("NSEC3 for {m} should exist");
                };

                let nsec3 = nsec3.clone();
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
            for m in &iss.modified_nsecs {
                let Some(nsec) = iss.nsecs.get(m) else {
                    panic!("NSEC for {m} should exist");
                };

                let nsec = nsec.clone();
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
            iss.rrsigs.insert_new_records(sigs);
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
        let opt_nsec3param = iss.old_apex.get(&Rtype::NSEC3PARAM);
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
            let ZoneRecordData::Nsec3param(nsec3param) = nsec3param_records[0].data() else {
                panic!("ZoneRecordData::Nsec3param expected");
            };
            if *nsec3param != iss.nsec3param {
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
    old_apex: HashMap<Rtype, Vec<Zrd>>,

    /// Non-apex RRsets of the previously signed zone. With the exeception of
    /// NSEC, NSEC3 and RRSIG records.
    old_data: HashMap<(Name<Bytes>, Rtype), Vec<Zrd>>,

    /// Saved copy of old_apex for generating diffs for the zone store.
    old_apex_saved: HashMap<Rtype, Vec<Zrd>>,

    /// After incremental signing, this contains the apex RRsets (with the
    /// exception of NSEC, NSEC3, and RRSIG records) of the newly signed
    /// zone.
    new_apex: HashMap<Rtype, Vec<Zrd>>,

    /// After incremental signing, this contains the non-apex RRsets
    /// (with the exeception of NSEC, NSEC3, and RRSIG records) of the newly
    /// signed zone.
    new_data: BTreeMap<(Name<Bytes>, Rtype), Vec<Zrd>>,

    /// The apex of the new version of the unsigned zone.
    new_apex_saved: HashMap<Rtype, Vec<Zrd>>,

    nsecs: Nsecs,

    /// NSEC3 records of the previously signed zone.
    old_nsec3s: BTreeMap<Name<Bytes>, Zrd>,

    /// NSEC3 records of the newly signed zone.
    nsec3s: BTreeMap<Name<Bytes>, Zrd>,

    // Stores old and new RRSIG records and creates diffs.
    rrsigs: Rrsigs<'zd>,

    /// List of RRsets that are added or deleted.
    changes: HashMap<Name<Bytes>, ChangesValue>,

    /// List of NSEC or NSEC3 records that have been modified and needs to
    /// be signed.
    // TODO: rewrite to rely on changes collection within nsecs and nsec3s.
    modified_nsecs: HashSet<Name<Bytes>>,

    /// Signing keys.
    keys: Vec<SigningKey<Bytes, KeyPair>>,

    /// Inception time to use for signatures.
    inception: Timestamp,

    /// Expiration time to use for signatures.
    expiration: Timestamp,

    // NSEC3 parameters.
    nsec3param: Nsec3param<Bytes>,
}

impl<'a> IncrementalSigningState<'a> {
    pub fn new(
        origin: Name<Bytes>,
        policy: &PolicyVersion,
        zone_signer: &ZoneSigner,
        center: &Arc<Center>,
        keyset_state: &KeySetState,
        status: Arc<RwLock<SigningStatusPerZone>>,
    ) -> Result<Self, SignerError> {
        let keys = load_keys(zone_signer, center, origin.clone(), keyset_state, status)?;

        let now = faketime_or_now();
        let now_u32 = Into::<Duration>::into(now.clone()).as_secs() as u32;
        let inception = (now_u32 - policy.signer.sig_inception_offset).into();
        let expiration = (now_u32 + policy.signer.sig_validity_time).into();

        // This is the only way to deal with opt-out. There is no data type
        // for flags or constant for opt-out. Creating an Nsec3param makes it
        // possible to set opt-out.
        let mut nsec3param = Nsec3param::default();
        match &policy.signer.denial {
            SignerDenialPolicy::NSec => (),
            SignerDenialPolicy::NSec3 { opt_out } => {
                if *opt_out {
                    nsec3param.set_opt_out_flag();
                }
            }
        }
        Ok(Self {
            origin,
            old_apex: HashMap::new(),
            old_apex_saved: HashMap::new(),
            new_apex: HashMap::new(),
            new_apex_saved: HashMap::new(),
            old_data: HashMap::new(),
            new_data: BTreeMap::new(),
            nsecs: Nsecs::new(),
            old_nsec3s: BTreeMap::new(),
            nsec3s: BTreeMap::new(),
            rrsigs: Rrsigs::new(),
            changes: HashMap::new(),
            modified_nsecs: HashSet::new(),
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
        // Collect records for a
        // name/RRtype and store a complete RRset in a hash table.
        let mut records = Vec::<Zrd>::new();

        // Loop over all records. Records do not have to be sorted though
        // performance may improve if records are grouped in RRsets.
        for entry in signed_reader.all_records() {
            let record: OldParsedRecord = entry.clone().into();
            let record: StoredRecord = record.flatten_into();
            let record: Zrd = record.into();

            match record.data() {
                ZoneRecordData::Rrsig(_rrsig) => {
                    self.rrsigs.add_existing_record(entry);
                }
                ZoneRecordData::Nsec(_) => {
                    // Assume (at most) one NSEC record per owner name.
                    // Directly insert into the btree map.
                    self.nsecs
                        .add_existing_record(record.owner().clone(), record);
                }
                ZoneRecordData::Nsec3(_) => {
                    // Assume (at most) one NSEC3 record per owner name.
                    // Directly insert into the btree map.
                    self.nsec3s.insert(record.owner().clone(), record);
                }
                _ => {
                    if records.is_empty() {
                        records.push(record);
                        continue;
                    }
                    if record.owner() == records[0].owner() && record.rtype() == records[0].rtype()
                    {
                        records.push(record);
                        continue;
                    }
                    let key = (records[0].owner().clone(), records[0].rtype());
                    if key.0 == self.origin {
                        self.old_apex.entry(key.1).or_default().append(&mut records);
                    } else {
                        self.old_data.entry(key).or_default().append(&mut records);
                    }
                    records = vec![];
                    records.push(record);
                }
            }
        }

        if !records.is_empty() {
            let key = (records[0].owner().clone(), records[0].rtype());
            if key.0 == self.origin {
                self.old_apex.entry(key.1).or_default().append(&mut records);
            } else {
                self.old_data.entry(key).or_default().append(&mut records);
            }
        }
        self.old_apex_saved = self.old_apex.clone();
        self.old_nsec3s = self.nsec3s.clone();
        Ok(())
    }

    pub fn load_unsigned_zone(&mut self, reader: &LoadedZoneReader) -> Result<(), SignerError> {
        // Collect records for a
        // name/RRtype and store a complete RRset in a btree.
        let mut records = Vec::<Zrd>::new();

        for entry in reader.regular_records() {
            let record: OldParsedRecord = entry.clone().into();
            let record: StoredRecord = record.flatten_into();
            let record: Zrd = record.into();

            // Skip record types we don't need.
            if record.rtype() == Rtype::NSEC
                || record.rtype() == Rtype::NSEC3
                || record.rtype() == Rtype::RRSIG
            {
                continue;
            }

            if records.is_empty() {
                records.push(record);
                continue;
            }
            if record.owner() == records[0].owner() && record.rtype() == records[0].rtype() {
                records.push(record);
                continue;
            }
            let key = (records[0].owner().clone(), records[0].rtype());
            if key.0 == self.origin {
                self.new_apex.entry(key.1).or_default().append(&mut records);
            } else {
                self.new_data.entry(key).or_default().append(&mut records);
            }
            records = vec![];
            records.push(record);
        }

        if !records.is_empty() {
            let key = (records[0].owner().clone(), records[0].rtype());
            if key.0 == self.origin {
                self.new_apex.entry(key.1).or_default().append(&mut records);
            } else {
                self.new_data.entry(key).or_default().append(&mut records);
            }
        }

        // Save a copy of the loaded new_apex to create a diff later.
        for (k, v) in &self.new_apex {
            self.new_apex_saved.insert(*k, v.clone());
        }

        // Remove an NSEC3PARAM and ZONEMD that we got from the unsigned
        // zone.
        self.new_apex.remove(&Rtype::NSEC3PARAM);
        self.new_apex.remove(&Rtype::ZONEMD);
        Ok(())
    }

    pub fn load_signed_only(&mut self) {
        // Copy old data to new data.

        for (k, v) in &self.old_data {
            self.new_data.insert(k.clone(), v.clone());
        }
        for (k, v) in &self.old_apex {
            self.new_apex.insert(*k, v.clone());
            self.new_apex_saved.insert(*k, v.clone());
        }
    }

    pub fn initial_diffs(&mut self) -> Result<(), SignerError> {
        let mut new_sigs = vec![];
        for new_rrset in self.new_data.values_mut() {
            let key = (new_rrset[0].owner().clone(), new_rrset[0].rtype());

            // XXX for compatibility with the full zone signer, always
            // ignore DNSKEY/CDS/CDNSKEY when not at apex.
            let rtype = new_rrset[0].rtype();
            if (rtype == Rtype::DNSKEY || rtype == Rtype::CDS || rtype == Rtype::CDNSKEY)
                && *new_rrset[0].owner() != self.origin
            {
                continue;
            }

            if let Some(mut old_rrset) = self.old_data.remove(&key) {
                let rtype = new_rrset[0].rtype();
                if (rtype == Rtype::DNSKEY || rtype == Rtype::CDS || rtype == Rtype::CDNSKEY)
                    && *new_rrset[0].owner() == self.origin
                {
                    // At apex, these types are signed by the key manager. No
                    // need to check for changes.
                    continue;
                }
                old_rrset.sort_by(|a, b| a.as_ref().data().canonical_cmp(b.as_ref().data()));
                new_rrset.sort_by(|a, b| a.as_ref().data().canonical_cmp(b.as_ref().data()));

                let new_name = old_base_name_to_revnamebuf(key.0);
                let key = (new_name, old_base_rtype_to_new_base_rtype(key.1));
                if *old_rrset != *new_rrset && self.rrsigs.remove(&key).is_some() {
                    sign_records(
                        &self.origin,
                        new_rrset,
                        &self.keys,
                        self.inception,
                        self.expiration,
                        &mut new_sigs,
                    )?;
                }
            } else if let Some((added, _)) = self.changes.get_mut(&key.0) {
                added.insert(new_rrset[0].rtype());
            } else {
                let mut added = HashSet::new();
                let removed = HashSet::new();
                added.insert(new_rrset[0].rtype());
                self.changes.insert(key.0, (added, removed));
            }
        }
        for new_rrset in self.new_apex.values_mut() {
            let key = (new_rrset[0].owner().clone(), new_rrset[0].rtype());
            if let Some(mut old_rrset) = self.old_apex.remove(&key.1) {
                let rtype = new_rrset[0].rtype();
                if (rtype == Rtype::DNSKEY || rtype == Rtype::CDS || rtype == Rtype::CDNSKEY)
                    && *new_rrset[0].owner() == self.origin
                {
                    // At apex, these types are signed by the key manager. No
                    // need to check for changes.
                    continue;
                }
                old_rrset.sort_by(|a, b| a.as_ref().data().canonical_cmp(b.as_ref().data()));
                new_rrset.sort_by(|a, b| a.as_ref().data().canonical_cmp(b.as_ref().data()));

                let new_name = old_base_name_to_revnamebuf(key.0);
                let key = (new_name, old_base_rtype_to_new_base_rtype(key.1));
                if *old_rrset != *new_rrset && self.rrsigs.remove(&key).is_some() {
                    sign_records(
                        &self.origin,
                        new_rrset,
                        &self.keys,
                        self.inception,
                        self.expiration,
                        &mut new_sigs,
                    )?;
                }
            } else if let Some((added, _)) = self.changes.get_mut(&key.0) {
                added.insert(new_rrset[0].rtype());
            } else {
                let mut added = HashSet::new();
                let removed = HashSet::new();
                added.insert(new_rrset[0].rtype());
                self.changes.insert(key.0, (added, removed));
            }
        }
        for sigs in new_sigs {
            self.rrsigs.insert_new_records(sigs);
        }
        for old_rrset in self.old_data.values() {
            // What is left in old_data is removed.
            let rtype = old_rrset[0].rtype();
            let key = (old_rrset[0].owner().clone(), rtype);
            let new_name = old_base_name_to_revnamebuf(old_rrset[0].owner());
            let new_key = (new_name, old_base_rtype_to_new_base_rtype(rtype));

            self.rrsigs.remove(&new_key);

            if let Some((_, removed)) = self.changes.get_mut(&key.0) {
                removed.insert(rtype);
            } else {
                let added = HashSet::new();
                let mut removed = HashSet::new();
                removed.insert(rtype);
                self.changes.insert(key.0, (added, removed));
            }
        }
        for old_rrset in self.old_apex.values() {
            // What is left in old_data is removed.
            let rtype = old_rrset[0].rtype();
            let key = (old_rrset[0].owner().clone(), rtype);
            let new_name = old_base_name_to_revnamebuf(old_rrset[0].owner());
            let new_key = (new_name, old_base_rtype_to_new_base_rtype(rtype));

            self.rrsigs.remove(&new_key);

            if let Some((_, removed)) = self.changes.get_mut(&key.0) {
                removed.insert(rtype);
            } else {
                let added = HashSet::new();
                let mut removed = HashSet::new();
                removed.insert(rtype);
                self.changes.insert(key.0, (added, removed));
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

        let changes = self.changes.clone();
        for (key, (add, delete)) in &changes {
            // The intersection between add and delete is empty.
            assert!(add.intersection(delete).next().is_none());

            if let Some(record_nsec) = self.nsecs.get(key) {
                let record_nsec = record_nsec.clone();
                let ZoneRecordData::Nsec(nsec) = record_nsec.data() else {
                    panic!("NSEC record expected");
                };

                // Convert the existing RRtype bitmap into a hash set.
                let mut curr = HashSet::new();
                for rtype in nsec.types() {
                    curr.insert(rtype);
                }

                // The intersection between curr and add is empty.
                assert!(curr.intersection(add).next().is_none());

                // delete is completely contained in curr. In other words the
                // difference between delete and curr is empty.
                assert!(delete.difference(&curr).next().is_none());

                if add.contains(&Rtype::NS) {
                    // Apex is special, but we can assume the NS RRset will not
                    // be added to apex.
                    assert!(*key != self.origin);

                    // Remove the signatures for the existing types.
                    for rtype in nsec.types().iter() {
                        // When NS is added, we should keep the signatures for
                        // DS and NSEC. The NSEC signature will be updated but
                        // there is no point in removing it first. Do not try to
                        // remove a signature for RRSIG because it does not exist.
                        if rtype == Rtype::DS || rtype == Rtype::NSEC || rtype == Rtype::RRSIG {
                            continue;
                        }
                        let new_name = old_base_name_to_revnamebuf(key);
                        let key = (new_name, old_base_rtype_to_new_base_rtype(rtype));
                        self.rrsigs.remove(&key);
                    }

                    // Restrict curr and add to these types.
                    let mask: HashSet<Rtype> =
                        [Rtype::NS, Rtype::DS, Rtype::NSEC, Rtype::RRSIG].into();

                    let curr = curr.intersection(&mask).copied().collect();
                    let add = add.intersection(&mask).copied().collect();

                    // Update the NSEC record.
                    nsec_update_bitmap(&record_nsec, nsec, &curr, &add, delete, self);

                    // Mark descendents as occluded after updating the bitmap.
                    // The reason is that nsec_update_bitmap uses the current
                    // next_name and nsec_set_occluded may change that.
                    nsec_set_occluded(key, self);

                    continue;
                }
                if delete.contains(&Rtype::NS) {
                    // Apex is special, but we can assume the NS RRset will not
                    // be removed from apex.
                    assert!(*key != self.origin);

                    // Curr does not include all types at this name. Add the
                    // missing types to curr.
                    let range_key = (key.clone(), 0.into());
                    let range = self.new_data.range(range_key..);
                    for ((r_name, r_type), _) in range {
                        if r_name != key {
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
                    new.remove(&Rtype::NSEC);
                    new.remove(&Rtype::RRSIG);
                    sign_rtype_set(key, &new, self)?;

                    // Names that were previously occluded are no longer.
                    nsec_clear_occluded(key, self)?;
                    continue;
                }
                if *key != self.origin && nsec.types().contains(Rtype::NS) {
                    // NS marks a delegation but only when the NS is not
                    // at the apex.

                    // If the add set contains DS then sign the DS RRset.
                    if add.contains(&Rtype::DS) {
                        let ds_set: HashSet<_> = [Rtype::DS].into();
                        sign_rtype_set(key, &ds_set, self)?;
                    }
                    nsec_update_bitmap(&record_nsec, nsec, &curr, add, delete, self);
                    continue;
                }

                // The add types need to be signed.
                sign_rtype_set(key, add, self)?;

                nsec_update_bitmap(&record_nsec, nsec, &curr, add, delete, self);
            } else {
                if add.is_empty() {
                    assert!(!delete.is_empty());
                    // No need to do anything.
                    continue;
                }
                assert!(delete.is_empty());
                if is_occluded(key, self) {
                    // No need to do anything.
                    continue;
                }

                if add.contains(&Rtype::NS) {
                    // Create a new NSEC record and sign only DS records (if any).
                    let rtypebitmap = nsec_rtypebitmap_from_iterator(add.iter());
                    nsec_insert(key, rtypebitmap, self);
                    if add.contains(&Rtype::DS) {
                        let ds_set: HashSet<_> = [Rtype::DS].into();
                        sign_rtype_set(key, &ds_set, self)?;
                    }

                    // nsec_set_occluded expects the NSEC for key to exist.
                    // So call this after inserting the new NSEC record.
                    nsec_set_occluded(key, self);
                    continue;
                }
                // Create a new NSEC record and sign all records.
                let rtypebitmap = nsec_rtypebitmap_from_iterator(add.iter());
                nsec_insert(key, rtypebitmap, self);
                sign_rtype_set(key, add, self)?;
            }
        }
        Ok(())
    }

    pub fn incremental_nsec3(&mut self) -> Result<(), SignerError> {
        // Should changes be sorted or not? If changes is sorted we will
        // process a new delegation before any glue. Which is more efficient.
        // Otherwise if glue comes first, the glue will be signed and inserted
        // in the NSEC chain only to be removed when the delegation is processed.
        // However, we removing a delegation, the situation is reversed. For now
        // assuming that sorting is not necessary.

        let opt_out_flag = self.nsec3param.opt_out_flag();

        let changes = self.changes.clone();
        for (key, (add, delete)) in &changes {
            // The intersection between add and delete is empty.
            assert!(add.intersection(delete).next().is_none());

            let (nsec3_hash_octets, nsec3_name) = nsec3_hash_parts(key, self);

            if let Some(record_nsec3) = self.nsec3s.get(&nsec3_name) {
                let record_nsec3 = record_nsec3.clone();
                let ZoneRecordData::Nsec3(nsec3) = record_nsec3.data() else {
                    panic!("NSEC3 record expected");
                };

                // Convert the existing RRtype bitmap into a hash set.
                let mut curr = HashSet::new();
                for rtype in nsec3.types() {
                    curr.insert(rtype);
                }

                // The intersection between curr and add is empty.
                assert!(curr.intersection(add).next().is_none());

                // delete is completely contained in curr. In other words the
                // difference between delete and curr is empty.
                assert!(delete.difference(&curr).next().is_none());

                if add.contains(&Rtype::NS) {
                    // Apex is special, but we can assume the NS RRset will not
                    // be added to apex.
                    assert!(*key != self.origin);

                    // Remove the signatures for the existing types.
                    for rtype in nsec3.types().iter() {
                        // When NS is added, we should keep the signatures for
                        // DS. Do not try to remove a signature for RRSIG because
                        // it does not exist.
                        if rtype == Rtype::DS || rtype == Rtype::RRSIG {
                            continue;
                        }
                        let new_name = old_base_name_to_revnamebuf(key);
                        let key = (new_name, old_base_rtype_to_new_base_rtype(rtype));
                        self.rrsigs.remove(&key);
                    }

                    // Restrict curr and add to these types.
                    let mask: HashSet<Rtype> = [Rtype::NS, Rtype::DS, Rtype::RRSIG].into();

                    let curr = curr.intersection(&mask).copied().collect();
                    let add = add.intersection(&mask).copied().collect();

                    // Update the NSEC3 record.
                    nsec3_update_bitmap(key, &record_nsec3, nsec3, &curr, &add, delete, self);

                    // Mark descendents as occluded after updating the bitmap.
                    // The reason is that nsec3_update_bitmap uses the current
                    // next_hash and nsec3_set_occluded may change that.
                    nsec3_set_occluded(key, self);

                    continue;
                }
                if delete.contains(&Rtype::NS) {
                    // Apex is special, but we can assume the NS RRset will not
                    // be removed from apex.
                    assert!(*key != self.origin);

                    // Curr does not include all types at this name. Add the
                    // missing types to curr.
                    let range_key = (key.clone(), 0.into());
                    let range = self.new_data.range(range_key..);
                    for ((r_name, r_type), _) in range {
                        if r_name != key {
                            break;
                        }
                        if add.contains(r_type) {
                            // Skip what we are trying to add.
                            continue;
                        }
                        curr.insert(*r_type);
                    }

                    let mut new =
                        nsec3_update_bitmap(key, &record_nsec3, nsec3, &curr, add, delete, self);

                    // Sign the types at this name except for NSEC, and RRSIG.
                    new.remove(&Rtype::RRSIG);
                    sign_rtype_set(key, &new, self)?;

                    // Names that were previously occluded are no longer.
                    nsec3_clear_occluded(key, self)?;
                    continue;
                }
                if *key != self.origin && nsec3.types().contains(Rtype::NS) {
                    // NS marks a delegation but only when the NS is not
                    // at the apex.

                    // If the add set contains DS then sign the DS RRset.
                    if add.contains(&Rtype::DS) {
                        let ds_set: HashSet<_> = [Rtype::DS].into();
                        sign_rtype_set(key, &ds_set, self)?;
                    }
                    nsec3_update_bitmap(key, &record_nsec3, nsec3, &curr, add, delete, self);
                    continue;
                }

                // The add types need to be signed.
                sign_rtype_set(key, add, self)?;

                nsec3_update_bitmap(key, &record_nsec3, nsec3, &curr, add, delete, self);
            } else {
                if add.is_empty() {
                    assert!(!delete.is_empty());

                    // Special magic for out-out. It is possible that an NS
                    // record got deleted. With opt-out there will not be an
                    // NSEC3 record if there is only a NS record and no DS record.
                    if opt_out_flag && delete.contains(&Rtype::NS) {
                        if is_occluded(key, self) {
                            // No need to do anything.
                            continue;
                        }
                        nsec3_clear_occluded(key, self)?;
                        continue;
                    }

                    // No need to do anything.
                    continue;
                }
                assert!(delete.is_empty());
                if is_occluded(key, self) {
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
                    let tmpkey = (key.clone(), Rtype::NS);
                    if self.new_data.contains_key(&tmpkey) {
                        // Found an NS record. It is safe to add NS to the add
                        // set.
                        add.insert(Rtype::NS);
                    }
                }

                if add.contains(&Rtype::NS) {
                    if opt_out_flag {
                        // Check if this is just an NS record. If so, don't
                        // create an NSEC3 record.
                        if !add.iter().any(|r| *r != Rtype::NS) {
                            continue;
                        }
                    }
                    // Create a new NSEC3 record and sign only DS records (if any).
                    // If add contains DS then add RRSIG to add.

                    let mut add = add.clone(); // In case we need to add RRSIG.
                    if add.contains(&Rtype::DS) {
                        let ds_set: HashSet<_> = [Rtype::DS].into();
                        sign_rtype_set(key, &ds_set, self)?;
                        add.insert(Rtype::RRSIG);
                    }

                    let rtypebitmap = nsec3_rtypebitmap_from_iterator(add.iter());

                    nsec3_insert_full(key, nsec3_hash_octets, &nsec3_name, rtypebitmap, self);
                    nsec3_set_occluded(key, self);
                    continue;
                }
                // The new name is not a delegation. Add RRSIG to the set of
                // Rtypes.
                let mut add_with_rrsig = add.clone();
                add_with_rrsig.insert(Rtype::RRSIG);

                // Create a new NSEC3 record and sign all records.
                let rtypebitmap = nsec3_rtypebitmap_from_iterator(add_with_rrsig.iter());
                nsec3_insert_full(key, nsec3_hash_octets, &nsec3_name, rtypebitmap, self);
                sign_rtype_set(key, &add, self)?;
            }
        }
        Ok(())
    }

    fn remove_nsec_nsec3(&mut self) {
        for k in self.nsecs.keys() {
            let new_name = old_base_name_to_revnamebuf(k);
            let key = (new_name, NewRtype::NSEC);
            self.rrsigs.remove(&key);
        }
        self.nsecs.remove_all();

        for k in self.nsec3s.keys() {
            let new_name = old_base_name_to_revnamebuf(k);
            let key = (new_name, NewRtype::NSEC3);
            self.rrsigs.remove(&key);
        }
        self.nsec3s = BTreeMap::new();
    }

    fn new_nsec_chain(&mut self) -> Result<(), SignerError> {
        let records = self.get_unsigned_sorted();
        let records: Vec<_> = records.into_iter().map(RecordFullCmp::to_record).collect();
        let records_iter = RecordsIter::new_from_refs(&records);
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
            self.nsecs
                .insert_new_record(record.owner().clone(), record.clone());
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
            self.rrsigs.insert_new_records(sig);
        }
        Ok(())
    }

    fn new_nsec3_chain(&mut self) -> Result<(), SignerError> {
        let records = self.get_unsigned_sorted();
        let records: Vec<_> = records.into_iter().map(RecordFullCmp::to_record).collect();
        let records_iter = RecordsIter::new_from_refs(&records);
        let config = GenerateNsec3Config::<_, DefaultSorter>::new(self.nsec3param.clone())
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
        let records = vec![record.clone()];

        // Insert in both old and new data.
        sign_records(
            &self.origin,
            &[record],
            &self.keys,
            self.inception,
            self.expiration,
            &mut new_sigs,
        )?;
        self.old_apex.insert(Rtype::NSEC3PARAM, records.clone());
        self.new_apex.insert(Rtype::NSEC3PARAM, records);

        for r in nsec3_records.nsec3s {
            let record = RecordFullCmp::new(
                r.owner().clone(),
                r.class(),
                r.ttl(),
                ZoneRecordData::Nsec3(r.data().clone()),
            );
            self.nsec3s.insert(record.owner().clone(), record.clone());
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
            self.rrsigs.insert_new_records(sig);
        }
        Ok(())
    }

    fn get_unsigned_sorted(&self) -> Vec<&Zrd> {
        // Create a Vec with all unsigned records to be able to sort them in
        // canonical order.

        let mut apex: Vec<_> = self.old_apex.values().flatten().collect();
        let mut data: Vec<_> = self.old_data.values().flatten().collect();
        data.append(&mut apex);
        data.par_sort_by(|e1, e2| CanonicalOrd::canonical_cmp(*e1, *e2));

        data
    }
}

struct Nsecs {
    nsecs: BTreeMap<Name<Bytes>, NsecChange>,
    changes: HashSet<Name<Bytes>>,
}

impl Nsecs {
    fn new() -> Self {
        Self {
            nsecs: BTreeMap::new(),
            changes: HashSet::new(),
        }
    }

    fn add_existing_record(&mut self, name: Name<Bytes>, value: Zrd) {
        let nsec_change = NsecChange::Original { old: value };
        self.nsecs.insert(name, nsec_change);
    }

    fn insert_new_record(&mut self, name: Name<Bytes>, value: Zrd) {
        let entry = self.nsecs.entry(name.clone());
        match entry {
            btree_map::Entry::Occupied(mut entry) => {
                let change = entry.get_mut();
                match change {
                    NsecChange::Original { old } | NsecChange::Modified { old, .. } => {
                        let new_change = NsecChange::Modified {
                            old: old.clone(),
                            new: value,
                        };
                        *change = new_change;

                        // No need for an insert for Modified, but it doesn't
                        // hurt.
                        self.changes.insert(name);
                    }
                    NsecChange::Removed { .. } => todo!(),
                    NsecChange::New { .. } => {
                        let new_change = NsecChange::New { new: value };
                        *change = new_change;
                    }
                }
            }
            btree_map::Entry::Vacant(entry) => {
                let change = NsecChange::New { new: value };
                entry.insert(change);
                self.changes.insert(name);
            }
        }
    }

    fn remove(&mut self, name: &Name<Bytes>) {
        let entry = self.nsecs.entry(name.clone());
        match entry {
            btree_map::Entry::Occupied(mut entry) => {
                let change = entry.get_mut();
                match change {
                    NsecChange::Original { old } | NsecChange::Modified { old, .. } => {
                        let new_change = NsecChange::Removed { old: old.clone() };
                        *change = new_change;

                        // No need for an insert for Modified, but it doesn't
                        // hurt.
                        self.changes.insert(name.clone());
                    }
                    NsecChange::Removed { .. } => todo!(),
                    NsecChange::New { .. } => {
                        // Remove the new entry.
                        entry.remove();
                        self.changes.remove(name);
                    }
                }
            }
            btree_map::Entry::Vacant(_entry) => {
                todo!();
            }
        }
    }

    fn remove_all(&mut self) {
        for (name, change) in self.nsecs.iter_mut() {
            match change {
                NsecChange::Original { old } => {
                    let new_change = NsecChange::Removed { old: old.clone() };
                    *change = new_change;

                    // No need for an insert for Modified, but it doesn't
                    // hurt.
                    self.changes.insert(name.clone());
                }
                NsecChange::Removed { .. } => todo!(),
                NsecChange::Modified { .. } => todo!(),
                NsecChange::New { .. } => todo!(),
            }
        }
    }

    fn get(&self, name: &Name<Bytes>) -> Option<&Zrd> {
        if let Some(change) = self.nsecs.get(name) {
            match change {
                NsecChange::Original { old } => return Some(old),
                NsecChange::Removed { .. } => todo!(),
                NsecChange::Modified { new, .. } | NsecChange::New { new } => return Some(new),
            }
        }
        None
    }

    fn get_change(&self, name: &Name<Bytes>) -> Option<&NsecChange> {
        self.nsecs.get(name)
    }

    fn keys(&self) -> NsecsKeysIter<'_> {
        NsecsKeysIter::new(self.nsecs.iter())
    }

    fn values(&self) -> NsecsValuesIter<'_> {
        NsecsValuesIter::new(self.nsecs.values())
    }

    fn range<R>(&self, range: R) -> NsecRange<'_>
    where
        R: RangeBounds<Name<Bytes>>,
    {
        NsecRange::new(self.nsecs.range(range))
    }

    fn changes_iter(&self) -> hash_set::Iter<'_, Name<Bytes>> {
        self.changes.iter()
    }
}

enum NsecChange {
    Original { old: Zrd },
    Removed { old: Zrd },
    Modified { old: Zrd, new: Zrd },
    New { new: Zrd },
}

struct NsecsKeysIter<'a> {
    iter: btree_map::Iter<'a, Name<Bytes>, NsecChange>,
}

impl<'a> NsecsKeysIter<'a> {
    fn new(iter: btree_map::Iter<'a, Name<Bytes>, NsecChange>) -> Self {
        Self { iter }
    }
}

type NsecKeyItem<'a> = &'a Name<Bytes>;

impl<'a> Iterator for NsecsKeysIter<'a> {
    type Item = NsecKeyItem<'a>;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        loop {
            if let Some((name, item)) = self.iter.next() {
                match item {
                    NsecChange::Original { .. }
                    | NsecChange::Modified { .. }
                    | NsecChange::New { .. } => return Some(name),
                    NsecChange::Removed { .. } => continue,
                }
            }
            break;
        }
        None
    }
}

struct NsecsValuesIter<'a> {
    iter: btree_map::Values<'a, Name<Bytes>, NsecChange>,
}

impl<'a> NsecsValuesIter<'a> {
    fn new(iter: btree_map::Values<'a, Name<Bytes>, NsecChange>) -> Self {
        Self { iter }
    }
}

type NsecItem<'a> = &'a Zrd;

impl<'a> Iterator for NsecsValuesIter<'a> {
    type Item = NsecItem<'a>;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        loop {
            if let Some(item) = self.iter.next() {
                match item {
                    NsecChange::Original { old } => return Some(old),
                    NsecChange::Removed { .. } => continue,
                    NsecChange::Modified { new, .. } | NsecChange::New { new } => return Some(new),
                }
            }
            break;
        }
        None
    }
}

struct NsecRange<'a> {
    range: btree_map::Range<'a, Name<Bytes>, NsecChange>,
}

impl<'a> NsecRange<'a> {
    fn new(range: btree_map::Range<'a, Name<Bytes>, NsecChange>) -> Self {
        Self { range }
    }
}

impl<'a> Iterator for NsecRange<'a> {
    type Item = (&'a Name<Bytes>, &'a Zrd);
    fn next(&mut self) -> std::option::Option<<Self as Iterator>::Item> {
        todo!()
    }
}

impl<'a> DoubleEndedIterator for NsecRange<'a> {
    fn next_back(&mut self) -> Option<<Self as Iterator>::Item> {
        loop {
            if let Some((name, item)) = self.range.next_back() {
                match item {
                    NsecChange::Original { old } => return Some((name, old)),
                    NsecChange::Removed { .. } => continue,
                    NsecChange::Modified { new, .. } | NsecChange::New { new } => {
                        return Some((name, new));
                    }
                }
            }
            break;
        }
        None
    }
}

struct Rrsigs<'zd> {
    // Store the existing RRSIG records. The incremental signer doesn't
    // need them, but we need them to inform the zone store which records
    // have been removed.
    old_rrsigs: HashMap<(&'zd RevName, NewRtype), Vec<&'zd RegularRecord>>,

    changes: HashMap<(RevNameBuf, NewRtype), RrsigChange<'zd>>,
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
        let buf_key = (RevNameBuf::copy_from(record.owner()), rrsig.type_covered());

        // First check the changes map.
        match self.changes.entry(buf_key) {
            hash_map::Entry::Occupied(mut entry) => {
                let change = entry.get_mut();
                match change {
                    RrsigChange::Delete { .. } => {
                        // Create a new empty change, either insert of
                        // modify depending on the existing RRSIGS.
                        let key = (record.owner(), rrsig.type_covered());
                        let new_change = if let Some(rrsigs) = self.old_rrsigs.get(&key) {
                            RrsigChange::Modified {
                                old: rrsigs.to_vec(),
                                new: vec![record],
                            }
                        } else {
                            todo!();
                        };
                        *change = new_change;
                    }
                    RrsigChange::Modified { new, .. } | RrsigChange::Insert { new, .. } => {
                        new.push(record);
                    }
                }
            }
            hash_map::Entry::Vacant(entry) => {
                // Whether to new change is Modified or Insert depends on
                // whether RRSIGs already exist or not.
                let key = (record.owner(), rrsig.type_covered());
                let change = if let Some(_sigs) = self.old_rrsigs.get(&key) {
                    todo!();
                } else {
                    // Nothing yet. Create an Insert.
                    RrsigChange::Insert { new: vec![record] }
                };
                entry.insert(change);
            }
        }
    }

    fn insert_new_records(&mut self, records: Vec<RegularRecord>) {
        let NewRecordData::Rrsig(rrsig) = records[0].data() else {
            panic!("ZoneRecordData::Rrsig expected");
        };
        let buf_key = (
            RevNameBuf::copy_from(records[0].owner()),
            rrsig.type_covered(),
        );

        // First check the changes map.
        match self.changes.entry(buf_key) {
            hash_map::Entry::Occupied(mut entry) => {
                let change = entry.get_mut();
                match change {
                    RrsigChange::Delete { .. } => {
                        // Create a new empty change, either insert or
                        // modify depending on the existing RRSIGS.
                        let key = (records[0].owner(), rrsig.type_covered());
                        let new_change = if let Some(rrsigs) = self.old_rrsigs.get(&key) {
                            RrsigChange::Modified {
                                old: rrsigs.to_vec(),
                                new: records,
                            }
                        } else {
                            todo!();
                        };
                        *change = new_change;
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

    fn len(&self) -> usize {
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

        let ilen = (len as isize) + changes;
        if ilen >= 0 {
            ilen as usize
        } else {
            unreachable!()
        }
    }

    fn remove(&mut self, key: &(RevNameBuf, NewRtype)) -> Option<()> {
        // Remove normally returns the removed item, but we don't need
        // that. We should switch to a boolean.

        // Check if the old version has RRSIGs.
        let old_key = (key.0.as_ref(), key.1);
        if let Some(rrsigs) = self.old_rrsigs.get(&old_key) {
            // There are RRSIGs in the old version. Check if they have been
            // deleted before.
            let mut result = Some(());
            match self.changes.entry(key.clone()) {
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
            match self.changes.entry(key.clone()) {
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

type RrsigIterItem<'a> = ((&'a RevName, &'a NewRtype), Vec<&'a RegularRecord>);
impl<'a> IntoIterator for &'a Rrsigs<'a> {
    type Item = RrsigIterItem<'a>;
    type IntoIter = RrsigIter<'a>;
    fn into_iter(self) -> <Self as IntoIterator>::IntoIter {
        RrsigIter::new(self.old_rrsigs.iter(), &self.changes)
    }
}

#[allow(clippy::type_complexity)]
struct RrsigIter<'a> {
    iter: Option<hash_map::Iter<'a, (&'a RevName, NewRtype), Vec<&'a RegularRecord>>>,
    changes: &'a HashMap<(RevNameBuf, NewRtype), RrsigChange<'a>>,
    changes_iter: Option<hash_map::Iter<'a, (RevNameBuf, NewRtype), RrsigChange<'a>>>,
}

impl<'a> RrsigIter<'a> {
    fn new(
        iter: hash_map::Iter<'a, (&RevName, NewRtype), Vec<&RegularRecord>>,
        changes: &'a HashMap<(RevNameBuf, NewRtype), RrsigChange>,
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
            loop {
                let next = iter.next();
                if let Some(((name, rtype), sigs)) = next {
                    // Check if changes has something.
                    let key = (RevNameBuf::copy_from(name), *rtype);
                    if self.changes.get(&key).is_some() {
                        // Get it from changes if not deleted.
                        continue;
                    }

                    return Some(((name, rtype), sigs.to_vec()));
                }

                // End of iterator.
                break;
            }
            self.iter = None;
            self.changes_iter = Some(self.changes.iter());
        }
        if let Some(changes_iter) = &mut self.changes_iter {
            loop {
                let next = changes_iter.next();
                if let Some(((name, rtype), change)) = next {
                    match change {
                        RrsigChange::Delete { .. } => {
                            // Nothing here.
                            continue;
                        }
                        RrsigChange::Modified { new, .. } | RrsigChange::Insert { new, .. } => {
                            let new: Vec<&RegularRecord> = new.iter().collect();
                            return Some(((name.as_ref(), rtype), new));
                        }
                    }
                }

                // End of iterator.
                break;
            }
            self.changes_iter = None;
        }
        None
    }
}

#[allow(clippy::type_complexity)]
struct RrsigsValuesIter<'a> {
    iter: Option<hash_map::Iter<'a, (&'a RevName, NewRtype), Vec<&'a RegularRecord>>>,
    changes: &'a HashMap<(RevNameBuf, NewRtype), RrsigChange<'a>>,
    changes_values: Option<hash_map::Values<'a, (RevNameBuf, NewRtype), RrsigChange<'a>>>,
}

impl<'a> RrsigsValuesIter<'a> {
    fn new(
        iter: hash_map::Iter<'a, (&RevName, NewRtype), Vec<&RegularRecord>>,
        changes: &'a HashMap<(RevNameBuf, NewRtype), RrsigChange>,
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
            loop {
                let next = iter.next();
                if let Some(((name, rtype), sigs)) = next {
                    // Check if changes has something.
                    let key = (RevNameBuf::copy_from(name), *rtype);
                    if self.changes.get(&key).is_some() {
                        // Get it from changes if not deleted.
                        continue;
                    }

                    return Some(sigs.to_vec());
                }

                // End of iterator.
                break;
            }
            self.iter = None;
            self.changes_values = Some(self.changes.values());
        }
        if let Some(changes_values) = &mut self.changes_values {
            loop {
                let next = changes_values.next();
                if let Some(change) = next {
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

                // End of iterator.
                break;
            }
            self.changes_values = None;
        }
        None
    }
}

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
    keys: &[SigningKey<Bytes, KeyPair>],
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
    for key in keys {
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

fn nsec_insert(
    name: &Name<Bytes>,
    rtypebitmap: RtypeBitmap<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    // Try to find the NSEC record that comes before the one we are trying
    // to insert. Assume that the apex NSEC will always exist can sort
    // before anything else.
    let mut range = iss.nsecs.range(..name);
    let (previous_name, previous_record) = range
        .next_back()
        .expect("previous NSEC record should exist");
    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    let ZoneRecordData::Nsec(previous_nsec) = previous_record.data() else {
        panic!("NSEC record expected");
    };
    let next = previous_nsec.next_name();
    let new_nsec = Nsec::new(next.clone(), rtypebitmap);
    let new_record = RecordFullCmp::new(
        name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec(new_nsec),
    );
    iss.nsecs.insert_new_record(name.clone(), new_record);
    iss.modified_nsecs.insert(name.clone());
    let previous_nsec = Nsec::new(name.clone(), previous_nsec.types().clone());
    let previous_record = RecordFullCmp::new(
        previous_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec(previous_nsec),
    );
    iss.nsecs
        .insert_new_record(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
}

fn nsec_remove(name: &Name<Bytes>, next_name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Try to find the NSEC record that comes before the one we are trying
    // to remove. Assume that the apex NSEC will always exist can sort
    // before anything else.
    let mut range = iss.nsecs.range(..name);
    let (previous_name, previous_record) = range
        .next_back()
        .expect("previous NSEC record should exist");
    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    let ZoneRecordData::Nsec(previous_nsec) = previous_record.data() else {
        panic!("NSEC record expected");
    };
    let previous_nsec = Nsec::new(next_name.clone(), previous_nsec.types().clone());
    let previous_record = RecordFullCmp::new(
        previous_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec(previous_nsec),
    );
    iss.nsecs
        .insert_new_record(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
    iss.nsecs.remove(name);
    iss.modified_nsecs.remove(name);
    let key = (old_base_name_to_revnamebuf(name), NewRtype::NSEC);
    iss.rrsigs.remove(&key);
}

// Return the effective result HashSet even when the NSEC record gets deleted.
fn nsec_update_bitmap(
    record: &Zrd,
    nsec: &Nsec<Bytes, Name<Bytes>>,
    curr: &HashSet<Rtype>,
    add: &HashSet<Rtype>,
    delete: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) -> HashSet<Rtype> {
    let set_nsec_rrsig: HashSet<_> = [Rtype::NSEC, Rtype::RRSIG].into();

    // Update curr.
    let curr: HashSet<_> = curr.union(add).copied().collect();
    let curr = curr.difference(delete).copied().collect();

    let owner = record.owner();
    if curr == set_nsec_rrsig {
        nsec_remove(owner, nsec.next_name(), iss);
        return curr;
    }

    let rtypebitmap = nsec_rtypebitmap_from_iterator(curr.iter());
    let nsec = Nsec::new(nsec.next_name().clone(), rtypebitmap);
    let record = RecordFullCmp::new(
        record.owner().clone(),
        record.class(),
        record.ttl(),
        ZoneRecordData::Nsec(nsec),
    );
    iss.nsecs.insert_new_record(owner.clone(), record);

    iss.modified_nsecs.insert(owner.clone());
    curr
}

fn nsec_set_occluded(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    let Some(nsec_record) = iss.nsecs.get(name) else {
        panic!("NSEC for {name} expected to exist");
    };
    let ZoneRecordData::Nsec(nsec) = nsec_record.data() else {
        panic!("NSEC record expected");
    };
    let nsec = nsec.clone();
    let mut next = nsec.next_name().clone();
    loop {
        if !next.ends_with(name) {
            break;
        }

        // For consistency, make sure next is not equal to name.
        if next == name {
            break;
        }
        let curr = next;
        let Some(nsec_record) = iss.nsecs.get(&curr) else {
            panic!("NSEC for {name} expected to exist");
        };
        let ZoneRecordData::Nsec(nsec) = nsec_record.data() else {
            panic!("NSEC record expected");
        };
        let nsec = nsec.clone();
        next = nsec.next_name().clone();

        nsec_remove(&curr, &next, iss);

        // Remove all signatures.
        for rtype in nsec.types().iter() {
            let key = (
                old_base_name_to_revnamebuf(&curr),
                old_base_rtype_to_new_base_rtype(rtype),
            );
            iss.rrsigs.remove(&key);
        }
    }
}

fn nsec_clear_occluded(
    name: &Name<Bytes>,
    iss: &mut IncrementalSigningState,
) -> Result<(), SignerError> {
    let key = (name.clone(), Rtype::SOA);
    let range = iss.new_data.range(key..);
    let mut opt_curr_name: Option<&Name<Bytes>> = None;
    let mut curr_types: HashSet<Rtype> = HashSet::new();
    let mut work = vec![];

    // Keep track of delegations. Name below a delegation remain occluded.
    let mut delegation: Option<Name<Bytes>> = None;

    for ((key_name, key_rtype), _) in range {
        // There is no easy way to avoid name showing up in the range. Just
        // filter out name.
        if key_name == name {
            continue;
        }

        // Make sure curr_name is below name.
        if !key_name.ends_with(name) {
            break;
        }
        if let Some(d) = &delegation
            && key_name.ends_with(d)
            && key_name != d
        {
            // Skip.
            continue;
        }

        if *key_rtype == Rtype::NS {
            // Set key_name as a delegation.
            delegation = Some(key_name.clone());
        }
        if let Some(curr_name) = opt_curr_name {
            if key_name == curr_name {
                curr_types.insert(*key_rtype);
            } else {
                work.push((curr_name.clone(), curr_types));
                opt_curr_name = Some(key_name);
                curr_types = [*key_rtype].into();
            }
        } else {
            opt_curr_name = Some(key_name);
            curr_types.insert(*key_rtype);
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
        sign_rtype_set(&curr_name, &curr_types, iss)?;
        nsec_insert(&curr_name, rtypebitmap, iss);
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
    owner: &Name<Bytes>,
    nsec3_record: &Zrd,
    nsec3: &Nsec3<Bytes>,
    rtypes: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) {
    // Just update an NSEC3 record without further logic.
    let rtypebitmap = nsec3_rtypebitmap_from_iterator(rtypes.iter());
    let nsec3 = Nsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt().clone(),
        nsec3.next_owner().clone(),
        rtypebitmap,
    );
    let record = RecordFullCmp::new(
        nsec3_record.owner().clone(),
        nsec3_record.class(),
        nsec3_record.ttl(),
        ZoneRecordData::Nsec3(nsec3),
    );
    iss.nsec3s.insert(owner.clone(), record);

    iss.modified_nsecs.insert(owner.clone());
}

fn nsec3_remove_full(
    name: &Name<Bytes>,
    nsec3_name: &Name<Bytes>,
    nsec3_next: &OwnerHash<Bytes>,
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

        let Some(record_nsec3) = iss.nsec3s.get(&nsec3_name) else {
            // No NSEC3 record, nothing to do.
            return;
        };

        let ZoneRecordData::Nsec3(nsec3) = record_nsec3.data() else {
            panic!("NSEC3 record expected");
        };

        if !nsec3.types().is_empty() {
            // There are types here.
            return;
        }

        // Check the descendents.
        let key = (name.clone(), Rtype::SOA);
        let range = iss.new_data.range(key..);
        let mut opt_curr_name: Option<&Name<Bytes>> = None;

        for ((key_name, _), _) in range {
            // There is no easy way to avoid name showing up in the range. Just
            // filter out name.
            if *key_name == name {
                continue;
            }

            // Make sure curr_name is below name.
            if !key_name.ends_with(&name) {
                break;
            }

            if let Some(curr_name) = opt_curr_name
                && key_name == curr_name
            {
                // Already checked.
                continue;
            }

            opt_curr_name = Some(key_name);

            let (_, nsec3_name) = nsec3_hash_parts(key_name, iss);

            if iss.nsec3s.contains_key(&nsec3_name) {
                // NSEC3 record is found. Our target is not an ET.
                return;
            };
        }

        // No descendents with NSEC3 records are found. Delete this one.
        let next_owner = nsec3.next_owner().clone();
        nsec3_remove_one(&nsec3_name, &next_owner, iss);

        // We remove the NSEC3 record for the name. Get the parent. We should
        // be below apex, so the parent has to exist.
        name = name.parent().expect("parent should exist");
    }
}

fn nsec3_remove_one(
    nsec3_name: &Name<Bytes>,
    nsec3_next: &OwnerHash<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    // Try to find the NSEC3 record that comes before the one we are trying
    // to remove.
    let mut range = iss.nsec3s.range::<Name<_>, _>(..nsec3_name);
    let (previous_name, previous_record) = if let Some(kv) = range.next_back() {
        kv
    } else {
        let mut range = iss.nsec3s.range::<Name<_>, _>(nsec3_name..);
        range
            .next_back()
            .expect("at least one element should exist")
    };

    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    drop(range);
    let ZoneRecordData::Nsec3(previous_nsec) = previous_record.data() else {
        panic!("NSEC3 record expected");
    };
    let previous_nsec3 = Nsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt().clone(),
        nsec3_next.clone(),
        previous_nsec.types().clone(),
    );
    let previous_record = RecordFullCmp::new(
        previous_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec3(previous_nsec3),
    );
    iss.nsec3s.insert(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
    iss.nsec3s.remove(nsec3_name);
    iss.modified_nsecs.remove(nsec3_name);
    let key = (old_base_name_to_revnamebuf(nsec3_name), NewRtype::NSEC3);
    iss.rrsigs.remove(&key);
}

fn nsec3_set_occluded(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Loop over all names below name, if there is an NSEC3 record then
    // delete all signatures and the NSEC3 record.

    let key = (name.clone(), Rtype::SOA);
    let range = iss.new_data.range(key..);
    let mut opt_curr_name: Option<&Name<Bytes>> = None;
    let mut work = vec![];

    for ((key_name, _), _) in range {
        // There is no easy way to avoid name showing up in the range. Just
        // filter out name.
        if key_name == name {
            continue;
        }

        // Make sure curr_name is below name.
        if !key_name.ends_with(name) {
            break;
        }

        if let Some(curr_name) = opt_curr_name
            && key_name == curr_name
        {
            // Looked at this name already.
            continue;
        }

        opt_curr_name = Some(key_name);

        let (_, nsec3_name) = nsec3_hash_parts(key_name, iss);

        let Some(record_nsec3) = iss.nsec3s.get(&nsec3_name) else {
            // No NSEC3 record, nothing to do.
            continue;
        };

        let ZoneRecordData::Nsec3(nsec3) = record_nsec3.data() else {
            panic!("NSEC3 record expected");
        };

        work.push((key_name.clone(), nsec3_name));

        // Remove all signatures.
        for rtype in nsec3.types().iter() {
            let key = (
                old_base_name_to_revnamebuf(key_name),
                old_base_rtype_to_new_base_rtype(rtype),
            );
            iss.rrsigs.remove(&key);
        }
    }
    for (key_name, nsec3_name) in work {
        let record_nsec3 = iss.nsec3s.get(&nsec3_name).expect("NSEC3 should exist");

        let ZoneRecordData::Nsec3(nsec3) = record_nsec3.data() else {
            panic!("NSEC3 record expected");
        };

        let nsec3_next = nsec3.next_owner().clone();
        nsec3_remove_full(&key_name, &nsec3_name, &nsec3_next, iss);
    }
}

fn nsec3_clear_occluded(
    name: &Name<Bytes>,
    iss: &mut IncrementalSigningState,
) -> Result<(), SignerError> {
    let key = (name.clone(), Rtype::SOA);
    let range = iss.new_data.range(key..);
    let mut opt_curr_name: Option<&Name<Bytes>> = None;
    let mut curr_types: HashSet<Rtype> = HashSet::new();
    let mut work = vec![];

    // Keep track of delegations. Name below a delegation remain occluded.
    let mut delegation: Option<Name<Bytes>> = None;

    for ((key_name, key_rtype), _) in range {
        // There is no easy way to avoid name showing up in the range. Just
        // filter out name.
        if key_name == name {
            continue;
        }

        // Make sure curr_name is below name.
        if !key_name.ends_with(name) {
            break;
        }
        if let Some(d) = &delegation
            && key_name.ends_with(d)
            && key_name != d
        {
            // Skip.
            continue;
        }

        if *key_rtype == Rtype::NS {
            // Set key_name as a delegation.
            delegation = Some(key_name.clone());
        }
        if let Some(curr_name) = opt_curr_name {
            if key_name == curr_name {
                curr_types.insert(*key_rtype);
            } else {
                work.push((curr_name.clone(), curr_types));
                opt_curr_name = Some(key_name);
                curr_types = [*key_rtype].into();
            }
        } else {
            opt_curr_name = Some(key_name);
            curr_types.insert(*key_rtype);
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
        sign_rtype_set(&curr_name, &curr_types, iss)?;

        let (nsec3_hash_octets, nsec3_name) = nsec3_hash_parts(&curr_name, iss);

        nsec3_insert_full(&curr_name, nsec3_hash_octets, &nsec3_name, rtypebitmap, iss);
    }
    Ok(())
}

fn nsec3_insert_full(
    name: &Name<Bytes>,
    nsec3_hash: OwnerHash<Bytes>,
    nsec3_name: &Name<Bytes>,
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

        if iss.nsec3s.contains_key(&nsec3_name) {
            // Found something. We are done.
            return;
        }

        let rtypebitmap = RtypeBitmap::<Bytes>::builder();
        let rtypebitmap = rtypebitmap.finalize();
        nsec3_insert_one(nsec3_hash_octets, &nsec3_name, rtypebitmap, iss);

        // Get the parent. We should be below apex, so the parent has to exist.
        name = name.parent().expect("parent should exist");
    }
}

fn nsec3_insert_one(
    nsec3_hash: OwnerHash<Bytes>,
    nsec3_name: &Name<Bytes>,
    rtypebitmap: RtypeBitmap<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    // Try to find the NSEC3 record that comes before the one we are trying
    // to insert. It is possible that we try to insert before the first NSEC3
    // record. In that case, logically try to insert after the last NSEC3
    // record.
    let mut range = iss.nsec3s.range::<Name<_>, _>(..nsec3_name);
    let (previous_name, previous_record) = if let Some(kv) = range.next_back() {
        kv
    } else {
        let mut range = iss.nsec3s.range::<Name<_>, _>(nsec3_name..);
        range
            .next_back()
            .expect("at least one element should exist")
    };
    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    drop(range);
    let ZoneRecordData::Nsec3(previous_nsec3) = previous_record.data() else {
        panic!("NSEC3 record expected");
    };
    let next = previous_nsec3.next_owner();
    let new_nsec3 = Nsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt().clone(),
        next.clone(),
        rtypebitmap,
    );
    let new_record = RecordFullCmp::new(
        nsec3_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec3(new_nsec3),
    );
    iss.nsec3s.insert(nsec3_name.clone(), new_record);
    iss.modified_nsecs.insert(nsec3_name.clone());
    let previous_nsec3 = Nsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt().clone(),
        nsec3_hash,
        previous_nsec3.types().clone(),
    );
    let previous_record = RecordFullCmp::new(
        previous_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec3(previous_nsec3),
    );
    iss.nsec3s.insert(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
}

// Return the effective result HashSet even when the NSEC3 record gets deleted.
fn nsec3_update_bitmap(
    name: &Name<Bytes>,
    nsec3_record: &Zrd,
    nsec3: &Nsec3<Bytes>,
    curr: &HashSet<Rtype>,
    add: &HashSet<Rtype>,
    delete: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) -> HashSet<Rtype> {
    // Update curr.
    let curr: HashSet<_> = curr.union(add).copied().collect();
    let mut curr: HashSet<_> = curr.difference(delete).copied().collect();
    let owner = nsec3_record.owner();

    // Check if we need to add or remove RRSIG. Assume that apex has a SOA
    // record.
    if curr.contains(&Rtype::NS) && !curr.contains(&Rtype::SOA) {
        // For an NS not at origin, there is an RRSIG if there is also a
        // DS record.
        if curr.contains(&Rtype::DS) {
            // Yes, add RRSIG.
            curr.insert(Rtype::RRSIG);
        } else {
            // No. Remove RRSIG.
            curr.remove(&Rtype::RRSIG);
        }
    } else {
        // Is there anything apart from RRSIG?
        if curr.iter().any(|r| *r != Rtype::RRSIG) {
            // Yes. Add RRSIG.
            curr.insert(Rtype::RRSIG);
        } else {
            // No. Remove RRSIG.
            curr.remove(&Rtype::RRSIG);
        }
    }

    if curr.is_empty() {
        // The NSEC3 bitmp will be empty, but this may now have become an
        // empty non-terminal. Our only option is to update the NSEC3 record
        // and then call nsec3_remove_et to see if it is empty can can be
        // removed.
        nsec3_update(owner, nsec3_record, nsec3, &curr, iss);
        nsec3_remove_et(name, iss);
        return curr;
    }

    if iss.nsec3param.opt_out_flag() && !curr.iter().any(|r| *r != Rtype::NS) {
        // The new bitmap has nothing except for NS. We would like to delete
        // the NSEC3. However there may still be descendents that need to be
        // removed with nsec3_set_occluded. Update this NSEC3 to be empty and
        // call nsec3_remove_et to remove it if there are no descendents.

        let empty_curr = HashSet::new();
        nsec3_update(owner, nsec3_record, nsec3, &empty_curr, iss);
        nsec3_remove_et(name, iss);
        return curr;
    }

    nsec3_update(owner, nsec3_record, nsec3, &curr, iss);
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
    let nsec3_hash_octets = OwnerHash::<Bytes>::octets_from(
        nsec3_hash::<_, _, BytesMut>(
            name,
            iss.nsec3param.hash_algorithm(),
            iss.nsec3param.iterations(),
            iss.nsec3param.salt(),
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
        if iss.new_data.contains_key(&(curr.clone(), Rtype::NS)) {
            // Name is occluded.
            return true;
        }
    }
}

fn sign_rtype_set(
    name: &Name<Bytes>,
    set: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) -> Result<(), SignerError> {
    let mut new_sigs = vec![];
    for rtype in set {
        let key = (name.clone(), *rtype);
        let Some(records) = (if *name == iss.origin {
            iss.new_apex.get(&key.1)
        } else {
            iss.new_data.get(&key)
        }) else {
            panic!("Expected something for {name}/{rtype}");
        };
        sign_records(
            &iss.origin,
            records,
            &iss.keys,
            iss.inception,
            iss.expiration,
            &mut new_sigs,
        )?;
    }
    for sigs in new_sigs {
        iss.rrsigs.insert_new_records(sigs);
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

/// Turn a RevName into an old base Name.
// TODO: add to domain.
fn revname_to_old_base_name(revname: &RevName) -> Name<Bytes> {
    let revnamebuf = RevNameBuf::copy_from(revname);
    let namebuf: NameBuf = revnamebuf.into();
    let buf = namebuf.as_bytes().to_vec();
    Name::<Bytes>::from_octets(buf.into()).expect("Name<Bytes> should be able to accept RevName")
}

/// Turn an old base Rtype into a new base Rtype.
// TODO: add to domain.
fn old_base_rtype_to_new_base_rtype(rtype: Rtype) -> NewRtype {
    rtype.to_int().into()
}

/// Turn a new base Rtype into an old base Rtype.
// TODO: add to domain.
fn new_base_rtype_to_old_base_rtype(rtype: NewRtype) -> Rtype {
    let v: u16 = rtype.into();
    v.into()
}
