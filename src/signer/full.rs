//! Full (non-incremental) signing.

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    env::{self, VarError},
    sync::{Arc, Mutex, RwLock},
    time::Instant,
};

use bytes::Bytes;
use domain::{
    base::{CanonicalOrd, Record, RelativeName, Serial, name::FlattenInto},
    dnssec::sign::{
        denial::{
            config::DenialConfig,
            nsec::GenerateNsecConfig,
            nsec3::{GenerateNsec3Config, Nsec3ParamTtlMode, Nsec3Records, generate_nsec3s},
        },
        error::SigningError,
        keys::keyset::KeyType,
        records::RecordsIter,
        signatures::rrsigs::GenerateRrsigConfig,
    },
    rdata::{Nsec3param, dnssec::Timestamp},
    zonefile::inplace::{Entry, Zonefile},
};
use domain::{
    dnssec::sign::{
        SigningConfig, denial::nsec::generate_nsecs, keys::keyset::UnixTime,
        signatures::rrsigs::sign_sorted_zone_records,
    },
    new::{
        base::{RType, SoaSerial as NewBaseSerial},
        rdata::RecordData,
    },
};
use domain_kmip::dep::kmip::client::pool::SyncConnPool;
use rayon::{
    iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelExtend, ParallelIterator},
    slice::ParallelSliceMut,
};
use tracing::{debug, info, trace};

use crate::{
    hsm::HsmStore,
    policy::{PolicyVersion, SignerDenialPolicy},
    signer::{
        incremental::LocalState,
        keys::ZoneSigningKeys,
        status::{SigningStatusPerZone, ZoneSigningStatus},
    },
    units::zone_signer::{KeySetState, MinTimestamp, SignerError},
    zonedata::{OldRecord, RegularRecord, SignedZoneBuilder},
};

#[expect(clippy::too_many_arguments)] // TODO
pub fn sign_zone(
    config: &crate::config::Config,
    zone_name: &domain::base::Name<Bytes>,
    policy: &PolicyVersion,
    hsm_store: &HsmStore,
    kmip_servers: &Mutex<HashMap<String, SyncConnPool>>,
    builder: &mut SignedZoneBuilder,
    local_state: &mut LocalState,
    keyset_state: KeySetState,
    status: Arc<RwLock<SigningStatusPerZone>>,
) -> Result<(), SignerError> {
    info!("Starting signing operation for zone '{zone_name}'");
    let start = Instant::now();

    let previous_serial = local_state.previous_serial;

    //
    // Lookup the zone to sign.
    //
    let mut writer = builder.replace().unwrap();
    let mut new_records = Vec::new();
    let loaded = writer
        .next_loaded()
        .or(writer.curr_loaded())
        .expect("a non-empty loaded instance must exist");
    let loaded_serial = loaded.soa().rdata.serial;

    let serial = super::next_signed_soa_serial(
        policy.signer.serial_policy,
        Serial::from(loaded_serial.get()),
        previous_serial,
    )?;

    local_state.previous_serial = Some(serial);
    let serial = NewBaseSerial::from(serial.into_int());
    let new_soa = {
        let mut soa = loaded.soa().clone();
        soa.rdata.serial = serial;
        soa
    };
    new_records.push(new_soa.clone().into());

    info!(
        "Serials for zone '{zone_name}': last signed={previous_serial:?}, current={loaded_serial}, serial policy={}, new={serial}",
        policy.signer.serial_policy
    );

    //
    // Record the start of signing for this zone.
    //
    {
        status
            .write()
            .unwrap()
            .status
            .start(loaded_serial)
            .map_err(|_| SignerError::InternalError("Invalid status".to_string()))?;
    }

    //
    // Create a signing configuration.
    //
    let signing_config = signing_config(policy)?;
    let rrsig_cfg = GenerateRrsigConfig::new(signing_config.inception, signing_config.expiration);

    //
    // Convert zone records into a form we can sign.
    //
    status.write().unwrap().current_action = "Collecting records to sign".to_string();
    debug!("Collecting records to sign for zone '{zone_name}'.");
    let walk_start = Instant::now();
    let mut records = loaded
        .unsigned_records()
        .filter(|r| r.rname != new_soa.rname || r.rtype != new_soa.rtype)
        .cloned()
        .map(OldRecord::from)
        .collect::<Vec<_>>();
    records.push(new_soa.clone().into());
    let walk_time = walk_start.elapsed();
    let unsigned_rr_count = records.len();

    {
        let mut v = status.write().unwrap();
        let v2 = &mut v.status;
        if let ZoneSigningStatus::InProgress(s) = v2 {
            s.unsigned_rr_count = Some(unsigned_rr_count);
            s.walk_time = Some(walk_time);
        }
    }

    local_state.apex_remove = keyset_state.apex_remove.clone();
    let mut apex_extra = keyset_state.apex_extra.clone();
    apex_extra.sort();
    local_state.apex_extra = apex_extra;

    for rr in &keyset_state.apex_extra {
        let mut zonefile = Zonefile::new();
        zonefile.extend_from_slice(rr.as_bytes());
        zonefile.extend_from_slice(b"\n");
        if let Ok(Some(Entry::Record(rec))) = zonefile.next_entry() {
            let record: OldRecord = rec.flatten_into();
            new_records.push(record.clone().into());
            records.push(record);
        }
    }

    debug!("Loading dnst keyset signing keys");
    // Load the signing keys indicated by the keyset state.
    let signing_keys = ZoneSigningKeys::load(
        config,
        zone_name,
        hsm_store,
        kmip_servers,
        &keyset_state,
        &status,
    )?;

    // Save the current zone signing keys and clear key_roll
    let mut key_tags = HashSet::new();
    for v in keyset_state.keyset.keys().values() {
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
    local_state.key_tags = key_tags;
    local_state.key_roll = None;

    //
    // Sort them into DNSSEC order ready for NSEC(3) generation.
    //
    debug!("Sorting collected records for zone '{zone_name}'.");
    status.write().unwrap().current_action = "Sorting records".to_string();
    let sort_start = Instant::now();
    // Note: This may briefly use lots of CPU and many CPU cores.
    records.par_sort_by(CanonicalOrd::canonical_cmp);
    let sort_time = sort_start.elapsed();
    let unsigned_rr_count = records.len();

    {
        let mut v = status.write().unwrap();
        let v2 = &mut v.status;
        if let ZoneSigningStatus::InProgress(s) = v2 {
            s.sort_time = Some(sort_time);
        }
    }

    //
    // Generate NSEC(3) RRs.
    //
    debug!("Generating denial records for zone '{zone_name}'.");
    status.write().unwrap().current_action = "Generating denial records".to_string();
    let denial_start = Instant::now();
    match &signing_config.denial {
        DenialConfig::AlreadyPresent => {}

        DenialConfig::Nsec(cfg) => {
            let nsecs = generate_nsecs(zone_name, RecordsIter::new_from_owned(&records), cfg)
                .map_err(|err: SigningError| {
                    SignerError::SigningError(format!("Failed to generate denial RRs: {err}"))
                })?;

            new_records.par_extend(
                nsecs
                    .par_iter()
                    .map(|r| OldRecord::from_record(r.clone()).into()),
            );
            records.par_extend(nsecs.into_par_iter().map(Record::from_record));
        }

        DenialConfig::Nsec3(cfg) => {
            // RFC 5155 7.1 step 5: "Sort the set of NSEC3 RRs into hash
            // order." We store the NSEC3s as we create them and sort them
            // afterwards.
            let Nsec3Records { nsec3s, nsec3param } =
                generate_nsec3s(zone_name, RecordsIter::new_from_owned(&records), cfg).map_err(
                    |err: SigningError| {
                        SignerError::SigningError(format!("Failed to generate denial RRs: {err}"))
                    },
                )?;

            // Add the generated NSEC3 records.
            new_records.par_extend(
                nsec3s
                    .par_iter()
                    .map(|r| OldRecord::from_record(r.clone()).into()),
            );
            new_records.push(OldRecord::from_record(nsec3param.clone()).into());
            records.par_extend(nsec3s.into_par_iter().map(Record::from_record));
            records.push(Record::from_record(nsec3param));
        }
    }
    // Use a stable sort; the stable sort algorithm detects runs of sorted
    // elements ('records' contains two concatenated pre-sorted runs) and
    // can efficiently sort around them.
    records.par_sort_by(CanonicalOrd::canonical_cmp);

    let unsigned_records = records;
    let denial_time = denial_start.elapsed();
    let denial_rr_count = unsigned_records.len() - unsigned_rr_count;

    {
        let mut v = status.write().unwrap();
        let v2 = &mut v.status;
        if let ZoneSigningStatus::InProgress(s) = v2 {
            s.denial_rr_count = Some(denial_rr_count);
            s.denial_time = Some(denial_time);
        }
    }

    //
    // Generate RRSIG RRs concurrently.
    //
    // Use N concurrent Rayon scoped threads to do blocking RRSIG
    // generation without interfering with Tokio task scheduling, and an
    // async task which receives generated RRSIGs via a Tokio
    // mpsc::channel and accumulates them into the signed zone.
    //
    debug!("Generating RRSIG records.");
    status.write().unwrap().current_action = "Generating signature records".to_string();

    // TODO: Configure Rayon's thread pool to set the number of threads. By
    // default, it relies on 'std::thread::available_parallelism()'.
    let parallelism = rayon::current_num_threads();

    {
        let mut v = status.write().unwrap();
        let v2 = &mut v.status;
        if let ZoneSigningStatus::InProgress(s) = v2 {
            s.threads_used = Some(parallelism);
        }
    }

    let generation_start = Instant::now();

    // Get the keys to sign with.  Domain's 'sign_sorted_zone_records()'
    // needs a slice of references, so we need to build that here.
    let keys = signing_keys.list.iter().collect::<Vec<_>>();

    // Sign the records in parallel.
    //
    // Records are split at top-level labels within the zone (e.g. between
    // `foo.example.org` and `bar.example.org` in the `example.org` zone); for
    // TLDs, which are by far the largest zones, this will result in many small
    // chunks which can be signed in parallel. Signing considerations do not
    // cross these boundaries; e.g. a zone cut (an `NS` record) in one top-level
    // name does not affect any other.

    // Split the records into segments.
    let segments = rayon::iter::split(0..unsigned_records.len(), |range| {
        // Stop splitting if the chunk is too small.
        //
        // Reduce the chunk size for tests so that small zones exercise the
        // splitting code.
        const MIN_CHUNK_SIZE: usize = if cfg!(test) { 4 } else { 1024 };
        if range.len() < MIN_CHUNK_SIZE {
            return (range, None);
        }

        // Find a top-level label boundary close to the midpoint.
        //
        // We could search _around_ the exact midpoint rather than right after
        // it, but there's no significant advantage to this. Most top-level
        // labels (in big zones) will have few records.
        let midpoint = range.start + range.len() / 2;
        let mut prev_top_level_label = None;
        let midpoint = unsigned_records[midpoint..range.end]
            .iter()
            // Extract the top-level label within the zone. If the record is at
            // the zone apex, store 'Some(None)'. If the record falls outside
            // the zone, store 'None'.
            .map(|r| {
                // This is mostly complicated due to borrowing issues.
                r.owner()
                    .for_slice()
                    .for_ref()
                    .strip_suffix(zone_name)
                    .ok()
                    .map(|rn| RelativeName::from_slice(rn.into_octets()).unwrap().last())
            })
            // Find the first position where the extracted values differ between
            // adjacent pairs of records. This will return true if and only if:
            // 1. The records are both within the zone and differ in their
            //    top-level labels.
            // 2. The latter record falls outside the zone. (The former record
            //    could not have fallen outside the zone, since if it did,
            //    '.position()' would have terminated already.)
            // We do not generate signatures for records outside the zone, so we
            // allow splitting anywhere within them.
            .position(|top_level_label| {
                // If this record falls outside the zone, stop immediately.
                let Some(curr) = top_level_label else {
                    return true;
                };

                // Retrieve the previous top-level label, and update it for the
                // next iteration.
                let prev = prev_top_level_label.replace(curr);

                // If there was no previous top-level label (i.e. this is the
                // first iteration), don't split here.
                let Some(prev) = prev else {
                    return false;
                };

                // Allow splitting here if the adjacent top-level labels differ.
                prev != curr
            })
            .map(|pos| midpoint + pos);

        // If we could not find a useful midpoint, give up. This should be
        // very rare, since `range` will cover many records.
        let Some(midpoint) = midpoint else {
            trace!("Could not find a useful midpoint");
            return (range, None);
        };

        // Split the records at this midpoint. The record *at* the midpoint
        // has a different top-level label from the record *before* it.
        let left = range.start..midpoint;
        let right = midpoint..range.end;
        (left, Some(right))
    });

    // Generate signatures from each segment.
    let signatures = segments.map(|range| {
        sign_sorted_zone_records(
            zone_name,
            RecordsIter::new_from_owned(&unsigned_records[range]),
            &keys,
            &rrsig_cfg,
        )
    });

    // Convert the signatures into new-base types and collect them together. If
    // errors occur, one error is arbitrarily chosen and returned.
    let signatures: Vec<RegularRecord> = signatures
        .try_fold(Vec::new, |mut a, b| {
            a.extend(b?.into_iter().map(|r| OldRecord::from_record(r).into()));
            Ok::<_, SigningError>(a)
        })
        .try_reduce(Vec::new, |mut a, mut b| {
            a.append(&mut b);
            Ok(a)
        })
        .map_err(|err| SignerError::SigningError(err.to_string()))?;

    let total_signatures = signatures.len();

    new_records.extend(signatures);
    new_records.par_sort();
    writer.set_records(new_records).unwrap();

    let generation_time = generation_start.elapsed();

    let generation_rate = total_signatures as f64 / generation_time.as_secs_f64().min(0.001);

    writer.set_soa(new_soa.clone()).unwrap();
    writer.apply().unwrap();

    debug!("Determining min expiration time");
    let reader = builder.next_signed().unwrap();
    let min_expiration = Arc::new(MinTimestamp::new());
    let saved_min_expiration = min_expiration.clone();
    for record in reader.generated_records() {
        let RecordData::Rrsig(sig) = record.rdata.get() else {
            continue;
        };

        // Ignore RRSIG records for DNSKEY, CDS, and CDNSKEY records; these
        // are generated by the key manager, using KSKs.
        if sig.rtype == RType::DNSKEY
            || sig.rtype == RType::from(59)
            || sig.rtype == RType::from(60)
        {
            continue;
        }

        min_expiration.add(u32::from(sig.expiration).into());
    }
    local_state.next_min_expiration = saved_min_expiration.get();

    local_state.last_signature_refresh = UnixTime::now();

    let total_time = start.elapsed();

    {
        let mut v = status.write().unwrap();
        let v2 = &mut v.status;
        if let ZoneSigningStatus::InProgress(s) = v2 {
            s.rrsig_count = Some(total_signatures);
            s.rrsig_reused_count = Some(0); // Not implemented yet
            s.rrsig_time = Some(generation_time);
            s.total_time = Some(total_time);
        }
        v.status.finish(true);
    }

    // Log signing statistics.
    info!(
        "Signing statistics for {zone_name} serial: {serial}:\n\
        Collected {unsigned_rr_count} records in {:.1}s, sorted in {:.1}s\n\
        Generated {denial_rr_count} NSEC(3) records in {:.1}s\n\
        Generated {total_signatures} signatures in {:.1}s ({generation_rate:.0}sig/s)
        Took {:.1}s in total, using {parallelism} threads",
        walk_time.as_secs_f64(),
        sort_time.as_secs_f64(),
        denial_time.as_secs_f64(),
        generation_time.as_secs_f64(),
        total_time.as_secs_f64()
    );

    Ok(())
}

//----------- signing_config() -------------------------------------------------

fn signing_config(
    policy: &PolicyVersion,
) -> Result<SigningConfig<Bytes, MultiThreadedSorter>, SignerError> {
    let denial = match &policy.signer.denial {
        SignerDenialPolicy::NSec => {
            DenialConfig::Nsec(GenerateNsecConfig::new().without_assuming_dnskeys_will_be_added())
        }
        SignerDenialPolicy::NSec3 { opt_out } => {
            let first = parse_nsec3_config(*opt_out);
            DenialConfig::Nsec3(first)
        }
    };

    let now = match env::var("CASCADE_FAKETIME") {
        Ok(val) => val
            .parse::<u32>()
            .map_err(|e| SignerError::InternalError(format!("cannot parse {e} as u32")))?,
        Err(VarError::NotPresent) => Timestamp::now().into_int(),
        Err(e) => return Err(SignerError::InternalError(e.to_string())),
    };
    let inception = now.wrapping_sub(policy.signer.sig_inception_offset);
    let expiration = now.wrapping_add(policy.signer.sig_validity_time);
    Ok(SigningConfig::new(
        denial,
        inception.into(),
        expiration.into(),
    ))
}

fn parse_nsec3_config(opt_out: bool) -> GenerateNsec3Config<Bytes, MultiThreadedSorter> {
    let mut params = Nsec3param::default();
    if opt_out {
        params.set_opt_out_flag()
    }

    // TODO: support other ttl_modes? Seems missing from the config right now
    let ttl_mode = Nsec3ParamTtlMode::Soa;
    GenerateNsec3Config::new(params).with_ttl_mode(ttl_mode)
}

//------------ MultiThreadedSorter -------------------------------------------

/// A parallelized sort implementation for signing.
struct MultiThreadedSorter;

impl domain::dnssec::sign::records::Sorter for MultiThreadedSorter {
    fn sort_by<N, D, F>(records: &mut Vec<Record<N, D>>, compare: F)
    where
        F: Fn(&Record<N, D>, &Record<N, D>) -> Ordering + Sync,
        Record<N, D>: CanonicalOrd + Send,
    {
        records.par_sort_by(compare);
    }
}
