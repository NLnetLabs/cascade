//! Full (non-incremental) signing.

use std::{
    cmp::Ordering,
    collections::HashSet,
    env::{self, VarError},
    sync::{Arc, RwLock},
    time::Instant,
};

use bytes::Bytes;
use cascade_zonedata::{OldRecord, RegularRecord, SignedZoneBuilder};
use domain::{
    base::{CanonicalOrd, Record, Serial, name::FlattenInto},
    dnssec::sign::{
        denial::{
            config::DenialConfig,
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
        base::{RType, Serial as NewBaseSerial},
        rdata::RecordData,
    },
    rdata::ZoneRecordData,
};
use jiff::{Timestamp as JiffTimestamp, Zoned, tz::TimeZone};
use rayon::{
    iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelExtend, ParallelIterator},
    slice::ParallelSliceMut,
};
use tracing::{debug, info};

use crate::{
    center::Center,
    manager::record_zone_event,
    policy::{PolicyVersion, SignerDenialPolicy, SignerSerialPolicy},
    signer::{
        SigningTrigger,
        incremental::LocalState,
        keys::ZoneSigningKeys,
        status::{SigningStatusPerZone, ZoneSigningStatus},
    },
    units::{
        key_manager::mk_dnst_keyset_state_file_path,
        zone_signer::{KeySetState, MinTimestamp, SignerError},
    },
    zone::{HistoricalEvent, Zone},
};

pub fn sign_zone(
    center: &Arc<Center>,
    zone: &Arc<Zone>,
    builder: &mut SignedZoneBuilder,
    trigger: SigningTrigger,
    status: Arc<RwLock<SigningStatusPerZone>>,
) -> Result<(), SignerError> {
    let zone_name = &zone.name;

    info!("[ZS]: Starting signing operation for zone '{zone_name}'");
    let start = Instant::now();

    let mut local_state = LocalState::new(zone)?;

    let policy = {
        // Use a block to make sure that the lock is clearly dropped.
        let zone_state = zone.read();

        zone_state.policy.clone().unwrap()
    };
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

    let serial: Serial = match policy.signer.serial_policy {
        SignerSerialPolicy::Keep => {
            let loaded_serial = Serial::from(Into::<u32>::into(loaded_serial));
            if let Some(previous_serial) = previous_serial
                && loaded_serial <= previous_serial
            {
                return Err(SignerError::KeepSerialPolicyViolated);
            }

            loaded_serial
        }
        SignerSerialPolicy::Counter => {
            // Always increment the serial number, ignore the serial
            // number in the unsigned zone.
            let previous_serial = previous_serial.unwrap_or(Serial::from(0));
            previous_serial.add(1)
        }
        SignerSerialPolicy::UnixTime => {
            let mut serial = Serial::now();
            if let Some(previous_serial) = previous_serial
                && serial <= previous_serial
            {
                serial = previous_serial.add(1);
            }

            serial
        }
        SignerSerialPolicy::DateCounter => {
            let ts = JiffTimestamp::now();
            let zone = Zoned::new(ts, TimeZone::UTC);
            let serial =
                ((zone.year() as u32 * 100 + zone.month() as u32) * 100 + zone.day() as u32) * 100;
            let mut serial: Serial = serial.into();

            if let Some(previous_serial) = previous_serial
                && serial <= previous_serial
            {
                serial = previous_serial.add(1);
            }

            serial
        }
    };
    local_state.previous_serial = Some(serial);
    let serial = NewBaseSerial::from(serial.into_int());
    let new_soa = {
        let mut soa = loaded.soa().clone();
        soa.rdata.serial = serial;
        soa
    };
    new_records.push(new_soa.clone().into());

    info!(
        "[ZS]: Serials for zone '{zone_name}': last signed={previous_serial:?}, current={loaded_serial}, serial policy={}, new={serial}",
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
    let signing_config = signing_config(&policy)?;
    let rrsig_cfg = GenerateRrsigConfig::new(signing_config.inception, signing_config.expiration);

    //
    // Convert zone records into a form we can sign.
    //
    status.write().unwrap().current_action = "Collecting records to sign".to_string();
    debug!("[ZS]: Collecting records to sign for zone '{zone_name}'.");
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

    debug!("Reading dnst keyset DNSKEY RRs and RRSIG RRs");
    status.write().unwrap().current_action = "Fetching apex RRs from the key manager".to_string();
    // Read the DNSKEY RRs and DNSKEY RRSIG RR from the keyset state.
    let state_path = mk_dnst_keyset_state_file_path(&center.config.keys_dir, &zone.name);
    let state = std::fs::read_to_string(&state_path)
        .map_err(|_| SignerError::CannotReadStateFile(state_path.into_string()))?;
    let state: KeySetState = serde_json::from_str(&state).unwrap();

    local_state.apex_remove = state.apex_remove.clone();
    let mut apex_extra = state.apex_extra.clone();
    apex_extra.sort();
    local_state.apex_extra = apex_extra;

    for rr in &state.apex_extra {
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
    let signing_keys = ZoneSigningKeys::load(center, zone, &state, &status)?;

    // Save the current zone signing keys and clear key_roll
    let mut key_tags = HashSet::new();
    for v in state.keyset.keys().values() {
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
    debug!("[ZS]: Sorting collected records for zone '{zone_name}'.");
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
    debug!("[ZS]: Generating denial records for zone '{zone_name}'.");
    status.write().unwrap().current_action = "Generating denial records".to_string();
    let denial_start = Instant::now();
    match &signing_config.denial {
        DenialConfig::AlreadyPresent => {}

        DenialConfig::Nsec(cfg) => {
            let nsecs = generate_nsecs(&zone.name, RecordsIter::new_from_owned(&records), cfg)
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
                generate_nsec3s(&zone.name, RecordsIter::new_from_owned(&records), cfg).map_err(
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
    debug!("[ZS]: Generating RRSIG records.");
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

    // TODO: This generation code is incorrect; 'sign_sorted_zone_records'
    // looks for zone cuts, but zone cuts may need to be detected _across_
    // the segments we split the records into. Zone cut detection needs to
    // be re-implemented here with parallel execution in mind. This also
    // applies to NSEC(3) generation, but it is currently single-threaded.

    // Disable parallel signing for now. This may also split RRsets.
    let signatures = if false {
        // Split the records into segments.
        let segments = rayon::iter::split(0..unsigned_records.len(), |range| {
            // Always sign at least 1024 records at a time.
            if range.len() < 1024 {
                return (range, None);
            }

            let midpoint = range.start + range.len() / 2;
            let left = range.start..midpoint;
            let right = midpoint..range.end;
            (left, Some(right))
        });

        // Generate signatures from each segment.
        let signatures = segments.map(|range| {
            sign_sorted_zone_records(
                &zone.name,
                RecordsIter::new_from_owned(&unsigned_records[range]),
                &keys,
                &rrsig_cfg,
            )
        });

        // Convert the signatures into new-base types and collect them together.
        // If errors occur, one error is arbitrarily chosen and returned.
        signatures
            .try_fold(Vec::new, |mut a, b| {
                a.extend(b?.into_iter().map(|r| OldRecord::from_record(r).into()));
                Ok::<_, SigningError>(a)
            })
            .try_reduce(Vec::new, |mut a, mut b| {
                a.append(&mut b);
                Ok(a)
            })
            .map_err(|err| SignerError::SigningError(err.to_string()))?
    } else {
        let signatures = sign_sorted_zone_records(
            &zone.name,
            RecordsIter::new_from_owned(&unsigned_records),
            &keys,
            &rrsig_cfg,
        )
        .map_err(|err| SignerError::SigningError(err.to_string()))?;
        let signatures: Vec<RegularRecord> = signatures
            .into_iter()
            .map(|s| {
                let r = Record::new(
                    s.owner().clone(),
                    s.class(),
                    s.ttl(),
                    ZoneRecordData::Rrsig(s.data().clone()),
                );
                r.into()
            })
            .collect();
        signatures
    };

    let total_signatures = signatures.len();

    new_records.extend(signatures);
    new_records.par_sort();
    writer.set_records(new_records).unwrap();

    let generation_time = generation_start.elapsed();

    let generation_rate = total_signatures as f64 / generation_time.as_secs_f64().min(0.001);

    writer.set_soa(new_soa.clone()).unwrap();
    writer.apply().unwrap();

    debug!("SIGNER: Determining min expiration time");
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

    record_zone_event(
        center,
        zone,
        HistoricalEvent::SigningSucceeded {
            trigger: trigger.into(),
        },
        Some(Serial(serial.into())),
    );

    local_state.last_signature_refresh = UnixTime::now();
    local_state.save(center, zone);

    Ok(())
}

//----------- signing_config() -------------------------------------------------

fn signing_config(
    policy: &PolicyVersion,
) -> Result<SigningConfig<Bytes, MultiThreadedSorter>, SignerError> {
    let denial = match &policy.signer.denial {
        SignerDenialPolicy::NSec => DenialConfig::Nsec(Default::default()),
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
