//! Restoring persisted zone data.

use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
    sync::Arc,
};

use cascade_zonedata::{
    DiffData, LoadedZonePatcher, LoadedZoneRestorer, RegularRecord, SignedZonePatcher,
    SignedZoneRestorer, SoaRecord,
};
use domain::{
    new::{
        base::{
            RType, Record, Serial,
            name::{NameBuf, RevNameBuf},
            parse::{ParseMessageBytes, SplitMessageBytes},
        },
        rdata::{BoxedRecordData, Soa},
    },
    utils::dst::UnsizedCopy,
};
use tracing::{info, trace};

use crate::{center::Center, zone::Zone};

/// Restore the loaded instance data of a zone.
///
/// Returns Ok(true) if data was stored, Ok(false) if there was nothing to
/// restore, or Err(..) on error.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn restore_loaded(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    restorer: &mut LoadedZoneRestorer,
) -> io::Result<bool> {
    let mut state = zone.write(center);
    if state.persisted_loaded_diff_paths.is_empty() {
        return io::Result::Ok(false);
    }

    info!("Restoring loaded zone from persisted data");
    state.storage.diffs.clear();

    // Determine the paths to read from. Each zone is persisted as an AXFR
    // plus zero or more IXFRs. The restorer takes a base path ending in an
    // unsigned integer number and loads that file plus N more, where the
    // final number in the path is replaced by the previous number plus one
    // each time.
    let loaded_source = center
        .config
        .zone_state_dir
        .join(format!("{}.loaded.0", zone.name));
    let count = state.persisted_loaded_diff_paths.len();
    let mut buf = Vec::<u8>::new();
    drop(state);

    // Process the initial "loaded" AXFR wire format dump.
    let (soa, records) =
        load_axfr_wire_dump(loaded_source.as_std_path(), &mut buf).map_err(|err| {
            io::Error::other(format!("Loading snapshot '{loaded_source}' failed: {err}"))
        })?;
    let mut loaded_replacer = restorer.fill().ok_or(io::Error::other(
        "Internal error: Could not acquire replacer".to_string(),
    ))?;
    loaded_replacer.set_soa(soa.clone()).unwrap();
    loaded_replacer.set_records(records).unwrap();
    loaded_replacer.apply().unwrap();
    trace!(
        "Restored loaded snapshot for SOA serial {} for zone '{}' from file '{loaded_source}'",
        soa.rdata.serial, zone.name
    );

    if count == 1 {
        return io::Result::Ok(true);
    }

    let mut source = loaded_source.to_path_buf();
    let mut all_serials = vec![];

    for i in 1..count {
        let mut loaded_patcher = restorer
            .patch()
            .ok_or(io::Error::other("Internal error: Patch failed".to_string()))?;
        source.set_extension(i.to_string());

        let (start_serial, end_serial) =
            load_ixfr_wire_dump(source.as_std_path(), &mut buf, |event| {
                apply_ixfr_event_to_loaded_data(&mut loaded_patcher, event);
            })
            .map_err(|err| io::Error::other(format!("Loading diff '{source}' failed: {err}",)))?;

        loaded_patcher.next_patchset().map_err(|err| {
            io::Error::other(format!("Internal error: Next patchset failed: {err}"))
        })?;

        loaded_patcher
            .apply()
            .map_err(|err| io::Error::other(format!("Internal error: Apply failed: {err}")))?;

        if let Some(diff) = restorer.take_diff() {
            // Store the loaded diff to be used as part of serving an IXFR.
            let mut state = zone.write(center);
            state
                .storage
                .diffs
                .push((diff.into(), DiffData::new().into()));

            trace!(
                "Stored IXFR loaded diff for SOA serial {} from file '{loaded_source}': serial {start_serial} -> {end_serial}",
                soa.rdata.serial,
            );
        }

        let start_serial: u32 = start_serial.into();
        let end_serial: u32 = end_serial.into();
        all_serials.push((start_serial, end_serial));
    }
    trace!(
        "Restored loaded diff for SOA serial {} for zone '{}' from file '{loaded_source}' with diff serials: {all_serials:?}",
        soa.rdata.serial, zone.name
    );

    info!("Restored loaded zone snapshot and {} diffs", count - 1);
    io::Result::Ok(true)
}

/// Restore the loaded instance data of a zone.
///
/// Returns Ok(true) if data was stored, Ok(false) if there was nothing to
/// restore, or Err(..) on error.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn restore_signed(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    restorer: &mut SignedZoneRestorer,
) -> io::Result<bool> {
    let state = zone.read();
    if state.persisted_signed_diff_paths.is_empty() {
        return io::Result::Ok(false);
    }

    // Determine the paths to read from. Each zone is persisted as an AXFR
    // plus zero or more IXFRs. The restorer takes a base path ending in an
    // unsigned integer number and loads that file plus N more, where the
    // final number in the path is replaced by the previous number plus one
    // each time.
    let signed_source = center
        .config
        .zone_state_dir
        .join(format!("{}.signed.0", zone.name));
    let count = state.persisted_signed_diff_paths.len();
    let mut buf = Vec::<u8>::new();
    drop(state);

    // Process the initial "signed" AXFR wire format dump.
    let (soa, records) =
        load_axfr_wire_dump(signed_source.as_std_path(), &mut buf).map_err(|err| {
            io::Error::other(format!(
                "Loading snapshot from '{signed_source}' failed: {err}"
            ))
        })?;
    let mut signed_replacer = restorer.fill().ok_or(io::Error::other(
        "Internal error: Could not acquire replacer".to_string(),
    ))?;
    signed_replacer.set_soa(soa.clone()).unwrap();
    signed_replacer.set_records(records).unwrap();
    signed_replacer.apply().unwrap();
    trace!(
        "Restored signed snapshot for SOA serial {} for zone '{}' from file '{signed_source}'",
        soa.rdata.serial, zone.name
    );

    if count == 1 {
        return io::Result::Ok(true);
    }

    // Process zero or more "signed" IXFR wire format dumps.
    let mut source = signed_source.to_path_buf();
    let mut all_serials = vec![];

    // Load each diff and apply it to the zone, retrieving a single DiffData
    // per signed diff. Store each signed DiffData alongside the corresponding
    // loaded DiffData that was restored earlier in restore_loaded(). These
    // DiffData's will be used to respond to IXFR requests, while at the same
    // time also building up the entire signed zone that should be served for
    // AXFR requests.
    for i in 1..count {
        let mut signed_patcher = restorer
            .patch()
            .ok_or(io::Error::other("Internal error: Patch failed".to_string()))?;
        source.set_extension(i.to_string());

        let (start_serial, end_serial) =
            load_ixfr_wire_dump(source.as_std_path(), &mut buf, |event| {
                apply_ixfr_event_to_signed_data(&mut signed_patcher, event);
            })
            .map_err(|err| io::Error::other(format!("Loading diff '{source}' failed: {err}")))?;

        signed_patcher.next_patchset().map_err(|err| {
            io::Error::other(format!("Internal error: Next patchset failed: {err}"))
        })?;

        signed_patcher
            .apply()
            .map_err(|err| io::Error::other(format!("Internal error: Apply failed: {err}")))?;

        if let Some(signed_diff) = restorer.take_diff() {
            let mut state = zone.write(center);
            // Get the diff pair (loaded diff and missing signed diff) that
            // this signed diff needs to be inserted into. If the signed diff
            // was caused by incremental signing then a loaded diff won't have
            // been available to restore, we need to use an empty loaded diff
            // in that case.
            if let Some(partial_diff) = state.storage.diffs.get_mut(i - 1) {
                // Insert the signed diff alongside the loaded diff, unless
                // the signed diff already unexpectedly exists.
                assert!(partial_diff.1.is_empty());
                partial_diff.1 = signed_diff.into();
                trace!(
                    "Updated signed part of IXFR in-memory diff for SOA loaded serial -{:?}:+{:?} -> signed serial -{:?}:+{:?} from file '{signed_source}'",
                    partial_diff
                        .0
                        .removed_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                    partial_diff
                        .0
                        .added_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                    partial_diff
                        .1
                        .removed_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                    partial_diff
                        .1
                        .added_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                );
            } else {
                let loaded_diff = Arc::new(DiffData::new());
                trace!(
                    "Storing IXFR in-memory diff for SOA loaded serial -{:?}:+{:?} -> signed serial -{:?}:+{:?} from file '{signed_source}'",
                    loaded_diff
                        .removed_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                    loaded_diff
                        .added_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                    signed_diff
                        .removed_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                    signed_diff
                        .added_soa
                        .as_ref()
                        .map(|soa_rr| soa_rr.rdata.serial),
                );
                state.storage.diffs.push((loaded_diff, signed_diff.into()));
            }
        }

        let start_serial: u32 = start_serial.into();
        let end_serial: u32 = end_serial.into();
        all_serials.push((start_serial, end_serial));
    }
    trace!(
        "Restored signed diff for SOA serial {} for zone '{}' from file '{signed_source}' with diff serials: {all_serials:?}",
        soa.rdata.serial, zone.name
    );

    info!("Restored signed zone snapshot and {} diffs", count - 1);
    io::Result::Ok(true)
}

fn parse_rr(
    buf: &[u8],
    pos: usize,
) -> Result<(Record<RevNameBuf, BoxedRecordData>, usize), String> {
    Record::<RevNameBuf, BoxedRecordData>::split_message_bytes(buf, pos)
        .map_err(|err| format!("Invalid wire format RR: {err}"))
}

fn parse_soa(buf: &[u8], pos: usize) -> Result<(SoaRecord, Soa<NameBuf>, usize), String> {
    let (first_rr, rest) = Record::<RevNameBuf, Soa<NameBuf>>::split_message_bytes(buf, pos)
        .map_err(|err| {
            format!("Failed to parse record of persisted XFR dump as a SOA record: {err}")
        })?;

    if first_rr.rtype != RType::SOA {
        return Err(format!(
            "Persisted XFR dump record has RTYPE '{}' which is not a SOA RR.",
            first_rr.rtype.code
        ));
    }

    // Save the SOA rdata for comparison later, before we convert it from
    // using NameBuf typed fields to having Box<Name> typed fields (which
    // is the format we store resource records in longer term in memory).
    let soa_rdata = first_rr.rdata.clone();
    let soa_rr = SoaRecord(first_rr.transform_ref(
        |name: &RevNameBuf| (*name).unsized_copy_into(),
        |data: &Soa<NameBuf>| data.map_names_by_ref(|name| (*name).unsized_copy_into()),
    ));

    Ok((soa_rr, soa_rdata, rest))
}

fn load_file_into_memory(source: &Path, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    buf.clear();
    BufReader::new(File::open(source)?).read_to_end(buf)
}

fn load_axfr_wire_dump(
    source: &Path,
    buf: &mut Vec<u8>,
) -> io::Result<(SoaRecord, Vec<RegularRecord>)> {
    load_file_into_memory(source, buf)?;

    let (start_soa, start_soa_rdata, mut rest) = parse_soa(buf, 0).map_err(|err| {
        io::Error::other(format!(
            "Failed to parse persisted snapshot initial SOA: {err}"
        ))
    })?;

    let mut records = vec![];
    loop {
        // Parse remaining resource records from the current read
        // index in the buffer, each time receiving back the 'rest'
        // index at which parsing should start on the next iteration
        // of the loop.
        let r;
        (r, rest) = parse_rr(buf, rest).map_err(|err| {
            io::Error::other(format!(
                "Failed to parse persisted snapshot resource record at pos {rest}: {err}"
            ))
        })?;

        // If the parsed record is a SOA it should be identical to
        // the SOA record that started the AXFR dump and signals the
        // end of the dump.
        //
        // TODO: If the SOA is not at the apex should we keep it and
        // keep going?
        if r.rtype == RType::SOA {
            // An AXFR ends with a SOA RR identical to the start SOA.
            // Since we persisted the AXFR wire dump to disk it is a
            // very unexpected error if it does not match the starting
            // SOA.
            if (r.rname.as_ref() == &*start_soa.0.rname
                || r.rclass == start_soa.0.rclass
                || r.ttl == start_soa.ttl)
                && let Ok(soa_rdata) = Soa::<NameBuf>::parse_message_bytes(r.rdata.bytes(), 0)
                && soa_rdata == start_soa_rdata
            {
                break;
            }
        }

        let r = r.transform(|name| name.unsized_copy_into(), |data| data);
        records.push(RegularRecord(r));
    }

    Ok((start_soa, records))
}

fn load_ixfr_wire_dump<F>(
    source: &Path,
    buf: &mut Vec<u8>,
    mut rr_handler: F,
) -> io::Result<(Serial, Serial)>
where
    F: FnMut(IxfrEvent),
{
    load_file_into_memory(source, buf)?;

    let buf = buf.as_slice();
    let (start_soa, start_soa_rdata, mut rest) = parse_soa(buf, 0).map_err(|err| {
        io::Error::other(format!("Failed to parse persisted diff initial SOA: {err}"))
    })?;

    let mut oldest_soa = None;

    // Parse one or more diff sequences.
    loop {
        // Parse one diff sequence:
        //   "Each difference sequence represents one update to the
        //    zone (one SOA serial change) consisting of deleted RRs
        //    and added RRs.  The first RR of the deleted RRs is the
        //    older SOA RR and the first RR of the added RRs is the
        //    newer SOA RR."
        // Iterate over a sequence of resource records to remove
        // followed by a sequence of resource records to add,

        // Read the first deleted RR which should be a SOA RR.
        let r;
        (r, rest) = parse_rr(buf, rest).map_err(|err| {
            io::Error::other(format!(
                "Failed to parse persisted diff resource record at pos {rest}: {err}"
            ))
        })?;

        if r.rtype != RType::SOA {
            // If this is the first RR of the sequence it MUST
            // be a SOA RR.
            return Err(io::Error::other(format!(
                "Expected first record of persisted diff remove sequence to be a SOA RR but found RTYPE {}",
                r.rtype.code
            )));
        }

        if oldest_soa.is_none() {
            let soa = Soa::<NameBuf>::parse_message_bytes(r.rdata.bytes(), 0).unwrap();
            oldest_soa = Some(soa);
        }

        let r = RegularRecord(r.transform(|name| name.unsized_copy_into(), |data| data));
        rr_handler(IxfrEvent::Remove(r));

        // Read more removed RRs until a SOA signals the end of the
        // removed RRs and the start of the added RRs.
        loop {
            let r;
            (r, rest) = parse_rr(buf, rest).map_err(|err| {
                io::Error::other(format!(
                    "Failed to parse persisted diff removed resource record at pos {rest}: {err}"
                ))
            })?;

            let r = RegularRecord(r.transform(|name| name.unsized_copy_into(), |data| data));
            if r.rtype == RType::SOA {
                rr_handler(IxfrEvent::Add(r));
                break;
            } else {
                rr_handler(IxfrEvent::Remove(r));
            }
        }

        // Read more added RRs until a SOA signals the end of added RRs.
        loop {
            let r;
            (r, rest) = parse_rr(buf, rest).map_err(|err| {
                io::Error::other(format!(
                    "Failed to parse persisted diff added resource record at pos {rest}: {err}"
                ))
            })?;

            let r =
                RegularRecord(r.transform(|name| name.unsized_copy_into(), |data| data.clone()));
            if r.rtype == RType::SOA {
                if is_same_soa(&start_soa, &start_soa_rdata, &r) {
                    // This SOA signals the end of the IXFR dump.
                    return Ok((oldest_soa.unwrap().serial, start_soa.rdata.serial));
                }

                rr_handler(IxfrEvent::EndOfUpdate);
                rr_handler(IxfrEvent::Remove(r));
                break;
            } else {
                rr_handler(IxfrEvent::Add(r));
            }
        }
    }
}

fn is_same_soa(start_soa: &SoaRecord, start_soa_rdata: &Soa<NameBuf>, r: &RegularRecord) -> bool {
    if (r.rtype == RType::SOA
        && r.rname.as_ref() == &*start_soa.0.rname
        && r.rclass == start_soa.0.rclass
        && r.ttl == start_soa.ttl)
        && let Ok(soa_rdata) = Soa::<NameBuf>::parse_message_bytes(r.rdata.bytes(), 0)
    {
        return &soa_rdata == start_soa_rdata;
    }
    false
}

enum IxfrEvent {
    Remove(RegularRecord),
    Add(RegularRecord),
    EndOfUpdate,
}

fn apply_ixfr_event_to_loaded_data(patcher: &mut LoadedZonePatcher<'_>, event: IxfrEvent) {
    match event {
        IxfrEvent::Remove(r) if r.rtype == RType::SOA => patcher.remove_soa(r.into()).unwrap(),
        IxfrEvent::Remove(r) => patcher.remove(r).unwrap(),
        IxfrEvent::Add(r) if r.rtype == RType::SOA => patcher.add_soa(r.into()).unwrap(),
        IxfrEvent::Add(r) => patcher.add(r).unwrap(),
        IxfrEvent::EndOfUpdate => patcher.next_patchset().unwrap(),
    }
}

fn apply_ixfr_event_to_signed_data(patcher: &mut SignedZonePatcher<'_>, event: IxfrEvent) {
    match event {
        IxfrEvent::Remove(r) if r.rtype == RType::SOA => patcher.remove_soa(r.into()).unwrap(),
        IxfrEvent::Remove(r) => patcher.remove(r).unwrap(),
        IxfrEvent::Add(r) if r.rtype == RType::SOA => patcher.add_soa(r.into()).unwrap(),
        IxfrEvent::Add(r) => patcher.add(r).unwrap(),
        IxfrEvent::EndOfUpdate => patcher.next_patchset().unwrap(),
    }
}
