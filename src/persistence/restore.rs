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
    // Remove any existing diffs.
    {
        let mut state = zone.write(center);
        state.storage.diffs.clear();
    }

    let state = zone.read();
    let mut paths_iter = state.persistence.loaded_diff_paths.iter();
    let Some(snapshot_path) = paths_iter.next() else {
        return io::Result::Ok(false);
    };

    info!("Restoring persisted loaded data for zone '{}'", zone.name);
    trace!(
        "Restoring from paths: {:?}",
        state.persistence.loaded_diff_paths
    );

    // Determine the paths to read from. Each zone is persisted as an AXFR
    // plus zero or more IXFRs. The restorer takes a base path ending in an
    // unsigned integer number and loads that file plus N more, where the
    // final number in the path is replaced by the previous number plus one
    // each time.
    let mut buf = Vec::<u8>::new();

    // Process the initial "loaded" AXFR wire format dump.
    let (soa, records) = load_axfr_wire_dump(snapshot_path, &mut buf).map_err(|err| {
        io::Error::other(format!(
            "Loading snapshot '{}' failed: {err}",
            snapshot_path.display()
        ))
    })?;
    let mut loaded_replacer = restorer.fill().ok_or(io::Error::other(
        "Internal error: Could not acquire replacer".to_string(),
    ))?;
    loaded_replacer.set_soa(soa.clone()).unwrap();
    loaded_replacer.set_records(records).unwrap();
    loaded_replacer.apply().unwrap();
    trace!(
        "Restored loaded snapshot for SOA serial {} for zone '{}' from file '{}'",
        soa.rdata.serial,
        zone.name,
        snapshot_path.display()
    );

    let mut all_serials = vec![];
    let mut diffs_to_store: Vec<Arc<DiffData>> = vec![];

    for diff_path in paths_iter {
        trace!(
            "Loading and applying loaded diff form '{}'",
            diff_path.display()
        );
        let mut loaded_patcher = restorer
            .patch()
            .ok_or(io::Error::other("Internal error: Patch failed".to_string()))?;

        let (start_serial, end_serial) = load_ixfr_wire_dump(diff_path, &mut buf, |event| {
            apply_ixfr_event_to_loaded_data(&mut loaded_patcher, event);
        })
        .map_err(|err| {
            io::Error::other(format!(
                "Loading diff '{}' failed: {err}",
                diff_path.display()
            ))
        })?;

        loaded_patcher.next_patchset().map_err(|err| {
            io::Error::other(format!("Internal error: Next patchset failed: {err}"))
        })?;

        loaded_patcher
            .apply()
            .map_err(|err| io::Error::other(format!("Internal error: Apply failed: {err}")))?;

        if let Some(diff) = restorer.take_diff() {
            diffs_to_store.push(diff.into());
            trace!(
                "Extracted IXFR loaded diff for SOA serial {} from file '{}': serial {start_serial} -> {end_serial}",
                soa.rdata.serial,
                diff_path.display()
            );
        }

        let start_serial: u32 = start_serial.into();
        let end_serial: u32 = end_serial.into();
        all_serials.push((start_serial, end_serial));
    }
    drop(state);

    let num_diffs_to_restore = diffs_to_store.len();
    trace!(
        "Restoring {} loaded diffs for zone {} with serials: {all_serials:?}",
        num_diffs_to_restore, zone.name
    );

    let mut state = zone.write(center);
    for diff in diffs_to_store {
        // Store the loaded diff to be used as part of serving an IXFR.
        state.storage.diffs.store_loaded_diff(diff);
    }

    info!(
        "Restored loaded zone snapshot and {num_diffs_to_restore} diffs for zone '{}'",
        zone.name
    );
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
    let mut path_infos_iter = state.persistence.signed_diff_paths.iter();
    let Some((snapshot_path, _serial)) = path_infos_iter.next() else {
        return io::Result::Ok(false);
    };

    info!("Restoring persisted signed data for zone '{}'", zone.name);
    trace!(
        "Restoring from paths: {:?}",
        state.persistence.signed_diff_paths
    );

    // Determine the paths to read from. Each zone is persisted as an AXFR
    // plus zero or more IXFRs. The restorer takes a base path ending in an
    // unsigned integer number and loads that file plus N more, where the
    // final number in the path is replaced by the previous number plus one
    // each time.
    let mut buf = Vec::<u8>::new();

    // Process the initial "signed" AXFR wire format dump.
    let (soa, records) = load_axfr_wire_dump(snapshot_path, &mut buf).map_err(|err| {
        io::Error::other(format!(
            "Loading snapshot from '{}' failed: {err}",
            snapshot_path.display()
        ))
    })?;
    let mut signed_replacer = restorer.fill().ok_or(io::Error::other(
        "Internal error: Could not acquire replacer".to_string(),
    ))?;
    signed_replacer.set_soa(soa.clone()).unwrap();
    signed_replacer.set_records(records).unwrap();
    signed_replacer.apply().unwrap();
    trace!(
        "Restored signed snapshot for SOA serial {} for zone '{}' from file '{}'",
        soa.rdata.serial,
        zone.name,
        snapshot_path.display()
    );

    let mut all_serials = vec![];
    let mut diffs_to_store: Vec<(Option<Serial>, Arc<DiffData>)> = vec![];

    // Load each diff and apply it to the zone, retrieving a single DiffData
    // per signed diff. Store each signed DiffData alongside the corresponding
    // loaded DiffData that was restored earlier in restore_loaded(). These
    // DiffData's will be used to respond to IXFR requests, while at the same
    // time also building up the entire signed zone that should be served for
    // AXFR requests.
    for (diff_path, loaded_serial) in path_infos_iter {
        trace!(
            "Loading and applying signed diff from '{}' for loaded serial {loaded_serial:?}",
            diff_path.display()
        );
        let mut signed_patcher = restorer
            .patch()
            .ok_or(io::Error::other("Internal error: Patch failed".to_string()))?;

        let (start_serial, end_serial) = load_ixfr_wire_dump(diff_path, &mut buf, |event| {
            apply_ixfr_event_to_signed_data(&mut signed_patcher, event);
        })
        .map_err(|err| {
            io::Error::other(format!(
                "Loading diff '{}' failed: {err}",
                diff_path.display()
            ))
        })?;

        signed_patcher.next_patchset().map_err(|err| {
            io::Error::other(format!("Internal error: Next patchset failed: {err}"))
        })?;

        signed_patcher
            .apply()
            .map_err(|err| io::Error::other(format!("Internal error: Apply failed: {err}")))?;

        if let Some(diff) = restorer.take_diff() {
            diffs_to_store.push((*loaded_serial, diff.into()));
            trace!(
                "Extracted IXFR signed diff for SOA serial {} from file '{}': serial {start_serial} -> {end_serial}",
                soa.rdata.serial,
                diff_path.display()
            );
        }

        let start_serial: u32 = start_serial.into();
        let end_serial: u32 = end_serial.into();
        all_serials.push((start_serial, end_serial));
    }
    drop(state);

    let num_diffs_to_restore = diffs_to_store.len();
    trace!(
        "Restoring {} signed diffs for zone {} with serials: {all_serials:?}",
        num_diffs_to_restore, zone.name
    );

    let mut state = zone.write(center);
    for (loaded_serial, diff) in diffs_to_store {
        // Store the signed diff to be used as part of serving an IXFR.
        state
            .storage
            .diffs
            .store_signed_diff(loaded_serial, diff);
    }

    info!(
        "Restored signed zone snapshot and {num_diffs_to_restore} diffs for zone '{}'",
        zone.name
    );
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
