//! Restoring persisted zone data.

use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
    sync::Arc,
};

use camino::Utf8Path;
use cascade_zonedata::{
    DiffData, LoadedZonePatcher, LoadedZoneRestorer, RegularRecord, SignedZonePatcher,
    SignedZoneRestorer, SoaRecord,
};
use domain::{
    new::{
        base::{RType, Record, SoaSerial, name::RevNameBuf, parse::ParseError, wire::SplitBytes},
        rdata::RecordData,
    },
    utils::dst::UnsizedCopy,
};
use tracing::{info, trace};

use crate::{center::Center, persistence::discard_excess_diffs, zone::Zone};

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
    let diff_infos;
    let restore_base_idx;

    // Use a block so that we don't hold the zone state lock longer than
    // necessary.
    {
        let state = zone.read();
        diff_infos = state.persistence.loaded_diffs.diffs().clone();
        restore_base_idx = state
            .persistence
            .loaded_diffs
            .first_diff_to_apply_on_restore();
    }

    let mut diff_infos_iter = diff_infos.iter();
    let Some(snapshot_path) = diff_infos_iter.next().map(|d| d.path()) else {
        return io::Result::Ok(false);
    };

    info!("Restoring persisted loaded data for zone '{}'", zone.name);
    trace!("Restoring from loaded diffs: restore_base_idx={restore_base_idx}, {diff_infos:?}");

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
    loaded_replacer.add(soa.clone().into()).unwrap();
    loaded_replacer.apply().unwrap();
    trace!(
        "Restored loaded snapshot for SOA serial {} for zone '{}' from file '{}'",
        soa.rdata.serial,
        zone.name,
        snapshot_path.display()
    );

    let mut all_serials = vec![];
    let mut diffs_to_store: Vec<Arc<DiffData>> = vec![];

    for (idx, diff_info) in diff_infos_iter.enumerate() {
        // Note: idx is zero-based but as we skipped over the first entry (the
        // snapshot) we need to add one to get a correct index.
        let (start_serial, end_serial) = if (idx + 1) < restore_base_idx {
            trace!(
                "Building standalone loaded IXFR diff #{idx} from '{}'",
                diff_info.path().display()
            );
            let mut diff = Box::new(DiffData::new());
            let (start_serial, end_serial) =
                load_ixfr_wire_dump(diff_info.path(), &mut buf, |event| {
                    apply_ixfr_event_to_diff_data(&mut diff, event);
                })
                .map_err(|err| {
                    io::Error::other(format!(
                        "Loading diff '{}' failed: {err}",
                        diff_info.path().display()
                    ))
                })?;
            diffs_to_store.push(diff.into());
            (start_serial, end_serial)
        } else {
            trace!(
                "Loading and applying loaded diff #{idx} from '{}'",
                diff_info.path().display()
            );
            let mut loaded_patcher = restorer
                .patch()
                .ok_or(io::Error::other("Internal error: Patch failed".to_string()))?;

            let (start_serial, end_serial) =
                load_ixfr_wire_dump(diff_info.path(), &mut buf, |event| {
                    apply_ixfr_event_to_loaded_data(&mut loaded_patcher, event);
                })
                .map_err(|err| {
                    io::Error::other(format!(
                        "Loading diff '{}' failed: {err}",
                        diff_info.path().display()
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
                    diff_info.path().display()
                );
            }
            (start_serial, end_serial)
        };

        let start_serial: u32 = start_serial.into();
        let end_serial: u32 = end_serial.into();
        all_serials.push((start_serial, end_serial));
    }

    let num_diffs_to_restore = diffs_to_store.len();
    trace!(
        "Restoring {num_diffs_to_restore} loaded diffs for zone {} with serials: {all_serials:?}",
        zone.name
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

/// Restore the signed instance data of a zone.
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
    let diff_infos;
    let restore_base_idx;

    // Use a block so that we don't hold the zone state lock longer than
    // necessary.
    {
        let state = zone.read();
        diff_infos = state.persistence.signed_diffs.diffs().clone();
        restore_base_idx = state
            .persistence
            .signed_diffs
            .first_diff_to_apply_on_restore();
    }

    let mut diff_infos_iter = diff_infos.iter();
    let Some(snapshot_path) = diff_infos_iter.next().map(|d| d.path()) else {
        return io::Result::Ok(false);
    };

    info!("Restoring persisted signed data for zone '{}'", zone.name);
    trace!("Restoring from signed diffs: restore_base_idx={restore_base_idx}, {diff_infos:?}",);

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
    signed_replacer.add(soa.clone().into()).unwrap();
    signed_replacer.apply().unwrap();
    trace!(
        "Restored signed snapshot for SOA serial {} for zone '{}' from file '{}'",
        soa.rdata.serial,
        zone.name,
        snapshot_path.display()
    );

    let mut all_serials = vec![];
    let mut diffs_to_store: Vec<(Option<SoaSerial>, Arc<DiffData>)> = vec![];

    // Load each diff and apply it to the zone, retrieving a single DiffData
    // per signed diff. Store each signed DiffData alongside the corresponding
    // loaded DiffData that was restored earlier in restore_loaded(). These
    // DiffData's will be used to respond to IXFR requests, while at the same
    // time also building up the entire signed zone that should be served for
    // AXFR requests. Skip diffs that were included in the snapshot during the
    // last compaction event but still need to be loaded into memory to serve
    // in IXFR responses.
    for (idx, diff_info) in diff_infos_iter.enumerate() {
        // Note: idx is zero-based but as we skipped over the first entry (the
        // snapshot) we need to add one to get a correct index.
        let (start_serial, end_serial) = if (idx + 1) < restore_base_idx {
            trace!(
                "Building standalone signed IXFR diff #{idx} from '{}'",
                diff_info.path().display()
            );
            let mut diff = Box::new(DiffData::new());
            let (start_serial, end_serial) =
                load_ixfr_wire_dump(diff_info.path(), &mut buf, |event| {
                    apply_ixfr_event_to_diff_data(&mut diff, event);
                })
                .map_err(|err| {
                    io::Error::other(format!(
                        "Loading diff '{}' failed: {err}",
                        diff_info.path().display()
                    ))
                })?;
            diffs_to_store.push((diff_info.loaded_serial(), diff.into()));
            (start_serial, end_serial)
        } else {
            trace!(
                "Loading and applying signed diff #{idx} from '{}' for loaded serial {:?}",
                diff_info.path().display(),
                diff_info.loaded_serial()
            );
            let mut signed_patcher = restorer
                .patch()
                .ok_or(io::Error::other("Internal error: Patch failed".to_string()))?;

            let (start_serial, end_serial) =
                load_ixfr_wire_dump(diff_info.path(), &mut buf, |event| {
                    apply_ixfr_event_to_signed_data(&mut signed_patcher, event);
                })
                .map_err(|err| {
                    io::Error::other(format!(
                        "Loading diff '{}' failed: {err}",
                        diff_info.path().display()
                    ))
                })?;

            signed_patcher.next_patchset().map_err(|err| {
                io::Error::other(format!("Internal error: Next patchset failed: {err}"))
            })?;

            signed_patcher
                .apply()
                .map_err(|err| io::Error::other(format!("Internal error: Apply failed: {err}")))?;

            if let Some(diff) = restorer.take_diff() {
                diffs_to_store.push((diff_info.loaded_serial(), diff.into()));
                trace!(
                    "Extracted IXFR signed diff for SOA serial {} from file '{}': serial {start_serial} -> {end_serial}",
                    soa.rdata.serial,
                    diff_info.path().display()
                );
            }
            (start_serial, end_serial)
        };

        let start_serial: u32 = start_serial.into();
        let end_serial: u32 = end_serial.into();
        all_serials.push((start_serial, end_serial));
    }

    let num_diffs_to_restore = diffs_to_store.len();
    trace!(
        "Restoring {num_diffs_to_restore} signed diffs for zone {} with serials: {all_serials:?}",
        zone.name
    );

    {
        let mut state = zone.write(center);
        for (loaded_serial, diff) in diffs_to_store {
            // Store the signed diff to be used as part of serving an IXFR.
            state.storage.diffs.store_signed_diff(loaded_serial, diff);
        }
    }

    discard_excess_diffs(center, zone);

    info!(
        "Restored signed zone snapshot and {num_diffs_to_restore} diffs for zone '{}'",
        zone.name
    );
    io::Result::Ok(true)
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
    let mut records = parse_records(buf);

    // Parse the SOA record.
    let soa = records
        .next()
        .unwrap_or(Err(ParseError))
        .map_err(|err| io::Error::other(err.to_string()))?;
    if soa.rtype != RType::SOA {
        return Err(io::Error::other(format!(
            "First record has type '{}' but should be 'SOA'",
            soa.rtype.code
        )));
    }

    let mut regular = Vec::new();
    let mut record;
    loop {
        record = records
            .next()
            .unwrap_or(Err(ParseError))
            .map_err(|err| io::Error::other(err.to_string()))?;
        if record.rtype == RType::SOA {
            break;
        }
        regular.push(record);
    }

    // Ensure the file ended with the top-level SOA.
    if record != soa {
        return Err(io::Error::other("file does not end with top-level SOA"));
    }

    // Check for trailing data.
    if records.next().is_some() {
        return Err(io::Error::other("unexpected trailing data in file"));
    }

    Ok((soa.into(), regular))
}

fn load_ixfr_wire_dump<F>(
    source: &Path,
    buf: &mut Vec<u8>,
    mut rr_handler: F,
) -> io::Result<(SoaSerial, SoaSerial)>
where
    F: FnMut(IxfrEvent),
{
    load_file_into_memory(source, buf)?;
    let mut records = parse_records(buf);

    // Parse the new SOA record.
    let top_soa = records
        .next()
        .unwrap_or(Err(ParseError))
        .map_err(|err| io::Error::other(err.to_string()))?;
    if top_soa.rtype != RType::SOA {
        return Err(io::Error::other(format!(
            "First record has type '{}' but should be 'SOA'",
            top_soa.rtype.code
        )));
    }

    // Parse the SOA record removal from the first diff sequence.
    let earliest_removed_soa = records
        .next()
        .unwrap_or(Err(ParseError))
        .map_err(|err| io::Error::other(err.to_string()))?;
    let RecordData::Soa(earliest_removed_soa_data) = earliest_removed_soa.rdata.get() else {
        return Err(io::Error::other(format!(
            "First patchset record has type '{}' but should be 'SOA'",
            earliest_removed_soa.rtype.code
        )));
    };
    let earliest_removed_serial = earliest_removed_soa_data.serial;
    let mut latest_added_soa;

    let mut next_soa = earliest_removed_soa;
    loop {
        // Parse a diff sequence.

        // The SOA record removal for this diff.
        let removed_soa = next_soa; // from the previous iteration
        (rr_handler)(IxfrEvent::Remove(removed_soa));

        // Parse regular record removals.
        let mut record;
        loop {
            record = records
                .next()
                .unwrap_or(Err(ParseError))
                .map_err(|err| io::Error::other(err.to_string()))?;
            if record.rtype == RType::SOA {
                next_soa = record;
                break;
            }

            (rr_handler)(IxfrEvent::Remove(record));
        }

        // The SOA record addition for this diff.
        let added_soa = next_soa;
        latest_added_soa = added_soa.clone();
        (rr_handler)(IxfrEvent::Add(added_soa));

        // Parse regular record additions.
        let mut record;
        loop {
            record = records
                .next()
                .unwrap_or(Err(ParseError))
                .map_err(|err| io::Error::other(err.to_string()))?;
            if record.rtype == RType::SOA {
                next_soa = record;
                break;
            }

            (rr_handler)(IxfrEvent::Add(record));
        }

        // The SOA record removal for the next diff, or the top-level SOA.
        if next_soa == top_soa {
            break;
        }
        (rr_handler)(IxfrEvent::EndOfUpdate);
        // `next_soa` gets processed in the next iteration.
    }

    // Ensure the latest added SOA matches the top-level SOA.
    if latest_added_soa != top_soa {
        return Err(io::Error::other("top-level SOA was not added by last diff"));
    }

    // Check for trailing data.
    if records.next().is_some() {
        return Err(io::Error::other("unexpected trailing data in file"));
    }

    let latest_added_serial = match latest_added_soa.rdata.get() {
        RecordData::Soa(soa) => soa.serial,
        _ => unreachable!(),
    };

    Ok((earliest_removed_serial, latest_added_serial))
}

enum IxfrEvent {
    Remove(RegularRecord),
    Add(RegularRecord),
    EndOfUpdate,
}

fn apply_ixfr_event_to_loaded_data(patcher: &mut LoadedZonePatcher<'_>, event: IxfrEvent) {
    match event {
        IxfrEvent::Remove(r) if r.rtype == RType::SOA => {
            patcher.remove(r.clone()).unwrap();
            patcher.remove_soa(r.into()).unwrap();
        }
        IxfrEvent::Remove(r) => patcher.remove(r).unwrap(),
        IxfrEvent::Add(r) if r.rtype == RType::SOA => {
            patcher.add(r.clone()).unwrap();
            patcher.add_soa(r.into()).unwrap()
        }
        IxfrEvent::Add(r) => patcher.add(r).unwrap(),
        IxfrEvent::EndOfUpdate => patcher.next_patchset().unwrap(),
    }
}

fn apply_ixfr_event_to_signed_data(patcher: &mut SignedZonePatcher<'_>, event: IxfrEvent) {
    match event {
        IxfrEvent::Remove(r) if r.rtype == RType::SOA => {
            patcher.remove(r.clone()).unwrap();
            patcher.remove_soa(r.into()).unwrap();
        }
        IxfrEvent::Remove(r) => patcher.remove(r).unwrap(),
        IxfrEvent::Add(r) if r.rtype == RType::SOA => {
            patcher.add(r.clone()).unwrap();
            patcher.add_soa(r.into()).unwrap()
        }
        IxfrEvent::Add(r) => patcher.add(r).unwrap(),
        IxfrEvent::EndOfUpdate => patcher.next_patchset().unwrap(),
    }
}

fn apply_ixfr_event_to_diff_data(diff: &mut Box<DiffData>, event: IxfrEvent) {
    match event {
        IxfrEvent::Remove(r) if r.rtype == RType::SOA => {
            diff.removed_records.push(r.clone());
            diff.removed_soa = Some(r.into());
        }
        IxfrEvent::Remove(r) => diff.removed_records.push(r),
        IxfrEvent::Add(r) if r.rtype == RType::SOA => {
            diff.added_records.push(r.clone());
            diff.added_soa = Some(r.into());
        }
        IxfrEvent::Add(r) => diff.added_records.push(r),
        IxfrEvent::EndOfUpdate => {}
    }
}

/// Parse records in the wire format from `data`.
fn parse_records(mut data: &[u8]) -> impl Iterator<Item = Result<RegularRecord, ParseError>> {
    // TODO: Add parsing functionality in `domain::new` that can tell us whether
    // a partial input contains a full record or not, so that we can stream the
    // file through a small buffer.

    std::iter::from_fn(move || {
        if data.is_empty() {
            return None;
        }

        Some(Record::split_bytes(data).map(|(record, rest)| {
            data = rest;
            RegularRecord(record.transform(|n: RevNameBuf| n.unsized_copy_into(), |d| d))
        }))
    })
}
