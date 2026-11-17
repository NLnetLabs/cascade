//! Restoring persisted zone data.

use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
    sync::Arc,
};

use bytes::Bytes;
use cascade_zonedata::{DiffData, RegularRecord, SoaRecord, ZoneRestorer};
use domain::{
    base::Name,
    new::{
        base::{RType, Record, SoaSerial, name::RevNameBuf, parse::ParseError, wire::SplitBytes},
        rdata::RecordData,
    },
    utils::dst::UnsizedCopy,
};
use tracing::{trace, warn};

use crate::{
    center::Center,
    policy::PolicyVersion,
    zone::{
        InMemoryDiffLimits, InMemoryDiffTrimmer, SignedInstanceId, Zone,
        instance::{LoadedInstanceId, ObsoleteInstances, PersistedInstance},
    },
};

/// Restore the persisted data of a zone.
///
/// Returns `true` if an instance was restored successfully.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn restore_both(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    restorer: &mut ZoneRestorer,
    policy: &PolicyVersion,
    persisted: Option<&PersistedInstance>,
    obsolete: &ObsoleteInstances,
    snapshot_id: Option<SignedInstanceId>,
) -> io::Result<Option<Restored>> {
    let Some(snapshot_id) = snapshot_id else {
        // Diffs are stored relative to the snapshot.
        trace!("Skipping restoration -- Can't restore without a snapshot");
        return Ok(None);
    };

    // Find the most recent signed instance.
    let Some(latest_signed) = persisted
        .as_ref()
        .map(|p| &p.signed)
        .or_else(|| obsolete.signed().next_back().map(|i| &i.inner))
    else {
        // No instances exist to be restored. Stop.
        trace!("Skipping restoration -- there's nothing to restore");
        return Ok(None);
    };

    // Limits for the in-memory diffs that will be restored.
    let limits = InMemoryDiffLimits::compute(policy, latest_signed);

    // Find the snapshotted loaded instance.
    let mut loaded = persisted
        .as_ref()
        .map(|p| &p.loaded)
        .into_iter()
        .chain(obsolete.per_load.iter().rev().map(|is| &is.loaded.inner));
    let mut loaded_after_snapshot = Vec::new();
    let loaded_snapshot = loop {
        let Some(i) = loaded.next() else {
            warn!("Bug: Could not find the snapshotted loaded instance");
            return Ok(None);
        };

        if i.id == snapshot_id.0 {
            // Found the snapshotted instance. Stop.
            break i;
        }

        loaded_after_snapshot.push(i);
    };

    // Find the snapshotted signed instance.
    let mut signed = persisted
        .as_ref()
        .map(|p| &p.signed)
        .into_iter()
        .chain(obsolete.signed().rev().map(|i| &**i));
    let mut signed_after_snapshot = Vec::new();
    let signed_snapshot = loop {
        let Some(i) = signed.next() else {
            warn!("Bug: Could not find the snapshotted signed instance");
            return Ok(None);
        };

        if i.id == snapshot_id {
            // Found the snapshotted instance. Stop.
            break i;
        }

        signed_after_snapshot.push(i);
    };

    // A temporary buffer used for loading persisted files.
    let mut buf = Vec::<u8>::new();

    // Restore the snapshots.
    restore_loaded_snapshot(
        loaded_snapshot
            .snapshot_path(&zone.name, &center.config)
            .as_std_path(),
        &mut buf,
        restorer,
    )?;
    restore_signed_snapshot(
        signed_snapshot
            .snapshot_path(&zone.name, &center.config)
            .as_std_path(),
        &mut buf,
        restorer,
    )?;

    let mut restored_obsolete = RestoredObsolete::default();

    // Restore loaded diffs after the snapshot (from oldest to newest).
    let mut prev = loaded_snapshot;
    for i in loaded_after_snapshot.into_iter().rev() {
        let path = i.diff_from_prev_path(&zone.name, &center.config);
        trace!(
            id = ?i.id, %path,
            "Restoring post-snapshot loaded instance diff"
        );
        let diff = restore_diff(path.as_std_path(), &mut buf)?;

        restorer
            .patch_loaded()
            .ok_or(io::Error::other("Internal error: Patch failed"))?
            .apply_patchset(diff.clone())
            .map_err(|err| {
                io::Error::other(format!("Internal error: Could not apply diff: {err}"))
            })?;

        // The diff maps from the preceding instance to this one.
        // Save it in terms of that preceding instance.
        restored_obsolete.loaded_diffs.insert(prev.id, diff.into());
        prev = i;
    }

    // Restore signed diffs after the snapshot (from oldest to newest).
    let mut prev = signed_snapshot;
    for i in signed_after_snapshot.into_iter().rev() {
        let path = i.diff_from_prev_path(&zone.name, &center.config);
        trace!(
            id = ?i.id, %path,
            "Restoring post-snapshot signed instance diff"
        );
        let diff = restore_diff(path.as_std_path(), &mut buf)?;

        restorer
            .patch_signed()
            .ok_or(io::Error::other("Internal error: Patch failed"))?
            .apply_patchset(diff.clone())
            .map_err(|err| {
                io::Error::other(format!("Internal error: Could not apply diff: {err}"))
            })?;

        // The diff maps from the preceding instance to this one.
        // Save it in terms of that preceding instance.
        restored_obsolete.signed_diffs.insert(prev.id, diff.into());
        prev = i;
    }

    // Collect diffs to save in memory up to policy limits.
    // Don't let errors here cause restoration as a whole to fail.
    let _ = restore_obsolete(
        &mut restored_obsolete,
        obsolete,
        limits,
        &mut buf,
        &zone.name,
        &center.config,
    );

    Ok(Some(Restored {
        obsolete: restored_obsolete,
    }))
}

/// The result of restoration.
pub struct Restored {
    /// The restoration of obsolete instances, if any.
    pub obsolete: RestoredObsolete,
}

/// Restore obsolete instances.
///
/// The persisted diffs of obsolete instances will be restored, from the newest
/// to the oldest instances, while respecting the specified limits for in-memory
/// diffs.
fn restore_obsolete(
    restored: &mut RestoredObsolete,
    instances: &ObsoleteInstances,
    limits: InMemoryDiffLimits,
    buf: &mut Vec<u8>,
    zone_name: &Name<Bytes>,
    config: &crate::Config,
) -> io::Result<()> {
    let mut trimmer = InMemoryDiffTrimmer::new(limits);

    let mut old_loaded_diffs = std::mem::take(&mut restored.loaded_diffs);
    let mut old_signed_diffs = std::mem::take(&mut restored.signed_diffs);

    for i in instances.latest_signed.iter().rev() {
        trimmer.account_signed(i);
        if trimmer.exceeded() {
            break;
        }

        if let Some(diff) = old_signed_diffs.remove(&i.id) {
            restored.signed_diffs.insert(i.id, diff);
            continue;
        }

        let path = i.diff_into_next_path(zone_name, config);
        trace!(
            id = ?i.id, %path,
            "Loading obsolete signed instance diff",
        );
        let diff = restore_diff(path.as_std_path(), buf)?;
        restored.signed_diffs.insert(i.id, diff.into());
    }

    for is in instances.per_load.iter().rev() {
        let i = &is.loaded;
        trimmer.account_loaded(i);
        if trimmer.exceeded() {
            break;
        }

        if let Some(diff) = old_loaded_diffs.remove(&i.id) {
            restored.loaded_diffs.insert(i.id, diff);
        } else {
            let path = i.diff_into_next_path(zone_name, config);
            trace!(
                id = ?i.id, %path,
                "Loading obsolete loaded instance diff",
            );
            let diff = restore_diff(path.as_std_path(), buf)?;
            restored.loaded_diffs.insert(i.id, diff.into());
        }

        // Load the related signed diffs.
        for i in is.signed.iter().rev() {
            trimmer.account_signed(i);
            if trimmer.exceeded() {
                break;
            }

            if let Some(diff) = old_signed_diffs.remove(&i.id) {
                restored.signed_diffs.insert(i.id, diff);
                continue;
            }

            let path = i.diff_into_next_path(zone_name, config);
            trace!(
                id = ?i.id, %path,
                "Loading obsolete signed instance diff",
            );
            let diff = restore_diff(path.as_std_path(), buf)?;
            restored.signed_diffs.insert(i.id, diff.into());
        }
    }

    Ok(())
}

/// The result of restoring obsolete instances.
#[derive(Default)]
pub struct RestoredObsolete {
    /// Diffs of obsolete loaded instances to save in memory.
    pub loaded_diffs: foldhash::HashMap<LoadedInstanceId, Arc<DiffData>>,

    /// Diffs of obsolete signed instances to save in memory.
    pub signed_diffs: foldhash::HashMap<SignedInstanceId, Arc<DiffData>>,
}

impl RestoredObsolete {
    /// Apply to an [`ObsoleteInstances`], adding the relevant diffs.
    pub fn apply(mut self, instances: &mut ObsoleteInstances) {
        for i in &mut instances.latest_signed {
            if let Some(diff) = self.signed_diffs.remove(&i.id) {
                i.diff_into_next = Some(diff);
            }
        }
        for is in &mut instances.per_load {
            let i = &mut is.loaded;
            if let Some(diff) = self.loaded_diffs.remove(&i.id) {
                i.diff_into_next = Some(diff);
            }
            for i in &mut is.signed {
                if let Some(diff) = self.signed_diffs.remove(&i.id) {
                    i.diff_into_next = Some(diff);
                }
            }
        }
        if !self.loaded_diffs.is_empty() || !self.signed_diffs.is_empty() {
            warn!(
                loaded = ?self.loaded_diffs.keys(),
                signed = ?self.signed_diffs.keys(),
                "Bug: some diffs were not used"
            );
        }
    }
}

/// Restore a snapshot of a loaded instance.
fn restore_loaded_snapshot(
    path: &Path,
    buf: &mut Vec<u8>,
    restorer: &mut ZoneRestorer,
) -> io::Result<()> {
    let (soa, records) = load_axfr_wire_dump(path, buf).map_err(|err| {
        io::Error::other(format!(
            "Loading snapshot '{}' failed: {err}",
            path.display()
        ))
    })?;
    let serial = soa.rdata.serial;
    let mut loaded_replacer = restorer.fill_loaded().ok_or(io::Error::other(
        "Internal error: Could not acquire replacer",
    ))?;
    loaded_replacer.set_soa(soa.clone()).unwrap();
    loaded_replacer.set_records(records).unwrap();
    loaded_replacer.add(soa.into()).unwrap();
    loaded_replacer.apply().unwrap();
    trace!(
        "Restored loaded snapshot for SOA serial {serial} from file '{}'",
        path.display()
    );
    Ok(())
}

/// Restore a snapshot of a signed instance.
fn restore_signed_snapshot(
    path: &Path,
    buf: &mut Vec<u8>,
    restorer: &mut ZoneRestorer,
) -> io::Result<()> {
    let (soa, records) = load_axfr_wire_dump(path, buf).map_err(|err| {
        io::Error::other(format!(
            "Loading snapshot '{}' failed: {err}",
            path.display()
        ))
    })?;
    let serial = soa.rdata.serial;
    let mut signed_replacer = restorer.fill_signed().ok_or(io::Error::other(
        "Internal error: Could not acquire replacer",
    ))?;
    signed_replacer.set_soa(soa.clone()).unwrap();
    signed_replacer.set_records(records).unwrap();
    signed_replacer.add(soa.into()).unwrap();
    signed_replacer.apply().unwrap();
    trace!(
        "Restored signed snapshot for SOA serial {serial} from file '{}'",
        path.display()
    );
    Ok(())
}

/// Restore a diff.
fn restore_diff(path: &Path, buf: &mut Vec<u8>) -> io::Result<Box<DiffData>> {
    let mut diff = Box::new(DiffData::new());
    load_ixfr_wire_dump(path, buf, |event| {
        apply_ixfr_event_to_diff_data(&mut diff, event);
    })
    .map_err(|err| io::Error::other(format!("Loading diff '{}' failed: {err}", path.display())))?;

    if diff.removed_soa != diff.added_soa {
        // The SOA record changed.
        diff.removed_records
            .extend(diff.removed_soa.clone().map(Into::into));
        diff.added_records
            .extend(diff.added_soa.clone().map(Into::into));
        diff.removed_records.sort_unstable();
        diff.added_records.sort_unstable();
    }

    Ok(diff)
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

fn apply_ixfr_event_to_diff_data(diff: &mut Box<DiffData>, event: IxfrEvent) {
    match event {
        IxfrEvent::Remove(r) if r.rtype == RType::SOA => {
            diff.removed_soa = Some(r.into());
        }
        IxfrEvent::Remove(r) => diff.removed_records.push(r),
        IxfrEvent::Add(r) if r.rtype == RType::SOA => {
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
