//! Persisting zone data.

use std::{
    fs::File,
    io::{BufWriter, ErrorKind, Write},
    path::Path,
    sync::Arc,
};

use cascade_zonedata::{
    DiffData, LoadedZonePersisted, LoadedZonePersister, SignedZonePersisted, SignedZonePersister,
};

use domain::new::base::wire::{BuildBytes, TruncationError};
use tracing::{trace, warn};

use crate::{
    center::Center,
    zone::{Zone, save_state_now},
};

/// Persist the data for a loaded instance of a zone.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn persist_loaded(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    persister: LoadedZonePersister,
) -> LoadedZonePersisted {
    if !persister.loaded_diff().is_empty() {
        // Determine the path to write to and update the record of written
        // paths here as we don't want to give responsibility for working with
        // ZoneState to the persistence crate. Accumulate a set of diffs per
        // unsigned and signed zone, each stored at a path one suffixed by an
        // index which rises by one when persisted.
        // TODO: Don't keep an unlimited number of diffs.
        // TODO: Compact diffs when idle?
        let destination = {
            let mut handle = zone.write_handle(center);
            let next_idx = handle.state.persisted_loaded_diff_paths.len();
            let destination = center
                .config
                .zone_state_dir
                .join(format!("{}.loaded.{next_idx}", zone.name));

            handle
                .state
                .persisted_loaded_diff_paths
                .push(destination.clone().into());

            destination
        };

        // Update the set of persisted zone data file paths BEFORE writing
        // the new file because if we crash/lose power between writing the new
        // file and storing the updated set of paths:
        //   - We would not know when restoring that a diff is missing.
        //     This isn't ultimately a problem as we also would not ever
        //     have served the updated zone from the publication server as
        //     persistence has to complete before publication occurs.
        //   - The new file would be unused but left behind on disk. It may
        //     later be overwritten by a new diff but until then it would
        //     be unused and also not removed by cleaning of diff files that
        //     occurs if restoration fails, as the path would not be known
        //     to us.

        // TODO: Saving state first then writing the file could lead to a
        // situation where a zone that was published consisting of a snapshot
        // and N diffs would be discarded if the path to the N+1th diff was
        // recorded in state and persisted but actually writing the N+1th
        // diff file failed. On restore the file would be looked for and not
        // found and all loaded and signed content including diffs would be
        // discarded at that point. One way around this could be to track
        // (e.g. using an Option field) that this path is in the process of
        // being written but has not yet finished yet, and then on restore if
        // the Option is Some the referred to path can just be deleted.
        save_state_now(center, zone);

        persist_to_file(destination.as_std_path(), persister.loaded_diff().clone());
    }

    // Store the loaded diff in-memory for serving IXFR out.

    let loaded_diff = persister.loaded_diff();

    // Only store a diff if something has changed compared to the previous
    // version of the loaded zone, otherwise this is not a diff to a previous
    // version of the zone but actually a snapshot of the zone after having
    // been loaded for the first time. If the SOA serial didn't change
    // (which is legal for a loaded zone) don't store a diff because the IXFR
    // protocol requires a SOA serial number change so we won't be able to
    // serve the diff anyway.
    if !loaded_diff.is_empty() && loaded_diff.removed_soa.is_some() {
        // Store anything that changed when the zone was re-loaded, i.e.
        // unsigned zone content changes. Note that the SOA SERIAL is not
        // required to change unless using 'keep' policy and so we should not
        // require the SOA to have been removed and a new one added.
        let mut handle = zone.write_handle(center);

        let loaded_only_diff = (persister.loaded_diff().clone(), DiffData::new().into());
        trace!(
            "Storing IXFR in-memory diff for SOA loaded serial -{:?}:+{:?}",
            loaded_only_diff
                .0
                .removed_soa
                .as_ref()
                .map(|soa_rr| soa_rr.rdata.serial),
            loaded_only_diff
                .0
                .added_soa
                .as_ref()
                .map(|soa_rr| soa_rr.rdata.serial),
        );
        handle.state.storage.diffs.push(loaded_only_diff);
    }

    persister.mark_complete()
}

/// Persist the data for a signed instance of a zone.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn persist_signed(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    persister: SignedZonePersister,
) -> SignedZonePersisted {
    if !persister.signed_diff().is_empty() {
        let loaded_diff = persister.loaded_diff();
        let signed_diff = persister.signed_diff();

        // Determine the path to write to and update the record of written
        // paths here as we don't want to give responsibility for working with
        // ZoneState to the persistence crate. Accumulate a set of diffs per
        // unsigned and signed zone, each stored at a path one suffixed by an
        // index which rises by one when persisted.
        // TODO: Don't keep an unlimited number of diffs.
        // TODO: Compact diffs when idle?
        let destination = {
            let mut handle = zone.write_handle(center);
            let next_idx = handle.state.persisted_signed_diff_paths.len();
            let destination = center
                .config
                .zone_state_dir
                .join(format!("{}.signed.{next_idx}", zone.name));

            handle
                .state
                .persisted_signed_diff_paths
                .push(destination.clone().into());

            destination
        };

        // Update the set of persisted zone data file paths BEFORE writing
        // the new file because if we crash/lose power between writing the new
        // file and storing the updated set of paths:
        //   - We would not know when restoring that a diff is missing.
        //     This isn't ultimately a problem as we also would not ever
        //     have served the updated zone from the publication server as
        //     persistence has to complete before publication occurs.
        //   - The new file would be unused but left behind on disk. It may
        //     later be overwritten by a new diff but until then it would
        //     be unused and also not removed by cleaning of diff files that
        //     occurs if restoration fails, as the path would not be known
        //     to us.

        // TODO: Saving state first then writing the file could lead to a
        // situation where a zone that was published consisting of a snapshot
        // and N diffs would be discarded if the path to the N+1th diff was
        // recorded in state and persisted but actually writing the N+1th
        // diff file failed. On restore the file would be looked for and not
        // found and all loaded and signed content including diffs would be
        // discarded at that point. One way around this could be to track
        // (e.g. using an Option field) that this path is in the process of
        // being written but has not yet finished yet, and then on restore if
        // the Option is Some the referred to path can just be deleted.
        save_state_now(center, zone);

        // Write the diff to disk as a binary AXFR snapshot or binary IXFR
        // diff.
        persist_to_file(destination.as_std_path(), signed_diff.clone());

        // Store the diffs in-memory for serving IXFR out.
        //
        // Only store a diff if the SOA from the previous version of the
        // signed zone was removed and a new one added, otherwise this is not
        // a diff to a previous version of the zone but actually a snapshot of
        // the zone after having been signed for the first time.
        if signed_diff.removed_soa.is_some() && signed_diff.removed_soa != signed_diff.added_soa {
            // Store anything that changed when the zone was re-loaded, i.e.
            // unsigned zone content changes. Note that the SOA SERIAL is not
            // required to change unless using 'keep' policy and so we should
            // not require the SOA to have been removed and a new one added.

            // Store anything that changed when the zone was re-signed, i.e.
            // changes DNSSEC RRs that can be caused by unsigned content
            // changes or changing from NSEC <-> NSEC3 or using a new key
            // to sign with or just regenerating signatures to avoid them
            // expiring. Signed zones MUST always have a new SOA SERIAL
            // compared to the previous version of the signed zone.

            let mut handle = zone.write_handle(center);

            // If we have a new signed diff to store because records in the
            // loaded part of the zone changed, e.g. due to changes in the
            // zone content or receipt of a changed DNSKEY set from the key
            // manager, then the loaded diff will have been stored in-memory
            // by loaded zone persistence, but the corresponding signed diff
            // will not yet have been stored in-memory, we have to do that
            // now. In this case we have to update the last stored in-memory
            // diff. We drop the partial diff and push a replacement full
            // diff instead.
            //
            // Alternatively if we have a new signed diff to store because
            // records in the signed part of the zone changed, e.g. due to
            // signature re-generation to ensure that existing signatures
            // don't expire, then there will be no corresponding loaded diff
            // yet in-memory. In this case we have to push an entirely new
            // diff to the in-memory collection without dropping an existing
            // diff first.

            let mut action = "Storing new";
            if let Some(potentially_partial_diff) = handle.state.storage.diffs.last()
                && potentially_partial_diff.1.is_empty()
            {
                // Remove the partial diff, it will be replaced by a
                // complete diff.
                let _partial_diff = handle.state.storage.diffs.pop();
                action = "Updating existing";
            }

            let loaded_diff = loaded_diff.cloned().unwrap_or(DiffData::new().into());
            trace!(
                "{action} IXFR in-memory diff for SOA loaded serial -{:?}:+{:?} -> signed serial -{:?}:+{:?}",
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
            handle
                .state
                .storage
                .diffs
                .push((loaded_diff, signed_diff.clone()));
        }
    }

    persister.mark_complete()
}

//------------ persist_to_file() ----------------------------------------------

fn persist_to_file(destination: &Path, diff: Arc<DiffData>) {
    // Write the diff in AXFR / IXFR wire format to disk.
    let f = match File::create_new(destination) {
        Ok(f) => f,
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            // This is not expected. When persisting the zone data to a file
            // we save Cascade zone state "now" so that the persisted paths in
            // use are known on next restart, so we should know this path was
            // in use and be attempting to write to a different non-existing
            // path. If for some reason zone state was not persisted after the
            // persisted zone data file was created, e.g. a power outage in
            // combination with a change to persistence logic compared to how
            // it is at the time of writing so that zone state was not ensured
            // to be persisted before proceeding, that could cause this.
            warn!(
                "Overwriting existing persisted zone data file at '{}'.",
                destination.display()
            );
            File::create(destination).unwrap_or_else(|err| {
                panic!(
                    "Failed to persist zone data to '{}': {err}",
                    destination.display()
                );
            })
        }
        Err(err) => {
            panic!(
                "Failed to persist zone data to '{}': {err}",
                destination.display()
            );
        }
    };
    let mut f = BufWriter::new(f);

    let mut buf = vec![0u8; 1024];

    fn write_rr<BB: BuildBytes, RR, W>(buf: &mut Vec<u8>, rr: &RR, mut writer: W)
    where
        RR: std::ops::Deref<Target = BB>,
        W: Write,
    {
        let buf_len = buf.len();

        let num_bytes_to_write = match rr.build_bytes(buf) {
            Ok(unused_buf_part) => {
                // Build succeeded, now determine how many bytes were built.
                buf_len - unused_buf_part.len()
            }
            Err(TruncationError) => {
                // Build failed due to insufficient buffer space, resize the
                // buffer to be large enough then redo the build which should
                // not fail this time.
                let num_required_bytes = rr.built_bytes_size();
                buf.resize(num_required_bytes, 0u8);
                rr.build_bytes(buf).unwrap();
                num_required_bytes
            }
        };

        // Failure to write would be imply there is a serious problem with
        // the environment in which Cascade is running, and being unable to
        // persist a zone means we can't allow downstreams to consume it as if
        // we get terminated we will not be able to serve the same zone again
        // (which would only actually be a real problem if we are unable to
        // bump the serial). So, treat a write failure as fatal.
        writer.write_all(&buf[0..num_bytes_to_write]).unwrap();
    }

    let added_soa = diff.added_soa.clone().unwrap();

    // IXFR format has the form:
    //   - New SOA
    //   - Old SOA
    //   - Deleted records
    //   - New SOA
    //   - Added records
    //   - New SOA
    //
    // AXFR format has the form:
    //   - New SOA
    //   - Records
    //   - New SOA
    //
    // Write AXFR if no records were deleted by the diff, else write IXFR.

    write_rr(&mut buf, &added_soa, &mut f);

    // Start deleted records block by writing the old SOA, if any.
    if let Some(removed_soa) = &diff.removed_soa {
        write_rr(&mut buf, removed_soa, &mut f);

        // Write the deleted records.
        for r in &diff.removed_records {
            if r.rname == removed_soa.rname && r.rtype == removed_soa.rtype {
                continue;
            }

            write_rr(&mut buf, r, &mut f);
        }

        // Start added records block by writing the new SOA
        write_rr(&mut buf, &added_soa, &mut f);
    }

    // Write the added records.
    for r in &diff.added_records {
        if r.rname == added_soa.rname && r.rtype == added_soa.rtype {
            continue;
        }

        write_rr(&mut buf, r, &mut f);
    }

    // Finish the AXFR/IXFR by writing the new SOA again
    write_rr(&mut buf, &added_soa, &mut f);

    trace!(
        "Persisted zone to file '{}': SOA {:?} -> {:?}: {} records removed, {} records added",
        destination.display(),
        diff.removed_soa.as_ref().map(|v| v.rdata.serial),
        diff.added_soa.as_ref().map(|v| v.rdata.serial),
        diff.removed_records.is_empty(),
        diff.added_records.len(),
    );
}
