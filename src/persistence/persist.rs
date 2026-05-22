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
    zone::{Zone, ZoneHandle, save_state_now},
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
        // paths here as we don't want to give responsibility for working
        // with ZoneState to the persistence crate. Accumulate a set of
        // diffs per unsigned and signed zone, each stored at a path one
        // suffixed by an index which rises by one when persisted.
        // TODO: Don't keep an unlimited number of diffs.
        // TODO: Compact diffs when idle?
        {
            let mut state = zone.state.lock().unwrap();
            let handle = ZoneHandle {
                zone,
                state: &mut state,
                center,
            };
            let next_idx = handle.state.persisted_loaded_diff_paths.len();
            let destination = center
                .config
                .zone_state_dir
                .join(format!("{}.loaded.{next_idx}", zone.name));
            persist_to_file(destination.as_std_path(), persister.loaded_diff().clone());
            handle
                .state
                .persisted_loaded_diff_paths
                .push(destination.into());
        }
        save_state_now(center, zone);
    }

    // Store the loaded diff in-memory for serving IXFR out.

    let loaded_diff = persister.loaded_diff();

    // Only store a diff if something has changed compared to the previous
    // version of the loaded zone, otherwise this is not a diff to a previous
    // version of the zone but actually a snapshot of the zone after having
    // been loaded for the first time. If the SOA serial didn't change (which
    // is legal for a loaded zone) don't store a diff because the IXFR protocol
    // requires a SOA serial number change so we won't be able to serve the diff
    // anyway.
    if !loaded_diff.is_empty() && loaded_diff.removed_soa.is_some() {
        // Store anything that changed when the zone was re-loaded, i.e.
        // unsigned zone content changes. Note that the SOA SERIAL is not
        // required to change unless using 'keep' policy and so we should not
        // require the SOA to have been removed and a new one added.
        let mut state = zone.state.lock().unwrap();

        let loaded_only_diff = (persister.loaded_diff().clone(), DiffData::new().into());
        state.storage.diffs.push(loaded_only_diff);
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
        {
            let mut state = zone.state.lock().unwrap();
            let handle = ZoneHandle {
                zone,
                state: &mut state,
                center,
            };
            let next_idx = handle.state.persisted_signed_diff_paths.len();
            let destination = center
                .config
                .zone_state_dir
                .join(format!("{}.signed.{next_idx}", zone.name));

            // Write the diff to disk as a binary AXFR snapshot or binary IXFR
            // diff.
            persist_to_file(destination.as_std_path(), signed_diff.clone());
            handle
                .state
                .persisted_signed_diff_paths
                .push(destination.into());
        }
        save_state_now(center, zone);

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

            let mut state = zone.state.lock().unwrap();
            let partial_diff = state.storage.diffs.last_mut().unwrap();
            let loaded_diff = loaded_diff.cloned().unwrap_or(DiffData::new().into());
            trace!(
                "Storing IXFR diff for SOA serial {:?} -> {:?}",
                loaded_diff
                    .removed_soa
                    .as_ref()
                    .map(|soa_rr| soa_rr.rdata.serial),
                signed_diff
                    .added_soa
                    .as_ref()
                    .map(|soa_rr| soa_rr.rdata.serial),
            );
            let complete_diff = (loaded_diff, signed_diff.clone());
            *partial_diff = complete_diff;
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
        // Earlier attempt using presentation format instead of wire format.
        // let r: OldRecord = loaded_diff.added_soa.clone().unwrap().into();
        // writeln!(f, "{r}").unwrap();

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
            write_rr(&mut buf, r, &mut f);
        }

        // Start added records block by writing the new SOA
        write_rr(&mut buf, &added_soa, &mut f);
    }

    // Write the added records.
    for r in &diff.added_records {
        write_rr(&mut buf, r, &mut f);
    }

    // Finish the AXFR/IXFR by writing the new SOA again
    write_rr(&mut buf, &added_soa, &mut f);

    trace!(
        "Persisted zone to file '{}': SOA {:?} -> {:?}: {} records removed, {} records added",
        destination.display(),
        diff.removed_soa.as_ref().map(|v| v.rdata.serial),
        diff.added_soa.as_ref().map(|v| v.rdata.serial),
        if !diff.removed_records.is_empty() {
            diff.removed_records.len() + 1
        } else {
            0
        },
        if !diff.added_records.is_empty() {
            diff.added_records.len() + 1
        } else {
            0
        },
    );
}
