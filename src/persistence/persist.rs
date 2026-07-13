//! Persisting zone data.

use std::{
    io::{BufWriter, Write},
    path::Path,
    sync::Arc,
};

use cascade_zonedata::{
    DiffData, LoadedZonePersisted, LoadedZonePersister, RegularRecord, SignedZonePersisted,
    SignedZonePersister, SoaRecord,
};
use domain::new::base::wire::{BuildBytes, TruncationError};
use tracing::trace;

use crate::{
    center::Center,
    zone::{LastPublished, Zone, save_state_now},
};

/// Persist the data for a loaded instance of a zone.
///
/// Data is persisted in the form of an AXFR wire format snapshot file plus
/// zero or more IXFR wire format diff files.
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
    let loaded_diff = persister.loaded_diff();
    if !loaded_diff.is_empty() {
        let destination = {
            let mut handle = zone.write_handle(center);
            let loaded_serial = loaded_diff.removed_soa.as_ref().map(|s| s.rdata.serial);
            handle
                .state
                .persistence
                .loaded_diffs
                .push(zone, center, loaded_serial, None)
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

        persist_to_file(&destination, loaded_diff.clone());

        // We don't add the loaded diff to the in-memory store used for
        // serving IXFR responses, that is done later in persist_signed() as
        // the store is only used for answering requests to the publication
        // server, and because if we add it here then abandon signing for some
        // reason we would then have to remove the loaded diff that we added.
    }

    persister.mark_complete()
}

/// Persist the data for a signed instance of a zone.
///
/// Data is persisted in the form of an AXFR wire format snapshot file plus
/// zero or more IXFR wire format diff files.
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

        let destination = {
            let mut handle = zone.write_handle(center);
            let loaded_serial =
                loaded_diff.and_then(|d| d.removed_soa.as_ref().map(|s| s.rdata.serial));
            let signed_serial = signed_diff.removed_soa.as_ref().map(|s| s.rdata.serial);
            handle
                .state
                .persistence
                .signed_diffs
                .push(zone, center, loaded_serial, signed_serial)
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
        persist_to_file(&destination, signed_diff.clone());

        // Store the diffs in-memory for serving IXFR out.
        store_for_ixfr_out(center, zone, loaded_diff, signed_diff);
    }

    persister.mark_complete()
}

//------------ persist_to_file() ----------------------------------------------

pub fn persist_to_file(destination: &Path, diff: Arc<DiffData>) {
    persist_to_file_from_parts(
        destination,
        diff.removed_soa.clone(),
        diff.added_soa.clone().unwrap(),
        diff.removed_records.iter(),
        diff.added_records.iter(),
    );
}

// TODO: It would be nice to take the records by reference.
pub fn persist_to_file_from_parts<
    'd,
    I: Iterator<Item = &'d RegularRecord>,
    J: Iterator<Item = &'d RegularRecord>,
>(
    destination: &Path,
    removed_soa: Option<SoaRecord>,
    added_soa: SoaRecord,
    removed_records: I,
    added_records: J,
) {
    // Atomic writing based on crate::util::write_file().
    let dir = destination
        .parent()
        .expect("'destination' must be a file, so it must have a parent");
    std::fs::create_dir_all(dir).unwrap_or_else(|err| {
        panic!(
            "Failed to persist zone data to '{}': {err}",
            destination.display()
        );
    });

    // Obtain a temporary file in the same directory.
    let tmp_file = tempfile::Builder::new()
        .tempfile_in(dir)
        .unwrap_or_else(|err| {
            panic!(
                "Failed to persist zone data to '{}': {err}",
                destination.display()
            );
        });

    // Write the diff in AXFR / IXFR wire format to disk.
    let mut f = BufWriter::new(tmp_file);

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

    let mut n_rrs_removed = 0;
    let mut n_rr_added = 0;

    write_rr(&mut buf, &added_soa, &mut f);

    // Start deleted records block by writing the old SOA, if any.
    if let Some(removed_soa) = &removed_soa {
        write_rr(&mut buf, removed_soa, &mut f);
        n_rrs_removed += 1;

        // Write the deleted records.
        for r in removed_records {
            if r.rname == removed_soa.rname && r.rtype == removed_soa.rtype {
                continue;
            }
            write_rr(&mut buf, r, &mut f);
            n_rrs_removed += 1;
        }

        // Start added records block by writing the new SOA
        write_rr(&mut buf, &added_soa, &mut f);
    }

    // Write the added records.
    for r in added_records {
        if r.rname == added_soa.rname && r.rtype == added_soa.rtype {
            continue;
        }
        write_rr(&mut buf, r, &mut f);
        n_rr_added += 1;
    }

    // Finish the AXFR/IXFR by writing the new SOA again
    write_rr(&mut buf, &added_soa, &mut f);
    n_rr_added += 1;

    // Replace the target path with the temporary file.
    let tmp_file = f.into_inner().unwrap();
    let _ = tmp_file.persist(destination).unwrap_or_else(|err| {
        panic!(
            "Failed to persist zone data to '{}': {err}",
            destination.display()
        );
    });

    trace!(
        "Persisted zone to file '{}': SOA {:?} -> {:?}: {n_rrs_removed} records removed, {n_rr_added} records added",
        destination.display(),
        removed_soa.as_ref().map(|v| v.rdata.serial),
        added_soa.rdata.serial,
    );
}

//------------ store_for_ixfr_out() ------------------------------------------

fn store_for_ixfr_out(
    center: &Arc<Center>,
    zone: &Arc<Zone>,
    loaded_diff: Option<&Arc<DiffData>>,
    signed_diff: &Arc<DiffData>,
) {
    // Only store a diff if the SOA from the previous version of the
    // signed zone was removed and a new one added, otherwise this is not
    // a diff to a previous version of the zone but actually a snapshot of
    // the zone after having been signed for the first time.
    // Ignore the diff if it is not acceptable, e.g. if it changes more than
    // X% of the records in the zone or crosses some other threshold.
    if signed_diff.removed_soa.is_some() && signed_diff.added_soa.is_some() {
        discard_excess_diffs(center, zone);
        store_diff(center, zone, loaded_diff, signed_diff);
    }
}

fn store_diff(
    center: &Arc<Center>,
    zone: &Arc<Zone>,
    loaded_diff: Option<&Arc<DiffData>>,
    signed_diff: &Arc<DiffData>,
) {
    let loaded_serial = loaded_diff.and_then(|d| d.removed_soa.as_ref().map(|s| s.rdata.serial));
    let diffs = &mut zone.write(center).storage.diffs;
    if let Some(loaded_diff) = loaded_diff {
        diffs.store_loaded_diff(loaded_diff.clone());
    }
    diffs.store_signed_diff(loaded_serial, signed_diff.clone());
}

//------------ discard_excess_diffs() ----------------------------------------

pub fn discard_excess_diffs(center: &Arc<Center>, zone: &Arc<Zone>) {
    let mut state = zone.write(center);
    if let Some(policy) = state.policy.as_ref()
        && let Some(last_published) = state.last_published.as_ref()
    {
        // Fetch diff purging settings from policy.
        let max_diffs = policy.server.outbound.max_diffs;
        let max_size_percentage = policy.server.outbound.max_diffs_size;

        // Calculate the maximum number of records that a set of diffs can be based on
        // the policy settings. IxfrZoneDiffs can't do this for us as it has
        // no access to `last_published`.
        let max_size = calc_max_diff_size(max_size_percentage, last_published);

        trace!(
            "Discarding excess in-memory diffs for zone '{}' with settings max_diffs={max_diffs}, current_size={}, max_size={max_size_percentage}% ({max_size} RRs)",
            zone.name, last_published.num_records
        );
        state.storage.diffs.trim(max_diffs, max_size);
    }
}

/// Calculate the maximum size a diff can be as a percentage of the last
/// published zone.
fn calc_max_diff_size(max_size_percentage: usize, last_published: &LastPublished) -> usize {
    let current_size = last_published.num_records as f64;
    let percentage = max_size_percentage as f64 / 100.0;
    (current_size * percentage) as usize
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use domain::base::Serial;

    use crate::zone::LastPublished;

    use super::calc_max_diff_size;

    #[test]
    pub fn test_calc_max_diff_size() {
        let empty_zone = last_published(0);
        assert_eq!(calc_max_diff_size(0, &empty_zone), 0);
        assert_eq!(calc_max_diff_size(50, &empty_zone), 0);
        assert_eq!(calc_max_diff_size(100, &empty_zone), 0);
        assert_eq!(calc_max_diff_size(1000, &empty_zone), 0);

        let small_zone = last_published(5);
        assert_eq!(calc_max_diff_size(0, &small_zone), 0);
        assert_eq!(calc_max_diff_size(50, &small_zone), 2);
        assert_eq!(calc_max_diff_size(100, &small_zone), 5);
        assert_eq!(calc_max_diff_size(1000, &small_zone), 50);

        let large_zone = last_published(500000);
        assert_eq!(calc_max_diff_size(0, &large_zone), 0);
        assert_eq!(calc_max_diff_size(50, &large_zone), 250000);
        assert_eq!(calc_max_diff_size(100, &large_zone), 500000);
        assert_eq!(calc_max_diff_size(1000, &large_zone), 5000000);
    }

    fn last_published(num_records: usize) -> LastPublished {
        LastPublished {
            loaded_serial: Serial::from(0),
            signed_serial: Serial::from(0),
            timestamp: SystemTime::now(),
            num_records,
        }
    }
}
