//! Persisting zone data.

use std::{
    io::{BufWriter, Write},
    path::Path,
    sync::Arc,
};

use cascade_zonedata::{DiffData, RegularRecord, SoaRecord};
use domain::new::base::wire::{BuildBytes, TruncationError};
use tracing::{debug, trace};

use crate::{
    center::Center,
    zone::{
        Zone,
        instance::{UpcomingInstance, UpcomingLoadedInstance},
    },
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
pub fn persist_loaded(zone: &Arc<Zone>, center: &Arc<Center>, upcoming: &UpcomingLoadedInstance) {
    debug!("Persisting the loaded instance");

    if upcoming.diff_from_prev.removed_soa.is_some() {
        // Store a diff from the current to the upcoming instance.
        let path = upcoming.diff_from_prev_path(&zone.name, &center.config);
        persist_to_file(path.as_std_path(), &upcoming.diff_from_prev);
    } else {
        // There is no previous instance, so a diff is unhelpful; store a
        // snapshot instead.

        let path = upcoming.snapshot_path(&zone.name, &center.config);
        // TODO: Use a snapshot-specific persistence function.
        assert!(upcoming.diff_from_prev.removed_records.is_empty());
        persist_to_file(path.as_std_path(), &upcoming.diff_from_prev);
    }

    debug!("Persisting the loaded instance completed");
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
pub fn persist_signed(zone: &Arc<Zone>, center: &Arc<Center>, upcoming: &UpcomingInstance) {
    debug!("Persisting the signed instance");

    let upcoming = upcoming.signed.as_ref().unwrap();
    if upcoming.diff_from_prev.removed_soa.is_some() {
        // Store a diff from the current to the upcoming instance.
        let path = upcoming.diff_from_prev_path(&zone.name, &center.config);
        persist_to_file(path.as_std_path(), &upcoming.diff_from_prev);
    } else {
        // There is no previous instance, so a diff is unhelpful; store a
        // snapshot instead.

        let path = upcoming.snapshot_path(&zone.name, &center.config);
        // TODO: Use a snapshot-specific persistence function.
        assert!(upcoming.diff_from_prev.removed_records.is_empty());
        persist_to_file(path.as_std_path(), &upcoming.diff_from_prev);
    }

    debug!("Persisting the signed instance completed");
}

//------------ persist_to_file() ----------------------------------------------

pub fn persist_to_file(destination: &Path, diff: &DiffData) {
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
