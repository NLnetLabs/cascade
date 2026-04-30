//! Persisting zone data.

use std::{
    fs::File,
    io::{BufWriter, Write},
    path::Path,
    sync::Arc,
};

use cascade_zonedata::{
    DiffData, LoadedZonePersisted, LoadedZonePersister, SignedZonePersisted, SignedZonePersister,
};

use domain::new::base::wire::{BuildBytes, TruncationError};

use crate::{
    center::Center,
    zone::{Zone, ZoneHandle},
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
    // Determine the path to write to and update the record of written
    // paths here as we don't want to give responsibility for working
    // with ZoneState to the persistence crate. Accumulate a set of
    // diffs per unsigned and signed zone, each stored at a path one
    // suffixed by an index which rises by one when persisted.
    // TODO: Don't keep an unlimited number of diffs.
    // TODO: Compact diffs when idle?
    let mut state = zone.state.lock().unwrap();
    let handle = ZoneHandle {
        zone: &zone,
        state: &mut state,
        center: &center,
    };
    let next_idx = handle.state.persisted_loaded_diffs.len();
    let destination = center
        .config
        .zone_state_dir
        .join(format!("{}.loaded.{next_idx}", zone.name));
    persist_to_file(destination.as_std_path(), persister.loaded_diff().clone());
    handle.state.persisted_loaded_diffs.push(destination.into());
    handle.zone.mark_dirty(handle.state, handle.center);
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
    // Determine the path to write to and update the record of written
    // paths here as we don't want to give responsibility for working
    // with ZoneState to the persistence crate. Accumulate a set of
    // diffs per unsigned and signed zone, each stored at a path one
    // suffixed by an index which rises by one when persisted.
    // TODO: Don't keep an unlimited number of diffs.
    // TODO: Compact diffs when idle?
    let mut state = zone.state.lock().unwrap();
    let handle = ZoneHandle {
        zone: &zone,
        state: &mut state,
        center: &center,
    };
    let next_idx = handle.state.persisted_signed_diffs.len();
    let destination = center
        .config
        .zone_state_dir
        .join(format!("{}.signed.{next_idx}", zone.name));
    persist_to_file(destination.as_std_path(), persister.signed_diff().clone());
    handle.state.persisted_loaded_diffs.push(destination.into());
    handle.zone.mark_dirty(handle.state, handle.center);
    persister.mark_complete()
}

//------------ persist_to_file() ----------------------------------------------

fn persist_to_file(destination: &Path, loaded_diff: Arc<DiffData>) {
    // Write the diff in AXFR / IXFR wire format to disk.
    let f = File::create_new(destination).unwrap_or_else(|err| {
        panic!(
            "Failed to persist unsigned zone data to '{}': {err}",
            destination.display()
        );
    });
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

    let added_soa = loaded_diff.added_soa.clone().unwrap();

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
    if let Some(removed_soa) = &loaded_diff.removed_soa {
        write_rr(&mut buf, removed_soa, &mut f);

        // Write the deleted records.
        for r in &loaded_diff.removed_records {
            write_rr(&mut buf, r, &mut f);
        }

        // Start added records block by writing the new SOA
        write_rr(&mut buf, &added_soa, &mut f);
    }

    // Write the added records.
    for r in &loaded_diff.added_records {
        write_rr(&mut buf, r, &mut f);
    }

    // Finish the AXFR/IXFR by writing the new SOA again
    write_rr(&mut buf, &added_soa, &mut f);
}
