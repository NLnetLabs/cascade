use std::sync::Arc;

use cascade_zonedata::SignedZoneReader;
use tracing::{debug, trace, warn};

use crate::{
    center::Center,
    persistence::persist::persist_to_file_from_parts,
    policy::PolicyVersion,
    zone::{
        OwnedZoneHandle, SignedInstanceId, Zone,
        instance::{CurrentInstance, ObsoleteInstances},
    },
};

//----------- compact() --------------------------------------------------------

/// Compact a zone.
///
/// Update the snapshot of the zone and trim persisted diffs.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn compact<'a>(
    zone: &'a Arc<Zone>,
    center: &'a Arc<Center>,
    current_reader: SignedZoneReader<'_>,
    policy: &PolicyVersion,
    current: &CurrentInstance,
    obsolete: &ObsoleteInstances,
    old_snapshot_id: SignedInstanceId,
) -> OwnedZoneHandle<'a> {
    debug_assert!(
        old_snapshot_id != current.signed.id,
        "should not call `compact()` if there is nothing to do"
    );

    debug!("Compacting persisted zone data");
    trace!(?old_snapshot_id);

    // Write a new snapshot.
    if current.loaded.id != old_snapshot_id.0 {
        // The current loaded instance has not been snapshotted yet.

        let reader = current_reader.loaded();
        let path = current.loaded.snapshot_path(&zone.name, &center.config);
        persist_to_file_from_parts(
            path.as_std_path(),
            None,
            reader.soa().clone(),
            std::iter::empty(),
            reader.regular_records().iter(),
        );
    }
    {
        debug_assert!(old_snapshot_id != current.signed.id);

        let reader = current_reader;
        let path = current.signed.snapshot_path(&zone.name, &center.config);
        persist_to_file_from_parts(
            path.as_std_path(),
            None,
            reader.soa().clone(),
            std::iter::empty(),
            reader.generated_records().iter(),
        );
    }

    let new_snapshot_id = current.signed.id;

    // Find all diffs that lie after the old snapshot. They lie before the new
    // snapshot and they need to be renamed accordingly. Use hard links so the
    // files are still present at the old paths (so Cascade can cleanly recover
    // the old state in case of a crash) without duplicating their content.
    //
    // The diffs used to be stored relative to the previous instance, they now
    // need to be stored relative to the next instance. This includes the diff
    // for the current instance. The diffs will be iterated over from newest to
    // oldest, starting with the current instance.

    // Paths to remove after the new files are written.
    let mut to_remove = Vec::new();

    // NOTE: If the current loaded instance was already snapshotted, this loop
    // will not run.
    let mut next = &current.loaded;
    for prev in obsolete
        .per_load
        .iter()
        .rev()
        .map(|is| &is.loaded)
        .take_while(|i| i.id >= old_snapshot_id.0)
    {
        // Move the diff from `next` to `prev`.
        let src = next.diff_from_prev_path(&zone.name, &center.config);
        let dst = prev.diff_into_next_path(&zone.name, &center.config);
        trace!(%src, %dst, "Hard-linking persisted loaded diff");
        if let Err(error) = std::fs::hard_link(&*src, &*dst) {
            warn!(%src, %dst, "Could not shift persisted diff: {error}");
            // TODO: How should we handle this?
        }
        to_remove.push(src);
        next = &prev.inner;
    }
    debug_assert!(next.id == old_snapshot_id.0);
    if next.id != new_snapshot_id.0 {
        to_remove.push(next.snapshot_path(&zone.name, &center.config));
    }

    let mut next = &current.signed;
    for prev in obsolete
        .signed()
        .rev()
        .take_while(|i| i.id >= old_snapshot_id)
    {
        // Move the diff from `next` to `prev`.
        let src = next.diff_from_prev_path(&zone.name, &center.config);
        let dst = prev.diff_into_next_path(&zone.name, &center.config);
        trace!(%src, %dst, "Hard-linking persisted signed diff");
        if let Err(error) = std::fs::hard_link(&*src, &*dst) {
            warn!(%src, %dst, "Could not shift persisted diff: {error}");
            // TODO: How should we handle this?
        }
        to_remove.push(src);
        next = &prev.inner;
    }
    debug_assert!(next.id == old_snapshot_id);
    debug_assert!(next.id != new_snapshot_id);
    to_remove.push(next.snapshot_path(&zone.name, &center.config));

    // Update the snapshot ID and persist the zone state. After this, if
    // Cascade crashes and restarts, it will use the new snapshot.
    let mut handle = zone.write_handle(center);
    if handle.state.persistence.snapshot_id != Some(old_snapshot_id) {
        warn!("Bug: snapshot ID changed concurrently to compaction");
    }
    if handle
        .state
        .instances
        .current
        .as_ref()
        .is_none_or(|c| c.signed.id != new_snapshot_id)
    {
        warn!("Bug: current instance changed during compaction");
    }
    handle.state.persistence.snapshot_id = Some(new_snapshot_id);
    let _ = handle.get().save_state_now();
    std::mem::drop(handle);

    // Remove the old snapshot and the old diff paths.
    for path in to_remove {
        trace!(%path, "Removing old persisted file");
        if let Err(error) = std::fs::remove_file(&*path) {
            warn!(%path, "Could not remove old persisted file: {error}");
            // Removal is non-essential, so this doesn't break Cascade.
        }
    }

    // Trim old persisted diffs. Some diffs might lie after the old snapshot
    // (making them essential to restoration), but they will lie before the new
    // one, so they might now be amenable to trimming.
    let mut handle = zone.write_handle(center);
    handle.state.instances.discard_excess_diffs(
        policy,
        new_snapshot_id,
        &zone.name,
        &center.config,
    );

    handle
}
