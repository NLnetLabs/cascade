//! Zone-specific persistence management.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};

use cascade_zonedata::{
    DiffData, LoadedZonePersister, LoadedZoneRestorer, SignedZonePersister, SignedZoneRestorer,
};
use domain::new::base::Serial;
use tracing::{debug, info, trace, trace_span, warn};

use crate::{
    center::Center,
    util::BackgroundTasks,
    zone::{Zone, ZoneHandle, ZoneState, save_state_now},
};

//----------- ZonePersistenceHandle --------------------------------------------

/// A handle for data persistence related operations on a [`Zone`].
pub struct ZonePersistenceHandle<'a> {
    /// The zone being operated on.
    pub zone: &'a Arc<Zone>,

    /// The locked zone state.
    pub state: &'a mut ZoneState,

    /// Cascade's global state.
    pub center: &'a Arc<Center>,
}

impl ZonePersistenceHandle<'_> {
    /// Access the generic [`ZoneHandle`].
    pub const fn zone(&mut self) -> ZoneHandle<'_> {
        ZoneHandle {
            zone: self.zone,
            state: self.state,
            center: self.center,
        }
    }

    /// Compact persisted data for the zone.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn start_compaction(&mut self) {
        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("compact");
        self.state
            .persistence
            .ongoing
            .spawn_blocking(span, move || {
                PersistenceState::compact(&center, &zone);
                let mut handle = zone.write_handle(&center);
                handle.state.persistence.ongoing.finish();
            });
    }

    /// Begin restoring data for the zone.
    ///
    /// A background task will be spawned to restore the zone's data (for both
    /// the loaded and signed instances).
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn start_restore(&mut self, restorer: LoadedZoneRestorer) {
        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("restore");
        self.state
            .persistence
            .ongoing
            .spawn_blocking(span, move || {
                debug!("Attempting to restore persisted zone data");

                // Try to restore the loaded instance.
                let mut restorer = restorer;
                let restored = match super::restore_loaded(&zone, &center, &mut restorer) {
                    Ok(true) => {
                        // Data was restored. Use it.
                        restorer.finish().unwrap_or_else(|_| {
                            unreachable!("Loaded zone restoration should have built new zone data")
                        })
                    }
                    Ok(false) => {
                        // There was nothing to restore.
                        abandon_loaded_restoration(&center, &zone, restorer);
                        return;
                    }
                    Err(err) => {
                        warn!("Abandoning loaded restoration: {err}");
                        abandon_loaded_restoration(&center, &zone, restorer);
                        return;
                    }
                };

                // Obtain the signed zone restorer.
                let mut restorer = {
                    zone.write_handle(&center)
                        .storage()
                        .finish_loaded_restoration(restored)
                };

                // Try to restore the signed instance.
                let restored = match super::restore_signed(&zone, &center, &mut restorer) {
                    Ok(true) => {
                        // Data was restored. Use it.
                        restorer.finish().unwrap_or_else(|_| {
                            unreachable!("Signed zone restoration should have built new zone data")
                        })
                    }
                    Ok(false) => {
                        // There was nothing to restore.
                        abandon_signed_restoration(&center, &zone, restorer);
                        return;
                    }
                    Err(err) => {
                        warn!("Abandoning signed restoration: {err}");
                        abandon_signed_restoration(&center, &zone, restorer);
                        return;
                    }
                };

                let mut handle = zone.write_handle(&center);
                trace!(
                    "Restored diffs: {:?}",
                    handle.state.persistence.loaded_diffs
                );
                handle.storage().finish_signed_restoration(restored);
                handle.state.persistence.ongoing.finish();
            });
    }

    /// Begin persisting a loaded zone instance.
    ///
    /// A background task will be spawned to perform the provided zone
    /// persistence and transition to the next state.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn start_loaded_persistence(&mut self, persister: LoadedZonePersister) {
        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("loaded_persistence");
        self.state
            .persistence
            .ongoing
            .spawn_blocking(span, move || {
                debug!("Persisting the loaded instance");
                let persisted = super::persist_loaded(&zone, &center, persister);
                debug!("Persisting the loaded instance completed");

                // NOTE: The outer function, which is spawning the background
                // task, has a lock of the zone state. Thus, the following lock
                // cannot be taken until the outer function terminates.
                let mut handle = zone.write_handle(&center);
                handle.get().start_new_sign(persisted);
                handle.state.persistence.ongoing.finish();
            });
    }

    /// Begin persisting a signed zone instance.
    ///
    /// A background task will be spawned to perform the provided zone
    /// persistence and transition to the next state.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn start_signed_persistence(&mut self, persister: SignedZonePersister) {
        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("signed_persistence");
        self.state
            .persistence
            .ongoing
            .spawn_blocking(span, move || {
                debug!("Persisting the signed instance");
                let persisted = super::persist_signed(&zone, &center, persister);
                debug!("Persisting the signed instance completed");

                // NOTE: The outer function, which is spawning the background
                // task, has a lock of the zone state. Thus, the following lock
                // cannot be taken until the outer function terminates.
                let mut handle = zone.write_handle(&center);

                handle.get().start_switch(persisted);

                handle.state.persistence.ongoing.finish();
            });
    }
}

fn abandon_loaded_restoration(
    center: &Arc<Center>,
    zone: &Arc<Zone>,
    restorer: LoadedZoneRestorer,
) {
    reset_state_due_to_abandoned_restore(center, zone);
    let mut handle = zone.write_handle(center);
    handle.storage().abandon_loaded_restoration(restorer);
    handle.state.persistence.ongoing.finish();
}

fn abandon_signed_restoration(
    center: &Arc<Center>,
    zone: &Arc<Zone>,
    restorer: SignedZoneRestorer,
) {
    reset_state_due_to_abandoned_restore(center, zone);
    let mut handle = zone.write_handle(center);
    handle.storage().abandon_signed_restoration(restorer);
    handle.state.persistence.ongoing.finish();
}

fn reset_state_due_to_abandoned_restore(center: &Arc<Center>, zone: &Arc<Zone>) {
    {
        let mut state = zone.write(center);
        clear_persisted_zone_data(center, &mut state);

        // In case this zone was signed in the past we have to make sure that
        // any attempt to enqueue a re-signing operation will be skipped as
        // doing so will fail due to the lack of loaded zone content.
        // TODO: Find a better way to prevent this issue as changing the
        // min_expiration timestamps is a very indirect and non-obvious way of
        // preventing re-signing.
        state.min_expiration = None;
        state.next_min_expiration = None;

        // Also remove any already enqueued signing operation that is blocked
        // by the ongoing restore as it will otherwise immediately start once
        // the restore completes.
        state.signer.cancel_enqueued_signing_operations();
    }
    save_state_now(center, zone);
}

fn clear_persisted_zone_data(center: &Center, state: &mut ZoneState) {
    // We can't use the persisted data so remove the paths from state, remove
    // the corresponding files on disk and remove any diffs that we loaded
    // into memory.
    for file_info in state
        .persistence
        .loaded_diffs
        .diff_infos
        .iter()
        .chain(state.persistence.signed_diffs.diff_infos.iter())
    {
        if file_info.path.exists()
            && file_info
                .path
                .starts_with(center.config.zone_state_dir.as_std_path())
        {
            info!(
                "Removing unusable persisted zone data file '{}'",
                file_info.path.display()
            );
            if let Err(err) = std::fs::remove_file(&file_info.path) {
                warn!(
                    "Failed to remove unusable persisted zone data file '{}': {err}",
                    file_info.path.display()
                );
            }
        }
    }
    state.persistence.loaded_diffs.clear();
    state.persistence.signed_diffs.clear();
    state.storage.diffs.clear();
}

//----------- PersistenceState -----------------------------------------------

/// State related to data persistence for a zone.
#[derive(Debug)]
pub struct PersistenceState {
    /// Ongoing persist/restore operations.
    pub ongoing: BackgroundTasks,

    /// Locations of persisted unsigned zone diffs to enable IXFR from
    /// the upstream to resume on restart, and to enable a complete latest
    /// unsigned version of the zone to be reconstituted.
    pub loaded_diffs: PersistedDiffManager,

    /// Locations of persisted signed zone diffs to ensure IXFR out toward
    /// downstreams is still possible after restart, and to enable a complete
    /// latest signed version of the zone to be reconsituted. For each path
    /// we also remember the associated loaded zone serial otherwise we lose
    /// track of which loaded serial the signed diff relates to. Only signed
    /// diffs triggered by a change in the loaded zone actually has an
    /// associated loaded diff serial.
    pub signed_diffs: PersistedDiffManager,
}

impl PersistenceState {
    pub fn compact(center: &Arc<Center>, zone: &Arc<Zone>) {
        // Is the zone available at the publication server? We need to read
        // from that view so that we can update the zone snapshot files on
        // disk so we can't do anything while Cascade is still starting up
        // and hasn't yet assigned the viewer or for a zone that hasn't been
        // published yet.
        let Some(viewer) = center.publication_server.viewer(zone) else {
            trace!(
                "Ignoring compaction request for zone '{}': no publication viewer available",
                zone.name
            );
            return;
        };

        let mut state = zone.write(center);

        let Some(ref policy) = state.policy else {
            trace!(
                "Ignoring compaction request for zone '{}': no policy available",
                zone.name
            );
            return;
        };

        // Grab some values that we need then release the state lock.
        let max_diffs = policy.server.outbound.max_diffs;
        // The number of actual diffs is one less than the set of diff paths
        // as the first path is to the snapshot, not to a diff.
        let num_signed_diffs = state.persistence.signed_diffs.len().saturating_sub(1);
        let loaded_snapshot_path = state.persistence.loaded_diffs.diff_infos.first().cloned();
        let signed_snapshot_path = state.persistence.signed_diffs.diff_infos.first().cloned();

        // Is compaction needed? Compare the allowed number of diffs to the
        // actual number of persisted diffs. For that we need a policy, which
        // the zone _should_ have. If not, abort.
        trace!(
            "Checking if compaction is needed for zone '{}': {num_signed_diffs} > {max_diffs}",
            zone.name
        );
        if num_signed_diffs > max_diffs {
            debug!(
                "Compacting persisted diffs for zone '{}' with {} diffs > {} max diffs",
                zone.name, num_signed_diffs, max_diffs
            );
            let num_diffs_to_remove = num_signed_diffs.abs_diff(max_diffs);
            let loaded_snapshot_path = &loaded_snapshot_path.unwrap().path;
            let signed_snapshot_path = &signed_snapshot_path.unwrap().path;

            // Get access to the published records for the zone, so that we
            // can write new loaded and signed snapshot files to disk.
            if let Ok(viewer) = viewer.try_read()
                && let Some(reader) = viewer.read()
            {
                debug!(
                    "Writing loaded zone snapshot to {}",
                    loaded_snapshot_path.display()
                );
                crate::persistence::persist_to_file_from_parts(
                    loaded_snapshot_path,
                    None,
                    reader.soa().clone(),
                    [].iter(),
                    reader.loaded_records(),
                );

                debug!(
                    "Writing new signed zone snapshot to {}",
                    signed_snapshot_path.display()
                );
                crate::persistence::persist_to_file_from_parts(
                    signed_snapshot_path,
                    None,
                    reader.soa().clone(),
                    [].iter(),
                    reader.generated_records().iter(),
                );

                // Now that we have re-written the snapshots using the latest
                // published version of the zone we don't need any of the
                // on-disk persisted diffs that were previously applied on top
                // of the old snapshot to re-create the zone.
                //
                // We might still however need some of those on-disk diffs so
                // that we can reload them on startup to be able to serve them
                // as IXFR diffs to downstream nameservers.
                //
                // Check which ones we can delete and after deleting them
                // update our record of the first on-disk diff file that
                // should be applied on top of the updated snapshot.

                // Remove the first N oldest signed diffs and their
                // corresponding loaded diffs. Skip the first "diff" as it is
                // the snapshot, not a diff.
                let mut idx = 0;
                let mut loaded_serials_to_remove = vec![];
                state
                    .persistence
                    .signed_diffs
                    .diff_infos
                    .retain(|diff_info| {
                        // Keep only the snapshot and diffs newer than the ones
                        // to remove.
                        let keep = idx == 0 || idx > num_diffs_to_remove;
                        trace!("Compaction for zone '{}': removing {num_diffs_to_remove} diffs: retain diff #{idx}: {keep}", zone.name);
                        idx += 1;

                        if !keep {
                            // Remove the corresponding loaded diff.
                            if let Some(loaded_serial) = diff_info.loaded_serial {
                                loaded_serials_to_remove.push(loaded_serial);
                            }
                        }
                        keep
                    });

                // Remove the corresponding loaded diffs.
                for loaded_serial in loaded_serials_to_remove.into_iter() {
                    if let Some(found_item) = state
                        .persistence
                        .loaded_diffs
                        .diffs()
                        .iter()
                        .find(|item| item.loaded_serial == Some(loaded_serial))
                        .cloned()
                    {
                        trace!(
                            "Compaction for zone '{}': removing loaded diff for loaded serial {loaded_serial}",
                            zone.name
                        );
                        let _ = state
                            .persistence
                            .loaded_diffs
                            .diff_infos
                            .remove(&found_item);
                    }
                }

                state.persistence.loaded_diffs.restore_base_idx =
                    state.persistence.loaded_diffs.len();
                state.persistence.signed_diffs.restore_base_idx =
                    state.persistence.signed_diffs.len();
                trace!(
                    "Compaction complete: next_idx: loaded={}, signed={}, restore_base_idx: loaded={}, signed={}",
                    state.persistence.loaded_diffs.next_idx,
                    state.persistence.signed_diffs.next_idx,
                    state.persistence.loaded_diffs.restore_base_idx,
                    state.persistence.signed_diffs.restore_base_idx
                );
            }
        }
    }
}

impl Default for PersistenceState {
    fn default() -> Self {
        Self {
            ongoing: Default::default(),
            loaded_diffs: PersistedDiffManager::new(PersistedDiffRecordSource::Loaded),
            signed_diffs: PersistedDiffManager::new(PersistedDiffRecordSource::Signed),
        }
    }
}

//----------- PersistedDiffRecordSource --------------------------------------

/// The source of the persisted diff records.
#[derive(Clone, Copy, Debug)]
pub enum PersistedDiffRecordSource {
    Loaded,
    Signed,
}

//----------- PersistedDiffManager -------------------------------------------

/// Metadata about a related collection of persisted zone data files.
#[derive(Clone, Debug)]
pub struct PersistedDiffManager {
    /// Which kind of data are we storing, loaded or signed?
    record_source: PersistedDiffRecordSource,

    /// The index value to use when constructing the next file name to write
    /// to.
    next_idx: usize,

    /// The index of the first diff_info to apply to the snapshot when restoring.
    ///
    /// After compaction the on-disk diffs that existed must no longer be applied
    /// to the base snapshot as the new snapshot includes them, but we should
    /// still track their paths so that we can load them for use in responding to
    /// IXFR client requests. So we need to remember which index to start applying
    /// diffs to the snapshot from.
    restore_base_idx: usize,

    /// The collection of persisted data file paths in this set.
    diff_infos: BTreeSet<PersistedDiffFileInfo>,
}

impl PersistedDiffManager {
    pub fn new(record_source: PersistedDiffRecordSource) -> Self {
        Self::from_parts(record_source, 0, 0, Default::default())
    }

    pub fn from_parts(
        record_source: PersistedDiffRecordSource,
        next_idx: usize,
        restore_base_idx: usize,
        diff_infos: BTreeSet<PersistedDiffFileInfo>,
    ) -> Self {
        Self {
            record_source,
            next_idx,
            restore_base_idx,
            diff_infos,
        }
    }

    pub fn push(
        &mut self,
        zone: &Arc<Zone>,
        center: &Arc<Center>,
        loaded_serial: Option<Serial>,
        signed_serial: Option<Serial>,
    ) -> PathBuf {
        // Catch issues like https://github.com/NLnetLabs/cascade/issues/825:
        // If both serials are None the diff represents a snapshot which we
        // should only receive if we have no stored diff paths already. We
        // could delete the existing diff_infos entries at this point but that
        // would leave behind any actual diffs at those paths on disk, and
        // if we are wrong we will interfere with normal Cascade operation by
        // discarding diff paths that we should not be discarding. So we can't
        // handle this heere and should never get into this state so just
        // abort as something is seriously wrong.
        assert!(self.diff_infos.is_empty() || loaded_serial.is_some() || signed_serial.is_some());

        let zone_name = &zone.name;
        let data_file_type = match self.record_source {
            PersistedDiffRecordSource::Loaded => "loaded",
            PersistedDiffRecordSource::Signed => "signed",
        };

        let path = center
            .config
            .zone_state_dir
            .join(format!("{zone_name}.{data_file_type}.{}", self.next_idx))
            .into_std_path_buf();
        let file_info = PersistedDiffFileInfo {
            path: path.clone(),
            loaded_serial,
            signed_serial,
        };

        assert!(self.diff_infos.insert(file_info));

        // replace with strict_add() once our MSRV reaches 1.91.0.
        assert_ne!(self.next_idx, usize::MAX);
        self.next_idx += 1;

        path
    }

    pub fn cleanup(&mut self, serial: Option<Serial>) {
        // If no serial number is provided we can only cleanup the initial
        // snapshot, and we should only do that if we have only a snapshot
        // and no diffs.
        assert!(!self.is_empty());
        assert!(self.diff_infos.len() == 1 || serial.is_some());

        // We can't just remove a diff out of the middle of a sequence,
        // we can only cleanup the last diff. If it's a snapshot we are
        // cleaning up that should be the last entry, we can't orphan diffs
        // by removing the snapshot they apply to.
        let last = self.diff_infos.pop_last().unwrap();
        if let Some(serial) = serial {
            // When removing a diff the specified serial must match that of
            // the last diff that we have.
            assert_eq!(last.loaded_serial, Some(serial));
        } else {
            // In the case of removing a snapshot, set next_idx back to 0
            // so that the snapshot is always numbered 0. Nothing should
            // depend on this but it just feels a bit nicer to see 0 in the
            // filename of the snapshot and know that that should be the
            // snapshot.
            // TODO: Maybe we should separate out snapshot files from diff
            // files.
            self.next_idx = 0;
        }

        trace!(
            "Removing persisted zone data file '{}' for cleaned serial {serial:?}",
            last.path.display()
        );
        if let Err(err) = std::fs::remove_file(&last.path) {
            warn!(
                "Unable to cleanup persisted data for serial {serial:?} by deleting '{}': {err}",
                last.path.display()
            );
        }
    }

    pub fn clear(&mut self) {
        self.diff_infos.clear();
        self.next_idx = 0;
        self.restore_base_idx = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.diff_infos.is_empty()
    }

    pub fn next_idx(&self) -> usize {
        self.next_idx
    }

    pub fn diffs(&self) -> &BTreeSet<PersistedDiffFileInfo> {
        &self.diff_infos
    }

    pub fn len(&self) -> usize {
        self.diff_infos.len()
    }

    pub fn restore_base_idx(&self) -> usize {
        self.restore_base_idx
    }
}

//----------- PersistedZoneDataFileInfo --------------------------------------

/// Information about a single persisted zone data file.
#[derive(Clone, Debug)]
pub struct PersistedDiffFileInfo {
    /// The location on disk where the zone data file exists.
    path: PathBuf,

    /// The loaded serial number that the data file relates to.
    ///
    /// This can be None for a signed diff resulting from changes only to the
    /// signed zone.
    loaded_serial: Option<Serial>,

    /// The signed serial number that the data file relates to.
    ///
    /// This can be none for a loaded diff.
    signed_serial: Option<Serial>,
}

impl PersistedDiffFileInfo {
    pub fn new(
        path: PathBuf,
        loaded_serial: Option<Serial>,
        signed_serial: Option<Serial>,
    ) -> Self {
        Self {
            path,
            loaded_serial,
            signed_serial,
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn loaded_serial(&self) -> Option<Serial> {
        self.loaded_serial
    }

    pub fn signed_serial(&self) -> Option<Serial> {
        self.signed_serial
    }
}

impl PartialEq for PersistedDiffFileInfo {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Eq for PersistedDiffFileInfo {}

impl PartialOrd for PersistedDiffFileInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PersistedDiffFileInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.path.cmp(&other.path)
    }
}

//----------- IxfrZoneDiffs --------------------------------------------------

/// The set of diffs for a single zone, to be used to serve IXFR responses
/// from the publication server to clients.
///
/// Note: These diffs are not used to serve IXFR responses from review servers
/// to clients as during review the current diff is already available to the
/// review server via the current state of the zone storage state machine.
///
/// A new diff is added to this set once the loaded or signed change to the
/// zone is approved at a pipeline review stage.
///
/// Loaded and signed diffs are stored separetely, as they are produced
/// separately. In order to reply to an IXFR request both the signed diff
/// and the loaded diff that corresponds to it, if any, are needed. There is
/// therefore a relationship between signed diffs and loaded diffs.
///
/// Diffs are added at three separate moments in the zone pipeline lifecycle:
///
/// - loaded diff without signed diff: a change to the loaded part of the zone
///   was approved but the pipeline has not yet progressed as far as changing
///   and approving the signed part of the zone.
///
/// - loaded diff and signed diff: a change to the loaded part of the zone
///   was approved and the pipeline progressed to also updating the signed part
///   of the zone to correspond to the loaded zone changes and those signed
///   changes were also approved.
///
/// - signed diff without loaded diff: a change to the signed part of the zone
///   was approved without any change to the loaded part of the zone, e.g.
///   because the signer policy settings were changed or the zone had to be
///   re-signed using new keys or because signatures nearing expiration had to
///   be regenerated.
///
/// The diffs should form a continuous chain, with one diff moving from SOA
/// serial N to N+1 and the next diff moving from N+1 to N+2. The chain should
/// begin at the SOA serial that the client currently has, and continue up to
/// and including the SOA serial of the latest published version of the zone.
///
/// For signed diffs finding the right diff to serve is easy as the SOA
/// serial of the signed zone corresponds to the SOA serial provided by the
/// client. For loaded diffs however they contain the loaded serial number
/// which may differ to that of the signed serial number (not in the case of
/// 'keep' serial policy however). As we receive the loaded and signed diffs
/// at different moments in the zone pipeline lifecycle we need to keep track
/// when receiving a signed diff of which loaded SOA serial the signed diff
/// relates to, so that we can later serve them together.
///
/// To ensure memory usage can be controlled diffs can be "trimmed" discarding
/// older diffs if the total number or size of the diffs exceeds configured
/// bounds.
#[derive(Default)]
pub struct IxfrZoneDiffs {
    /// Diffs in the loaded part of the zone from one serial number to
    /// another. Indexed by the serial number being removed from the loaded
    /// zone the diff belongs to.
    loaded_diffs: BTreeMap<u32, Arc<DiffData>>,

    /// Diffs in the signed part of the zone from one serial number to
    /// another, along with the serial number being removed from the
    /// loaded diff they correspond to (if any, as a re-signed zone has no
    /// corresponding change in the loaded zone). Indexed by the serial number
    /// being removed from the the signed zone the diff belongs to.
    signed_diffs: BTreeMap<u32, RelatedSignedDiff>,
}

impl IxfrZoneDiffs {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn clear(&mut self) {
        self.loaded_diffs.clear();
        self.signed_diffs.clear();
    }

    pub fn num_loaded_diffs(&self) -> usize {
        self.loaded_diffs.len()
    }

    pub fn num_signed_diffs(&self) -> usize {
        self.signed_diffs.len()
    }

    pub fn store_loaded_diff(&mut self, diff: Arc<DiffData>) {
        let from_serial = diff.removed_soa.as_ref().map(|s| s.rdata.serial).unwrap();
        let to_serial = diff.added_soa.as_ref().map(|s| s.rdata.serial).unwrap();
        let old = self.loaded_diffs.insert(from_serial.into(), diff);
        log_stored_diff("loaded", old.is_some(), from_serial, to_serial);
    }

    pub fn store_signed_diff(&mut self, loaded_serial: Option<Serial>, diff: Arc<DiffData>) {
        let from_serial = diff.removed_soa.as_ref().map(|s| s.rdata.serial).unwrap();
        let to_serial = diff.added_soa.as_ref().map(|s| s.rdata.serial).unwrap();
        let related_diff = RelatedSignedDiff::new(diff, loaded_serial);
        let old = self.signed_diffs.insert(from_serial.into(), related_diff);
        log_stored_diff("signed", old.is_some(), from_serial, to_serial);
    }

    pub fn get(&self, from_serial: Serial) -> Vec<(Arc<DiffData>, Arc<DiffData>)> {
        let mut diffs = vec![];

        let mut wanted_from: u32 = from_serial.into();
        while let Some(signed_related_diff) = self.signed_diffs.get(&wanted_from) {
            let loaded_diff = if let Some(loaded_serial) = signed_related_diff.related_loaded_serial
            {
                self.loaded_diffs
                    .get(&loaded_serial)
                    .cloned()
                    // We really should have the diff
                    .unwrap()
            } else {
                // No loaded diff is associated with this signed diff, so
                // use an empty diff
                Default::default()
            };

            // Update wanted_from so that on the next iteration of the loop we
            // fetch the diff that removes the SOA serial that this diff adds.
            wanted_from = signed_related_diff
                .diff
                .added_soa
                .as_ref()
                .unwrap()
                .rdata
                .serial
                .into();

            diffs.push((loaded_diff, signed_related_diff.diff.clone()));
        }

        diffs
    }

    pub fn trim(&mut self, max_diffs: usize, max_size: usize) {
        // First check and trim excess diffs.
        let num_signed_diffs = self.num_signed_diffs();
        debug!(
            "Checking for diffs to discard: {num_signed_diffs} signed diffs > max_diffs ({max_diffs})?"
        );
        if num_signed_diffs > max_diffs {
            // Prune the oldest diffs so that we end up storing no more than
            // max_diffs signed diffs.
            let num_diffs_to_prune = num_signed_diffs - max_diffs;
            debug!("Discarding {num_diffs_to_prune} in-memory diffs");
            for _ in 0..num_diffs_to_prune {
                let _ = self.discard_first_diff_pair();
            }
        }

        // Next trim enough diffs to bring the total number of RRs stored
        // under the specified limit.
        let loaded_diff_sizes = self
            .loaded_diffs
            .values()
            .map(Self::calc_diff_size)
            .collect::<Vec<usize>>();
        let signed_diff_sizes = self
            .signed_diffs
            .values()
            .map(|rd| Self::calc_diff_size(&rd.diff))
            .collect::<Vec<usize>>();
        let mut total_rr_count =
            loaded_diff_sizes.iter().sum::<usize>() + signed_diff_sizes.iter().sum::<usize>();

        debug!("Checking for diffs to discard: {total_rr_count} RRs > max_size ({max_size}) RRs??");
        while total_rr_count > max_size {
            if let Some((loaded_diff, signed_diff)) = self.discard_first_diff_pair() {
                total_rr_count -= Self::calc_diff_size(&signed_diff);
                if let Some(loaded_diff) = loaded_diff {
                    total_rr_count -= Self::calc_diff_size(&loaded_diff);
                }
                debug!("Discarded in-memory diff: updated total RR count = {total_rr_count}");
            } else {
                break;
            }
        }
    }

    fn discard_first_diff_pair(&mut self) -> Option<(Option<Arc<DiffData>>, Arc<DiffData>)> {
        if let Some(e) = self.signed_diffs.first_entry() {
            trace!("Discarding in-memory signed diff for serial {}", e.key());
            let RelatedSignedDiff {
                diff,
                related_loaded_serial,
            } = e.remove();
            if let Some(loaded_serial) = related_loaded_serial {
                trace!("Discarding related in-memory loaded diff for serial {loaded_serial}");
                let loaded_diff = self.loaded_diffs.remove(&loaded_serial);
                Some((loaded_diff, diff))
            } else {
                Some((None, diff))
            }
        } else {
            None
        }
    }

    fn calc_diff_size(diff: &Arc<DiffData>) -> usize {
        diff.removed_soa.as_ref().map(|_| 1).unwrap_or(0)
            + diff.added_soa.as_ref().map(|_| 1).unwrap_or(0)
            + diff.removed_records.len()
            + diff.added_records.len()
    }
}

impl std::fmt::Display for IxfrZoneDiffs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, (key, diff)) in self.loaded_diffs.iter().enumerate() {
            let from = diff.removed_soa.as_ref().map(|s| s.rdata.serial);
            let to = diff.added_soa.as_ref().map(|s| s.rdata.serial);
            writeln!(
                f,
                "IxfrZoneDiffs: loaded #{i}: serial (diff key {key}) -{from:?}+{to:?} (-{}+{} records)",
                diff.removed_records.len(),
                diff.added_records.len(),
            )?;
        }

        for (i, (key, related_signed_diff)) in self.signed_diffs.iter().enumerate() {
            let diff = &related_signed_diff.diff;
            let loaded_serial = &related_signed_diff.related_loaded_serial;

            let from = diff.removed_soa.as_ref().map(|s| s.rdata.serial);
            let to = diff.added_soa.as_ref().map(|s| s.rdata.serial);
            writeln!(
                f,
                "IxfrZoneDiffs: signed #{i}: serial (diff key {key}, loaded serial {loaded_serial:?}) -{from:?}+{to:?} (-{}+{} records)",
                diff.removed_records.len(),
                diff.added_records.len(),
            )?;
        }

        std::fmt::Result::Ok(())
    }
}

//------------ RelatedSignedDiff ---------------------------------------------

struct RelatedSignedDiff {
    /// The signed diff.
    pub diff: Arc<DiffData>,

    /// The removed serial number of the loaded diff that this signed diff
    /// relates to, if any.
    pub related_loaded_serial: Option<u32>,
}

impl RelatedSignedDiff {
    fn new(diff: Arc<DiffData>, loaded_serial: Option<Serial>) -> Self {
        Self {
            diff,
            related_loaded_serial: loaded_serial.map(Into::into),
        }
    }
}

fn log_stored_diff(r#type: &'static str, updating: bool, from: Serial, to: Serial) {
    if updating {
        trace!("Updating existing IXFR in-memory diff for SOA {type} serial -{from:?}:+{to:?}");
    } else {
        trace!("Storing IXFR in-memory diff for SOA {type} serial -{from:?}:+{to:?}");
    }
}
