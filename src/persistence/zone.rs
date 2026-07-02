//! Zone-specific persistence management.

use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use cascade_zonedata::{
    DiffData, LoadedZonePersister, LoadedZoneRestorer, SignedZonePersister, SignedZoneRestorer,
};
use domain::new::base::Serial;
use tracing::{debug, info, trace, trace_span, warn};

use crate::{
    center::Center,
    server::{LoadedReviewServer, PublicationServer, SignedReviewServer},
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
                    handle.state.persistence.loaded_diff_paths
                );
                let (loaded_reviewer, signed_reviewer, viewer) =
                    handle.storage().finish_signed_restoration(restored);

                // Register the zone against the zone servers.
                LoadedReviewServer::add_zone(handle.center, handle.zone.clone(), loaded_reviewer);
                SignedReviewServer::add_zone(handle.center, handle.zone.clone(), signed_reviewer);
                PublicationServer::add_zone(handle.center, handle.zone.clone(), viewer);

                // Send a notification that the state machine is now passive.
                handle.storage().on_passive();

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

                handle.get().finish_signed_persistence(persisted);

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
    let (loaded_reviewer, signed_reviewer, viewer) =
        handle.storage().abandon_loaded_restoration(restorer);

    // Update the zone servers.
    LoadedReviewServer::add_zone(handle.center, handle.zone.clone(), loaded_reviewer);
    SignedReviewServer::add_zone(handle.center, handle.zone.clone(), signed_reviewer);
    PublicationServer::add_zone(handle.center, handle.zone.clone(), viewer);

    // Send a notification that the state machine is now passive.
    handle.storage().on_passive();

    handle.state.persistence.ongoing.finish();
}

fn abandon_signed_restoration(
    center: &Arc<Center>,
    zone: &Arc<Zone>,
    restorer: SignedZoneRestorer,
) {
    reset_state_due_to_abandoned_restore(center, zone);
    let mut handle = zone.write_handle(center);
    let (loaded_reviewer, signed_reviewer, viewer) =
        handle.storage().abandon_signed_restoration(restorer);

    // Update the zone servers.
    LoadedReviewServer::add_zone(handle.center, handle.zone.clone(), loaded_reviewer);
    SignedReviewServer::add_zone(handle.center, handle.zone.clone(), signed_reviewer);
    PublicationServer::add_zone(handle.center, handle.zone.clone(), viewer);

    // Send a notification that the state machine is now passive.
    handle.storage().on_passive();

    handle.state.persistence.ongoing.finish();
}

fn reset_state_due_to_abandoned_restore(center: &Arc<Center>, zone: &Arc<Zone>) {
    {
        let mut handle = zone.write_handle(center);
        clear_persisted_zone_data(center, &mut handle.state);

        // In case this zone was signed in the past we have to make sure that
        // any attempt to enqueue a re-signing operation will be skipped as
        // doing so will fail due to the lack of loaded zone content.
        // TODO: Find a better way to prevent this issue as changing the
        // min_expiration timestamps is a very indirect and non-obvious way of
        // preventing re-signing.
        handle.state.min_expiration = None;
        handle.state.next_min_expiration = None;

        // Also remove any already enqueued signing operation that is blocked
        // by the ongoing restore as it will otherwise immediately start once
        // the restore completes.
        handle.signer().cancel_enqueued_signing_operations();
    }
    save_state_now(center, zone);
}

fn clear_persisted_zone_data(center: &Center, state: &mut ZoneState) {
    // We can't use the persisted data so remove the paths from state, remove
    // the corresponding files on disk and remove any diffs that we loaded
    // into memory.
    for p in state.persistence.loaded_diff_paths.iter().chain(
        state
            .persistence
            .signed_diff_paths
            .iter()
            .map(|(p, _serial)| p),
    ) {
        if p.exists() && p.starts_with(center.config.zone_state_dir.as_std_path()) {
            info!(
                "Removing unusable persisted zone data file '{}'",
                p.display()
            );
            if let Err(err) = std::fs::remove_file(p) {
                warn!(
                    "Failed to remove unusable persisted zone data file '{}': {err}",
                    p.display()
                );
            }
        }
    }
    state.persistence.loaded_diff_paths.clear();
    state.persistence.signed_diff_paths.clear();
    state.storage.diffs.clear();
}

//----------- PersistenceState -----------------------------------------------

/// State related to data persistence for a zone.
#[derive(Debug, Default)]
pub struct PersistenceState {
    /// Ongoing persist/restore operations.
    pub ongoing: BackgroundTasks,

    /// Locations of persisted unsigned zone diffs to enable IXFR from
    /// the upstream to resume on restart, and to enable a complete latest
    /// unsigned version of the zone to be reconstituted.
    pub loaded_diff_paths: Vec<PathBuf>,

    /// Locations of persisted signed zone diffs to ensure IXFR out toward
    /// downstreams is still possible after restart, and to enable a complete
    /// latest signed version of the zone to be reconsituted. For each path
    /// we also remember the associated loaded zone serial otherwise we lose
    /// track of which loaded serial the signed diff relates to. Only signed
    /// diffs triggered by a change in the loaded zone actually has an
    /// associated loaded diff serial.
    pub signed_diff_paths: Vec<(PathBuf, Option<Serial>)>,
}

//----------- IxfrZoneDiffs --------------------------------------------------

/// The set of diffs for a single zone, to be used to serve IXFR responses
/// from the publication server to clients.
///
/// Note: These diffs are not currently used to serve IXFR responses from
/// review servers to clients as during review the current diff is already
/// available to the review server via the current state of the zone storage
/// state machine.
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

struct RelatedSignedDiff {
    /// The signed diff.
    diff: Arc<DiffData>,

    /// The removed serial number of the loaded diff that this signed diff
    /// relates to, if any.
    related_loaded_serial: Option<u32>,
}

impl RelatedSignedDiff {
    fn new(diff: Arc<DiffData>, loaded_serial: Option<Serial>) -> Self {
        Self {
            diff,
            related_loaded_serial: loaded_serial.map(Into::into),
        }
    }
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

fn log_stored_diff(r#type: &'static str, updating: bool, from: Serial, to: Serial) {
    if updating {
        trace!("Updating existing IXFR in-memory diff for SOA {type} serial -{from:?}:+{to:?}");
    } else {
        trace!("Storing IXFR in-memory diff for SOA {type} serial -{from:?}:+{to:?}");
    }
}
