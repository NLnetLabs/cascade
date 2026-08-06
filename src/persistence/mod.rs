//! Persisting zone data to and restoring from disk.
//!
//! # Summary
//!
//! On approval of loaded or signed diffs the persister:
//!   - Writes diffs to disk, so that Cascade can seamlessly resume operation
//!     after a crash restart. Separate files are stored for loaded vs signed
//!     data. Persistence files are stored alongside other state files for a
//!     zone in the zone-state configuration path, with the set of currently
//!     in-use persistence paths being stored in Cascade zone state.
//!   - Stores diffs in memory, so that RFC 1995 IXFR requests can be
//!     responded to with the set of diffs needed by the client.
//!
//! When re-starting Cascade, lost in-memory zone and IXFR diff data will be
//! restored from the disk files written by the persister.
//!
//! In-memory diffs are discarded, oldest first, when configured limits are
//! exceeded.
//!
//! Persisted disk files are also discarded oldest first but after a delay
//! to spread out the cost of "compacting" the zone (replacing the snapshot
//! with a new one that contains the current set of published zone records).
//!
//! # Data format
//!
//! Data is persisted as AXFR and IXFR message ANSWER sections in wire format.
//!
//! # Persistence
//!
//! Persistence is invoked immediately after zone approval, either because of
//! a successful review hook, or no review hook at all, or because the
//! operator overrode a failed review hook.
//!
//! Persisted data is stored separately for records received while loading the
//! zone vs changes that occur to the zone as a result of (re)signing it.
//!
//! For both loaded and signed changes, persistence stores an initial snapshot
//! and a sequence of zero or more diffs:
//!   - A loaded snapshot file is written immediately after approval of the
//!     initial version of a zone is received, whether from disk or via
//!     XFR-in. This file has the name `<zone-name>.loaded.0`.
//!   - A loaded diff file is written each time the input zone is reloaded,
//!     whether due to XFR-in or due to reloading of the input file from disk.
//!     Loaded diff files are named `<zone-name>.loaded.N` where N > 0 and
//!     increases by one each time a new diff is persisted.
//!   - A signed snapshot file is written immediately after approval of the
//!     first signed version of the zone resulting from full zone signing.
//!     This file has the name `<zone-name>.signed.0`.
//!   - A signed diff file is written each time the zone is re-signed, whether
//!     due to changes in the input zone or changes in the signing keys or the
//!     replacing of signatures for records whose signatures need refreshing.
//!     Signed diff files are named `<zone-name>.signed.N` where N > 0 and
//!     increases by one each time a new diff is persisted.
//!
//! After a diff is persisted successfully:
//!   - The diff is stored in memory alongside the zone in
//!     [`StorageState::diffs`](crate::zone::StorageState::diffs) so that it
//!     can be served in response to an IXFR request from a downstream
//!     nameserver.
//!   - The path that the diff file was written to is appended to
//!     [`PersistenceState::loaded_diffs`](crate::persistence::zone::PersistenceState::loaded_diffs) or
//!     [`PersistenceState::signed_diffs`](crate::persistence::zone::PersistenceState::signed_diffs) and the zone state is
//!     immediately saved to disk.
//!
//! # Panics
//!
//! If persistence fails due to an I/O error this will cause Cascade to panic.
//! If the underlying storage that Cascade depends on is not reliable we have
//! no way of knowing what else may be failing and abort as it is not safe to
//! continue under such circumstances.
//!
//! # Compaction
//!
//! The `Compacter` replaces an existing snapshot and diffs with an
//! up-tao-date snapshot. It may leave some diffs behind [1..N] such that entry
//! 0 is still the snapshot but the first applicable diff is entry N. Diffs
//! 1..N can be left behind in the case that they are still required to
//! respond to IXFR requests but not for restoration (as they have been folded
//! into the updated snapshot).
//!
//! Compaction is done as a background operation periodically. This is to
//! prevent a situation where a rapdily changing large zone has to be locked
//! for compaction after every small change and being a large zone the
//! compaction process would be comparatively slow. Given that compaction is
//! an optimization it does not need to be done on every change to the zone.
//!
//! # Restoration
//!
//! Zones are created in memory at Cascade startup in storage state
//! `RestoringLoaded`. If the zone loader attempts to start loading the zone
//! the load will fail because the zone storage is not yet in the `Passive`
//! state. Instead a refresh will be enqueud and acted upon once the zone
//! storage enters the `Passive` state.
//!
//! On startup Cascade starts a zone restorer which will attempt to restore
//! all known zones. If restoration fails the zone will move to the `Passive`
//! state and any subsequent load of data will be handled as usual. As long
//! as the last used serial number was successfully persisted to state and
//! restored from state the newly signed zone will receive a higher serial
//! number than the last published zone that we failed to restore. Failure
//! to restore also results in deletion of all persisted data for the zone
//! and updating of the state to clear the paths to the no longer existing
//! persisted data files. Failure to remove a persisted data file will be
//! logged as a WARNing and Cascade will continue.
//!
//! Restoration of a zone is achieved by replacing the current (empty) zone
//! content with the loaded snapshot, then applying each applicable loaded
//! diff file to the snapshot one at a time. If the `Compacter` has folded
//! diffs into the snapshot it may be that restoration must skip some diffs
//! as they exist already in the snapshot and were kept only because they
//! are still needed to respond to IXFR requests.
//!
//! Any diff that was available at a review server will have been lost.
//! However as only approved data gets persisted, there should be no need
//! to still be able to query the review server for an IXFR diff after
//! Cascsade restarts.
//!
//! # Purging
//!
//! To avoid excess disk and memory usage, diffs in excess of configured
//! limits are discarded.
//!
//! # Architecture
//!
//! - The zone storage state machine has states relating to persistence
//!   and restoration and invokes code in this module to actually implement
//!   those responsibilities.
//! - IXFR diffs for use by the publication server are stored in zone
//!   storage. IXFR diffs for use by the preview servers are accessed from
//!   the in-memory temporary diffs held in review related storage machine
//!   states.
//! - Three "units" defined in this module are stored in `Center` and run
//!   by `Manager`: `Persister`, `Restorer` and `Compacter`. Restorer runs
//!   on startup. Compacter runs in the background continuously. Persister
//!   does not "run" but instead provides callback `on_zone_policy_changed`.
//! - The relationship between a signed diff and the loaded diff it
//!   corresponds to is tracked both in persistence and in-memory diff state.
//! - Persistence is done atomically, writing first to a temporary file and
//!   then replacing any previous file with an atomic rename.
//! - Diffs are stored and accessed using the same data type as already used
//!   by Cascade to transport diffs between pipeline stages when needed,
//!   namely `DiffData`.
//! - `PersistenceState` per zone uses two instances of `PersistedDiffManager`
//!   to keep track of persisted zone data files and implemements compaction
//!   of a single zone. Compaction requires access to the latest published
//!   version of a zone in order to replace the existing persisted snapshot
//!   with an up-to-date version. Access to the published zone is done via the
//!   viewer for the zone.
//! - `IxfrZoneDiffs` stores diffs used when responding to an RFC 1995 IXFR
//!   request, and offers lookup and trim operations.
//!
//! # TODO
//!
//! The current implementation could be improved by:
//!
//! - Removing next_idx and instead using a UUID to make persistence paths
//!   unique. This would avoid the need for incrementing the id, and keeping
//!   track of the last id both in memory and in persisted state.
//! - Don't access and mutate the state of PersistedDiffManager from outside
//!   the type as this makes it dangerous to change the way
//!   PersistedDiffManager manipulates its own state as code outside
//!   PersistedDiffManager may depend on assumptions about how the internal
//!   state is constructed.
//! - Track snapshots separately to diffs rather than treating the first diff
//!   as a snapshot, to make it clearer which logic applies only to snapshots
//!   which logic applies only to diffs, and which logic applies to both.
//! - Track diffs left behind after compaction but still required for IXFR
//!   responses separately to diffs that should be applied on restore to the
//!   persistedsnapshot.
//! - Storing persistent diff info could possibly be done as a Vec-like type
//!   instead of as a BTreeSet. Attempts to do so introduced confusing error
//!   prone index logic but that was before serial number relationships were
//!   stored with diffs and included error prone assumptions involved in
//!   attempting to determine such relationships from vec indices alone. It
//!   may now require less and simpler index calculation logic. However, the
//!   set type currrently also ensures no duplicate entries by diff path. If
//!   next_idx were replaced by a UUID the paths would always be unique which
//!   would diminish or remove the need for a 'set' type.
//! - Make compaction occur when a zone is idle, rather than periodically.
use std::{sync::Arc, time::Duration};

use crate::{
    center::Center,
    policy::PolicyVersion,
    util::AbortOnDrop,
    zone::{Zone, ZoneByName},
};

mod persist;
mod restore;
use restore::{restore_loaded, restore_signed};
use tracing::trace;

pub mod zone;

//----------- Persister --------------------------------------------------------

/// The zone data persister.
///
/// This component is responsible for persisting zone data, so it can be
/// restored (and Cascade can resume operation) after a crash / restart.
#[derive(Debug)]
pub struct Persister {}

impl Persister {
    /// Construct a new [`Persister`].
    pub fn new() -> Self {
        Self {}
    }

    pub fn on_zone_policy_changed(
        &self,
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        old: Option<Arc<PolicyVersion>>,
        new: Arc<PolicyVersion>,
    ) {
        if let Some(old) = old
            && old.server.outbound.max_diffs <= new.server.outbound.max_diffs
            && old.server.outbound.max_diffs_size <= new.server.outbound.max_diffs_size
        {
            // Nothing changed, at least not in a way that affects us.
            // Increased diff limits doesn't require action, only a reduction
            // in limits requires us to act.
            return;
        }

        discard_excess_diffs(center, zone);
    }
}

impl Default for Persister {
    fn default() -> Self {
        Self::new()
    }
}

//----------- Compacter --------------------------------------------------------

/// The zone data compacter.
///
/// Compacts zone data on disk periodically, keeping the number of diffs within
/// the configured maximum per zone.
#[derive(Debug)]
pub struct Compacter {}

impl Compacter {
    /// Construct a new [`Compacter`].
    pub fn new() -> Self {
        Self {}
    }

    /// Drive this [`Compacter`].
    pub fn run(center: Arc<Center>) -> AbortOnDrop {
        AbortOnDrop::from(tokio::spawn(async move {
            // TODO: Make compaction interval configurable?
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;

                // Obtain a list of all zones.
                let zones = {
                    let state = center.state.lock().unwrap();
                    // TODO: To avoid invoking compaction unnecessarily we
                    // could store a flag with the zone to say that the diffs
                    // have been changed since last compaction and reset it on
                    // compaction, and filter unchanged zones out here.
                    state
                        .zones
                        .iter()
                        .filter(|ZoneByName(z)| !z.state.read().maintenance_mode)
                        .map(|ZoneByName(z)| z.clone())
                        .collect::<Vec<_>>()
                };

                // Compact each zone one at a time.
                // TODO: Add a configuration setting to control the maximum
                // number of zones to compact concurrently?
                for zone in zones {
                    // Spawn the compaction task on a Tokio blocking task
                    // thread so as not to block any other async tasks on the
                    // same executor thread with a long running compaction.
                    let mut handle = zone.write_handle(&center);
                    handle.persistence().start_compaction();
                }
            }
        }))
    }
}

impl Default for Compacter {
    fn default() -> Self {
        Self::new()
    }
}

//----------- Restorer ---------------------------------------------------------

/// The zone data restorer.
///
/// This component is responsible for restoring the data of persisted zones when
/// Cascade starts up. Its primary functionality is in [`Restorer::run()`].
#[derive(Debug)]
pub struct Restorer {}

impl Restorer {
    /// Construct a new [`Restorer`].
    pub fn new() -> Self {
        Self {}
    }

    /// Drive this [`Restorer`].
    ///
    /// At startup, the set of zones will be traversed, and for zones that were
    /// restored from state files, restore operations for their zone data will
    /// be initiated.
    pub fn run(center: Arc<Center>) -> AbortOnDrop {
        AbortOnDrop::from(tokio::spawn(async move {
            // Obtain a list of all zones (that need restoring).
            let zones = {
                let state = center.state.lock().unwrap();
                state
                    .zones
                    .iter()
                    .filter(|&z| z.0.restored)
                    .map(|ZoneByName(z)| z.clone())
                    .collect::<Vec<_>>()
            };

            // Attempt to restore data for every zone.
            for zone in zones {
                let mut handle = zone.write_handle(&center);

                // Zones that are _not_ restored from disk will move out the
                // 'restorer' field and use it to initialize the zone data to
                // an empty state. For zones that _are_ restored from disk, the
                // 'restorer' field is moved out over here.
                let restorer = handle.state.storage.restorer.take().unwrap();

                handle.persistence().start_restore(restorer);
            }
        }))
    }
}

impl Default for Restorer {
    fn default() -> Self {
        Self::new()
    }
}

//------------ discard_excess_diffs() ----------------------------------------

/// Calculate from policy and published zone metadata the limits to apply
/// and then trim zone diffs to be within those limits.
//
// TODO: Ideally this would be done as part of PersistentDiffManager::trim()
// but PersistentDiffManager has no access to policy or instance signed
// metadata.
pub fn discard_excess_diffs(center: &Arc<Center>, zone: &Arc<Zone>) {
    let mut state = zone.write(center);

    if let Some(policy) = state.policy.as_ref()
        && let Some(signed_metadata) = state.signed_metadata()
    {
        // Fetch diff purging settings from policy.
        let max_diffs = policy.server.outbound.max_diffs;
        let max_size_percentage = policy.server.outbound.max_diffs_size;

        // Calculate the maximum number of records that a set of diffs can be based on
        // the policy settings. IxfrZoneDiffs can't do this for us as it has
        // no access to `last_published`.
        let current_size = signed_metadata.num_records().get();
        let max_size = calc_max_diff_size(max_size_percentage, current_size);

        trace!(
            "Discarding excess in-memory diffs for zone '{}' with settings max_diffs={max_diffs}, current_size={current_size}, max_size={max_size_percentage}% ({max_size} RRs)",
            zone.name,
        );
        state.storage.diffs.trim(max_diffs, max_size);
    }
}

/// Calculate the maximum size a diff can be as a percentage of the last
/// published zone.
fn calc_max_diff_size(max_size_percentage: usize, current_size: u64) -> usize {
    let percentage = max_size_percentage as f64 / 100.0;
    (current_size as f64 * percentage) as usize
}

#[cfg(test)]
mod tests {
    use super::calc_max_diff_size;

    #[test]
    pub fn test_calc_max_diff_size() {
        let empty_zone = 0;
        assert_eq!(calc_max_diff_size(0, empty_zone), 0);
        assert_eq!(calc_max_diff_size(50, empty_zone), 0);
        assert_eq!(calc_max_diff_size(100, empty_zone), 0);
        assert_eq!(calc_max_diff_size(1000, empty_zone), 0);

        let small_zone = 5;
        assert_eq!(calc_max_diff_size(0, small_zone), 0);
        assert_eq!(calc_max_diff_size(50, small_zone), 2);
        assert_eq!(calc_max_diff_size(100, small_zone), 5);
        assert_eq!(calc_max_diff_size(1000, small_zone), 50);

        let large_zone = 500000;
        assert_eq!(calc_max_diff_size(0, large_zone), 0);
        assert_eq!(calc_max_diff_size(50, large_zone), 250000);
        assert_eq!(calc_max_diff_size(100, large_zone), 500000);
        assert_eq!(calc_max_diff_size(1000, large_zone), 5000000);
    }
}
