//! Persisting zone data to and restoring from disk.
//!
//! # Summary
//!
//! Zone contents are persisted to disk so that Cascade can reuse them when it
//! restarts. This allows it to reuse record signatures, as recomputing them for
//! the whole zone may be expensive. Cascade also persists the contents of zones
//! as they are loaded (i.e. before signing), because it serves a view of that
//! data from its loaded review server.
//!
//! In addition to the most up-to-date data for a zone, Cascade also persists
//! historical data: the data for obsolete instances of zones. Cascade can serve
//! IXFR requests; by persisting old instances, it is able to continue doing so
//! across restarts.
//!
//! Zone data is persisted in two forms: _snapshots_ and _diffs_. A snapshot is
//! a complete copy of data; a diff stores the differences in data between two
//! consecutive instances of a zone. Every zone has at most one snapshot, but
//! any number of diffs.
//!
//! An instance of a zone persisted as a snapshot might not be the latest one.
//! There may be newer instances of the zone, which are persisted as diffs.
//! When starting up, Cascade will load the snapshot and then apply those diffs
//! to it to rebuild an up-to-date view of the zone.
//!
//! As new instances are built over time, the set of diffs grows. This
//! causes two problems: rebuilding an up-to-date view of the zone becomes
//! slower over time, and disk usage grows. To address the former, Cascade
//! periodically performs _compaction_, persisting a new snapshot of a more
//! up-to-date instance and removing the old one. To address the latter,
//! Cascade periodically trims the persisted diffs, removing old diffs past
//! policy-defined limits.
//!
//! # Data format
//!
//! Data is persisted as AXFR and IXFR message ANSWER sections in wire format,
//! without name compression. Thus, they are compact binary files, and it should
//! be possible to inspect and manipulate them by adapting existing DNS tools.
//!
//! Every snapshot and diff is stored in a dedicated file, under Cascade's zone
//! state directory. Diffs are assigned different file names based on their
//! position relative to the snapshot (i.e. whether they lie before or after
//! the snapshot). See e.g. [`LoadedInstance::diff_into_next_path()`].
//!
//! # Failures
//!
//! If persistence fails due to an I/O error this will cause Cascade to panic.
//! If the underlying storage that Cascade depends on is not reliable we have
//! no way of knowing what else may be failing and abort as it is not safe to
//! continue under such circumstances.
//!
//! If restoration fails, Cascade will assume files may be corrupted, and it
//! will remove all persistence files for the affected zone.

use std::{sync::Arc, time::Duration};

use cascade_zonedata::ZoneRestorer;
use tracing::{debug, warn};

use crate::{
    center::Center,
    policy::PolicyVersion,
    server::{LoadedReviewServer, PublicationServer, SignedReviewServer},
    util::AbortOnDrop,
    zone::{
        OwnedZoneHandle, SignedInstanceId, Zone, ZoneByName,
        instance::{ObsoleteInstances, PersistedInstance},
    },
};

mod compact;
mod persist;
mod restore;

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

                // TODO: Make compaction occur when a zone is idle, rather than
                // periodically?

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

                if let Some(instance) = &handle.state.instances.lost_upcoming {
                    let _ =
                        instance.remove_persistence_files(&handle.zone.name, &handle.center.config);
                }
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

//------------ restore() -------------------------------------------------------

/// Restore a zone from persisted data.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
fn restore<'a>(
    zone: &'a Arc<Zone>,
    center: &'a Arc<Center>,
    mut restorer: ZoneRestorer,
    policy: &PolicyVersion,
    persisted: Option<&PersistedInstance>,
    obsolete: &ObsoleteInstances,
    snapshot_id: Option<SignedInstanceId>,
) -> OwnedZoneHandle<'a> {
    debug!("Attempting to restore persisted zone data");

    // Perform the underlying restore operation.
    let result = restore::restore_both(
        zone,
        center,
        &mut restorer,
        policy,
        persisted,
        obsolete,
        snapshot_id,
    );

    let mut handle = zone.write_handle(center);

    let (loaded_reviewer, signed_reviewer, viewer) = match result {
        Ok(Some(restored)) => {
            // Apply the collected changes to the zone state.
            restored
                .obsolete
                .apply(&mut handle.state.instances.obsolete);

            let restored = restorer.finish().unwrap_or_else(|_| {
                unreachable!("Zone restoration should have built new zone data")
            });
            let viewers = handle.storage().finish_restoration(restored);

            // Mark restoration as complete.
            handle.state.instances.restore();
            handle.signer().on_restoration();

            viewers
        }

        Ok(None) => {
            handle.persistence().reset_state_due_to_abandoned_restore();
            handle.storage().abandon_restoration(restorer)
        }

        Err(error) => {
            warn!("Abandoning restoration: {error}");
            handle.persistence().reset_state_due_to_abandoned_restore();
            handle.storage().abandon_restoration(restorer)
        }
    };

    // Register the zone against the zone servers.
    LoadedReviewServer::add_zone(handle.center, handle.zone.clone(), loaded_reviewer);
    SignedReviewServer::add_zone(handle.center, handle.zone.clone(), signed_reviewer);
    PublicationServer::add_zone(handle.center, handle.zone.clone(), viewer);

    // Send a notification that the state machine is now passive.
    handle.storage().on_passive();

    handle
}
