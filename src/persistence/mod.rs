//! Persisting zone data to and restoring from disk.
//!
//! The zone persister saves the data for loaded and signed zones to disk, so
//! that Cascade can seamlessly resume operation after a crash / restart. At
//! startup it tries to restore data for all known zones.
//!
//! When re-starting Cascade in-memory zone and IXFR diff data will be lost
//! unless persisted and restored. This module implements persistence
//! and restoration using files on disk stored in the zone-state directory
//! alongside the JSON '.db' zone state files.
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
//!     `StorageState::diffs` so that it can be served in response to an IXFR
//!     request from a downstream nameserver.
//!   - The path that the diff file was written to is appended to
//!     `ZoneState::persisted_loaded_diff_paths` or
//!     `ZoneState::persisted_signed_diff_paths` and the zone state is
//!     immediately saved to disk.
//!
//! # Panics
//!
//! If persistence fails due to an I/O error this will cause Cascade to panic.
//! If the underlying storage that Cascade depends on is not reliable we have
//! no way of knowing what else may be failing and abort as it is not safe to
//! continue under such circumstances.
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
//! content with the loaded snapshot, then applying each loaded diff file
//! to the snapshot one at a time. The diffs are also kept in-memory for
//! responding to IXFR requests from downstream nameservers. The signed
//! snapshot and diffs are also restored like this.
//!
//! Any diff that was available at a review server will have been lost.
//! However as only approved data gets persisted, there should be no need
//! to still be able to query the review server for an IXFR diff after
//! Cascsade restarts.
//!
//! TODO: What happens if loaded data is approved and persisted, but
//! Cascade is terminated before signing occurs. In such a case if restore
//! is done as described above signing can occur as usual, but will a
//! signed review hook be able to query the loaded review server for the
//! loaded diff?

use std::sync::Arc;

use crate::{center::Center, util::AbortOnDrop, zone::ZoneByName};

mod persist;
use persist::{persist_loaded, persist_signed};

mod restore;
use restore::{restore_loaded, restore_signed};

pub mod zone;

//----------- Persister --------------------------------------------------------

/// The zone data persister.
///
/// This component is responsible for persisting zone data, so it can be
/// restored (and Cascade can resume operation) after a crash / restart.
#[derive(Debug)]
pub struct Persister {
    // TODO: Do we need any global state for persistence?
}

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
