//! Persisting zone data to and restoring from disk.
//!
//! The zone persister saves the data for loaded and signed zones to disk, so
//! that Cascade can seamlessly resume operation after a crash / restart. At
//! startup, it tries to restore data for all known zones.

use std::sync::Arc;

use crate::{
    center::Center,
    util::AbortOnDrop,
    zone::{ZoneByName, ZoneHandle},
};

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
                let mut state = zone.state.lock().unwrap();
                let mut handle = ZoneHandle {
                    zone: &zone,
                    state: &mut state,
                    center: &center,
                };

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
