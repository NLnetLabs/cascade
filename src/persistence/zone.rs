//! Zone-specific persistence management.

use std::sync::Arc;

use cascade_zonedata::LoadedZonePersister;
use tracing::{debug, trace_span};

use crate::{
    center::Center,
    util::BackgroundTasks,
    zone::{Zone, ZoneHandle, ZoneState},
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

                // NOTE: The outer function, which is spawning the background task,
                // has a lock of the zone state. Thus, the following lock cannot be
                // taken until the outer function terminates.
                let mut state = zone.state.lock().unwrap();
                let mut handle = ZoneHandle {
                    zone: &zone,
                    state: &mut state,
                    center: &center,
                };

                handle.begin_signing(persisted);

                handle.state.persistence.ongoing.finish();
            });
    }
}

//----------- PersistenceState -------------------------------------------------

/// State related to data persistence for a zone.
#[derive(Debug, Default)]
pub struct PersistenceState {
    /// Ongoing persist/restore operations.
    pub ongoing: BackgroundTasks,
}
