//! Zone-specific persistence management.

use std::sync::Arc;

use cascade_zonedata::{LoadedZonePersister, LoadedZoneRestorer, SignedZonePersister};
use tracing::{debug, info, trace, trace_span};

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

    /// Begin restoring data for the zone.
    ///
    /// A background task will be spawned to restore the zone's data (for both
    /// the loaded and signed instances).
    #[tracing::instrument(
        level = "trace",
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
                    Ok(()) => restorer.finish().unwrap_or_else(|_| {
                        unreachable!(
                            "'restore_loaded()' always completes restoration on successful return"
                        )
                    }),
                    Err(_) => {
                        trace!("Abandoning loaded restoration");
                        let mut state = zone.state.lock().unwrap();
                        let mut handle = ZoneHandle {
                            zone: &zone,
                            state: &mut state,
                            center: &center,
                        };
                        handle.storage().abandon_loaded_restoration(restorer);
                        handle.state.persistence.ongoing.finish();
                        return;
                    }
                };

                // Obtain the signed zone restorer.
                let mut restorer = {
                    let mut state = zone.state.lock().unwrap();
                    let mut handle = ZoneHandle {
                        zone: &zone,
                        state: &mut state,
                        center: &center,
                    };
                    handle.storage().finish_loaded_restoration(restored)
                };

                // Try to restore the signed instance.
                let restored = match super::restore_signed(&zone, &center, &mut restorer) {
                    Ok(()) => restorer.finish().unwrap_or_else(|_| {
                        unreachable!(
                            "'restore_signed()' always completes restoration on successful return"
                        )
                    }),
                    Err(_) => {
                        trace!("Abandoning signed restoration");
                        let mut state = zone.state.lock().unwrap();
                        let mut handle = ZoneHandle {
                            zone: &zone,
                            state: &mut state,
                            center: &center,
                        };
                        handle.storage().abandon_signed_restoration(restorer);
                        handle.state.persistence.ongoing.finish();
                        return;
                    }
                };

                info!("Restored the zone's persisted data");
                let mut state = zone.state.lock().unwrap();
                let mut handle = ZoneHandle {
                    zone: &zone,
                    state: &mut state,
                    center: &center,
                };
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

                // NOTE: The outer function, which is spawning the background
                // task, has a lock of the zone state. Thus, the following lock
                // cannot be taken until the outer function terminates.
                let mut state = zone.state.lock().unwrap();
                let mut handle = ZoneHandle {
                    zone: &zone,
                    state: &mut state,
                    center: &center,
                };

                handle.start_new_sign(persisted);

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

                // NOTE: The outer function, which is spawning the background
                // task, has a lock of the zone state. Thus, the following lock
                // cannot be taken until the outer function terminates.
                let mut state = zone.state.lock().unwrap();
                let mut handle = ZoneHandle {
                    zone: &zone,
                    state: &mut state,
                    center: &center,
                };

                handle.start_switch(persisted);

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
