//! Zone-specific persistence management.

use std::sync::Arc;

use cascade_zonedata::{
    LoadedZonePersister, LoadedZoneRestorer, SignedZonePersister, SignedZoneRestorer,
};
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

                let mut state = zone.state.lock().unwrap();
                trace!("Restored diffs: {:?}", state.persisted_loaded_diff_paths);
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
                debug!("Persisting the loaded instance completed");

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
                debug!("Persisting the signed instance completed");

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

fn abandon_loaded_restoration(
    center: &Arc<Center>,
    zone: &Arc<Zone>,
    restorer: LoadedZoneRestorer,
) {
    reset_state_due_to_abandoned_restore(center, zone);
    let mut state = zone.state.lock().unwrap();
    let mut handle = ZoneHandle {
        zone,
        state: &mut state,
        center,
    };
    handle.storage().abandon_loaded_restoration(restorer);
    handle.state.persistence.ongoing.finish();
}

fn abandon_signed_restoration(
    center: &Arc<Center>,
    zone: &Arc<Zone>,
    restorer: SignedZoneRestorer,
) {
    reset_state_due_to_abandoned_restore(center, zone);
    let mut state = zone.state.lock().unwrap();
    let mut handle = ZoneHandle {
        zone,
        state: &mut state,
        center,
    };
    handle.storage().abandon_signed_restoration(restorer);
    handle.state.persistence.ongoing.finish();
}

fn reset_state_due_to_abandoned_restore(center: &Arc<Center>, zone: &Arc<Zone>) {
    {
        let mut state = zone.state.lock().unwrap();
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
    // We can't use the persisted data so remove the paths from state and also
    // the corresponding files on disk.
    for p in state
        .persisted_loaded_diff_paths
        .iter()
        .chain(state.persisted_signed_diff_paths.iter())
    {
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
    state.persisted_loaded_diff_paths.clear();
    state.persisted_signed_diff_paths.clear();
}

//----------- PersistenceState -------------------------------------------------

/// State related to data persistence for a zone.
#[derive(Debug, Default)]
pub struct PersistenceState {
    /// Ongoing persist/restore operations.
    pub ongoing: BackgroundTasks,
}
