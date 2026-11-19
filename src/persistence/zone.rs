//! Zone-specific persistence management.

use std::sync::Arc;

use bytes::Bytes;
use camino::Utf8PathBuf;
use domain::base::Name;
use tracing::{debug, error, trace, trace_span, warn};

use crate::{
    center::Center,
    persistence::{
        compact::compact,
        persist::{persist_loaded, persist_signed},
    },
    util::BackgroundTasks,
    zone::{
        LoadedInstance, SignedInstance, SignedInstanceId, Zone, ZoneHandle, ZoneState,
        instance::{LostUpcomingInstance, ObsoleteInstances, UpcomingInstance},
    },
    zonedata::{LoadedZonePersister, SignedZonePersister, ZoneRestorer},
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

    pub(super) fn reset_state_due_to_abandoned_restore(&mut self) {
        self.clear();

        // Mark the persisted instance as obsolete.
        self.state.instances.obsolete_persisted();

        // Forget about the old snapshot, if any.
        self.state.persistence.snapshot_id = None;

        // Remove any already enqueued signing operation that is blocked by
        // the ongoing restore as it will otherwise immediately start once the
        // restore completes.
        self.zone().signer().cancel_enqueued_signing_operations();

        // TODO: self the error?
        let _ = self.zone().save_state_now();
    }

    pub fn clear(&mut self) {
        // Clear the upcoming instance, if any.
        if let Some(instance) = &self.state.instances.upcoming {
            let _ = instance.remove_persistence_files(&self.zone.name, &self.center.config);
        }

        // Clear all obsolete instances.
        let _ = self
            .state
            .instances
            .obsolete
            .remove_persistence_files(&self.zone.name, &self.center.config);
    }

    /// Compact persisted data for the zone.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn start_compaction(&mut self) {
        let Some(current) = self.state.instances.current.clone() else {
            trace!("Skipping compaction: no current instance");
            return;
        };
        let Some(snapshot_id) = self.state.persistence.snapshot_id else {
            warn!("Bug: current instance set but no snapshot ID found");
            return;
        };
        if snapshot_id == current.signed.id {
            trace!("Skipping compaction: snapshot is up-to-date");
            return;
        }
        let obsolete = self.state.instances.obsolete.clone();
        let Some(policy) = self.state.policy.clone() else {
            trace!("Skipping compaction: missing policy");
            return;
        };
        let Some(viewer) = self.center.publication_server.viewer(self.zone) else {
            trace!("Skipping compaction: missing publication viewer");
            return;
        };
        let Ok(viewer) = viewer.try_read_owned() else {
            trace!("Skipping compaction: could not lock publication viewer");
            return;
        };
        if viewer.read().is_none() {
            trace!("Skipping compaction: publication viewer appears empty");
            return;
        }
        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("compact");
        self.state
            .persistence
            .ongoing
            .spawn_blocking(span, move || {
                let mut handle = compact(
                    &zone,
                    &center,
                    viewer.read().unwrap(),
                    &policy,
                    &current,
                    &obsolete,
                    snapshot_id,
                );
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
    pub fn start_restore(&mut self, restorer: ZoneRestorer) {
        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("restore");
        let policy = self.state.policy.clone().unwrap();
        let persisted = self.state.instances.persisted.clone();
        let obsolete = self.state.instances.obsolete.clone();
        let snapshot_id = self.state.persistence.snapshot_id;
        self.state
            .persistence
            .ongoing
            .spawn_blocking(span, move || {
                let mut handle = super::restore(
                    &zone,
                    &center,
                    restorer,
                    &policy,
                    persisted.as_ref(),
                    &obsolete,
                    snapshot_id,
                );
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
        let upcoming = self
            .state
            .instances
            .upcoming
            .as_ref()
            .and_then(|i| i.loaded.as_ref())
            .unwrap()
            .clone();

        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("loaded_persistence");
        self.state
            .persistence
            .ongoing
            .spawn_blocking(span, move || {
                persist_loaded(&zone, &center, &upcoming);
                let persisted = persister.mark_complete();

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
        let upcoming = self.state.instances.upcoming.clone().unwrap();

        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("signed_persistence");
        self.state
            .persistence
            .ongoing
            .spawn_blocking(span, move || {
                persist_signed(&zone, &center, &upcoming);
                let persisted = persister.mark_complete();

                // NOTE: The outer function, which is spawning the background
                // task, has a lock of the zone state. Thus, the following lock
                // cannot be taken until the outer function terminates.
                let mut handle = zone.write_handle(&center);

                handle.get().finish_signed_persistence(persisted);

                handle.state.persistence.ongoing.finish();
            });
    }
}

//----------- PersistenceState -----------------------------------------------

/// State related to data persistence for a zone.
///
/// Each zone consists of records from the loaded zone and, once signed,
/// changes in the set of records that result from signing.
///
/// Each time a zone is reloaded from the source records may change resulting
/// in a loaded diff. Each time a zone is (re)signed records that were created
/// by the last signing operation may be changed resulting in a signed diff.
#[derive(Debug, Default)]
pub struct PersistenceState {
    /// Ongoing persist/restore operations.
    pub ongoing: BackgroundTasks,

    /// The ID of an instance whose snapshot has been persisted to disk.
    ///
    /// If this is [`Some`], snapshots of the loaded and signed instance have
    /// been persisted to disk. When Cascade restarts, they will be used to
    /// restore zone data. The field is cleared if the snapshots are unusable.
    pub snapshot_id: Option<SignedInstanceId>,
}

//----------- Instances --------------------------------------------------------

impl UpcomingInstance {
    /// Remove persistence files associated with this instance.
    pub fn remove_persistence_files(
        &self,
        zone_name: &Name<Bytes>,
        config: &crate::Config,
    ) -> std::io::Result<()> {
        // TODO: Propagate error information **without short-circuiting**.
        if let Some(loaded) = &self.loaded {
            let _ = loaded.remove_persistence_files(zone_name, config);
        }
        if let Some(signed) = &self.signed {
            let _ = signed.remove_persistence_files(zone_name, config);
        }
        Ok(())
    }
}

impl ObsoleteInstances {
    /// Remove persistence files associated with this instance.
    pub fn remove_persistence_files(
        &self,
        zone_name: &Name<Bytes>,
        config: &crate::Config,
    ) -> std::io::Result<()> {
        // TODO: Propagate error information **without short-circuiting**.
        for is in &self.per_load {
            let _ = is.loaded.remove_persistence_files(zone_name, config);
            for i in &is.signed {
                let _ = i.remove_persistence_files(zone_name, config);
            }
        }
        for i in &self.latest_signed {
            let _ = i.remove_persistence_files(zone_name, config);
        }
        Ok(())
    }
}

impl LostUpcomingInstance {
    /// Remove persistence files associated with this instance.
    pub fn remove_persistence_files(
        &self,
        zone_name: &Name<Bytes>,
        config: &crate::Config,
    ) -> std::io::Result<()> {
        // TODO: Propagate error information **without short-circuiting**.
        if let Some(loaded) = &self.loaded {
            let _ = loaded.remove_persistence_files(zone_name, config);
        }
        if let Some(signed) = &self.signed {
            let _ = signed.remove_persistence_files(zone_name, config);
        }
        Ok(())
    }
}

impl LoadedInstance {
    /// Remove persistence files associated with this instance.
    pub fn remove_persistence_files(
        &self,
        zone_name: &Name<Bytes>,
        config: &crate::Config,
    ) -> std::io::Result<()> {
        for path in [
            self.diff_into_next_path(zone_name, config),
            self.diff_from_prev_path(zone_name, config),
            self.snapshot_path(zone_name, config),
        ] {
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    debug!(%path, "Removed persistence file");
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    trace!(%path, "Persistence file does not exist");
                }
                Err(err) => {
                    error!(%path, "Persistence file could not be removed: {err}");
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    /// The path to the persisted prev-diff file, if any.
    ///
    /// If the diff *from this instance to the succeeding one* has been
    /// persisted, it will be stored at this path.
    pub fn diff_into_next_path(
        &self,
        zone_name: &Name<Bytes>,
        config: &crate::Config,
    ) -> Utf8PathBuf {
        let mut path = config
            .zone_state_dir
            .join(self.persistence_basename(zone_name))
            .into_string();
        path.push_str(".into-next.diff");
        path.into()
    }

    /// The path to the persisted diff file from the preceding instance.
    ///
    /// If the diff *from the preceding instance to this one* has been
    /// persisted, it will be stored at this path.
    pub fn diff_from_prev_path(
        &self,
        zone_name: &Name<Bytes>,
        config: &crate::Config,
    ) -> Utf8PathBuf {
        let mut path = config
            .zone_state_dir
            .join(self.persistence_basename(zone_name))
            .into_string();
        path.push_str(".from-prev.diff");
        path.into()
    }

    /// The path to the persisted snapshot at this instance, if any.
    ///
    /// If a snapshot for this instance has been persisted, it will be stored
    /// at this path.
    pub fn snapshot_path(&self, zone_name: &Name<Bytes>, config: &crate::Config) -> Utf8PathBuf {
        let mut path = config
            .zone_state_dir
            .join(self.persistence_basename(zone_name))
            .into_string();
        path.push_str(".snapshot");
        path.into()
    }

    /// A base name for persisted files for this instance.
    pub fn persistence_basename(&self, zone_name: &Name<Bytes>) -> String {
        format!("{zone_name}.L{}-SOA{}", self.id.0, self.serial().get())
    }
}

impl SignedInstance {
    /// Remove persistence files associated with this instance.
    pub fn remove_persistence_files(
        &self,
        zone_name: &Name<Bytes>,
        config: &crate::Config,
    ) -> std::io::Result<()> {
        for path in [
            self.diff_into_next_path(zone_name, config),
            self.diff_from_prev_path(zone_name, config),
            self.snapshot_path(zone_name, config),
        ] {
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    debug!(%path, "Removed persistence file");
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    trace!(%path, "Persistence file does not exist");
                }
                Err(err) => {
                    error!(%path, "Persistence file could not be removed: {err}");
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    /// The path to the persisted prev-diff file, if any.
    ///
    /// If the diff *from this instance to the succeeding one* has been
    /// persisted, it will be stored at this path.
    pub fn diff_into_next_path(
        &self,
        zone_name: &Name<Bytes>,
        config: &crate::Config,
    ) -> Utf8PathBuf {
        let mut path = config
            .zone_state_dir
            .join(self.persistence_basename(zone_name))
            .into_string();
        path.push_str(".into-next.diff");
        path.into()
    }

    /// The path to the persisted diff file from the preceding instance.
    ///
    /// If the diff *from the preceding instance to this one* has been
    /// persisted, it will be stored at this path.
    pub fn diff_from_prev_path(
        &self,
        zone_name: &Name<Bytes>,
        config: &crate::Config,
    ) -> Utf8PathBuf {
        let mut path = config
            .zone_state_dir
            .join(self.persistence_basename(zone_name))
            .into_string();
        path.push_str(".from-prev.diff");
        path.into()
    }

    /// The path to the persisted snapshot at this instance, if any.
    ///
    /// If a snapshot for this instance has been persisted, it will be stored
    /// at this path.
    pub fn snapshot_path(&self, zone_name: &Name<Bytes>, config: &crate::Config) -> Utf8PathBuf {
        let mut path = config
            .zone_state_dir
            .join(self.persistence_basename(zone_name))
            .into_string();
        path.push_str(".snapshot");
        path.into()
    }

    /// A base name for persisted files for this instance.
    pub fn persistence_basename(&self, zone_name: &Name<Bytes>) -> String {
        format!(
            "{zone_name}.L{}-S{}-SOA{}",
            self.id.0.0,
            self.id.1,
            self.serial().get()
        )
    }
}
