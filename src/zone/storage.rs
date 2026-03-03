//! Storing zone data.
//!
//! This module integrates the `cascade-zonedata` subcrate with the main daemon.
//! It imports [`ZoneDataStorage`], the core state machine for tracking zone
//! data, and adds helpers around it to simplify common transitions.

use std::{fmt, sync::Arc};

use cascade_zonedata::{
    LoadedZoneBuilder, LoadedZoneBuilt, LoadedZonePersister, LoadedZoneReader, LoadedZoneReviewer,
    SignedZoneReviewer, ZoneCleaner, ZoneDataStorage, ZoneViewer,
};
use domain::zonetree;
use tracing::{info, trace, trace_span, warn};

use crate::{
    center::Center,
    util::AbortOnDrop,
    zone::{HistoricalEvent, PipelineMode, Zone, ZoneHandle, ZoneState},
};

//----------- StorageZoneHandle ------------------------------------------------

/// A handle for storage-related operations on a [`Zone`].
pub struct StorageZoneHandle<'a> {
    /// The zone being operated on.
    pub zone: &'a Arc<Zone>,

    /// The locked zone state.
    pub state: &'a mut ZoneState,

    /// Cascade's global state.
    pub center: &'a Arc<Center>,
}

impl StorageZoneHandle<'_> {
    /// Access the generic [`ZoneHandle`].
    pub const fn zone(&mut self) -> ZoneHandle<'_> {
        ZoneHandle {
            zone: self.zone,
            state: self.state,
            center: self.center,
        }
    }
}

/// # Loader Operations
impl StorageZoneHandle<'_> {
    /// Begin loading a new instance of the zone.
    ///
    /// If the zone data storage is not busy, a [`LoadedZoneBuilder`] will be
    /// returned through which a new instance of the zone can be loaded.
    /// Follow up by calling:
    ///
    /// - [`Self::finish_load()`] when loading succeeds.
    ///
    /// - [`Self::give_up_load()`] when loading fails.
    ///
    /// If the zone data storage is busy, [`None`] is returned; the loader
    /// should enqueue the load operation and wait for an idle notification.
    pub fn start_load(&mut self) -> Option<LoadedZoneBuilder> {
        // Examine the current state.
        let machine = &mut self.state.storage.machine;
        match machine.take() {
            ZoneDataStorage::Passive(s) => {
                // The zone storage is passive; no other operations are ongoing,
                // and it is possible to begin building a new instance.
                trace!(
                    zone = %self.zone.name,
                    "Obtaining a 'LoadedZoneBuilder' for performing a load"
                );

                let (s, builder) = s.load();
                *machine = ZoneDataStorage::Loading(s);
                Some(builder)
            }

            other => {
                // The zone storage is in the middle of another operation.
                trace!(
                    zone = %self.zone.name,
                    "Deferring load because data storage is busy"
                );

                *machine = other;
                None
            }
        }
    }

    /// Complete a load.
    ///
    /// The prepared loaded instance of the zone is finalized, and passed on
    /// to the loaded zone reviewer.
    pub fn finish_load(&mut self, built: LoadedZoneBuilt) {
        // Examine the current state.
        let machine = &mut self.state.storage.machine;
        match machine.take() {
            ZoneDataStorage::Loading(s) => {
                trace!(
                    zone = %self.zone.name,
                    "Successfully finishing the ongoing load"
                );

                let (s, loaded_reviewer) = s.finish(built);
                *machine = ZoneDataStorage::ReviewLoadedPending(s);

                // TODO: Use the instance ID here, which will not require
                // examining the zone contents.
                let serial = loaded_reviewer.read_loaded().unwrap().soa().rdata.serial;
                self.state.record_event(
                    HistoricalEvent::NewVersionReceived,
                    Some(domain::base::Serial(serial.into())),
                );

                self.start_loaded_review(loaded_reviewer);
            }

            _ => unreachable!(
                "'ZoneDataStorage::Loading' is the only state where a 'LoadedZoneBuilt' is available"
            ),
        }
    }

    /// Give up on the ongoing load.
    ///
    /// Any intermediate artifacts will be cleaned up automatically, in the
    /// background. Once the zone storage is idle, a notification will be sent.
    pub fn give_up_load(&mut self, builder: LoadedZoneBuilder) {
        // Examine the current state.
        let machine = &mut self.state.storage.machine;
        match machine.take() {
            ZoneDataStorage::Loading(s) => {
                trace!(
                    zone = %self.zone.name,
                    "Giving up on the ongoing load"
                );

                let (s, cleaner) = s.give_up(builder);
                *machine = ZoneDataStorage::Cleaning(s);
                self.start_cleanup(cleaner);
            }

            _ => unreachable!(
                "'ZoneDataStorage::Loading' is the only state where a 'LoadedZoneBuilder' is available"
            ),
        }
    }
}

/// # Loader Review Operations
impl StorageZoneHandle<'_> {
    /// Initiate review of a new loaded instance of a zone.
    fn start_loaded_review(&mut self, loaded_reviewer: LoadedZoneReviewer) {
        // NOTE: This function provides compatibility with 'zonetree's.

        let zone = self.zone.clone();
        let center = self.center.clone();
        let task = tokio::task::spawn_blocking(move || {
            let span = trace_span!("start_loaded_review", zone = %zone.name);
            let _guard = span.enter();

            // Read the loaded instance.
            let reader = loaded_reviewer
                .read_loaded()
                .unwrap_or_else(|| unreachable!("The loader never returns an empty instance"));
            let serial = reader.soa().rdata.serial;

            // Build a `zonetree` for the new instance.
            let zonetree = Self::build_loaded_zonetree(&zone, &reader);

            // Insert the new `zonetree`.
            center.unsigned_zones.rcu(|tree| {
                let mut tree = Arc::unwrap_or_clone(tree.clone());
                let _ = tree.remove_zone(&zone.name, domain::base::iana::Class::IN);
                tree.insert_zone(zonetree.clone()).unwrap();
                tree
            });

            let mut state = zone.state.lock().unwrap();

            // Resume the pipeline if needed.
            let review = match state.pipeline_mode.clone() {
                PipelineMode::Running => true,
                PipelineMode::SoftHalt(message) => {
                    info!("Resuming soft-halted pipeline (halt message: {message})");
                    state.resume();
                    true
                }
                PipelineMode::HardHalt(_) => {
                    // TODO: Is this the right behavior?
                    warn!("Not reviewing newly-loaded instance because pipeline is hard-halted");
                    false
                }
            };

            // TODO: Pass on the reviewer to the zone server.
            let old_loaded_reviewer =
                std::mem::replace(&mut state.storage.loaded_reviewer, loaded_reviewer);

            // Transition into the reviewing state.
            tracing::debug!("Transitioning zone state...");
            match state.storage.machine.take() {
                ZoneDataStorage::ReviewLoadedPending(s) => {
                    let s = s.start(old_loaded_reviewer);
                    state.storage.machine = ZoneDataStorage::ReviewingLoaded(s);
                }

                _ => unreachable!(
                    "'ZoneDataStorage::ReviewLoadedPending' is the only state where a 'LoadedZoneReviewer' is available"
                ),
            }

            if review {
                info!("Initiating review of newly-loaded instance");

                // TODO: 'on_seek_approval_for_zone' tries to lock zone state.
                std::mem::drop(state);

                center.unsigned_review_server.on_seek_approval_for_zone(
                    &center,
                    zone.name.clone(),
                    domain::base::Serial(serial.into()),
                );

                state = zone.state.lock().unwrap();
            }

            // Clean up the background task.
            //
            // NOTE: The outer function is known to have finished by this
            // point (due to the above zone state lock), and it will set
            // 'background_task'. Thus, a race condition is impossible.
            let task = state
                .storage
                .background_task
                .take()
                .expect("The background task 'task' has been set");
            assert_eq!(
                task.id(),
                tokio::task::id(),
                "A different background task is registered"
            );
        });

        self.state.storage.background_task = Some(task.into());
    }

    /// Build a `zonetree` for an loaded instance of a zone.
    fn build_loaded_zonetree(zone: &Arc<Zone>, reader: &LoadedZoneReader<'_>) -> zonetree::Zone {
        use zonetree::{types::ZoneUpdate, update::ZoneUpdater};

        let zone =
            zonetree::ZoneBuilder::new(zone.name.clone(), domain::base::iana::Class::IN).build();

        let mut updater = force_future(ZoneUpdater::new(zone.clone())).unwrap();

        // Clear all existing records.
        force_future(updater.apply(ZoneUpdate::DeleteAllRecords)).unwrap();

        // Add every record in turn.
        for record in reader.records() {
            let record: cascade_zonedata::OldRecord = record.clone().into();
            force_future(updater.apply(ZoneUpdate::AddRecord(record))).unwrap();
        }

        // Commit the update with the SOA record.
        let soa: cascade_zonedata::OldRecord = reader.soa().clone().into();
        force_future(updater.apply(ZoneUpdate::Finished(soa))).unwrap();

        zone
    }

    /// Approve a loaded instance of a zone.
    pub fn approve_loaded(&mut self) {
        // Examine the current state.
        let machine = &mut self.state.storage.machine;
        match machine.take() {
            ZoneDataStorage::ReviewingLoaded(s) => {
                // TODO: Specify the instance ID.
                info!(
                    zone = %self.zone.name,
                    "The loaded instance has been approved"
                );

                trace!(
                    zone = %self.zone.name,
                    "Persisting the loaded instance"
                );

                let (s, persister) = s.mark_approved();
                *machine = ZoneDataStorage::PersistingLoaded(s);
                self.start_loaded_persistence(persister);
            }

            _ => panic!("The zone is not undergoing loader review"),
        }
    }
}

/// # Background Tasks
impl StorageZoneHandle<'_> {
    /// Run a cleanup of zone data.
    ///
    /// A background task will be spawned to perform the provided zone cleaning
    /// and transition to the next state.
    fn start_cleanup(&mut self, cleaner: ZoneCleaner) {
        let zone = self.zone.clone();
        let center = self.center.clone();
        let task = tokio::task::spawn_blocking(move || {
            // Perform the cleaning.
            let cleaned = cleaner.clean();

            // Transition the state machine.
            //
            // NOTE: The outer function, which is spawning the background task,
            // has a lock of the zone state. Thus, the following lock cannot be
            // taken until the outer function terminates.
            let mut state = zone.state.lock().unwrap();
            let mut handle = ZoneHandle {
                zone: &zone,
                state: &mut state,
                center: &center,
            };
            let machine = &mut handle.state.storage.machine;
            match machine.take() {
                ZoneDataStorage::Cleaning(s) => {
                    let s = s.mark_complete(cleaned);
                    *machine = ZoneDataStorage::Passive(s);
                }

                _ => unreachable!(
                    "'ZoneDataStorage::Cleaning' is the only state where a 'ZoneCleaner' is available"
                ),
            }

            // Clean up the background task.
            //
            // NOTE: The outer function is known to have finished by this
            // point (due to the above zone state lock), and it will set
            // 'background_task'. Thus, a race condition is impossible.
            let task = handle
                .state
                .storage
                .background_task
                .take()
                .expect("The background task 'task' has been set");
            assert_eq!(
                task.id(),
                tokio::task::id(),
                "A different background task is registered"
            );

            // Notify the rest of Cascade that the storage is idle.
            handle.storage().on_idle();
        });

        self.state.storage.background_task = Some(task.into());
    }

    /// Begin persisting a loaded zone instance.
    ///
    /// A background task will be spawned to perform the provided zone
    /// persistence and transition to the next state.
    fn start_loaded_persistence(&mut self, persister: LoadedZonePersister) {
        let zone = self.zone.clone();
        let center = self.center.clone();
        let task = tokio::task::spawn_blocking(move || {
            // Perform the persisting.
            let persisted = persister.persist();

            // NOTE: The outer function, which is spawning the background task,
            // has a lock of the zone state. Thus, the following lock cannot be
            // taken until the outer function terminates.
            let mut state = zone.state.lock().unwrap();
            let mut handle = ZoneHandle {
                zone: &zone,
                state: &mut state,
                center: &center,
            };

            // Clean up the background task.
            //
            // NOTE: The outer function is known to have finished by this
            // point (due to the above zone state lock), and it will set
            // 'background_task'. Thus, a race condition is impossible.
            let task = handle
                .state
                .storage
                .background_task
                .take()
                .expect("The background task 'task' has been set");
            assert_eq!(
                task.id(),
                tokio::task::id(),
                "A different background task is registered"
            );

            // Transition the state machine.
            let machine = &mut handle.state.storage.machine;
            match machine.take() {
                ZoneDataStorage::PersistingLoaded(s) => {
                    // For now, transition all the way back to 'Passive' state.
                    let (s, mut builder) = s.mark_complete(persisted);
                    builder.clear();
                    let built = builder.finish().unwrap_or_else(|_| unreachable!());
                    let (s, reviewer) = s.finish(built);
                    let old_signed_reviewer =
                        std::mem::replace(&mut handle.state.storage.signed_reviewer, reviewer);
                    let s = s.start(old_signed_reviewer);
                    let (s, persister) = s.mark_approved();
                    let persisted = persister.persist();
                    let (s, viewer) = s.mark_complete(persisted);
                    let old_viewer = std::mem::replace(&mut handle.state.storage.viewer, viewer);
                    let (s, cleaner) = s.switch(old_viewer);
                    *machine = ZoneDataStorage::Cleaning(s);
                    handle.storage().start_cleanup(cleaner);
                }

                _ => unreachable!(
                    "'ZoneDataStorage::PersistingLoaded' is the only state where a 'LoadedZonePersister' is available"
                ),
            }

            // Notify the rest of Cascade that the storage is idle.
            handle.storage().on_idle();
        });

        self.state.storage.background_task = Some(task.into());
    }

    /// Respond to the data storage idling.
    ///
    /// When the data storage idles, it is possible to initiate a new load or
    /// resigning of the zone. This method checks for enqueued loads or resigns
    /// and begins them appropriately.
    fn on_idle(&mut self) {
        // TODO: Check whether resigning is needed. It has higher priority than
        // loading a new instance.
        //
        // TODO: If we introduce a top-level state machine for a zone, should
        // this method be implemented there?

        if self.zone().loader().start_pending() {
            // The zone storage is no longer idle.
            //return;
        }
    }
}

//----------- StorageState -----------------------------------------------------

/// The state of a zone's data storage.
pub struct StorageState {
    /// The underlying state machine.
    machine: ZoneDataStorage,

    /// The current loaded zone reviewer.
    //
    // TODO: Move into the zone server unit.
    loaded_reviewer: LoadedZoneReviewer,

    /// The current zone reviewer.
    //
    // TODO: Move into the zone server unit.
    signed_reviewer: SignedZoneReviewer,

    /// The current zone viewer.
    //
    // TODO: Move into the zone server unit.
    viewer: ZoneViewer,

    /// An ongoing background task for the zone data.
    ///
    /// When the zone data needs to be cleaned or persisted, a background task
    /// is automatically spawned and tracked here.
    background_task: Option<AbortOnDrop>,
}

impl StorageState {
    /// Construct a new [`StorageState`].
    pub fn new() -> Self {
        let (machine, loaded_reviewer, signed_reviewer, viewer) = ZoneDataStorage::new();

        Self {
            machine,
            loaded_reviewer,
            signed_reviewer,
            viewer,
            background_task: None,
        }
    }
}

impl Default for StorageState {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for StorageState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataStorage")
    }
}

//------------------------------------------------------------------------------

/// Force a [`Future`] to evaluate synchronously.
fn force_future<F: IntoFuture>(future: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let future = std::pin::pin!(future.into_future());
    match future.poll(&mut cx) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => {
            panic!("Could not evaluate the future synchronously")
        }
    }
}
