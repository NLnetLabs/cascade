//! Storing zone data.
//!
//! This module integrates the `cascade-zonedata` subcrate with the main daemon.
//! It imports [`ZoneDataStorage`], the core state machine for tracking zone
//! data, and adds helpers around it to simplify common transitions.

use std::{fmt, sync::Arc};

use cascade_zonedata::{
    LoadedZoneBuilder, LoadedZoneBuilt, LoadedZonePersister, LoadedZoneReader, LoadedZoneReviewer,
    SignedZoneBuilder, SignedZoneBuilt, SignedZoneReader, SignedZoneReviewer, ZoneCleaner,
    ZoneDataStorage, ZoneViewer,
};
use domain::zonetree;
use tracing::{info, trace, trace_span, warn};

use crate::{
    center::Center,
    util::{BackgroundTasks, force_future},
    zone::{HistoricalEvent, PipelineMode, SigningTrigger, Zone, ZoneHandle, ZoneState},
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
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn start_load(&mut self) -> Option<LoadedZoneBuilder> {
        // Examine the current state.
        let machine = &mut self.state.storage.machine;
        match machine.take() {
            ZoneDataStorage::Passive(s) => {
                // The zone storage is passive; no other operations are ongoing,
                // and it is possible to begin building a new instance.
                trace!(
                    machine.old = "Passive",
                    machine.new = "Loading",
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
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn finish_load(&mut self, built: LoadedZoneBuilt) {
        // Examine the current state.
        let machine = &mut self.state.storage.machine;
        match machine.take() {
            ZoneDataStorage::Loading(s) => {
                trace!(
                    machine.old = "Loading",
                    machine.new = "ReviewLoadedPending",
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
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn give_up_load(&mut self, builder: LoadedZoneBuilder) {
        // Examine the current state.
        let machine = &mut self.state.storage.machine;
        match machine.take() {
            ZoneDataStorage::Loading(s) => {
                trace!(
                    machine.old = "Loading",
                    machine.new = "Cleaning",
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
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    fn start_loaded_review(&mut self, loaded_reviewer: LoadedZoneReviewer) {
        // NOTE: This function provides compatibility with 'zonetree's.

        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("start_loaded_review");
        self.state.storage.background_tasks.spawn_blocking(span, move || {
            trace!("Converting the loaded instance to 'zonetree'");

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
            trace!(
                machine.old = "ReviewLoadedPending",
                machine.new = "ReviewingLoaded",
                "Initiating loaded review"
            );
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

            state.storage.background_tasks.finish();
        });
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
            let record: cascade_zonedata::OldParsedRecord = record.clone().into();
            force_future(updater.apply(ZoneUpdate::AddRecord(record))).unwrap();
        }

        // Commit the update with the SOA record.
        let soa: cascade_zonedata::OldParsedRecord = reader.soa().clone().into();
        force_future(updater.apply(ZoneUpdate::Finished(soa))).unwrap();

        zone
    }

    /// Approve a loaded instance of a zone.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
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

                trace!("Persisting the loaded instance");

                let (s, persister) = s.mark_approved();
                *machine = ZoneDataStorage::PersistingLoaded(s);
                self.start_loaded_persistence(persister);
            }

            _ => panic!("The zone is not undergoing loader review"),
        }
    }
}

/// # Signer Operations
impl StorageZoneHandle<'_> {
    /// Begin resigning the zone.
    ///
    /// If the zone data storage is not busy, a [`SignedZoneBuilder`] will be
    /// returned through which the instance of the zone can be resigned.
    /// Follow up by calling:
    ///
    /// - [`Self::finish_sign()`] when signing succeeds.
    ///
    /// - [`Self::give_up_sign()`] when signing fails.
    ///
    /// If the zone data storage is busy, [`None`] is returned; the signer
    /// should enqueue the re-sign operation and wait for an idle notification.
    pub fn start_resign(&mut self) -> Option<SignedZoneBuilder> {
        // Examine the current state.
        let machine = &mut self.state.storage.machine;
        match machine.take() {
            ZoneDataStorage::Passive(s) => {
                // The zone storage is passive; no other operations are ongoing,
                // and it is possible to begin re-signing.
                trace!(
                    zone = %self.zone.name,
                    "Obtaining a 'SignedZoneBuilder' for performing a re-sign"
                );

                let (s, builder) = s.resign();
                *machine = ZoneDataStorage::Signing(s);
                Some(builder)
            }

            other => {
                // The zone storage is in the middle of another operation.
                trace!(
                    zone = %self.zone.name,
                    "Deferring re-sign because data storage is busy"
                );

                *machine = other;
                None
            }
        }
    }

    /// Finish (re-)signing.
    ///
    /// The prepared signed instance of the zone is finalized, and passed on
    /// to the signed zone reviewer.
    pub fn finish_sign(&mut self, built: SignedZoneBuilt) {
        // Examine the current state.
        let machine = &mut self.state.storage.machine;
        match machine.take() {
            ZoneDataStorage::Signing(s) => {
                trace!(
                    zone = %self.zone.name,
                    "Successfully finishing the ongoing (re-)sign"
                );

                let (s, signed_reviewer) = s.finish(built);
                *machine = ZoneDataStorage::ReviewSignedPending(s);

                // TODO: Use the instance ID here, which will not require
                // examining the zone contents.
                let serial = signed_reviewer.read_signed().unwrap().soa().rdata.serial;
                self.state.record_event(
                    // TODO: Get the right trigger.
                    HistoricalEvent::SigningSucceeded {
                        trigger: SigningTrigger::SignatureExpiration,
                    },
                    Some(domain::base::Serial(serial.into())),
                );

                self.start_signed_review(signed_reviewer);
            }

            _ => unreachable!(
                "'ZoneDataStorage::Signing' is the only state where a 'SignedZoneBuilt' is available"
            ),
        }
    }

    /// Give up on the ongoing signing operation.
    ///
    /// Intermediate artifacts in the signed instance, and the upcoming loaded
    /// instance (if any), will be cleaned up automatically, in the background.
    /// Once the zone storage is idle, a notification will be sent.
    pub fn give_up_sign(&mut self, builder: SignedZoneBuilder) {
        // Examine the current state.
        let machine = &mut self.state.storage.machine;
        match machine.take() {
            ZoneDataStorage::Signing(s) => {
                trace!(
                    zone = %self.zone.name,
                    "Giving up on the ongoing (re-)sign"
                );

                let (s, loaded_reviewer) = s.give_up(builder);
                // TODO: Communicate the new reviewer handle to the zone server.
                let old_loaded_reviewer =
                    std::mem::replace(&mut self.state.storage.loaded_reviewer, loaded_reviewer);
                let (s, cleaner) = s.stop_review(old_loaded_reviewer);
                *machine = ZoneDataStorage::Cleaning(s);
                self.start_cleanup(cleaner);
            }

            _ => unreachable!(
                "'ZoneDataStorage::Signing' is the only state where a 'SignedZoneBuilder' is available"
            ),
        }
    }
}

/// # Signer Review Operations
impl StorageZoneHandle<'_> {
    /// Initiate review of a new signed instance of a zone.
    fn start_signed_review(&mut self, signed_reviewer: SignedZoneReviewer) {
        // NOTE: This function provides compatibility with 'zonetree's.

        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("start_signed_review");
        self.state.storage.background_tasks.spawn_blocking(span, move || {
            // Read the loaded instance.
            let loaded_reader = signed_reviewer
                .read_loaded()
                .unwrap_or_else(|| unreachable!("The loader never returns an empty instance"));

            // Read the signed instance.
            let signed_reader = signed_reviewer
                .read_signed()
                .unwrap_or_else(|| unreachable!("The signer never returns an empty instance"));
            let serial = signed_reader.soa().rdata.serial;

            // Build a `zonetree` for the new instance.
            let zonetree = Self::build_signed_zonetree(&zone, &loaded_reader, &signed_reader);

            // Insert the new `zonetree`.
            center.signed_zones.rcu(|tree| {
                let mut tree = Arc::unwrap_or_clone(tree.clone());
                let _ = tree.remove_zone(&zone.name, domain::base::iana::Class::IN);
                tree.insert_zone(zonetree.clone()).unwrap();
                tree
            });

            let mut state = zone.state.lock().unwrap();

            // TODO: Pass on the reviewer to the zone server.
            let old_signed_reviewer =
                std::mem::replace(&mut state.storage.signed_reviewer, signed_reviewer);

            // Transition into the reviewing state.
            tracing::debug!("Transitioning zone state...");
            match state.storage.machine.take() {
                ZoneDataStorage::ReviewSignedPending(s) => {
                    // For now, transition all the way back to 'Passive' state.
                    let s = s.start(old_signed_reviewer);
                    let (s, persister) = s.mark_approved();
                    let persisted = persister.persist();
                    let (s, viewer) = s.mark_complete(persisted);
                    let old_viewer = std::mem::replace(&mut state.storage.viewer, viewer);
                    let (s, cleaner) = s.switch(old_viewer);
                    state.storage.machine = ZoneDataStorage::Cleaning(s);
                    ZoneHandle {
                        zone: &zone,
                        state: &mut state,
                        center: &center,
                    }
                    .storage()
                    .start_cleanup(cleaner);
                }

                _ => unreachable!(
                    "'ZoneDataStorage::ReviewSignedPending' is the only state where a 'SignedZoneReviewer' is available"
                ),
            }

            info!("Initiating review of newly-signed instance");

            // TODO: 'on_seek_approval_for_zone' tries to lock zone state.
            std::mem::drop(state);

            center.signed_review_server.on_seek_approval_for_zone(
                &center,
                zone.name.clone(),
                domain::base::Serial(serial.into()),
            );

            state = zone.state.lock().unwrap();

            state.storage.background_tasks.finish()
        });
    }

    /// Build a `zonetree` for an signed instance of a zone.
    fn build_signed_zonetree(
        zone: &Arc<Zone>,
        loaded_reader: &LoadedZoneReader<'_>,
        signed_reader: &SignedZoneReader<'_>,
    ) -> zonetree::Zone {
        use zonetree::{types::ZoneUpdate, update::ZoneUpdater};

        let zone =
            zonetree::ZoneBuilder::new(zone.name.clone(), domain::base::iana::Class::IN).build();

        let mut updater = force_future(ZoneUpdater::new(zone.clone())).unwrap();

        // Clear all existing records.
        force_future(updater.apply(ZoneUpdate::DeleteAllRecords)).unwrap();

        // Add every record in turn.
        for record in signed_reader.records() {
            let record: cascade_zonedata::OldParsedRecord = record.clone().into();
            force_future(updater.apply(ZoneUpdate::AddRecord(record))).unwrap();
        }

        // Add every loaded record in turn (excluding SOA).
        //
        // TODO: Which other records to exclude? DNSKEY, RRSIGs?
        for record in loaded_reader.records() {
            let record: cascade_zonedata::OldParsedRecord = record.clone().into();
            force_future(updater.apply(ZoneUpdate::AddRecord(record))).unwrap();
        }

        // Commit the update with the SOA record.
        let soa: cascade_zonedata::OldParsedRecord = signed_reader.soa().clone().into();
        force_future(updater.apply(ZoneUpdate::Finished(soa))).unwrap();

        zone
    }

    // TODO: approve_signed()
}

/// # Background Tasks
impl StorageZoneHandle<'_> {
    /// Run a cleanup of zone data.
    ///
    /// A background task will be spawned to perform the provided zone cleaning
    /// and transition to the next state.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    fn start_cleanup(&mut self, cleaner: ZoneCleaner) {
        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("clean");
        self.state.storage.background_tasks.spawn_blocking(span, move || {
            trace!("Cleaning the zone");

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

            trace!("Transitioning the state machine to 'Passive'");
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

            // Notify the rest of Cascade that the storage is idle.
            handle.storage().on_idle();

            handle.state.storage.background_tasks.finish();
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
    fn start_loaded_persistence(&mut self, persister: LoadedZonePersister) {
        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("persist_loaded");
        self.state.storage.background_tasks.spawn_blocking(span, move || {
            trace!("Persisting the loaded instance");

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

            // Transition the state machine.
            trace!("Finished persisting");
            let machine = &mut handle.state.storage.machine;
            match machine.take() {
                ZoneDataStorage::PersistingLoaded(s) => {
                    // For now, transition all the way back to 'Passive' state.
                    trace!("Transitioning the state machine to 'Cleaning'");
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

            handle.state.storage.background_tasks.finish();
        });
    }

    /// Respond to the data storage idling.
    ///
    /// When the data storage idles, it is possible to initiate a new load or
    /// resigning of the zone. This method checks for enqueued loads or resigns
    /// and begins them appropriately.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    fn on_idle(&mut self) {
        // TODO: Check whether resigning is needed. It has higher priority than
        // loading a new instance.
        //
        // TODO: If we introduce a top-level state machine for a zone, should
        // this method be implemented there?

        if self.zone().loader().start_pending() {
            // The zone storage is no longer idle.
            return;
        }

        if self.zone().signer().start_pending() {
            // The zone storage is no longer idle.
            // return;
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

    /// Ongoing background tasks.
    ///
    /// When the zone data needs to be cleaned or persisted, a background task
    /// is automatically spawned and tracked here.
    background_tasks: BackgroundTasks,
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
            background_tasks: Default::default(),
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
