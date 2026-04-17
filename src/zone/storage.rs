//! Storing zone data.
//!
//! This module integrates the [`cascade_zonedata`] subcrate with the main
//! daemon. It imports [`ZoneDataStorage`], the core state machine for tracking
//! zone data, and adds helpers around it to simplify common transitions.
//!
//! Zone data storage consists of the following components:
//!
//! - The *current loaded instance*.
//! - The *current signed instance*.
//! - An *upcoming loaded instance*.
//! - An *upcoming signed instance*.
//!
//! The *current* instances have been approved and published. The *upcoming*
//! instances are being built and reviewed; once they are (both!) approved, they
//! will replace the current instances. Each instance is either read-locked (so
//! it can be served or reviewed) or write-locked (so it can be built into).
//! [`ZoneDataStorage`] is a state machine for manipulating instances.
//!
//! The zone data storage is *passive* or *busy*. In passive state, no instances
//! of the zone are being built, so new operations (e.g. loading and re-signing)
//! can be initiated. In busy state, an instance of the zone is being built, and
//! such operations must wait. When the data storage becomes passive, it will
//! call [`StorageZoneHandle::on_passive()`] to initiate enqueued operations.

use std::{fmt, sync::Arc};

use cascade_zonedata::{
    LoadedZoneBuilder, LoadedZoneBuilt, LoadedZonePersisted, LoadedZonePersister,
    LoadedZoneReviewer, SignedZoneBuilder, SignedZoneBuilt, SignedZonePersister,
    SignedZoneReviewer, SoaRecord, ZoneCleaner, ZoneDataStorage, ZoneViewer,
};
use domain::base::Serial;
use tracing::{info, trace, trace_span, warn};

use crate::{
    center::Center,
    server::{LoadedReviewServer, PublicationServer, SignedReviewServer},
    util::BackgroundTasks,
    zone::{HistoricalEvent, LastPublished, Zone, ZoneHandle, ZoneState},
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
    /// - [`Self::abandon_load()`] when loading fails.
    ///
    /// If the zone data storage is busy, [`None`] is returned; the loader
    /// should enqueue the load operation and wait for a passive notification.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn start_load(&mut self) -> Option<LoadedZoneBuilder> {
        // Examine the current state.
        let (transition, state) = transition(&mut self.state.storage.machine);
        match state {
            ZoneDataStorage::Passive(s) => {
                // The zone storage is passive; no other operations are ongoing,
                // and it is possible to begin building a new instance.
                trace!("Obtaining a 'LoadedZoneBuilder' for performing a load");

                let (s, builder) = s.load();
                transition.move_to(ZoneDataStorage::Loading(s));
                Some(builder)
            }

            other => {
                // The zone storage is in the middle of another operation.
                trace!("Deferring load because data storage is busy");

                transition.move_to(other);
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
        let (transition, state) = transition(&mut self.state.storage.machine);
        match state {
            ZoneDataStorage::Loading(s) => {
                trace!("Finishing the ongoing load");

                let (s, loaded_reviewer) = s.finish(built);
                transition.move_to(ZoneDataStorage::ReviewLoadedPending(s));

                // TODO: Use the instance ID here, which will not require
                // examining the zone contents.
                let serial = loaded_reviewer.read().unwrap().soa().rdata.serial;
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

    /// Abandon the ongoing load.
    ///
    /// The caller was performing a load operation which did not succeed; this
    /// method will consume its builder object and clean up any leftover data.
    ///
    /// Once the zone storage is passive, a notification will be sent to begin
    /// enqueued operations.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn abandon_load(&mut self, builder: LoadedZoneBuilder) {
        // Examine the current state.
        let (transition, state) = transition(&mut self.state.storage.machine);
        match state {
            ZoneDataStorage::Loading(s) => {
                trace!("Abandoning the ongoing load");

                let (s, cleaner) = s.give_up(builder);
                transition.move_to(ZoneDataStorage::Cleaning(s));
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
        self.state.storage.loaded_review_soa = loaded_reviewer.read().map(|r| r.soa().clone());

        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("start_loaded_review");
        self.state.storage.background_tasks.spawn(span, async move {
            // Read the loaded instance.
            let reader = loaded_reviewer
                .read()
                .unwrap_or_else(|| unreachable!("The loader never returns an empty instance"));
            let serial = reader.soa().rdata.serial;

            trace!("Updating the viewer in 'LoadedReviewServer'");
            let old_loaded_reviewer = LoadedReviewServer::update_viewer(&center, &zone, loaded_reviewer).await;

            let mut state = zone.state.lock().unwrap();

            // Transition into the reviewing state.
            match transition(&mut state.storage.machine) {
                (transition, ZoneDataStorage::ReviewLoadedPending(s)) => {
                    let s = s.start(old_loaded_reviewer);
                    transition.move_to(ZoneDataStorage::ReviewingLoaded(s));
                }

                _ => unreachable!(
                    "'ZoneDataStorage::ReviewLoadedPending' is the only state where a 'LoadedZoneReviewer' is available"
                ),
            }

            info!("Initiating review of newly-loaded instance");

            // TODO: 'on_seek_approval_for_zone' tries to lock zone state.
            std::mem::drop(state);

            LoadedReviewServer::start_review(
                &center,
                &zone,
                domain::base::Serial(serial.into()),
            );

            state = zone.state.lock().unwrap();

            state.storage.background_tasks.finish();
        });
    }

    /// Accept a loaded instance of a zone.
    ///
    /// A [`LoadedZonePersister`] is returned through which the instance must
    /// be persisted. Once persistence is complete, the [`LoadedZonePersisted`]
    /// should be passed to [`Self::start_new_sign()`].
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn accept_loaded(&mut self) -> LoadedZonePersister {
        // Examine the current state.
        let (transition, state) = transition(&mut self.state.storage.machine);
        match state {
            ZoneDataStorage::ReviewingLoaded(s) => {
                let (s, persister) = s.mark_approved();
                transition.move_to(ZoneDataStorage::PersistingLoaded(s));
                persister
            }

            _ => panic!("The zone is not undergoing loader review"),
        }
    }

    /// Give up on a loaded instance undergoing review.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn abandon_loaded_review(&mut self) {
        // Examine the current state.
        let loaded_reviewer = match transition(&mut self.state.storage.machine) {
            (transition, ZoneDataStorage::ReviewingLoaded(s)) => {
                // TODO: Specify the instance ID.
                info!("The loaded instance has been rejected; cleaning it up");

                let (s, loaded_reviewer) = s.give_up();
                self.state.storage.loaded_review_soa =
                    loaded_reviewer.read().map(|r| r.soa().clone());
                transition.move_to(ZoneDataStorage::CleanLoadedPending(s));
                loaded_reviewer
            }

            _ => panic!("The zone is not undergoing loader review"),
        };

        // Stop serving the abandoned instance.
        self.start_rewinding_loaded_review(loaded_reviewer);
    }
}

/// # Signer Operations
impl StorageZoneHandle<'_> {
    /// Start signing a new approved and persisted loaded instance.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn start_new_sign(&mut self, persisted: LoadedZonePersisted) -> SignedZoneBuilder {
        match transition(&mut self.state.storage.machine) {
            (transition, ZoneDataStorage::PersistingLoaded(s)) => {
                let (s, builder) = s.mark_complete(persisted);
                transition.move_to(ZoneDataStorage::Signing(s));
                builder
            }

            _ => unreachable!(
                "'ZoneDataStorage::PersistingLoaded' is the only state where a 'LoadedZonePersisted' is available"
            ),
        }
    }

    /// Begin resigning the zone.
    ///
    /// If the zone data storage is not busy, a [`SignedZoneBuilder`] will be
    /// returned through which the instance of the zone can be resigned.
    /// Follow up by calling:
    ///
    /// - [`Self::finish_sign()`] when signing succeeds.
    ///
    /// - [`Self::abandon_sign()`] when signing fails.
    ///
    /// If the zone data storage is busy, [`None`] is returned; the
    /// signer should enqueue the re-sign operation and wait for a passive
    /// notification.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn start_resign(&mut self) -> Option<SignedZoneBuilder> {
        // Examine the current state.
        let (transition, state) = transition(&mut self.state.storage.machine);
        match state {
            ZoneDataStorage::Passive(s) => {
                // The zone storage is passive; no other operations are ongoing,
                // and it is possible to begin re-signing.
                trace!("Obtaining a 'SignedZoneBuilder' for performing a re-sign");

                let (s, builder) = s.resign();
                transition.move_to(ZoneDataStorage::Signing(s));
                Some(builder)
            }

            other => {
                // The zone storage is in the middle of another operation.
                trace!("Deferring re-sign because data storage is busy");

                transition.move_to(other);
                None
            }
        }
    }

    /// Finish (re-)signing.
    ///
    /// The prepared signed instance of the zone is finalized, and passed on
    /// to the signed zone reviewer.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn finish_sign(&mut self, built: SignedZoneBuilt) {
        // Examine the current state.
        let (transition, state) = transition(&mut self.state.storage.machine);
        match state {
            ZoneDataStorage::Signing(s) => {
                trace!("Finishing the ongoing sign operation");

                let (s, signed_reviewer) = s.finish(built);
                transition.move_to(ZoneDataStorage::ReviewSignedPending(s));

                self.start_signed_review(signed_reviewer);
            }

            _ => unreachable!(
                "'ZoneDataStorage::Signing' is the only state where a 'SignedZoneBuilt' is available"
            ),
        }
    }

    /// Abandon the ongoing signing operation.
    ///
    /// The caller was performing a signing operation which did not succeed;
    /// this method will consume its builder object and clean up any leftover
    /// data. It will clean up the upcoming signed instance, **and** the
    /// upcoming loaded instance (if any).
    ///
    /// Once the zone storage is passive, a notification will be sent to begin
    /// enqueued operations.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn abandon_sign(&mut self, builder: SignedZoneBuilder) {
        // Examine the current state.
        let loaded_reviewer = match transition(&mut self.state.storage.machine) {
            (transition, ZoneDataStorage::Signing(s)) => {
                trace!("Abandoning the ongoing sign operation");

                let (s, loaded_reviewer) = s.give_up(builder);
                self.state.storage.loaded_review_soa =
                    loaded_reviewer.read().map(|r| r.soa().clone());
                transition.move_to(ZoneDataStorage::CleanLoadedPending(s));
                loaded_reviewer
            }

            _ => unreachable!(
                "'ZoneDataStorage::Signing' is the only state where a 'SignedZoneBuilder' is available"
            ),
        };

        // Stop serving the abandoned instance.
        self.start_rewinding_loaded_review(loaded_reviewer);
    }
}

/// # Signer Review Operations
impl StorageZoneHandle<'_> {
    /// Initiate review of a new signed instance of a zone.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    fn start_signed_review(&mut self, signed_reviewer: SignedZoneReviewer) {
        self.state.storage.signed_review_soa = signed_reviewer.read().map(|r| r.soa().clone());

        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("start_signed_review");
        self.state.storage.background_tasks.spawn(span, async move {
            // Read the instance.
            let reader = signed_reviewer
                .read()
                .unwrap_or_else(|| unreachable!("The signer never returns an empty instance"));
            let serial = reader.soa().rdata.serial;

            trace!("Updating the viewer in 'SignedReviewServer'");
            let old_signed_reviewer = SignedReviewServer::update_viewer(&center, &zone, signed_reviewer).await;

            let mut state = zone.state.lock().unwrap();

            // Transition into the reviewing state.
            match transition(&mut state.storage.machine) {
                (transition, ZoneDataStorage::ReviewSignedPending(s)) => {
                    let s = s.start(old_signed_reviewer);
                    transition.move_to(ZoneDataStorage::ReviewingSigned(s));
                }

                _ => unreachable!(
                    "'ZoneDataStorage::ReviewSignedPending' is the only state where a 'SignedZoneReviewer' is available"
                ),
            }

            info!("Initiating review of newly-signed instance");

            // TODO: 'on_seek_approval_for_zone' tries to lock zone state.
            std::mem::drop(state);

            SignedReviewServer::start_review(
                &center,
                &zone,
                domain::base::Serial(serial.into()),
            );

            state = zone.state.lock().unwrap();

            state.storage.background_tasks.finish()
        });
    }

    /// Accept a signed instance of a zone.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn accept_signed(&mut self) {
        // Examine the current state.
        let (transition, state) = transition(&mut self.state.storage.machine);
        match state {
            ZoneDataStorage::ReviewingSigned(s) => {
                // TODO: Specify the instance ID.
                info!("The signed instance has been approved; persisting it");

                let (s, persister) = s.mark_approved();
                transition.move_to(ZoneDataStorage::PersistingSigned(s));
                self.start_signed_persistence(persister);
            }

            _ => panic!("The zone is not undergoing signer review"),
        }
    }

    /// Give up on a signed instance undergoing review.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub fn abandon_signed_review(&mut self) {
        // Examine the current state.
        let (loaded_reviewer, signed_reviewer);
        match transition(&mut self.state.storage.machine) {
            (transition, ZoneDataStorage::ReviewingSigned(s)) => {
                // TODO: Specify the instance ID.
                info!("The signed instance has been rejected; cleaning it up");

                let new_s;
                (new_s, loaded_reviewer, signed_reviewer) = s.give_up();
                transition.move_to(ZoneDataStorage::CleanWholePending(new_s));
                self.state.storage.loaded_review_soa =
                    loaded_reviewer.read().map(|r| r.soa().clone());
                self.state.storage.signed_review_soa =
                    signed_reviewer.read().map(|r| r.soa().clone());
            }

            _ => panic!("The zone is not undergoing signer review"),
        };

        let span = trace_span!("reset_review_servers");
        let zone = self.zone.clone();
        let center = self.center.clone();
        self.state.storage.background_tasks.spawn(span, async move {
            trace!("Resetting the signed review server");
            let old_signed_reviewer =
                SignedReviewServer::update_viewer(&center, &zone, signed_reviewer).await;

            trace!("Resetting the loaded review server");
            let old_loaded_reviewer =
                LoadedReviewServer::update_viewer(&center, &zone, loaded_reviewer).await;

            // Examine the current state.
            let mut state = zone.state.lock().unwrap();
            let mut handle = ZoneHandle {
                zone: &zone,
                state: &mut state,
                center: &center,
            };
            let cleaner = match transition(&mut handle.state.storage.machine) {
                (transition, ZoneDataStorage::CleanWholePending(s)) => {
                    let (s, cleaner) = s
                        .stop_review(old_signed_reviewer)
                        .stop_review(old_loaded_reviewer);
                    transition.move_to(ZoneDataStorage::Cleaning(s));
                    cleaner
                }

                _ => unreachable!("The zone was left in 'CleanWholePending' state"),
            };

            handle.storage().start_cleanup(cleaner);

            handle.state.storage.background_tasks.finish();
        });
    }
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

            match transition(&mut handle.state.storage.machine) {
                (transition, ZoneDataStorage::Cleaning(s)) => {
                    let s = s.mark_complete(cleaned);
                    transition.move_to(ZoneDataStorage::Passive(s));
                }

                _ => unreachable!(
                    "'ZoneDataStorage::Cleaning' is the only state where a 'ZoneCleaner' is available"
                ),
            }

            // Notify the rest of Cascade that the storage is passive.
            handle.storage().on_passive();

            handle.state.storage.background_tasks.finish();
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
    fn start_signed_persistence(&mut self, persister: SignedZonePersister) {
        let zone = self.zone.clone();
        let center = self.center.clone();
        let span = trace_span!("persist_signed");
        self.state.storage.background_tasks.spawn(span, async move {
            trace!("Persisting the signed instance");

            // TODO: Perform the persisting.
            let persisted = persister.mark_complete();

            // Mark persistence as completed.
            let viewer = {
                let mut state = zone.state.lock().unwrap();
                let state = &mut *state;
                match transition(&mut state.storage.machine) {
                    (transition, ZoneDataStorage::PersistingSigned(s)) => {
                        let (s, viewer) = s.mark_complete(persisted);
                        transition.move_to(ZoneDataStorage::Switching(s));
                        state.storage.published_soa = viewer.read().map(|r| r.soa().clone());
                        state.storage.published_loaded_soa = viewer.read().map(|r| r.loaded().soa().clone());
                        viewer
                    }

                    _ => unreachable!(
                        "'ZoneDataStorage::PersistingSigned' is the only state where a 'SignedZonePersister' is available"
                    ),
                }
            };

            // Update the publication server.
            let old_viewer = PublicationServer::update_viewer(&center, &zone, viewer).await;

            // Begin cleaning up the old instance.
            let mut state = zone.state.lock().unwrap();
            let cleaner = match transition(&mut state.storage.machine) {
                (transition, ZoneDataStorage::Switching(s)) => {
                    let (s, cleaner) = s.switch(old_viewer);
                    transition.move_to(ZoneDataStorage::Cleaning(s));
                    cleaner
                }

                _ => unreachable!("just transitioned to 'Switching'"),
            };

            state.last_published = Some(LastPublished {
                loaded_serial: Serial(state.storage.published_loaded_soa.as_ref().unwrap().rdata.serial.into()),
                signed_serial: Serial(state.storage.published_soa.as_ref().unwrap().rdata.serial.into()),
            });

            let mut handle = ZoneHandle { zone: &zone, state: &mut state, center: &center };

            handle.storage().start_cleanup(cleaner);

            handle.state.storage.background_tasks.finish();
        });
    }

    /// Rewind the loaded review server.
    ///
    /// When an upcoming loaded instance is under review and is abandoned, the
    /// loaded review server must be updated to stop serving it. A background
    /// task will be started to achieve this.
    ///
    /// The loaded reviewer object for the current instance (not the one being
    /// abandoned) is received. The old reviewer will be returned to the state
    /// machine and the old instance will be cleaned up.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    fn start_rewinding_loaded_review(&mut self, loaded_reviewer: LoadedZoneReviewer) {
        assert!(
            matches!(
                self.state.storage.machine,
                ZoneDataStorage::CleanLoadedPending(_)
            ),
            "The zone is not in the 'CleanLoadedPending' state"
        );

        let span = trace_span!("rewind_loaded_review_server");
        let zone = self.zone.clone();
        let center = self.center.clone();
        self.state.storage.background_tasks.spawn(span, async move {
            trace!("Rewinding the loaded review server");

            // Rewind the loaded review server.
            let old_loaded_reviewer =
                LoadedReviewServer::update_viewer(&center, &zone, loaded_reviewer).await;

            // Examine the current state.
            let mut state = zone.state.lock().unwrap();
            let mut handle = ZoneHandle {
                zone: &zone,
                state: &mut state,
                center: &center,
            };
            let cleaner = match transition(&mut handle.state.storage.machine) {
                (transition, ZoneDataStorage::CleanLoadedPending(s)) => {
                    let (s, cleaner) = s.stop_review(old_loaded_reviewer);
                    transition.move_to(ZoneDataStorage::Cleaning(s));
                    cleaner
                }

                _ => unreachable!("The zone was in the 'CleanLoadedPending' state"),
            };

            // Initiate cleanup of the abandoned instance.
            handle.storage().start_cleanup(cleaner);

            handle.state.storage.background_tasks.finish();
        });
    }

    /// Respond to the zone storage being passive and ready for new operations.
    ///
    /// Only when the zone storage is passive (not just when the state machine
    /// is waiting) is it possible to start a new loading or signing operation.
    /// This method checks for enqueued loads or re-sign operations and begins
    /// them appropriately.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(zone = %self.zone.name),
    )]
    pub(crate) fn on_passive(&mut self) {
        // TODO: Check whether resigning is needed. It has higher priority than
        // loading a new instance.

        if self.zone().loader().start_pending() {
            // The zone is no longer passive.
            return;
        }

        if self.zone().signer().start_pending() {
            // The zone is no longer passive.
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
    ///
    /// This is only used during initialization.
    //
    // TODO: Output it directly somehow?
    pub loaded_reviewer: Option<LoadedZoneReviewer>,

    /// The current zone reviewer.
    ///
    /// This is only used during initialization.
    //
    // TODO: Output it directly somehow?
    pub signed_reviewer: Option<SignedZoneReviewer>,

    /// The current zone viewer.
    ///
    /// This is only used during initialization.
    //
    // TODO: Output it directly somehow?
    pub viewer: Option<ZoneViewer>,

    /// The SOA record of the loaded instance of the zone being reviewed, if
    /// any.
    //
    // TODO: This should move into a component of 'ZoneState' tracking the
    // upcoming zone instance.
    pub loaded_review_soa: Option<SoaRecord>,

    /// The SOA record of the signed instance of the zone being reviewed, if
    /// any.
    //
    // TODO: This should move into a component of 'ZoneState' tracking the
    // upcoming zone instance.
    pub signed_review_soa: Option<SoaRecord>,

    /// The SOA record of the published instance of the zone, if any.
    //
    // TODO: This should move into a component of 'ZoneState' tracking the
    // current i.e. published zone instance.
    pub published_soa: Option<SoaRecord>,

    /// The SOA record of the loaded instance underlying the published instance
    /// of the zone, if any.
    //
    // TODO: This should move into a component of 'ZoneState' tracking the
    // current i.e. published zone instance.
    pub published_loaded_soa: Option<SoaRecord>,

    /// Ongoing background tasks.
    ///
    /// When the zone data needs to be cleaned or persisted, a background task
    /// is automatically spawned and tracked here.
    background_tasks: BackgroundTasks,
}

impl StorageState {
    /// Construct a new [`StorageState`].
    pub fn new() -> Self {
        // TODO: Use 'restorer' to attempt restoring the zone.
        let (restorer, machine) = ZoneDataStorage::new();
        let ZoneDataStorage::RestoringLoaded(s) = machine else {
            unreachable!()
        };
        let (loaded_reviewer, signed_reviewer, viewer, s) = s.abandon(restorer);

        Self {
            machine: ZoneDataStorage::Passive(s),
            loaded_reviewer: Some(loaded_reviewer),
            signed_reviewer: Some(signed_reviewer),
            viewer: Some(viewer),
            loaded_review_soa: None,
            signed_review_soa: None,
            published_soa: None,
            published_loaded_soa: None,
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

//------------------------------------------------------------------------------

/// Initiate a transition of a [`ZoneDataStorage`].
const fn transition(storage: &mut ZoneDataStorage) -> (Transition<'_>, ZoneDataStorage) {
    let state = storage.take();
    (
        Transition {
            storage,
            previous: state.as_str(),
        },
        state,
    )
}

/// An ongoing [`ZoneDataStorage`] transition.
struct Transition<'a> {
    /// The storage.
    storage: &'a mut ZoneDataStorage,

    /// The previous state.
    previous: &'static str,
}

impl Transition<'_> {
    /// Complete the transition, moving to the specified state.
    fn move_to(self, state: ZoneDataStorage) {
        trace!(old = %self.previous, new = %state.as_str(), "Transitioning");
        *self.storage = state;
        std::mem::forget(self);
    }
}

impl Drop for Transition<'_> {
    fn drop(&mut self) {
        panic!("a 'ZoneDataStorage' transition failed");
    }
}
