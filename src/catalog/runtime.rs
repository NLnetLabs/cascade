//! Running catalog reconciliation in the background.
//!
//! Each registered catalog has a dedicated background task that periodically
//! transfers the catalog zone and reconciles its membership. The
//! [`CatalogManager`] owns these tasks and starts, stops and reloads them as
//! catalogs are registered, removed and reloaded.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use domain::base::Name;
use domain::zonetree::Zone;
use tokio::sync::Notify;
use tracing::{debug, error};

use crate::center::Center;
use crate::util::AbortOnDrop;

use super::reconcile;

/// The interval to wait before retrying after a failed reconciliation.
const RETRY_INTERVAL: Duration = Duration::from_secs(60);

//----------- CatalogManager -------------------------------------------------

/// Owns the background reconciliation tasks for all registered catalogs.
#[derive(Debug, Default)]
pub struct CatalogManager {
    /// The running tasks, keyed by catalog apex name.
    tasks: Mutex<foldhash::HashMap<Name<Bytes>, CatalogTask>>,

    /// The most recently generated produced catalog zones, keyed by produced
    /// catalog apex name.
    produced: Mutex<foldhash::HashMap<Name<Bytes>, Zone>>,
}

/// A running catalog reconciliation task.
#[derive(Debug)]
struct CatalogTask {
    /// The task handle, aborting the task when dropped.
    _handle: AbortOnDrop,

    /// A trigger to reconcile the catalog immediately.
    reload: Arc<Notify>,
}

impl CatalogManager {
    /// Creates a new, empty catalog manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts reconciliation tasks for all registered catalogs.
    pub fn init(center: &Arc<Center>) {
        let names: Vec<Name<Bytes>> = {
            let state = center.state.lock().unwrap();
            state.catalogs.keys().cloned().collect()
        };
        for name in names {
            Self::start(center, name);
        }
    }

    /// Starts a reconciliation task for the named catalog.
    ///
    /// If a task for the catalog is already running, it is replaced.
    pub fn start(center: &Arc<Center>, apex: Name<Bytes>) {
        let reload = Arc::new(Notify::new());
        let handle = AbortOnDrop::from(tokio::spawn(run(
            center.clone(),
            apex.clone(),
            reload.clone(),
        )));
        center.catalog_manager.tasks.lock().unwrap().insert(
            apex,
            CatalogTask {
                _handle: handle,
                reload,
            },
        );
    }

    /// Stops the reconciliation task for the named catalog, if any.
    pub fn stop(center: &Arc<Center>, apex: &Name<Bytes>) {
        center.catalog_manager.tasks.lock().unwrap().remove(apex);
    }

    /// Triggers an immediate reconciliation of the named catalog, if running.
    pub fn reload(center: &Arc<Center>, apex: &Name<Bytes>) {
        if let Some(task) = center.catalog_manager.tasks.lock().unwrap().get(apex) {
            task.reload.notify_one();
        }
    }

    /// Stores the latest generated produced catalog zone.
    pub fn set_produced(center: &Arc<Center>, apex: Name<Bytes>, zone: Zone) {
        center
            .catalog_manager
            .produced
            .lock()
            .unwrap()
            .insert(apex, zone);
    }

    /// Returns the latest generated produced catalog zone, if any.
    pub fn produced_zone(center: &Arc<Center>, apex: &Name<Bytes>) -> Option<Zone> {
        center
            .catalog_manager
            .produced
            .lock()
            .unwrap()
            .get(apex)
            .cloned()
    }
}

//----------- run() ----------------------------------------------------------

/// The reconciliation loop for a single catalog.
async fn run(center: Arc<Center>, apex: Name<Bytes>, reload: Arc<Notify>) {
    debug!("Starting catalog reconciliation task for '{apex}'");
    loop {
        // Stop if the catalog has been removed.
        if !center.state.lock().unwrap().catalogs.contains_key(&apex) {
            debug!("Catalog '{apex}' no longer registered; stopping task");
            return;
        }

        let wait = match reconcile::reconcile(&center, &apex).await {
            Ok(refresh) => refresh.into_duration(),
            Err(err) => {
                error!("Could not reconcile catalog '{apex}': {err}");
                RETRY_INTERVAL
            }
        };

        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = reload.notified() => {
                debug!("Reload triggered for catalog '{apex}'");
            }
        }
    }
}
