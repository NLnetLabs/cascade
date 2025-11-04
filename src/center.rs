//! Cascade's central command.

use std::collections::HashMap;
use std::{
    fmt, io,
    sync::{Arc, Mutex},
    time::Duration,
};

use arc_swap::ArcSwap;
use bytes::Bytes;
use domain::rdata::dnssec::Timestamp;
use domain::zonetree::StoredName;
use domain::{base::Name, zonetree::ZoneTree};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, trace};

use crate::api::KeyImport;
use crate::zone::PipelineMode;
use crate::{
    api,
    config::Config,
    log::Logger,
    manager::{ApplicationCommand, Update},
    policy::{Policy, PolicyVersion},
    tsig::TsigStore,
    zone::{Zone, ZoneByName, ZoneLoadSource},
};

//----------- Center -----------------------------------------------------------

/// Cascade's central command.
#[derive(Debug)]
pub struct Center {
    /// Global state.
    pub state: Mutex<State>,

    /// The configuration.
    pub config: Config,

    /// The logger.
    pub logger: &'static Logger,

    /// The latest unsigned contents of all zones.
    pub unsigned_zones: Arc<ArcSwap<ZoneTree>>,

    /// The latest ready-to-sign contents of all zones.
    pub signable_zones: Arc<ArcSwap<ZoneTree>>,

    /// The latest signed contents of all zones.
    pub signed_zones: Arc<ArcSwap<ZoneTree>>,

    /// The latest published contents of all zones.
    pub published_zones: Arc<ArcSwap<ZoneTree>>,

    /// Zones currently being re-signed.
    pub resign_busy: Mutex<HashMap<Name<Bytes>, Timestamp>>,

    /// The old TSIG key store.
    pub old_tsig_key_store: crate::common::tsig::TsigKeyStore,

    /// A channel to send units commands.
    pub app_cmd_tx: mpsc::UnboundedSender<(String, ApplicationCommand)>,

    /// A channel to send the central command updates.
    pub update_tx: mpsc::UnboundedSender<Update>,
}

//--- Actions

/// Add a zone.
pub async fn add_zone(
    center: &Arc<Center>,
    name: Name<Bytes>,
    policy_name: Box<str>,
    source: api::ZoneSource,
    key_imports: Vec<KeyImport>,
) -> Result<(), ZoneAddError> {
    let zone = Arc::new(Zone::new(name.clone()));

    {
        let mut state = center.state.lock().unwrap();

        // We check whether the state contains this zone, because
        // this is the most useful error to report.
        let zone_by_name = ZoneByName(zone.clone());
        if state.zones.contains(&zone_by_name) {
            return Err(ZoneAddError::AlreadyExists);
        }

        // Do this inside a block to prevent holding a mutable reference to
        // state.
        {
            let policy = state
                .policies
                .get_mut(&policy_name)
                .ok_or(ZoneAddError::NoSuchPolicy)?;
            if policy.mid_deletion {
                return Err(ZoneAddError::PolicyMidDeletion);
            }

            let mut zone_state = zone.state.lock().unwrap();
            zone_state.policy = Some(policy.latest.clone());
            policy.zones.insert(name.clone());
        }

        // Actually insert the zone now. This shouldn't fail since we've done
        // the `contains` check above and we hold a lock to the state, but it
        // doesn't hurt to have proper error handling here just in case.
        if !state.zones.insert(zone_by_name.clone()) {
            return Err(ZoneAddError::AlreadyExists);
        }
    }

    // Send out a registration command so that prerequisites for zone setup
    // (such as invoking dnst keyset create, ..., init) can be done _before_
    // the pipeline for the zone starts. We do this _after_ adding the zone
    // because otherwise updating zone history will fail. If registration
    // fails we will have to remove the added zone.
    if let Err(err) = register_zone(center, name.clone(), policy_name.clone(), key_imports).await {
        // Remove in reverse order what was added above.
        let mut state = center.state.lock().unwrap();
        let zone_by_name = ZoneByName(zone);
        state.zones.remove(&zone_by_name);
        if let Some(policy) = state.policies.get_mut(&policy_name) {
            policy.zones.remove(&name);
        }
        return Err(err);
    }

    {
        let mut state = center.state.lock().unwrap();
        center
            .update_tx
            .send(Update::Changed(Change::ZoneAdded(name.clone())))
            .unwrap();

        state.mark_dirty(center);
    }

    {
        match crate::zone::change_source(center, name.clone(), source) {
            Ok(()) => {}
            Err(crate::zone::ChangeSourceError::NoSuchZone) => unreachable!(),
            // NOTE: When proper TSIG support is added, it should be checked
            //       for _before_ the zone is added.
        }

        // NOTE: The zone is marked as dirty by the above operation.
    }

    info!("Added zone '{name}'");
    Ok(())
}

async fn register_zone(
    center: &Arc<Center>,
    name: Name<Bytes>,
    policy: Box<str>,
    key_imports: Vec<KeyImport>,
) -> Result<(), ZoneAddError> {
    let (report_tx, report_rx) = oneshot::channel();

    center
        .app_cmd_tx
        .send((
            "KM".into(),
            ApplicationCommand::RegisterZone {
                name,
                policy: policy.clone().into(),
                key_imports,
                report_tx,
            },
        ))
        .unwrap();

    report_rx
        .await
        .map_err(|err| {
            ZoneAddError::Other(format!(
                "Zone registration failed: internal command could not be sent: {err}"
            ))
        })?
        .map_err(|err| ZoneAddError::Other(format!("Zone registration failed: {err}")))
}

/// Remove a zone.
pub fn remove_zone(center: &Arc<Center>, name: Name<Bytes>) -> Result<(), ZoneRemoveError> {
    center
        .update_tx
        .send(Update::Changed(Change::ZoneRemoved(name.clone())))
        .unwrap();

    let mut state = center.state.lock().unwrap();
    let zone = state.zones.take(&name).ok_or(ZoneRemoveError::NotFound)?;
    let mut zone_state = zone.0.state.lock().unwrap();

    // Update the policy's referenced zones.
    if let Some(policy) = zone_state.policy.take() {
        let policy = state
            .policies
            .get_mut(&policy.name)
            .expect("every zone policy exists");
        assert!(policy.zones.remove(&name), "zone policies are consistent");

        state.mark_dirty(center);
    }

    info!("Removed zone '{name}'");
    Ok(())
}

pub fn get_zone(center: &Center, name: &StoredName) -> Option<Arc<Zone>> {
    let state = center.state.lock().unwrap();
    state.zones.get(name).map(|zone| zone.0.clone())
}

pub fn halt_zone(center: &Arc<Center>, zone_name: &StoredName, hard: bool, reason: &str) {
    let mut state = center.state.lock().unwrap();
    if let Some(zone) = state.zones.get(zone_name) {
        let mut zone_state = zone.0.state.lock().unwrap();
        if hard {
            if !matches!(zone_state.pipeline_mode, PipelineMode::HardHalt(_)) {
                zone_state.hard_halt(reason.to_string());
            }
        } else if !matches!(
            zone_state.pipeline_mode,
            PipelineMode::SoftHalt(_) | PipelineMode::HardHalt(_)
        ) {
            zone_state.soft_halt(reason.to_string());
        }
    }
    state.mark_dirty(center);
}

//----------- State ------------------------------------------------------------

/// Global state for Cascade.
#[derive(Debug, Default)]
pub struct State {
    /// Known zones.
    ///
    /// This field stores the live state of every zone.  Crucially, zones are
    /// concurrently accessible, as each one is locked behind a unique mutex.
    pub zones: foldhash::HashSet<ZoneByName>,

    /// Zone policies.
    ///
    /// A policy provides is a template for zone configuration, that can be used
    /// by many zones simultaneously.  It is the primary way to configure zones.
    ///
    /// This map points to the latest known version of each policy.  Changes to
    /// the policy result in new commits, which the associated zones are
    /// gradually transitioned to.
    ///
    /// Like global configuration, these are only reloaded on user request.
    pub policies: foldhash::HashMap<Box<str>, Policy>,

    /// The TSIG key store.
    ///
    /// TSIG keys are used for authenticating Cascade to zone sources, and for
    /// authenticating incoming requests for zones.
    pub tsig_store: TsigStore,

    /// An enqueued save of this state.
    ///
    /// The enqueued save operation will persist the current state in a short
    /// duration of time.  If the field is `None`, and the state is changed, a
    /// new save operation should be enqueued.
    pub enqueued_save: Option<tokio::task::JoinHandle<()>>,
}

//--- Initialization

impl State {
    /// Attempt to load the global state file.
    pub fn init_from_file(&mut self, config: &Config) -> io::Result<()> {
        let path = config.daemon.state_file.value();
        let spec = crate::state::Spec::load(path)?;
        spec.parse_into(self, |_| {});
        Ok(())
    }

    /// Mark the global state as dirty.
    ///
    /// A persistence operation for the global state will be enqueued (unless
    /// one already exists), so that it will be saved in the near future.
    pub fn mark_dirty(&mut self, center: &Arc<Center>) {
        if self.enqueued_save.is_some() {
            // A save is already enqueued; nothing to do.
            return;
        }

        // Enqueue a new save.
        let center = center.clone();
        let task = tokio::spawn(async move {
            // TODO: Make this time configurable.
            tokio::time::sleep(Duration::from_secs(5)).await;

            let (path, spec);
            {
                // Load the global state.
                let mut state = center.state.lock().unwrap();
                let Some(_) = state.enqueued_save.take_if(|s| s.id() == tokio::task::id()) else {
                    // 'enqueued_save' does not match what we set, so somebody
                    // else set it to 'None' first.  Don't do anything.
                    trace!("Ignoring enqueued save due to race");
                    return;
                };

                path = center.config.daemon.state_file.value().clone();
                spec = crate::state::Spec::build(&state);
            }

            // Save the global state.
            match spec.save(&path) {
                Ok(()) => debug!("Saved global state (to '{path}')"),
                Err(err) => {
                    error!("Could not save global state to '{path}': {err}");
                }
            }
        });
        self.enqueued_save = Some(task);
    }
}

//----------- Change -----------------------------------------------------------

/// A change to global state.
#[derive(Clone, Debug)]
pub enum Change {
    /// The configuration has been changed.
    ConfigChanged,

    /// A policy has been added.
    PolicyAdded(Arc<PolicyVersion>),

    /// A policy has been changed.
    PolicyChanged(Arc<PolicyVersion>, Arc<PolicyVersion>),

    /// A policy has been removed.
    PolicyRemoved(Arc<PolicyVersion>),

    /// A zone has been added.
    ZoneAdded(Name<Bytes>),

    /// The policy of a zone has changed.
    ZonePolicyChanged {
        /// The name of the zone.
        name: Name<Bytes>,

        /// The previous policy used by the zone.
        ///
        /// If this is [`None`], the zone did not previously have a policy.
        old: Option<Arc<PolicyVersion>>,

        /// The new policy used by the zone.
        ///
        /// If this has the same name as the old policy, the policy was updated
        /// (as per [`Self::PolicyChanged`]); if this has a different name, the
        /// policy for this zone was explicitly changed.
        new: Arc<PolicyVersion>,
    },

    /// The source of a zone has changed.
    ZoneSourceChanged(Name<Bytes>, ZoneLoadSource),

    /// A zone has been removed.
    ZoneRemoved(Name<Bytes>),
}

//----------- ZoneAddError -----------------------------------------------------

/// An error adding a zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZoneAddError {
    /// A zone of the same name already exists.
    AlreadyExists,
    /// No policy with that name exists.
    NoSuchPolicy,
    /// The specified policy is being deleted.
    PolicyMidDeletion,
    /// Some other error occurred.
    Other(String),
}

impl std::error::Error for ZoneAddError {}

impl fmt::Display for ZoneAddError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AlreadyExists => "a zone of this name already exists",
            Self::NoSuchPolicy => "no policy with that name exists",
            Self::PolicyMidDeletion => "the specified policy is being deleted",
            Self::Other(reason) => reason,
        })
    }
}

//----------- ZoneRemoveError --------------------------------------------------

/// An error removing a zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZoneRemoveError {
    /// No such name could be found.
    NotFound,
}

impl std::error::Error for ZoneRemoveError {}

impl fmt::Display for ZoneRemoveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no such zone was found",
        })
    }
}
