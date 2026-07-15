//! Cascade's central command.

use std::collections::HashMap;
use std::{
    fmt, io,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use domain::base::Name;
use domain::dnssec::sign::keys::keyset::UnixTime;
use tracing::{debug, error, info, trace};

use crate::api::{self, KeyImport, TsigAddError, TsigAddResult};
use crate::config::RuntimeConfig;
use crate::loader::Loader;
use crate::loader::zone::LoaderZoneHandle;
use crate::metrics::Metrics;
use crate::persistence::{Compacter, Persister, Restorer};
use crate::server::{LoadedReviewServer, PublicationServer, SignedReviewServer};
use crate::state::PolicySpec;
use crate::tsig::ImportError;
use crate::units::key_manager::KeyManager;
use crate::units::zone_signer::ZoneSigner;
use crate::zone::{HistoricalEvent, ZoneByPtr, ZoneHandle};
use crate::{
    config::Config,
    log::Logger,
    policy::Policy,
    tsig::TsigStore,
    zone::{Zone, ZoneByName},
};

//----------- Center -----------------------------------------------------------

/// Cascade's central command.
#[derive(Debug)]
pub struct Center {
    /// Global state.
    pub state: Mutex<State>,

    // The Prometheus metrics
    pub metrics: Metrics,

    /// The configuration.
    pub config: Config,

    /// The logger.
    pub logger: Logger,

    /// The zone loader.
    pub loader: Loader,

    /// The zone signer.
    pub signer: ZoneSigner,

    /// The key manager.
    pub key_manager: KeyManager,

    /// The zone data persister.
    pub persister: Persister,

    /// The zone data restorer.
    pub restorer: Restorer,

    /// The zone data compacter.
    pub compacter: Compacter,

    /// The review server for loaded instances of zones.
    pub loaded_review_server: LoadedReviewServer,

    /// The review server for signed instances of zones.
    pub signed_review_server: SignedReviewServer,

    /// The server for published instances of zones.
    pub publication_server: PublicationServer,

    /// Zones currently being re-signed.
    pub resign_busy: Mutex<HashMap<Name<Bytes>, UnixTime>>,
}

//--- Actions

/// Add a zone.
pub async fn add_zone(
    center: &Arc<Center>,
    name: Name<Bytes>,
    policy_name: Box<str>,
    api_source: api::ZoneSource,
    key_imports: Vec<KeyImport>,
) -> Result<(), ZoneAddError> {
    // Create and insert the zone.
    let zone;
    let source;

    {
        // Lock the global state to check consistency and insert the zone.
        let mut state = center.state.lock().unwrap();

        // Prioritize 'AlreadyExists' over other kinds of errors.
        if state.zones.contains(&name) {
            return Err(ZoneAddError::AlreadyExists);
        }

        // Look up the requested policy.
        {
            let policy = state
                .policies
                .get(&policy_name)
                .ok_or(ZoneAddError::NoSuchPolicy)?;
            if policy.mid_deletion {
                return Err(ZoneAddError::PolicyMidDeletion);
            }
        }

        // Create the zone and initialize its state.
        zone = Arc::new(Zone::new(name, &center.metrics));

        source = match api_source {
            api::ZoneSource::None => crate::loader::Source::None,
            api::ZoneSource::Zonefile { path } => crate::loader::Source::Zonefile { path },
            api::ZoneSource::Server { addr, tsig_key } => {
                let tsig_key = if let Some(key_name) = tsig_key {
                    // Lookup the key in the TSIG key store.
                    let key = state
                        .tsig_store
                        .get_mut(&key_name)
                        .ok_or(ZoneAddError::NoSuchTsigKey)?;

                    // Record that this zone uses this key.
                    key.zones.insert(ZoneByPtr(zone.clone()));

                    let key = key.inner.clone();

                    state.tsig_store.mark_dirty(center);

                    // Remember the found key.
                    Some(key)
                } else {
                    None
                };

                crate::loader::Source::Server { addr, tsig_key }
            }
        };

        {
            let mut zone_state = zone.state.write_cleanly();
            let restorer = zone_state.storage.restorer.take().unwrap();
            let policy = state
                .policies
                .get_mut(&policy_name)
                .ok_or(ZoneAddError::NoSuchPolicy)?;
            zone_state.policy = Some(policy.latest.clone());
            policy.zones.insert(zone.name.clone());

            // Don't try to restore zone data, since it's a completely new zone.
            //
            // This will clear the data for the zone.
            let mut handle = ZoneHandle {
                zone: &zone,
                state: &mut zone_state,
                center,
            };
            let (loaded_reviewer, signed_reviewer, viewer) =
                handle.storage().abandon_loaded_restoration(restorer);

            // Update the zone servers.
            LoadedReviewServer::add_zone(handle.center, handle.zone.clone(), loaded_reviewer);
            SignedReviewServer::add_zone(handle.center, handle.zone.clone(), signed_reviewer);
            PublicationServer::add_zone(handle.center, handle.zone.clone(), viewer);

            // Send a notification that the state machine is now passive.
            handle.storage().on_passive();
        }

        // Insert the zone in the global set.
        assert!(
            state.zones.insert(ZoneByName(zone.clone())),
            "Already checked that 'state.zones' does not contain 'name'"
        );
        state.mark_dirty(center);
    }

    // Send out a registration command so that prerequisites for zone setup
    // (such as invoking dnst keyset create, ..., init) can be done _before_
    // the pipeline for the zone starts. We do this _after_ adding the zone
    // because otherwise updating zone history will fail. If registration
    // fails we will have to remove the added zone.
    if let Err(err) =
        register_zone(center, zone.name.clone(), policy_name.clone(), key_imports).await
    {
        // Remove in reverse order what was added above.
        LoadedReviewServer::remove_zone(center, &zone);
        SignedReviewServer::remove_zone(center, &zone);
        PublicationServer::remove_zone(center, &zone);

        let mut state = center.state.lock().unwrap();

        state.zones.remove(&zone.name);

        if let Some(policy) = state.policies.get_mut(&policy_name) {
            policy.zones.remove(&zone.name);
        }

        state.mark_dirty(center);

        if let crate::loader::Source::Server {
            tsig_key: Some(key_name),
            ..
        } = &source
        {
            state
                .tsig_store
                .get_mut(key_name.name())
                .unwrap()
                .zones
                .remove(&ZoneByPtr(zone));

            state.tsig_store.mark_dirty(center);
        }

        return Err(err);
    }

    {
        let mut state = zone.write(center);

        state.record_event(HistoricalEvent::Added, None);

        // Set the source of the zone, and begin loading it.
        LoaderZoneHandle {
            zone: &zone,
            state: &mut state,
            center,
        }
        .set_source(source);

        // NOTE: The zone is marked as dirty by the above operation.
    }

    info!("Added zone '{}'", zone.name);
    Ok(())
}

async fn register_zone(
    center: &Arc<Center>,
    name: Name<Bytes>,
    policy: Box<str>,
    key_imports: Vec<KeyImport>,
) -> Result<(), ZoneAddError> {
    center
        .key_manager
        .on_register_zone(center, name, policy.clone().into(), key_imports)
        .await
        .map_err(|err| ZoneAddError::Other(format!("Zone registration failed: {err}")))
}

/// Remove a zone.
pub fn remove_zone(center: &Arc<Center>, name: Name<Bytes>) -> Result<(), ZoneRemoveError> {
    let mut state = center.state.lock().unwrap();

    let ZoneByName(zone) = state.zones.get(&name).ok_or(ZoneRemoveError::NotFound)?;

    // TODO(#871): support removing a zone during restoration.
    if zone.read().storage.is_restoring() {
        return Err(ZoneRemoveError::MidRestoration);
    }

    let ZoneByName(zone) = state
        .zones
        .take(&name)
        .expect("the zone was found just above");

    // Remove the zone from all the places it might be stored.
    // The zone might not have made it to these places, but that's not an issue
    // so we just ignore any errors.

    LoadedReviewServer::remove_zone(center, &zone);
    SignedReviewServer::remove_zone(center, &zone);
    PublicationServer::remove_zone(center, &zone);

    let mut zone_state = zone.state.write_cleanly();

    ZoneHandle {
        zone: &zone,
        state: &mut zone_state,
        center,
    }
    .loader()
    .prep_removal();

    // Update the policy's referenced zones.
    if let Some(policy) = zone_state.policy.take() {
        let policy = state
            .policies
            .get_mut(&policy.name)
            .expect("every zone policy exists");
        assert!(policy.zones.remove(&name), "zone policies are consistent");

        state.mark_dirty(center);
    }

    // Update the TSIG key's referenced zones.
    if let crate::loader::Source::Server {
        tsig_key: Some(key_name),
        ..
    } = &zone_state.loader.source
    {
        state
            .tsig_store
            .get_mut(key_name.name())
            .unwrap()
            .zones
            .remove(&ZoneByPtr(zone.clone()));
        state.tsig_store.mark_dirty(center);
    }

    // Persist the state file one last time.
    zone_state.record_event(HistoricalEvent::Removed, None);
    std::mem::drop(zone_state);
    crate::zone::save_state_now(center, &zone);

    // TODO: Remove the zone state file?

    info!("Removed zone '{name}'");
    Ok(())
}

pub fn get_zone(center: &Arc<Center>, name: &Name<Bytes>) -> Option<Arc<Zone>> {
    let state = center.state.lock().unwrap();
    state.zones.get(name).map(|zone| zone.0.clone())
}

pub async fn add_tsig_key(
    center: &Arc<Center>,
    name: Name<domain::dep::octseq::Array<255>>,
    alg: domain::tsig::Algorithm,
    secret: &[u8],
) -> Result<TsigAddResult, TsigAddError> {
    crate::tsig::import_key(center, name.clone(), alg, secret, false)
        .map_err(|ImportError::AlreadyExists| TsigAddError::AlreadyExists)?;

    info!("Added TSIG key '{name}'");

    Ok(TsigAddResult)
}

//----------- State ------------------------------------------------------------

/// Global state for Cascade.
#[derive(Debug, Default)]
pub struct State {
    /// Configuration that can change at runtime.
    ///
    /// Cascade supports dynamically changing a subset of its configuration at
    /// runtime.
    pub rt_config: RuntimeConfig,

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
    ///
    /// `zones` will be set to the names of zones that need to be loaded.
    /// `policies` will be set to the set of policies from the global state
    /// file, that need to be parsed and inserted in the state.
    pub fn init_from_file(
        config: &Config,
        zones: &mut foldhash::HashSet<Name<Bytes>>,
        policies: &mut foldhash::HashMap<Box<str>, PolicySpec>,
    ) -> io::Result<Self> {
        let path = config.daemon.state_file.value();
        let spec = crate::state::Spec::load(path)?;

        Ok(spec.parse(zones, policies))
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
    /// No TSIG key with that name exists.
    NoSuchTsigKey,
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
            Self::NoSuchTsigKey => "no TSIG key with that name exists",
            Self::Other(reason) => reason,
        })
    }
}

impl From<ZoneAddError> for api::ZoneAddError {
    fn from(value: ZoneAddError) -> Self {
        match value {
            ZoneAddError::AlreadyExists => Self::AlreadyExists,
            ZoneAddError::NoSuchPolicy => Self::NoSuchPolicy,
            ZoneAddError::PolicyMidDeletion => Self::PolicyMidDeletion,
            ZoneAddError::NoSuchTsigKey => Self::NoSuchTsigKey,
            ZoneAddError::Other(reason) => Self::Other(reason),
        }
    }
}

//----------- ZoneRemoveError --------------------------------------------------

/// An error removing a zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZoneRemoveError {
    /// No such name could be found.
    NotFound,

    /// The zone is being restored from disk.
    MidRestoration,
}

impl std::error::Error for ZoneRemoveError {}

impl fmt::Display for ZoneRemoveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no such zone was found",
            Self::MidRestoration => "the zone is being restored from disk",
        })
    }
}

impl From<ZoneRemoveError> for api::ZoneRemoveError {
    fn from(value: ZoneRemoveError) -> Self {
        match value {
            ZoneRemoveError::NotFound => Self::NotFound,
            ZoneRemoveError::MidRestoration => Self::MidRestoration,
        }
    }
}
