//! Zone-specific state and management.

use std::{
    borrow::Borrow,
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    io, mem,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use camino::Utf8Path;
use domain::{
    base::{iana::Class, Name, Serial},
    zonetree::{self, ZoneBuilder},
};
use domain::{rdata::dnssec::Timestamp, tsig};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace};

use crate::{
    api::{self, ZoneReviewStatus},
    center::{Center, Change},
    config::Config,
    payload::Update,
    policy::{Policy, PolicyVersion},
    zonemaintenance::types::{deserialize_duration_from_secs, serialize_duration_as_secs},
};

pub mod state;

//----------- Zone -------------------------------------------------------------

/// A zone.
#[derive(Debug)]
pub struct Zone {
    /// The name of this zone.
    pub name: Name<Bytes>,

    /// The state of this zone.
    ///
    /// This uses a mutex to ensure that all parts of the zone state are
    /// consistent with each other, and that changes to the zone happen in a
    /// single (sequentially consistent) order.
    pub state: Mutex<ZoneState>,

    /// The loaded contents of the zone.
    pub loaded: zonetree::Zone,

    /// The signed contents of the zone.
    pub signed: zonetree::Zone,

    /// The published contents of the zone.
    pub published: zonetree::Zone,
}

/// The state of a zone.
#[derive(Debug, Default)]
pub struct ZoneState {
    /// The policy (version) used by the zone.
    pub policy: Option<Arc<PolicyVersion>>,

    /// An enqueued save of this state.
    ///
    /// The enqueued save operation will persist the current state in a short
    /// duration of time.  If the field is `None`, and the state is changed, a
    /// new save operation should be enqueued.
    pub enqueued_save: Option<tokio::task::JoinHandle<()>>,

    /// Where to load the contents of the zone from.
    pub source: ZoneLoadSource,

    /// The minimum expiration time in the signed zone we are serving from
    /// the publication server.
    pub min_expiration: Option<Timestamp>,

    /// The minimum expiration time in the most recently signed zone. This
    /// value should be move to min_expiration after the signed zone is
    /// approved.
    pub next_min_expiration: Option<Timestamp>,

    /// Unsigned versions of the zone.
    pub unsigned: foldhash::HashMap<Serial, UnsignedZoneVersionState>,

    /// Signed versions of the zone.
    pub signed: foldhash::HashMap<Serial, SignedZoneVersionState>,

    /// History of interesting events that occurred for this zone.
    pub history: Vec<HistoryItem>,

    /// Whether or not the pipeline for this zone should be allowed to flow at
    /// the moment.
    // TODO: make the pipeline stop accepting new data when hard halted.
    pub pipeline_mode: PipelineMode,
    // TODO:
    // - A log?
    // - Initialization?
    // - Contents
    // - Loader state
    // - Key manager state
    // - Signer state
    // - Server state
}

impl ZoneState {
    pub fn hard_halt(&mut self, reason: String) {
        self.pipeline_mode = PipelineMode::HardHalt(reason);
    }

    pub fn soft_halt(&mut self, reason: String) {
        self.pipeline_mode = PipelineMode::SoftHalt(reason);
    }

    pub fn resume(&mut self) {
        self.pipeline_mode = PipelineMode::Running;
    }

    pub fn halted(&self, hard: bool) -> Option<String> {
        match &self.pipeline_mode {
            PipelineMode::SoftHalt(r) if !hard => Some(r.clone()),
            PipelineMode::HardHalt(r) if hard => Some(r.clone()),
            _ => None,
        }
    }

    pub fn record_event(&mut self, event: HistoricalEvent, serial: Option<Serial>) {
        self.history.push(HistoryItem::new(event, serial));
    }

    pub fn find_last_event(
        &self,
        typ: HistoricalEventType,
        serial: Option<Serial>,
    ) -> Option<&HistoryItem> {
        self.history
            .iter()
            .rev()
            .find(|item| item.event.is_of_type(typ) && (serial.is_none() || item.serial == serial))
    }
}

/// The state of an unsigned version of a zone.
#[derive(Clone, Debug)]
pub struct UnsignedZoneVersionState {
    /// The review state of the zone version.
    pub review: ZoneVersionReviewState,
}

/// The state of a signed version of a zone.
#[derive(Clone, Debug)]
pub struct SignedZoneVersionState {
    /// The serial number of the corresponding unsigned version of the zone.
    pub unsigned_serial: Serial,

    /// The review state of the zone version.
    pub review: ZoneVersionReviewState,
}

/// The review state of a version of a zone.
#[derive(Clone, Debug, Default)]
pub enum ZoneVersionReviewState {
    /// The zone is pending review.
    ///
    /// If a review script has been configured, it is running now.  Otherwise,
    /// the zone must be manually reviewed.
    #[default]
    Pending,

    /// The zone has been approved.
    ///
    /// This is a terminal state.  The zone may have progressed further through
    /// the pipeline, so it is no longer possible to reject it.
    Approved,

    /// The zone has been rejected.
    ///
    /// The zone has not yet been approved; it can be approved at any time.
    Rejected,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum PipelineMode {
    /// Newly received zone data will flow through the pipeline.
    #[default]
    Running,

    /// The current zone data could not be fully processed through the
    /// pipeline. When new zone data is received it will flow through the
    /// pipeline as normal.
    SoftHalt(String),

    /// The current zone data could not be fully processed through the
    /// pipeline. The pipeline for this zone will remain halted until manually
    /// restarted.
    HardHalt(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryItem {
    pub when: SystemTime,
    pub serial: Option<Serial>,
    pub event: HistoricalEvent,
}

impl HistoryItem {
    pub fn new(event: HistoricalEvent, serial: Option<Serial>) -> Self {
        Self {
            when: SystemTime::now(),
            serial,
            event,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HistoricalEventType {
    Added,
    Removed,
    PolicyChanged,
    SourceChanged,
    NewVersionReceived,
    SigningSucceeded,
    SigningFailed,
    UnsignedZoneReview,
    SignedZoneReview,
    KeySetCommand,
    KeySetError,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum HistoricalEvent {
    Added,
    Removed,
    PolicyChanged,
    SourceChanged,
    NewVersionReceived,
    SigningSucceeded {
        trigger: SigningTrigger,
    },
    SigningFailed {
        trigger: SigningTrigger,
        reason: String,
    },
    UnsignedZoneReview {
        status: ZoneReviewStatus,
    },
    SignedZoneReview {
        status: ZoneReviewStatus,
    },
    KeySetCommand {
        cmd: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        warning: Option<String>,
        #[serde(
            serialize_with = "serialize_duration_as_secs",
            deserialize_with = "deserialize_duration_from_secs"
        )]
        elapsed: Duration,
    },
    KeySetError {
        cmd: String,
        err: String,
        #[serde(
            serialize_with = "serialize_duration_as_secs",
            deserialize_with = "deserialize_duration_from_secs"
        )]
        elapsed: Duration,
    },
}

impl HistoricalEvent {
    pub fn is_of_type(&self, typ: HistoricalEventType) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match (self, typ) {
            (HistoricalEvent::Added, HistoricalEventType::Added) => true,
            (HistoricalEvent::Removed, HistoricalEventType::Removed) => true,
            (HistoricalEvent::PolicyChanged, HistoricalEventType::PolicyChanged) => true,
            (HistoricalEvent::SourceChanged, HistoricalEventType::SourceChanged) => true,
            (HistoricalEvent::NewVersionReceived, HistoricalEventType::NewVersionReceived) => true,
            (HistoricalEvent::SigningSucceeded { .. }, HistoricalEventType::SigningSucceeded) => {
                true
            }
            (HistoricalEvent::SigningFailed { .. }, HistoricalEventType::SigningFailed) => true,
            (
                HistoricalEvent::UnsignedZoneReview { .. },
                HistoricalEventType::UnsignedZoneReview,
            ) => true,
            (HistoricalEvent::SignedZoneReview { .. }, HistoricalEventType::SignedZoneReview) => {
                true
            }
            (HistoricalEvent::KeySetCommand { .. }, HistoricalEventType::KeySetCommand) => true,
            (HistoricalEvent::KeySetError { .. }, HistoricalEventType::KeySetError) => true,
            _ => false,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum SigningTrigger {
    ExternallyModifiedKeySetState,
    SignatureExpiration,
    ZoneChangesApproved,
    KeySetModifiedAfterCron,
}

/// How to load the contents of a zone.
#[derive(Clone, Debug, Default)]
pub enum ZoneLoadSource {
    /// Don't load the zone at all.
    #[default]
    None,

    /// Load the zone from a zonefile on disk.
    Zonefile {
        /// The path to the zonefile.
        path: Box<Utf8Path>,
    },

    /// Load the zone from a DNS server via XFR.
    Server {
        /// The TCP/UDP address of the server.
        addr: SocketAddr,

        /// A TSIG key to communicate with the server, if any.
        tsig_key: Option<Arc<tsig::Key>>,
    },
}

impl Zone {
    /// Construct a new [`Zone`].
    ///
    /// The zone is initialized to an empty state, where nothing is known about
    /// it and Cascade won't act on it.
    pub fn new(name: Name<Bytes>) -> Self {
        Self {
            name: name.clone(),
            state: Default::default(),
            loaded: ZoneBuilder::new(name.clone(), Class::IN).build(),
            signed: ZoneBuilder::new(name.clone(), Class::IN).build(),
            published: ZoneBuilder::new(name.clone(), Class::IN).build(),
        }
    }
}

//--- Loading / Saving

impl Zone {
    /// Reload the state of this zone.
    pub fn reload_state(
        self: &Arc<Self>,
        policies: &mut foldhash::HashMap<Box<str>, Policy>,
        config: &Config,
    ) -> io::Result<()> {
        // Load and parse the state file.
        let path = config.zone_state_dir.join(format!("{}.db", self.name));
        let spec = state::Spec::load(&path)?;

        // Merge the parsed data.
        let mut state = self.state.lock().unwrap();
        spec.parse_into(self, &mut state, policies);

        Ok(())
    }

    /// Mark the zone as dirty.
    ///
    /// A persistence operation for the zone will be enqueued (unless one
    /// already exists), so that it will be saved in the near future.
    pub fn mark_dirty(self: &Arc<Self>, state: &mut ZoneState, center: &Arc<Center>) {
        if state.enqueued_save.is_some() {
            // A save is already enqueued; nothing to do.
            return;
        }

        // Enqueue a new save.
        let zone = self.clone();
        let center = center.clone();
        let task = tokio::spawn(async move {
            // TODO: Make this time configurable.
            tokio::time::sleep(Duration::from_secs(5)).await;

            // Determine the save path from the global state.
            let name = &zone.name;
            let path = {
                let state = center.state.lock().unwrap();
                state.config.zone_state_dir.clone()
            };
            let path = path.join(format!("{name}.db"));

            // Load the actual zone contents.
            let spec = {
                let mut state = zone.state.lock().unwrap();
                let Some(_) = state.enqueued_save.take_if(|s| s.id() == tokio::task::id()) else {
                    // 'enqueued_save' does not match what we set, so somebody
                    // else set it to 'None' first.  Don't do anything.
                    trace!("Ignoring enqueued save due to race");
                    return;
                };
                state::Spec::build(&state)
            };

            // Save the zone state.
            match spec.save(&path) {
                Ok(()) => debug!("Saved state of zone '{name}' (to '{path}')"),
                Err(err) => {
                    error!("Could not save state of zone '{name}' to '{path}': {err}");
                }
            }
        });
        state.enqueued_save = Some(task);
    }
}

//----------- Actions ----------------------------------------------------------

/// Persist the state of a zone immediately.
pub fn save_state_now(center: &Center, zone: &Zone) {
    // Determine the save path from the global state.
    let name = &zone.name;
    let path = {
        let state = center.state.lock().unwrap();
        state.config.zone_state_dir.clone()
    };
    let path = path.join(format!("{name}.db"));

    // Load the actual zone contents.
    let spec = {
        let mut state = zone.state.lock().unwrap();

        // If there was an enqueued save operation, stop it.
        if let Some(save) = state.enqueued_save.take() {
            save.abort();
        }

        state::Spec::build(&state)
    };

    // Save the global state.
    match spec.save(&path) {
        Ok(()) => debug!("Saved the state of zone '{name}' (to '{path}')"),
        Err(err) => {
            error!("Could not save the state of zone '{name}' to '{path}': {err}");
        }
    }
}

/// Change the policy used by a zone.
pub fn change_policy(
    center: &Arc<Center>,
    name: Name<Bytes>,
    policy: Box<str>,
) -> Result<(), ChangePolicyError> {
    let mut state = center.state.lock().unwrap();
    let state = &mut *state;

    // Verify the operation will succeed.
    {
        state
            .zones
            .get(&name)
            .ok_or(ChangePolicyError::NoSuchZone)?;

        let policy = state
            .policies
            .get(&policy)
            .ok_or(ChangePolicyError::NoSuchPolicy)?;
        if policy.mid_deletion {
            return Err(ChangePolicyError::PolicyMidDeletion);
        }
    }

    // Perform the operation.
    let zone = state.zones.get(&name).unwrap();
    let mut zone_state = zone.0.state.lock().unwrap();

    // Unlink the previous policy of the zone.
    let old_policy = zone_state.policy.take();
    if let Some(policy) = &old_policy {
        let policy = state
            .policies
            .get_mut(&policy.name)
            .expect("zones and policies are consistent");
        assert!(
            policy.zones.remove(&name),
            "zones and policies are consistent"
        );
    }

    // Link the zone to the selected policy.
    let policy = state
        .policies
        .get_mut(&policy)
        .ok_or(ChangePolicyError::NoSuchPolicy)?;
    if policy.mid_deletion {
        return Err(ChangePolicyError::PolicyMidDeletion);
    }
    zone_state.policy = Some(policy.latest.clone());
    policy.zones.insert(name.clone());

    center
        .update_tx
        .send(Update::Changed(Change::ZonePolicyChanged {
            name: name.clone(),
            old: old_policy,
            new: policy.latest.clone(),
        }))
        .unwrap();

    zone.0.mark_dirty(&mut zone_state, center);

    info!("Set policy of zone '{name}' to '{}'", policy.latest.name);
    Ok(())
}

/// Change the source of the zone.
pub fn change_source(
    center: &Arc<Center>,
    name: Name<Bytes>,
    source: api::ZoneSource,
) -> Result<(), ChangeSourceError> {
    // Find the zone.
    let zone = {
        let state = center.state.lock().unwrap();
        state
            .zones
            .get(&name)
            .ok_or(ChangeSourceError::NoSuchZone)?
            .0
            .clone()
    };

    // Set the source in the zone.
    let mut state = zone.state.lock().unwrap();
    let new_source = match source {
        api::ZoneSource::None => ZoneLoadSource::None,

        api::ZoneSource::Zonefile { path } => ZoneLoadSource::Zonefile { path },

        // TODO: Look up the TSIG key.
        api::ZoneSource::Server { addr, .. } => ZoneLoadSource::Server {
            addr,
            tsig_key: None,
        },
    };
    let old_source = mem::replace(&mut state.source, new_source.clone());

    center
        .update_tx
        .send(Update::Changed(Change::ZoneSourceChanged(
            name.clone(),
            state.source.clone(),
        )))
        .unwrap();

    zone.mark_dirty(&mut state, center);

    info!("Set source of zone '{name}' from '{old_source:?}' to '{new_source:?}'");
    Ok(())
}

//----------- ZoneByName -------------------------------------------------------

/// A [`Zone`] keyed by its name.
#[derive(Clone)]
pub struct ZoneByName(pub Arc<Zone>);

impl Borrow<Name<Bytes>> for ZoneByName {
    fn borrow(&self) -> &Name<Bytes> {
        &self.0.name
    }
}

impl PartialEq for ZoneByName {
    fn eq(&self, other: &Self) -> bool {
        self.0.name == other.0.name
    }
}

impl Eq for ZoneByName {}

impl PartialOrd for ZoneByName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ZoneByName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.name.cmp(&other.0.name)
    }
}

impl Hash for ZoneByName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.name.hash(state)
    }
}

impl fmt::Debug for ZoneByName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

//----------- ZoneByPtr --------------------------------------------------------

/// A [`Zone`] keyed by its address in memory.
#[derive(Clone)]
pub struct ZoneByPtr(pub Arc<Zone>);

impl PartialEq for ZoneByPtr {
    fn eq(&self, other: &Self) -> bool {
        Arc::as_ptr(&self.0).cast::<()>() == Arc::as_ptr(&other.0).cast::<()>()
    }
}

impl Eq for ZoneByPtr {}

impl PartialOrd for ZoneByPtr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ZoneByPtr {
    fn cmp(&self, other: &Self) -> Ordering {
        Arc::as_ptr(&self.0)
            .cast::<()>()
            .cmp(&Arc::as_ptr(&other.0).cast::<()>())
    }
}

impl Hash for ZoneByPtr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).cast::<()>().hash(state)
    }
}

impl fmt::Debug for ZoneByPtr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

//----------- ChangePolicyError ------------------------------------------------

/// An error in changing the policy of a zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangePolicyError {
    /// The specified zone does not exist.
    NoSuchZone,

    /// The specified policy does not exist.
    NoSuchPolicy,

    /// The specified policy was being deleted.
    PolicyMidDeletion,
}

impl std::error::Error for ChangePolicyError {}

impl fmt::Display for ChangePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoSuchZone => "the specified zone does not exist",
            Self::NoSuchPolicy => "the specified policy does not exist",
            Self::PolicyMidDeletion => "the specified policy is being deleted",
        })
    }
}

//----------- ChangeSourceError ------------------------------------------------

/// An error in changing the source of a zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeSourceError {
    /// The specified zone does not exist.
    NoSuchZone,
}

impl std::error::Error for ChangeSourceError {}

impl fmt::Display for ChangeSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoSuchZone => "the specified zone does not exist",
        })
    }
}
