//! Zone-specific state and management.

use std::collections::HashSet;
use std::path::PathBuf;
use std::{
    borrow::Borrow,
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    sync::Arc,
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use cascade_cfg::Config;
use domain::base::{Name, Rtype, Serial};
use domain::dnssec::sign::keys::keyset::UnixTime;
use domain::rdata::dnssec::Timestamp;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, trace};

use crate::{
    api::{self, ZoneReviewStatus},
    center::Center,
    loader::zone::{LoaderState, LoaderZoneHandle},
    persistence::zone::{PersistenceState, ZonePersistenceHandle},
    policy::{Policy, PolicyVersion},
    signer::zone::{SignerState, SignerZoneHandle},
    tsig::TsigStore,
    util::{deserialize_duration_from_secs, serialize_duration_as_secs},
    zone::machine::ZoneStateMachine,
};

/// TODO: this temporary until there is a more permanent solution for fake time.
use crate::units::zone_signer::faketime_or_now;

mod storage;
pub use storage::{StorageState, StorageZoneHandle};

pub mod machine;
pub mod state;

mod lock;
pub use lock::{ReadableZoneState, WritableZoneState, ZoneStateLock};

//----------- Zone -------------------------------------------------------------

/// A zone.
#[derive(Debug)]
pub struct Zone {
    /// The name of this zone.
    pub name: Name<Bytes>,

    /// The state of this zone.
    ///
    /// The state is locked for consistency. For the underlying data, see
    /// [`ZoneState`].
    pub state: ZoneStateLock,

    /// Whether the zone was restored from the state file.
    ///
    /// This is set if the zone originates from a previous execution of Cascade
    /// and its state was loaded from a file (rather than being created in the
    /// current execution).
    pub restored: bool,
}

impl Zone {
    /// Construct a new zone.
    ///
    /// The zone is initialized to an empty state, where nothing is known about
    /// it and Cascade won't act on it.
    pub fn new(name: Name<Bytes>) -> Self {
        Self {
            name,
            state: ZoneStateLock::new(ZoneState::default()),
            restored: false,
        }
    }

    /// Restore a zone from a state file.
    ///
    /// A zone originating from a previous execution of Cascade is initialized,
    /// by reading and parsing the appropriate state file.
    ///
    /// `policies` should contain the set of policies loaded from the global
    /// state file. If the zone uses a policy that is not present in the global
    /// state file, it will restore the last seen version of that policy.
    ///
    /// Persisted zone data will not be restored in this function, as it may
    /// take a while (and should not block Cascade's initialization as a whole);
    /// it will be handled by [`crate::persistence::Restorer::run()`].
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(%name),
    )]
    pub fn restore(
        config: &Config,
        name: Name<Bytes>,
        policies: &mut foldhash::HashMap<Box<str>, Policy>,
        tsig_store: &TsigStore,
    ) -> Result<Self, state::LoadError> {
        let path = config.zone_state_dir.join(format!("{name}.db"));

        // Load the underlying state file.
        let state = match state::Spec::load(&path) {
            Ok(spec) => spec.parse(&name, policies, tsig_store)?,
            Err(error) => {
                error!("Failed to load the state of zone '{name}' from '{path}': {error}");
                return Err(state::LoadError::Read {
                    path: path.into(),
                    error,
                });
            }
        };

        debug!("Restored the state of zone '{name}' (from '{path}')");

        Ok(Self {
            name,
            state: ZoneStateLock::new(state),
            restored: true,
        })
    }

    /// Obtain a read lock over the zone state.
    ///
    /// A read lock which [deref]s to [`ZoneState`] is returned.
    ///
    /// The current thread is blocked until the read lock can be acquired.
    ///
    /// Prefer this to `self.state.read()`.
    ///
    /// [deref]: std::ops::Deref
    pub fn read(&self) -> ReadableZoneState<'_> {
        self.state.read()
    }

    /// Obtain a write lock and build a handle to the zone.
    ///
    /// An [`OwnedZoneHandle`] is returned, through which high-level zone
    /// operations are available.
    ///
    /// The current thread is blocked until the write lock can be acquired.
    ///
    /// The state will be marked dirty; some time after the lock is released,
    /// the (likely modified) state will be persisted to disk. To guarantee that
    /// the state is persisted at a particular point, use [`save_state_now()`].
    pub fn write_handle<'a>(self: &'a Arc<Self>, center: &'a Arc<Center>) -> OwnedZoneHandle<'a> {
        OwnedZoneHandle {
            zone: self,
            state: self.write(center),
            center,
        }
    }

    /// Obtain a write lock over the zone state.
    ///
    /// Prefer [`Self::write_handle()`], as it returns a convenient zone handle.
    ///
    /// The current thread is blocked until the write lock can be acquired.
    ///
    /// The state will be marked dirty; some time after the lock is released,
    /// the (likely modified) state will be persisted to disk. To guarantee that
    /// the state is persisted at a particular point, use [`save_state_now()`].
    pub fn write<'z>(self: &'z Arc<Self>, center: &Arc<Center>) -> WritableZoneState<'z> {
        let mut writer = self.state.write_cleanly();
        self.mark_dirty(&mut writer, center);
        writer
    }
}

//----------- ZoneHandle -------------------------------------------------------

/// A handle for working with a zone.
pub struct ZoneHandle<'a> {
    /// The zone being operated on.
    pub zone: &'a Arc<Zone>,

    /// The locked zone state.
    pub state: &'a mut ZoneState,

    /// Cascade's global state.
    pub center: &'a Arc<Center>,
}

impl ZoneHandle<'_> {
    /// Consider loader-specific operations.
    #[must_use]
    pub const fn loader(&mut self) -> LoaderZoneHandle<'_> {
        LoaderZoneHandle {
            zone: self.zone,
            state: self.state,
            center: self.center,
        }
    }

    /// Consider signer-specific operations.
    #[must_use]
    pub const fn signer(&mut self) -> SignerZoneHandle<'_> {
        SignerZoneHandle {
            zone: self.zone,
            state: self.state,
            center: self.center,
        }
    }

    /// Consider storage-specific operations.
    #[must_use]
    pub const fn storage(&mut self) -> StorageZoneHandle<'_> {
        StorageZoneHandle {
            zone: self.zone,
            state: self.state,
            center: self.center,
        }
    }

    /// Consider data persistence specific operations.
    #[must_use]
    pub const fn persistence(&mut self) -> ZonePersistenceHandle<'_> {
        ZonePersistenceHandle {
            zone: self.zone,
            state: self.state,
            center: self.center,
        }
    }
}

//----------- OwnedZoneHandle --------------------------------------------------

/// A [`ZoneHandle`] that owns a zone state write lock.
///
/// This is a convenience type. By owning the write lock, it can simplify
/// construction of `ZoneHandle`s for quick uses.
pub struct OwnedZoneHandle<'a> {
    /// The zone being operated on.
    pub zone: &'a Arc<Zone>,

    /// The locked zone state.
    pub state: WritableZoneState<'a>,

    /// Cascade's global state.
    pub center: &'a Arc<Center>,
}

impl OwnedZoneHandle<'_> {
    /// Get the corresponding [`ZoneHandle`].
    #[must_use]
    pub fn get(&mut self) -> ZoneHandle<'_> {
        ZoneHandle {
            zone: self.zone,
            state: &mut self.state,
            center: self.center,
        }
    }

    /// Consider loader-specific operations.
    #[must_use]
    pub fn loader(&mut self) -> LoaderZoneHandle<'_> {
        LoaderZoneHandle {
            zone: self.zone,
            state: &mut self.state,
            center: self.center,
        }
    }

    /// Consider signer-specific operations.
    #[must_use]
    pub fn signer(&mut self) -> SignerZoneHandle<'_> {
        SignerZoneHandle {
            zone: self.zone,
            state: &mut self.state,
            center: self.center,
        }
    }

    /// Consider storage-specific operations.
    #[must_use]
    pub fn storage(&mut self) -> StorageZoneHandle<'_> {
        StorageZoneHandle {
            zone: self.zone,
            state: &mut self.state,
            center: self.center,
        }
    }

    /// Consider data persistence specific operations.
    #[must_use]
    pub fn persistence(&mut self) -> ZonePersistenceHandle<'_> {
        ZonePersistenceHandle {
            zone: self.zone,
            state: &mut self.state,
            center: self.center,
        }
    }
}

//----------- ZoneState --------------------------------------------------------

/// The state of a zone.
#[derive(Debug)]
pub struct ZoneState {
    /// The top-level state machine
    pub machine: ZoneStateMachine,

    /// The policy (version) used by the zone.
    pub policy: Option<Arc<PolicyVersion>>,

    /// The catalog zone that manages this zone, if any.
    ///
    /// When set, this zone was added automatically from the named catalog
    /// zone. Such zones cannot be removed or reconfigured manually; they are
    /// managed entirely through their catalog.
    pub catalog: Option<Name<Bytes>>,

    /// Whether the zone is in maintenance mode
    ///
    /// Maintenance mode means that Cascade won't start loading and signing
    /// operations automatically.
    pub maintenance_mode: bool,

    /// Metadata related to the last published zone version.
    pub last_published: Option<LastPublished>,

    /// An enqueued save of this state.
    ///
    /// The enqueued save operation will persist the current state in a short
    /// duration of time.  If the field is `None`, and the state is changed, a
    /// new save operation should be enqueued.
    pub enqueued_save: Option<tokio::task::JoinHandle<()>>,

    /// The minimum expiration time in the signed zone we are serving from
    /// the publication server.
    pub min_expiration: Option<Timestamp>,

    /// The minimum expiration time in the most recently signed zone. This
    /// value should be move to min_expiration after the signed zone is
    /// approved.
    pub next_min_expiration: Option<Timestamp>,

    /// We expect this from the key manager. These are the types that
    /// the key manager takes control over in the apex. Use this to
    /// determine if the zone needs resigning. If what is stored here is
    /// different from what we get from the key manager, then update this
    /// field and resign the zone. Maybe this should be associated with
    /// a signed instance of a zone to avoid problems when a signed zone
    /// gets rejected.
    pub apex_remove: HashSet<Rtype>,

    /// Same comment as for apex_remove. But this is about the records
    /// that should be added to the apex after removing the apex_remove
    /// types.
    pub apex_extra: Vec<String>,

    /// This field is set based on the key tags of the keys that need to
    /// sign the zone. It doesn't say anything about how the zone is
    /// currently signed, just what the goal is. This field is used to
    /// detiermine when a ZSK or CSK key roll has started and the zone
    /// needs to be resigned with a new key.
    pub key_tags: HashSet<u16>,

    /// Record when key_tags has changed. We take this as the start of a key
    /// roll. This start time is used to compute which percentage of
    /// RRsets that should have signatures from the new key.
    pub key_roll: Option<UnixTime>,

    /// Record when the last time signtures were refreshed. This is used
    /// together with the signature_refresh_interval value in policy to
    /// determine when to refresh signatures next. Maybe this should be
    /// associated with a signed instance of a zone to avoid problems when
    /// a signed zone gets rejected.
    pub last_signature_refresh: UnixTime,

    /// Record the SOA serial of the last signed version of the zone.
    /// We use a serial only once, even if the signed zone gets rejected.
    /// It would be good to have a command where the user can set the
    /// serial for the Increment serial policy.
    pub previous_serial: Option<Serial>,

    /// Unsigned versions of the zone.
    pub unsigned: foldhash::HashMap<Serial, UnsignedZoneVersionState>,

    /// Signed versions of the zone.
    pub signed: foldhash::HashMap<Serial, SignedZoneVersionState>,

    /// History of interesting events that occurred for this zone.
    pub history: Vec<HistoryItem>,

    /// Locations of persisted unsigned zone diffs to enable IXFR from
    /// the upstream to resume on restart, and to enable a complete latest
    /// unsigned version of the zone to be reconstituted.
    // TODO: Move into `PersistenceState`.
    pub persisted_loaded_diff_paths: Vec<PathBuf>,

    /// Locations of persisted signed zone diffs to ensure IXFR out toward
    /// downstreams is still possible after restart, and to enable a complete
    /// latest signed version of the zone to be reconsituted.
    // TODO: Move into `PersistenceState`.
    pub persisted_signed_diff_paths: Vec<PathBuf>,

    /// Loading new versions of the zone.
    pub loader: LoaderState,

    /// Signing the zone.
    pub signer: SignerState,

    /// Data storage for the zone.
    pub storage: StorageState,

    /// Persisting zone data.
    pub persistence: PersistenceState,
    //
    // TODO:
    // - A log?
    // - Initialization?
    // - Key manager state
    // - Server state
}

impl ZoneState {
    pub fn halted_reason(&self) -> Option<String> {
        self.machine.display_halted_reason()
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

impl Default for ZoneState {
    fn default() -> Self {
        Self {
            machine: Default::default(),
            policy: Default::default(),
            catalog: Default::default(),
            maintenance_mode: Default::default(),
            last_published: Default::default(),
            enqueued_save: Default::default(),
            min_expiration: Default::default(),
            next_min_expiration: Default::default(),
            apex_remove: Default::default(),
            apex_extra: Default::default(),
            key_tags: Default::default(),
            key_roll: Default::default(),
            last_signature_refresh: faketime_or_now(),
            previous_serial: Default::default(),
            unsigned: Default::default(),
            signed: Default::default(),
            history: Default::default(),
            loader: Default::default(),
            signer: Default::default(),
            storage: Default::default(),
            persistence: Default::default(),
            persisted_loaded_diff_paths: Default::default(),
            persisted_signed_diff_paths: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LastPublished {
    pub loaded_serial: Serial,
    pub signed_serial: Serial,

    /// Time of publication
    pub timestamp: SystemTime,

    /// Number of records in the signed zone
    pub num_records: usize,
    //
    // TODO: add the size
    // /// Size in bytes
    // pub size: usize,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryItem {
    pub when: SystemTime,
    pub serial: Option<Serial>,
    pub event: HistoricalEvent,
}

impl From<HistoryItem> for api::HistoryItem {
    fn from(value: HistoryItem) -> Self {
        let HistoryItem {
            when,
            serial,
            event,
        } = value;
        Self {
            when,
            serial,
            event: event.into(),
        }
    }
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
    StartedLoad,
    StartedResign,
    Added,
    Removed,
    PolicyChanged,
    SourceChanged,
    NewVersionReceived,
    SigningSucceeded,
    SigningFailed,
    UnsignedZoneReview,
    SignedZoneReview,
    UnsignedHookFailed,
    SignedHookFailed,
    KeySetCommand,
    KeySetError,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum HistoricalEvent {
    StartedLoad,
    StartedResign,
    Added,
    Removed,
    PolicyChanged,
    SourceChanged,
    NewVersionReceived,
    LoadingFailed {
        reason: String,
    },
    SigningSucceeded {
        trigger: cascade_api::SigningTrigger,
    },
    SigningFailed {
        trigger: cascade_api::SigningTrigger,
        reason: String,
    },
    UnsignedZoneReview {
        status: ZoneReviewStatus,
    },
    SignedZoneReview {
        status: ZoneReviewStatus,
    },
    UnsignedHookFailed {
        err: String,
    },
    SignedHookFailed {
        err: String,
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
    fn get_type(&self) -> HistoricalEventType {
        match self {
            HistoricalEvent::StartedLoad => HistoricalEventType::StartedLoad,
            HistoricalEvent::StartedResign => HistoricalEventType::StartedResign,
            HistoricalEvent::Added => HistoricalEventType::Added,
            HistoricalEvent::Removed => HistoricalEventType::Removed,
            HistoricalEvent::PolicyChanged => HistoricalEventType::PolicyChanged,
            HistoricalEvent::SourceChanged => HistoricalEventType::SourceChanged,
            HistoricalEvent::NewVersionReceived => HistoricalEventType::NewVersionReceived,
            HistoricalEvent::SigningSucceeded { .. } => HistoricalEventType::SigningSucceeded,
            HistoricalEvent::SigningFailed { .. } => HistoricalEventType::SigningFailed,
            HistoricalEvent::UnsignedZoneReview { .. } => HistoricalEventType::UnsignedZoneReview,
            HistoricalEvent::SignedZoneReview { .. } => HistoricalEventType::SignedZoneReview,
            HistoricalEvent::UnsignedHookFailed { .. } => HistoricalEventType::UnsignedHookFailed,
            HistoricalEvent::SignedHookFailed { .. } => HistoricalEventType::SignedHookFailed,
            HistoricalEvent::KeySetCommand { .. } => HistoricalEventType::KeySetCommand,
            HistoricalEvent::KeySetError { .. } => HistoricalEventType::KeySetError,
            HistoricalEvent::LoadingFailed { .. } => HistoricalEventType::Error,
        }
    }

    pub fn is_of_type(&self, typ: HistoricalEventType) -> bool {
        self.get_type() == typ
    }
}

impl From<HistoricalEvent> for api::HistoricalEvent {
    fn from(value: HistoricalEvent) -> Self {
        match value {
            HistoricalEvent::StartedLoad => Self::StartedLoad,
            HistoricalEvent::StartedResign => Self::StartedResign,
            HistoricalEvent::Added => Self::Added,
            HistoricalEvent::Removed => Self::Removed,
            HistoricalEvent::PolicyChanged => Self::PolicyChanged,
            HistoricalEvent::SourceChanged => Self::SourceChanged,
            HistoricalEvent::NewVersionReceived => Self::NewVersionReceived,
            HistoricalEvent::SigningSucceeded { trigger } => Self::SigningSucceeded { trigger },
            HistoricalEvent::SigningFailed { trigger, reason } => {
                Self::SigningFailed { trigger, reason }
            }
            HistoricalEvent::UnsignedZoneReview { status } => Self::UnsignedZoneReview { status },
            HistoricalEvent::SignedZoneReview { status } => Self::SignedZoneReview { status },
            HistoricalEvent::UnsignedHookFailed { err } => Self::UnsignedHookFailed { err },
            HistoricalEvent::SignedHookFailed { err } => Self::SignedHookFailed { err },
            HistoricalEvent::KeySetCommand {
                cmd,
                warning,
                elapsed,
            } => Self::KeySetCommand {
                cmd,
                warning,
                elapsed,
            },
            HistoricalEvent::KeySetError { cmd, err, elapsed } => {
                Self::KeySetError { cmd, err, elapsed }
            }
            HistoricalEvent::LoadingFailed { reason } => Self::LoadingFailed { reason },
        }
    }
}

//--- Loading / Saving

impl Zone {
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
            let path = center.config.zone_state_dir.join(format!("{name}.db"));

            // Load the actual zone contents.
            let spec = {
                let mut state = zone.state.write_cleanly();
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
    let path = center.config.zone_state_dir.join(format!("{name}.db"));

    // Load the actual zone contents.
    let spec = {
        let mut state = zone.state.write_cleanly();

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

// /// Change the policy used by a zone.
// pub fn change_policy(
//     center: &Arc<Center>,
//     name: Name<Bytes>,
//     policy: Box<str>,
// ) -> Result<(), ChangePolicyError> {
//     let mut state = center.state.lock().unwrap();
//     let state = &mut *state;
//
//     // Verify the operation will succeed.
//     {
//         state
//             .zones
//             .get(&name)
//             .ok_or(ChangePolicyError::NoSuchZone)?;
//
//         let policy = state
//             .policies
//             .get(&policy)
//             .ok_or(ChangePolicyError::NoSuchPolicy)?;
//         if policy.mid_deletion {
//             return Err(ChangePolicyError::PolicyMidDeletion);
//         }
//     }
//
//     // Perform the operation.
//     let zone = state.zones.get(&name).unwrap();
//     let mut zone_state = zone.0.state.lock().unwrap();
//
//     // Unlink the previous policy of the zone.
//     let old_policy = zone_state.policy.take();
//     if let Some(policy) = &old_policy {
//         let policy = state
//             .policies
//             .get_mut(&policy.name)
//             .expect("zones and policies are consistent");
//         assert!(
//             policy.zones.remove(&name),
//             "zones and policies are consistent"
//         );
//     }
//
//     // Link the zone to the selected policy.
//     let policy = state
//         .policies
//         .get_mut(&policy)
//         .ok_or(ChangePolicyError::NoSuchPolicy)?;
//     if policy.mid_deletion {
//         return Err(ChangePolicyError::PolicyMidDeletion);
//     }
//     zone_state.policy = Some(policy.latest.clone());
//     policy.zones.insert(name.clone());
//
//     center
//         .update_tx
//         .send(Update::Changed(Change::ZonePolicyChanged {
//             name: name.clone(),
//             old: old_policy,
//             new: policy.latest.clone(),
//         }))
//         .unwrap();
//
//     zone.0.mark_dirty(&mut zone_state, center);
//
//     info!("Set policy of zone '{name}' to '{}'", policy.latest.name);
//     Ok(())
// }

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
        f.debug_struct("ZoneByPtr")
            .field("name", &self.0.name)
            .finish_non_exhaustive()
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
