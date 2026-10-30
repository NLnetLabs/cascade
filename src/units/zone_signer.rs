use std::collections::{HashMap, HashSet};
use std::env::{self, VarError};
use std::sync::{Arc, Mutex};

use domain::base::Rtype;
use domain::dnssec::sign::keys::keyset::{KeySet, UnixTime};
use domain::rdata::dnssec::Timestamp;
use domain_kmip::dep::kmip_protocol::net::sync_pool::ConnPool;
use serde::{Deserialize, Serialize};

use crate::center::Center;
use crate::common::scheduler::Scheduler;
use crate::signer::ResigningTrigger;
use crate::signer::keys::LoadError;
use crate::signer::queue::SigningQueue;
use crate::util::AbortOnDrop;
use crate::zone::ZoneByPtr;

// Re-signing zones before signatures expire works as follows:
// - compute when the first zone needs to be re-signed. Loop over unsigned
//   zones, take the min_expiration field for state, and subtract the remain
//   time for policy. If the min_expiration time is currently listed for the
//   zone in resign_busy then skip the zone. The minimum is when the first
//   zone needs to be re-signed. Sleep until this moment in the main select!
//   loop.
// - When the sleep is done, loop over all unsigned zones, and for each zone
//   check if the zone needs to be re-signed now. If so, send a message to
//   central command and add the zone the resign_busy. After that
//   recompute when the first zone needs to be re-signed.
// - central command forwards PublishSignedZone messages. When such a message
//   is received, recompute when the first zone eneds to be re-signed.

//------------ ZoneSigner ----------------------------------------------------

pub struct ZoneSigner {
    pub kmip_servers: Arc<Mutex<HashMap<String, ConnPool>>>,

    /// The re-signing scheduler.
    pub resign_scheduler: Scheduler<ZoneByPtr>,

    /// The signing queue.
    pub queue: SigningQueue,
}

impl ZoneSigner {
    pub fn new() -> Self {
        let max_concurrent_operations = 1;
        let resign_scheduler = Scheduler::new();
        let queue = SigningQueue::new(max_concurrent_operations.try_into().unwrap());

        Self {
            kmip_servers: Default::default(),
            resign_scheduler,
            queue,
        }
    }

    /// Launch the zone signer.
    pub fn run(center: Arc<Center>) -> AbortOnDrop {
        AbortOnDrop::from(tokio::spawn(async move {
            center
                .signer
                .resign_scheduler
                .run(|_time, ZoneByPtr(zone)| {
                    let mut handle = zone.write_handle(&center);

                    // The zone has been removed from the schedule, so update
                    // its state.
                    handle.state.signer.scheduled_resign_time = None;

                    handle
                        .signer()
                        .enqueue_resign(ResigningTrigger::SIGS_NEED_REFRESH);
                })
                .await
        }))
    }
}

/// Persistent state for the keyset command.
/// Copied from the keyset branch of dnst.
#[derive(Deserialize)]
pub struct KeySetState {
    /// Domain KeySet state.
    pub keyset: KeySet,

    pub apex_remove: HashSet<Rtype>,
    pub apex_extra: Vec<String>,
}

pub struct MinTimestamp(Mutex<Option<Timestamp>>);

impl MinTimestamp {
    pub fn new() -> Self {
        Self(Mutex::new(None))
    }
    pub fn add(&self, ts: Timestamp) {
        let mut min_ts = self.0.lock().expect("should not fail");
        if let Some(curr_min) = *min_ts {
            if ts < curr_min {
                *min_ts = Some(ts);
            }
        } else {
            *min_ts = Some(ts);
        }
    }
    pub fn get(&self) -> Option<Timestamp> {
        let min_ts = self.0.lock().expect("should not fail");
        *min_ts
    }
}

impl Default for MinTimestamp {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ZoneSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneSigner").finish()
    }
}

pub fn faketime_or_now() -> UnixTime {
    match env::var("CASCADE_FAKETIME") {
        Ok(val) => val.parse::<Timestamp>().unwrap().into(),
        Err(VarError::NotPresent) => UnixTime::now(),
        Err(_e) => panic!("Cannot parse environment variable CASCADE_FAKETIME"),
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum PassThroughMode {
    /// Pass-through is disabled.
    #[default]
    Off,

    /// Copy the DNSKEY RRset plus signatures from keyset into an already
    /// signed zone. The operator has to make sure that the DNSKEY RRset
    /// contains the public key of the key that signed the zone.
    CopyDnskeyRrset,

    /// Add the DNSKEY signatures from keyset. This requires that the DNSKEY
    /// RRset in the input zone is equal to the one from keyset.
    MergeDnskeySignatures,
}

#[derive(Clone, Debug)]
pub enum SignerError {
    InternalError(String),
    KeepSerialPolicyViolated,
    CannotReadStateFile(String),
    Load(String),
    PatchFailed(String),
    NothingToDo,
    SigningError(String),
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerError::InternalError(err) => write!(f, "Internal error: {err}"),
            SignerError::KeepSerialPolicyViolated => {
                f.write_str("Serial policy is Keep but upstream serial did not increase")
            }
            SignerError::CannotReadStateFile(path) => {
                write!(f, "Failed to read state file '{path}'")
            }
            SignerError::Load(err) => write!(f, "Could not load the signing keys: {err}"),
            SignerError::PatchFailed(err) => write!(f, "Patch failed: {err}"),
            SignerError::NothingToDo => write!(f, "Nothing To Do"),
            SignerError::SigningError(err) => write!(f, "Signing error: {err}"),
        }
    }
}

impl From<Box<LoadError>> for SignerError {
    fn from(error: Box<LoadError>) -> Self {
        Self::Load(error.to_string())
    }
}
