use std::collections::{HashMap, HashSet};
use std::env::{self, VarError};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use domain::base::Rtype;
use domain::dnssec::sign::keys::keyset::{KeySet, UnixTime};
use domain::rdata::dnssec::Timestamp;
use domain_kmip::dep::kmip::client::pool::SyncConnPool;
use domain_kmip::{self, ClientCertificate, ConnectionSettings};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::trace;

use crate::center::Center;
use crate::signer::ResigningTrigger;
use crate::signer::keys::LoadError;
use crate::signer::queue::SigningQueue;
use crate::signer::zone::resign_time;
use crate::util::AbortOnDrop;
use crate::zone::ZoneByName;

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
    pub kmip_servers: Arc<Mutex<HashMap<String, SyncConnPool>>>,

    /// A live view of the next scheduled global resigning time.
    next_resign_time_tx: watch::Sender<Option<tokio::time::Instant>>,
    next_resign_time_rx: watch::Receiver<Option<tokio::time::Instant>>,

    /// The signing queue.
    pub queue: SigningQueue,
}

impl ZoneSigner {
    pub fn new() -> Self {
        let max_concurrent_operations = 1;
        let (next_resign_time_tx, next_resign_time_rx) = watch::channel(None);
        let queue = SigningQueue::new(max_concurrent_operations.try_into().unwrap());

        Self {
            kmip_servers: Default::default(),
            next_resign_time_tx,
            next_resign_time_rx,
            queue,
        }
    }

    /// Launch the zone signer.
    pub fn run(center: Arc<Center>) -> AbortOnDrop {
        let this = &center.signer;
        let resign_time = this.next_resign_time(&center);
        this.next_resign_time_tx.send(resign_time).unwrap();

        AbortOnDrop::from(tokio::spawn({
            let mut next_resign_time = this.next_resign_time_rx.clone();
            let mut resign_time = resign_time;
            async move {
                async fn sleep_until(time: Option<tokio::time::Instant>) {
                    if let Some(time) = time {
                        tokio::time::sleep_until(time).await
                    } else {
                        std::future::pending().await
                    }
                }

                // Sleep until the resign time and then resign, but also watch
                // for changes to the resign time.
                loop {
                    tokio::select! {
                        _ = next_resign_time.changed() => {
                            // Update the resign time and keep going.
                            resign_time = *next_resign_time.borrow_and_update();
                        }

                        _ = sleep_until(resign_time) => {
                            // It's time to resign.
                            center.signer.resign_zones(&center);

                            // TODO: Should 'resign_zones()' do this?
                            center.signer.next_resign_time_tx.send(center.signer.next_resign_time(&center)).unwrap();
                        }
                    }
                }
            }
        }))
    }

    pub fn on_publish_signed_zone(&self, center: &Arc<Center>) {
        trace!("[ZS]: a zone is published, recompute next time to re-sign");
        let _ = self.next_resign_time_tx.send(self.next_resign_time(center));
    }

    pub fn on_zone_policy_changed(&self) {
        // Just recompute the resign timer. In the future we may want to
        // react to changes in policy, for example, whether NSEC is used
        // or NSEC3.
        let _ = self.next_resign_time_tx.send(Some(Instant::now()));
    }

    fn next_resign_time(&self, center: &Arc<Center>) -> Option<Instant> {
        #[allow(clippy::mutable_key_type)]
        let zones = {
            let state = center.state.lock().unwrap();
            state.zones.clone()
        };

        // Compute when to incrementally sign a zone again to refresh
        // signatures.
        zones
            .into_iter()
            // Load the scheduled re-signing time for each zone.
            .filter_map(|ZoneByName(zone)| {
                let mut zone_state = zone.write(center);
                let resign_time = resign_time(&zone_state);
                zone_state.signer.scheduled_resign_time = resign_time;
                resign_time
            })
            .min()
            .map(|t| {
                // We need to go from SystemTime to Tokio Instant, is there a
                // better way?

                // We are computing a timeout value. If the timeout is in the
                // past then we can just as well use zero.
                let since_now = t
                    .duration_since(SystemTime::now())
                    .unwrap_or(Duration::ZERO);

                Instant::now() + since_now
            })
    }

    fn resign_zones(&self, center: &Arc<Center>) {
        let now = SystemTime::now();

        #[allow(clippy::mutable_key_type)]
        let zones = {
            let state = center.state.lock().unwrap();
            state.zones.clone()
        };

        for ZoneByName(zone) in zones {
            let zone_name = &zone.name;
            let mut handle = zone.write_handle(center);

            let Some(resign_time) = handle.state.signer.scheduled_resign_time.take() else {
                continue;
            };

            if resign_time < now {
                trace!("[ZS]: re-signing: request signing of zone {zone_name}");

                handle
                    .signer()
                    .enqueue_resign(ResigningTrigger::SIGS_NEED_REFRESH);
            }
        }
    }
}

/// Persistent state for the keyset command.
/// Copied from the keyset branch of dnst.
#[derive(Deserialize, Serialize)]
pub struct KeySetState {
    /// Domain KeySet state.
    pub keyset: KeySet,

    pub ds_rrset: Vec<String>,
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

//------------ KMIP related --------------------------------------------------

#[derive(Clone, Debug)]
pub struct KmipServerConnectionSettings {
    /// Path to the client certificate file in PEM format
    pub client_cert_path: Option<PathBuf>,

    /// Path to the client certificate key file in PEM format
    pub client_key_path: Option<PathBuf>,

    /// Path to the client certificate and key file in PKCS#12 format
    pub client_pkcs12_path: Option<PathBuf>,

    /// Disable secure checks (e.g. verification of the server certificate)
    pub server_insecure: bool,

    /// Path to the server certificate file in PEM format
    pub server_cert_path: Option<PathBuf>,

    /// Path to the server CA certificate file in PEM format
    pub ca_cert_path: Option<PathBuf>,

    /// IP address, hostname or FQDN of the KMIP server
    pub server_addr: String,

    /// The TCP port number on which the KMIP server listens
    pub server_port: u16,

    /// The user name to authenticate with the KMIP server
    pub server_username: Option<String>,

    /// The password to authenticate with the KMIP server
    pub server_password: Option<String>,
}

impl Default for KmipServerConnectionSettings {
    fn default() -> Self {
        Self {
            server_addr: "localhost".into(),
            server_port: 5696,
            server_insecure: false,
            client_cert_path: None,
            client_key_path: None,
            client_pkcs12_path: None,
            server_cert_path: None,
            ca_cert_path: None,
            server_username: None,
            server_password: None,
        }
    }
}

impl From<KmipServerConnectionSettings> for ConnectionSettings {
    fn from(cfg: KmipServerConnectionSettings) -> Self {
        let client_cert = load_client_cert(&cfg);
        let _server_cert = cfg.server_cert_path.map(|p| load_binary_file(&p));
        let _ca_cert = cfg.ca_cert_path.map(|p| load_binary_file(&p));
        ConnectionSettings {
            host: cfg.server_addr,
            port: cfg.server_port,
            username: cfg.server_username,
            password: cfg.server_password,
            insecure: cfg.server_insecure,
            client_cert,
            server_cert: None,                             // TOOD
            ca_cert: None,                                 // TODO
            connect_timeout: Some(Duration::from_secs(5)), // TODO
            read_timeout: None,                            // TODO
            write_timeout: None,                           // TODO
            max_response_bytes: None,                      // TODO
        }
    }
}

fn load_client_cert(opt: &KmipServerConnectionSettings) -> Option<ClientCertificate> {
    match (
        &opt.client_cert_path,
        &opt.client_key_path,
        &opt.client_pkcs12_path,
    ) {
        (None, None, None) => None,
        (None, None, Some(path)) => Some(ClientCertificate::CombinedPkcs12 {
            cert_bytes: load_binary_file(path),
        }),
        (Some(_), None, None) | (None, Some(_), None) => {
            panic!("Client certificate authentication requires both a certificate and a key");
        }
        (_, Some(_), Some(_)) | (Some(_), _, Some(_)) => {
            panic!(
                "Use either but not both of: client certificate and key PEM file paths, or a PCKS#12 certficate file path"
            );
        }
        (Some(cert_path), Some(key_path), None) => Some(ClientCertificate::SeparatePem {
            cert_bytes: load_binary_file(cert_path),
            key_bytes: load_binary_file(key_path),
        }),
    }
}

pub fn load_binary_file(path: &Path) -> Vec<u8> {
    use std::{fs::File, io::Read};

    let mut bytes = Vec::new();
    File::open(path).unwrap().read_to_end(&mut bytes).unwrap();

    bytes
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
