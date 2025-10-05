use std::cmp::{min, Ordering};
use std::collections::{HashMap, VecDeque};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use camino::Utf8Path;
use domain::base::iana::Class;
use domain::base::name::FlattenInto;
use domain::base::{CanonicalOrd, Record, Rtype, Serial};
use domain::crypto::kmip::KeyUrl;
use domain::crypto::kmip::{self, ClientCertificate, ConnectionSettings};
use domain::crypto::sign::{KeyPair, SecretKeyBytes, SignRaw};
use domain::dep::kmip::client::pool::{ConnectionManager, SyncConnPool};
use domain::dnssec::common::parse_from_bind;
use domain::dnssec::sign::denial::config::DenialConfig;
use domain::dnssec::sign::denial::nsec3::{GenerateNsec3Config, Nsec3ParamTtlMode};
use domain::dnssec::sign::error::SigningError;
use domain::dnssec::sign::keys::keyset::{KeySet, KeyType};
use domain::dnssec::sign::keys::SigningKey;
use domain::dnssec::sign::records::{DefaultSorter, RecordsIter, Sorter};
use domain::dnssec::sign::signatures::rrsigs::{sign_sorted_zone_records, GenerateRrsigConfig};
use domain::dnssec::sign::traits::SignableZoneInPlace;
use domain::dnssec::sign::SigningConfig;
use domain::rdata::dnssec::Timestamp;
use domain::rdata::{Dnskey, Nsec3param, Rrsig, Soa, ZoneRecordData};
use domain::zonefile::inplace::{Entry, Zonefile};
use domain::zonetree::types::{StoredRecordData, ZoneUpdate};
use domain::zonetree::update::ZoneUpdater;
use domain::zonetree::{StoredName, StoredRecord, Zone, ZoneBuilder};
use jiff::tz::TimeZone;
use jiff::{Timestamp as JiffTimestamp, Zoned};
use log::warn;
use log::{debug, error, info, trace};
use rayon::slice::ParallelSliceMut;
use serde::{Deserialize, Serialize};
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::{oneshot, RwLock, Semaphore};
use tokio::task::spawn_blocking;
use tokio::time::{sleep_until, Instant};
#[cfg(feature = "tls")]
use tokio_rustls::rustls::ServerConfig;
use url::Url;

use crate::center::{get_zone, Center};
use crate::common::light_weight_zone::LightWeightZone;
use crate::comms::ApplicationCommand;
use crate::comms::Terminated;
use crate::payload::Update;
use crate::policy::{PolicyVersion, SignerDenialPolicy, SignerSerialPolicy};
use crate::units::http_server::KmipServerState;
use crate::units::key_manager::{
    mk_dnst_keyset_state_file_path, KmipClientCredentialsFile, KmipServerCredentialsFileMode,
};
use crate::zone::{HistoricalEventType, SigningTrigger};
use crate::zonemaintenance::types::{
    serialize_duration_as_secs, serialize_instant_as_duration_secs, serialize_opt_duration_as_secs,
    SigningFinishedReport, SigningInProgressReport, SigningReport, SigningRequestedReport,
};

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

/// A default poll interval in case no zones need to be resigned.
///
/// This simplifies code. Just a high value to avoid extra overhead.
const IDLE_RESIGNER_POLL_INTERVAL: Duration = Duration::from_secs(24 * 3600);

#[derive(Debug)]
pub struct ZoneSignerUnit {
    pub center: Arc<Center>,

    pub treat_single_keys_as_csks: bool,

    pub use_lightweight_zone_tree: bool,

    pub max_concurrent_operations: usize,

    pub max_concurrent_rrsig_generation_tasks: usize,
    // pub kmip_server_conn_settings: HashMap<String, KmipServerConnectionSettings>,
}

#[allow(dead_code)]
impl ZoneSignerUnit {
    fn default_max_concurrent_operations() -> usize {
        1
    }

    fn default_max_concurrent_rrsig_generation_tasks() -> usize {
        std::thread::available_parallelism().unwrap().get() - 1
    }
}

impl ZoneSignerUnit {
    pub async fn run(
        self,
        cmd_rx: mpsc::UnboundedReceiver<ApplicationCommand>,
        ready_tx: oneshot::Sender<bool>,
    ) -> Result<(), Terminated> {
        // TODO: metrics and status reporting

        // Notify the manager that we are ready.
        ready_tx.send(true).map_err(|_| Terminated)?;

        ZoneSigner::new(
            self.center,
            self.use_lightweight_zone_tree,
            self.max_concurrent_operations,
            self.max_concurrent_rrsig_generation_tasks,
            self.treat_single_keys_as_csks,
            // kmip_servers,
        )
        .run(cmd_rx)
        .await?;

        Ok(())
    }

    fn load_private_key(key_path: &Path) -> Result<SecretKeyBytes, Terminated> {
        let private_data = std::fs::read_to_string(key_path).map_err(|err| {
            error!("Unable to read file '{}': {err}", key_path.display());
            Terminated
        })?;

        // Note: Compared to the original ldns-signzone there is a minor
        // regression here because at the time of writing the error returned
        // from parsing indicates broadly the type of parsing failure but does
        // note indicate the line number at which parsing failed.
        let secret_key = SecretKeyBytes::parse_from_bind(&private_data).map_err(|err| {
            error!(
                "Unable to parse BIND formatted private key file '{}': {err}",
                key_path.display(),
            );
            Terminated
        })?;

        Ok(secret_key)
    }

    fn load_public_key(key_path: &Path) -> Result<Record<StoredName, Dnskey<Bytes>>, Terminated> {
        let public_data = std::fs::read_to_string(key_path).map_err(|_| {
            error!("loading public key from file '{}'", key_path.display(),);
            Terminated
        })?;

        // Note: Compared to the original ldns-signzone there is a minor
        // regression here because at the time of writing the error returned
        // from parsing indicates broadly the type of parsing failure but does
        // note indicate the line number at which parsing failed.
        let public_key_info = parse_from_bind(&public_data).map_err(|err| {
            error!(
                "Unable to parse BIND formatted public key file '{}': {}",
                key_path.display(),
                err
            );
            Terminated
        })?;

        Ok(public_key_info)
    }
}

//------------ ZoneSigner ----------------------------------------------------

struct ZoneSigner {
    center: Arc<Center>,
    use_lightweight_zone_tree: bool,
    concurrent_operation_permits: Semaphore,
    max_concurrent_rrsig_generation_tasks: usize,
    signer_status: Arc<RwLock<ZoneSignerStatus>>,
    _treat_single_keys_as_csks: bool,
    kmip_servers: Arc<Mutex<HashMap<String, SyncConnPool>>>,
    keys_dir: Box<Utf8Path>,
}

impl ZoneSigner {
    #[allow(clippy::too_many_arguments)]
    fn new(
        center: Arc<Center>,
        use_lightweight_zone_tree: bool,
        max_concurrent_operations: usize,
        max_concurrent_rrsig_generation_tasks: usize,
        treat_single_keys_as_csks: bool,
        // kmip_servers: HashMap<String, SyncConnPool>,
    ) -> Self {
        let state = center.state.lock().unwrap();
        let keys_dir = state.config.keys_dir.clone();
        drop(state);

        Self {
            center,
            use_lightweight_zone_tree,
            concurrent_operation_permits: Semaphore::new(max_concurrent_operations),
            max_concurrent_rrsig_generation_tasks,
            signer_status: Default::default(),
            _treat_single_keys_as_csks: treat_single_keys_as_csks,
            kmip_servers: Default::default(),
            keys_dir,
        }
    }

    async fn run(
        self,
        mut cmd_rx: mpsc::UnboundedReceiver<ApplicationCommand>,
    ) -> Result<(), crate::comms::Terminated> {
        let arc_self = Arc::new(self);
        let next_resign_time = arc_self.next_resign_time();
        let mut next_resign_time =
            next_resign_time.unwrap_or(Instant::now() + IDLE_RESIGNER_POLL_INTERVAL);
        loop {
            select! {
                _ = sleep_until(next_resign_time) => {
                    arc_self.clone().resign_zones();
                    next_resign_time = arc_self
                        .next_resign_time()
                        .unwrap_or(Instant::now() + IDLE_RESIGNER_POLL_INTERVAL);
                }
                opt_cmd = cmd_rx.recv() => {
                    let Some(cmd) = opt_cmd else { break };
                    if !arc_self
                        .clone()
                        .handle_command(cmd, &mut next_resign_time).await {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    fn mk_signing_report(&self, status: &ZoneSigningStatus) -> Option<SigningReport> {
        let now = Instant::now();
        let now_t = SystemTime::now();
        match status {
            ZoneSigningStatus::Requested(s) => {
                Some(SigningReport::Requested(SigningRequestedReport {
                    requested_at: now_t.checked_sub(now.duration_since(s.requested_at))?,
                }))
            }
            ZoneSigningStatus::InProgress(s) => {
                Some(SigningReport::InProgress(SigningInProgressReport {
                    requested_at: now_t.checked_sub(now.duration_since(s.requested_at))?,
                    zone_serial: s.zone_serial,
                    started_at: now_t.checked_sub(now.duration_since(s.started_at))?,
                    unsigned_rr_count: s.unsigned_rr_count,
                    walk_time: s.walk_time,
                    sort_time: s.sort_time,
                    denial_rr_count: s.denial_rr_count,
                    denial_time: s.denial_time,
                    rrsig_count: s.rrsig_count,
                    rrsig_reused_count: s.rrsig_reused_count,
                    rrsig_time: s.rrsig_time,
                    insertion_time: s.insertion_time,
                    total_time: s.total_time,
                    threads_used: s.threads_used,
                }))
            }
            ZoneSigningStatus::Finished(s) => {
                Some(SigningReport::Finished(SigningFinishedReport {
                    requested_at: now_t.checked_sub(now.duration_since(s.requested_at))?,
                    zone_serial: s.zone_serial,
                    started_at: now_t.checked_sub(now.duration_since(s.started_at))?,
                    unsigned_rr_count: s.unsigned_rr_count,
                    walk_time: s.walk_time,
                    sort_time: s.sort_time,
                    denial_rr_count: s.denial_rr_count,
                    denial_time: s.denial_time,
                    rrsig_count: s.rrsig_count,
                    rrsig_reused_count: s.rrsig_reused_count,
                    rrsig_time: s.rrsig_time,
                    insertion_time: s.insertion_time,
                    total_time: s.total_time,
                    threads_used: s.threads_used,
                    finished_at: now_t.checked_sub(now.duration_since(s.finished_at))?,
                }))
            }
        }
    }

    /// Handle incoming requests.
    ///
    /// Return true if the caller should continue, false when a Terminate
    /// command is received.
    async fn handle_command(
        self: Arc<Self>,
        cmd: ApplicationCommand,
        next_resign_time: &mut Instant,
    ) -> bool {
        info!("[ZS]: Received command: {cmd:?}");
        match cmd {
            ApplicationCommand::Terminate => {
                // self.status_reporter.terminated();
                return false;
            }

            ApplicationCommand::SignZone {
                zone_name,
                zone_serial, // TODO: the serial number is ignored, but is that okay?
                trigger,
            } => {
                let arc_self = self.clone();
                tokio::task::spawn(async move {
                    if let Err(err) = arc_self
                        .sign_zone(&zone_name, zone_serial.is_none(), trigger)
                        .await
                    {
                        error!("[ZS]: Signing of zone '{zone_name}' failed: {err}");

                        self.center
                            .update_tx
                            .send(Update::ZoneSigningFailedEvent {
                                zone_name,
                                zone_serial,
                                trigger,
                                reason: err,
                            })
                            .unwrap();
                    }
                });
            }

            ApplicationCommand::GetSigningReport {
                zone_name,
                report_tx,
            } => {
                if let Some(status) = self.signer_status.read().await.get(&zone_name) {
                    if let Some(report) = self.mk_signing_report(&status.status) {
                        let _ = report_tx.send(report).ok();
                    };
                }
            }
            ApplicationCommand::PublishSignedZone { .. } => {
                trace!("[ZS]: a zone is published, recompute next time to re-sign");
                *next_resign_time = self
                    .next_resign_time()
                    .unwrap_or(Instant::now() + IDLE_RESIGNER_POLL_INTERVAL);
            }
            _ => { /* Not for us */ }
        }
        true
    }

    /// Signs zone_name from the Manager::unsigned_zones zone collection,
    /// unless `resign_last_signed_zone_content` is true in which case
    /// it resigns the copy of the zone from the Manager::published_zones
    /// collection instead. An alternative way to do this would be to only
    /// read the right version of the unsigned zone, but that would only
    /// be possible if the unsigned zone were definitely a ZoneApex zone
    /// rather than a LightWeightZone (and XFR-in zones are LightWeightZone
    /// instances).
    async fn sign_zone(
        self: Arc<Self>,
        zone_name: &StoredName,
        resign_last_signed_zone_content: bool,
        trigger: SigningTrigger,
    ) -> Result<(), String> {
        // TODO: The signer_status mechanism is broken, as it is limited to
        // 100 slots so that if too many sign_zone() invocations occur the
        // newest will overwrite the oldest. When the permit is then finally
        // acquired, further down where start() is invoked it will fail
        // because the enqueued status item will no longer exist...
        info!("[ZS]: Waiting to start signing operation for zone '{zone_name}'.");
        self.signer_status.write().await.enqueue(zone_name.clone());

        let _permit = self.concurrent_operation_permits.acquire().await.unwrap();
        info!("[ZS]: Starting signing operation for zone '{zone_name}'");

        let start = Instant::now();

        //
        // Lookup the zone to sign.
        //
        let zone_to_sign = match resign_last_signed_zone_content {
            false => {
                let unsigned_zones = self.center.unsigned_zones.load();
                unsigned_zones.get_zone(&zone_name, Class::IN).cloned()
            }
            true => {
                let published_zones = self.center.published_zones.load();
                published_zones.get_zone(&zone_name, Class::IN).cloned()
            }
        };
        let Some(unsigned_zone) = zone_to_sign else {
            // In some cases, we might receive requests to sign zones that are
            // not yet available, because the requestor doesn't know the zone
            // hasn't been signed yet.  The requestors should be fixed; but this
            // is a quick fix for now.

            debug!("Ignoring request to sign unavailable zone '{zone_name}'");
            return Ok(());
        };
        let soa_rr = get_zone_soa(unsigned_zone.clone(), zone_name.clone())?;
        let ZoneRecordData::Soa(soa) = soa_rr.data() else {
            return Err(format!("SOA not found for zone '{zone_name}'"));
        };

        let (last_signed_serial, policy, kmip_server_state_dir, kmip_credentials_store_path) = {
            // Use a block to make sure that the mutex is clearly dropped.
            let state = self.center.state.lock().unwrap();
            let zone = state.zones.get(zone_name).unwrap();
            let zone_state = zone.0.state.lock().unwrap();
            let last_signed_serial = zone_state
                .find_last_event(HistoricalEventType::SigningSucceeded, None)
                .and_then(|item| item.serial);
            let kmip_server_state_dir = state.config.kmip_server_state_dir.clone();
            let kmip_credentials_store_path = state.config.kmip_credentials_store_path.clone();
            (
                last_signed_serial,
                zone_state.policy.clone().unwrap(),
                kmip_server_state_dir,
                kmip_credentials_store_path,
            )
        };

        let serial = match policy.signer.serial_policy {
            SignerSerialPolicy::Keep => {
                if let Some(previous_serial) = last_signed_serial {
                    if soa.serial() <= previous_serial {
                        return Err(
                            "Serial policy is Keep but upstream serial did not increase".into()
                        );
                    }
                }

                soa.serial()
            }
            SignerSerialPolicy::Counter => {
                let mut serial = soa.serial();
                if let Some(previous_serial) = last_signed_serial {
                    if serial <= previous_serial {
                        serial = previous_serial.add(1);
                    }
                }
                serial
            }
            SignerSerialPolicy::UnixTime => {
                let mut serial = Serial::now();
                if let Some(previous_serial) = last_signed_serial {
                    if serial <= previous_serial {
                        serial = previous_serial.add(1);
                    }
                }

                serial
            }
            SignerSerialPolicy::DateCounter => {
                let ts = JiffTimestamp::now();
                let zone = Zoned::new(ts, TimeZone::UTC);
                let serial = ((zone.year() as u32 * 100 + zone.month() as u32) * 100
                    + zone.day() as u32)
                    * 100;
                let mut serial: Serial = serial.into();

                if let Some(previous_serial) = last_signed_serial {
                    if serial <= previous_serial {
                        serial = previous_serial.add(1);
                    }
                }

                serial
            }
        };
        let new_soa = ZoneRecordData::Soa(Soa::new(
            soa.mname().clone(),
            soa.rname().clone(),
            serial,
            soa.refresh(),
            soa.retry(),
            soa.expire(),
            soa.minimum(),
        ));

        let soa_rr = Record::new(
            soa_rr.owner().clone(),
            soa_rr.class(),
            soa_rr.ttl(),
            new_soa,
        );

        self.signer_status
            .write()
            .await
            .start(zone_name, soa.serial());

        //
        // Lookup the signed zone to update, or create a new empty zone to
        // sign into.
        //
        let zone = self.get_or_insert_signed_zone(zone_name);

        //
        // Create a signing configuration.
        //
        // Ensure that the Mutexes are locked only in this block;
        let policy = {
            let zone = get_zone(&self.center, zone_name).unwrap();
            let zone_state = zone.state.lock().unwrap();
            zone_state.policy.clone()
        };
        let signing_config = self.signing_config(&policy.unwrap());
        let rrsig_cfg =
            GenerateRrsigConfig::new(signing_config.inception, signing_config.expiration);

        //
        // Convert zone records into a form we can sign.
        //
        trace!("[ZS]: Collecting records to sign for zone '{zone_name}'.");
        let walk_start = Instant::now();
        let passed_zone = unsigned_zone.clone();
        let mut records = spawn_blocking(|| collect_zone(passed_zone)).await.unwrap();
        records.push(soa_rr.clone());
        let walk_time = walk_start.elapsed();
        let unsigned_rr_count = records.len();

        self.signer_status.write().await.update(zone_name, |s| {
            s.unsigned_rr_count = Some(unsigned_rr_count);
            s.walk_time = Some(walk_time);
        });

        trace!("Reading dnst keyset DNSKEY RRs and RRSIG RRs");
        // Read the DNSKEY RRs and DNSKEY RRSIG RR from the keyset state.
        let state_path = mk_dnst_keyset_state_file_path(&self.keys_dir, zone.apex_name());
        let state = std::fs::read_to_string(&state_path)
            .map_err(|err| format!("Unable to read `dnst keyset` state file '{state_path}' while signing zone {zone_name}: {err}"))?;
        let state: KeySetState = serde_json::from_str(&state).unwrap();
        for dnskey_rr in state.dnskey_rrset {
            let mut zonefile = Zonefile::new();
            zonefile.extend_from_slice(dnskey_rr.as_bytes());
            zonefile.extend_from_slice(b"\n");
            if let Ok(Some(Entry::Record(rec))) = zonefile.next_entry() {
                eprintln!("Adding RR {dnskey_rr}");
                records.push(rec.flatten_into());
            }
        }

        trace!("Loading dnst keyset signing keys");
        // Load the signing keys indicated by the keyset state.
        let mut signing_keys = vec![];
        for (pub_key_name, key_info) in state.keyset.keys() {
            // Only use active ZSKs or CSKs to sign the records in the zone.
            if !matches!(key_info.keytype(),
                KeyType::Zsk(key_state)|KeyType::Csk(_, key_state) if key_state.signer())
            {
                continue;
            }

            if let Some(priv_key_name) = key_info.privref() {
                let priv_url = Url::parse(priv_key_name).expect("valid URL expected");
                let pub_url = Url::parse(pub_key_name).expect("valid URL expected");

                match (priv_url.scheme(), pub_url.scheme()) {
                    ("file", "file") => {
                        let priv_key_path = priv_url.path();
                        debug!("Attempting to load private key '{priv_key_path}'.");

                        let private_key = ZoneSignerUnit::load_private_key(Path::new(priv_key_path))
                            .map_err(|_| format!("Failed to load private key from '{priv_key_path}'"))?;

                        let pub_key_path = pub_url.path();
                        debug!("Attempting to load public key '{pub_key_path}'.");

                        let public_key = ZoneSignerUnit::load_public_key(Path::new(pub_key_path))
                            .map_err(|_| format!("Failed to load public key from '{pub_key_path}'"))?;

                        let key_pair = KeyPair::from_bytes(&private_key, public_key.data())
                            .map_err(|err| format!("Failed to create key pair for zone {zone_name} using key files {pub_key_path} and {priv_key_path}: {err}"))?;
                        let signing_key =
                            SigningKey::new(zone_name.clone(), public_key.data().flags(), key_pair);

                        signing_keys.push(signing_key);
                    }

                    ("kmip", "kmip") => {
                        let priv_key_url = KeyUrl::try_from(priv_url).map_err(|err| format!("Invalid KMIP URL for private key: {err}"))?;
                        let pub_key_url = KeyUrl::try_from(pub_url).map_err(|err| format!("Invalid KMIP URL for public key: {err}"))?;

                        // TODO: Replace the connection pool if the persisted KMIP server settings
                        // were updated more recently than the pool was created.

                        let mut kmip_servers = self.kmip_servers.lock().unwrap();
                        let kmip_conn_pool = match kmip_servers
                            .entry(priv_key_url.server_id().to_string()) {
                                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                                std::collections::hash_map::Entry::Vacant(e) => {
                                    // Try and load the KMIP server settings.
                                    let p = kmip_server_state_dir.join(priv_key_url.server_id());
                                    log::info!("Reading KMIP server state from '{p}'");
                                    let f = std::fs::File::open(p).unwrap();
                                    let kmip_server: KmipServerState = serde_json::from_reader(f).unwrap();
                                    let KmipServerState {
                                        server_id,
                                        ip_host_or_fqdn: host,
                                        port,
                                        insecure,
                                        connect_timeout,
                                        read_timeout,
                                        write_timeout,
                                        max_response_bytes,
                                        has_credentials,
                                        ..
                                    } = kmip_server;

                                    let mut username = None;
                                    let mut password = None;
                                    if has_credentials {
                                        let creds_file = KmipClientCredentialsFile::new(
                                            kmip_credentials_store_path.as_std_path(),
                                            KmipServerCredentialsFileMode::ReadOnly)
                                        .unwrap();

                                        let creds = creds_file.get(&server_id)
                                            .ok_or(format!("Missing credentials for KMIP server '{server_id}'"))?;

                                        username = Some(creds.username.clone());
                                        password = creds.password.clone();
                                    }

                                    let conn_settings = ConnectionSettings {
                                        host,
                                        port,
                                        username,
                                        password,
                                        insecure,
                                        client_cert: None, // TODO
                                        server_cert: None, // TODO
                                        ca_cert: None, // TODO
                                        connect_timeout: Some(connect_timeout),
                                        read_timeout: Some(read_timeout),
                                        write_timeout: Some(write_timeout),
                                        max_response_bytes: Some(max_response_bytes),
                                    };

                                    let pool = ConnectionManager::create_connection_pool(
                                        server_id.clone(),
                                        Arc::new(conn_settings.clone()),
                                        10,
                                        Some(Duration::from_secs(60)),
                                        Some(Duration::from_secs(60)),
                                    ).map_err(|err| format!("Failed to create connection pool for KMIP server '{server_id}': {err}"))?;

                                    e.insert(pool)
                                }
                            };

                        let _flags = priv_key_url.flags();

                        let key_pair = KeyPair::Kmip(kmip::sign::KeyPair::from_urls(
                            priv_key_url,
                            pub_key_url,
                            kmip_conn_pool.clone(),
                        ).map_err(|err| format!("Failed to create keypair for KMIP key IDs: {err}"))?);

                        let signing_key = SigningKey::new(zone_name.clone(), key_pair.flags(), key_pair);

                        signing_keys.push(signing_key);
                    }

                    (other1, other2) => return Err(format!("Using different key URI schemes ({other1} vs {other2}) for a public/private key pair is not supported.")),
                }

                debug!("Loaded key pair for zone {zone_name} from key pair");
            }
        }

        trace!("{} signing keys loaded", signing_keys.len());

        // TODO: If signing is disabled for a zone should we then allow the
        // unsigned zone to propagate through the pipeline?
        if signing_keys.is_empty() {
            warn!("No signing keys found for zone {zone_name}, aborting");
            return Ok(());
        }

        //
        // Sort them into DNSSEC order ready for NSEC(3) generation.
        //
        trace!("[ZS]: Sorting collected records for zone '{zone_name}'.");
        let sort_start = Instant::now();
        let mut records = spawn_blocking(|| {
            DefaultSorter::sort_by(&mut records, CanonicalOrd::canonical_cmp);
            records.dedup();
            records
        })
        .await
        .unwrap();
        let sort_time = sort_start.elapsed();

        self.signer_status.write().await.update(zone_name, |s| {
            s.sort_time = Some(sort_time);
        });

        //
        // Generate NSEC(3) RRs.
        //
        trace!("[ZS]: Generating denial records for zone '{zone_name}'.");
        let denial_start = Instant::now();
        let apex_owner = zone_name.clone();
        let unsigned_records = spawn_blocking(move || {
            // By not passing any keys to sign_zone() will only add denial RRs,
            // not RRSIGs. We could invoke generate_nsecs() or generate_nsec3s()
            // directly here instead.
            let no_keys: [&SigningKey<Bytes, KeyPair>; 0] = Default::default();
            records.sign_zone(&apex_owner, &signing_config, &no_keys)?;
            Ok(records)
        })
        .await
        .unwrap()
        .map_err(|err: SigningError| {
            format!("Failed to generate denial RRs for zone '{zone_name}': {err}")
        })?;
        let denial_time = denial_start.elapsed();
        let denial_rr_count = unsigned_records.len() - unsigned_rr_count;

        self.signer_status.write().await.update(zone_name, |s| {
            s.denial_rr_count = Some(denial_rr_count);
            s.denial_time = Some(denial_time);
        });

        //
        // Generate RRSIG RRs concurrently.
        //
        // Use N concurrent Rayon scoped threads to do blocking RRSIG
        // generation without interfering with Tokio task scheduling, and an
        // async task which receives generated RRSIGs via a Tokio
        // mpsc::channel and accumulates them into the signed zone.
        //
        trace!("[ZS]: Generating RRSIG records.");

        // Work out how many RRs have to be signed and how many concurrent
        // threads to sign with and how big each chunk to be signed should be.
        let rr_count = RecordsIter::new(&unsigned_records).count();
        let (parallelism, chunk_size) = self.determine_signing_concurrency(rr_count);
        info!("SIGNER: Using {parallelism} threads to sign {rr_count} owners in chunks of {chunk_size}.",);

        self.signer_status.write().await.update(zone_name, |s| {
            s.threads_used = Some(parallelism);
        });

        // Create a zone updater which will be used to add RRs resulting
        // from RRSIG generation to the signed zone. We set the create_diff
        // argument to false because we sign the zone by deleting all records
        // so from the point of view of the automatic diff creation logic all
        // records added to the zone appear to be new. Once we add support for
        // incremental signing (i.e. only regenerate, add and remove RRSIGs,
        // and update the NSEC(3) chain as needed, we can capture a diff of
        // the changes we make).
        let mut updater = ZoneUpdater::new(zone.clone(), false).await.unwrap();

        // Clear out any RRs in the current version of the signed zone. If the zone
        // supports versioning this is a NO OP.
        trace!("SIGNER: Deleting records in existing (if any) copy of signed zone.");
        updater.apply(ZoneUpdate::DeleteAllRecords).await.unwrap();

        // 'updater.apply()' is technically 'async', although we always
        // implement it here with synchronous methods.  This still forces
        // us to wrap the whole thing in a future, so we spawn a relatively
        // lightweight single-threaded Tokio runtime to handle it for us.

        // Insert all unsigned records into the updater.
        let unsigned_updater_task = spawn_blocking({
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();

            move || {
                runtime.block_on(async move {
                    let start = Instant::now();

                    for record in &unsigned_records {
                        let record = Record::from_record(record.clone());
                        updater.apply(ZoneUpdate::AddRecord(record)).await.unwrap();
                    }

                    debug!(
                        "Inserted {} unsigned records in {:.1}s",
                        unsigned_records.len(),
                        start.elapsed().as_secs_f64()
                    );

                    (unsigned_records, updater)
                })
            }
        });
        let (unsigned_records, mut updater) = unsigned_updater_task
            .await
            .map_err(|_| "Failed to insert unsigned records")?;

        // At the moment, 'ZoneUpdater' only allows single-threaded access.  It
        // needs to be passed all of our records, which get created across many
        // threads.  Rather than collecting all the records and inserting them
        // at once, we'll let the updater run in tandem with signing.  If the
        // updater can't keep up, the channel will accumulate a lot of objects,
        // but that's okay.
        let (updater_tx, updater_rx) = std::sync::mpsc::channel::<Vec<SigRecord>>();

        // The inserter task; it collects all signatures and adds them to the
        // zone.  It also computes the minimum expiration time for us.
        let inserter_task = spawn_blocking({
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();

            move || {
                runtime.block_on(async move {
                    let mut total_signatures = 0usize;
                    let start = Instant::now();

                    while let Ok(signatures) = updater_rx.recv() {
                        total_signatures += signatures.len();
                        for sig in signatures {
                            updater
                                .apply(ZoneUpdate::AddRecord(Record::from_record(sig)))
                                .await
                                .unwrap();
                        }
                    }

                    let duration = start.elapsed();
                    debug!(
                        "Inserted {total_signatures} signatures over {:.1}s",
                        duration.as_secs_f64()
                    );

                    (updater, total_signatures, duration)
                })
            }
        });

        // Generate all signatures via Rayon on separate threads.
        let generator_task = spawn_blocking({
            let zone_name = zone_name.clone();
            let signing_keys = Arc::new(signing_keys);

            move || {
                // TODO: Install a dedicated Rayon thread pool over here?

                let start = Instant::now();

                // Get the keys to sign with.  Domain's 'sign_sorted_zone_records()'
                // needs a slice of references, so we need to build that here.
                let keys = signing_keys.iter().collect::<Vec<_>>();

                let task = SignTask {
                    zone_name: &zone_name,
                    records: &unsigned_records,
                    range: 0..unsigned_records.len(),
                    config: &rrsig_cfg,
                    keys: &keys,
                    updater_tx: &updater_tx,
                };

                task.execute().map(|_| start.elapsed())
            }
        });

        // Wait for signature generation and insertion to finish.
        let generation_time = generator_task
            .await
            .map_err(|_| "Could not generate RRsigs")?
            .map_err(|err| format!("Signing failed: {err}"))?;
        let (mut updater, total_signatures, insertion_time) = inserter_task
            .await
            .map_err(|_| "Could not insert all records")?;

        let generation_rate = total_signatures as f64 / generation_time.as_secs_f64().min(0.001);
        let insertion_rate = total_signatures as f64 / insertion_time.as_secs_f64().min(0.001);

        // Finalize the signed zone update.
        let ZoneRecordData::Soa(soa_data) = soa_rr.data() else {
            unreachable!();
        };
        let zone_serial = soa_data.serial();

        // Store the serial in the state.
        // Note: We do NOT do this here because CentralCommand does it when it
        // sees the ZoneSignedEvent.
        // {
        //     // Use a block to make sure that the mutex is clearly dropped.
        //     let zone = get_zone(&self.center, zone_name).unwrap();
        //     let mut zone_state = zone.state.lock().unwrap();
        //     zone_state.record_event(
        //         HistoricalEvent::SigningSucceeded { trigger },
        //         Some(zone_serial),
        //     );
        //     zone.mark_dirty(&mut zone_state, &self.center);
        // }

        updater.apply(ZoneUpdate::Finished(soa_rr)).await.unwrap();

        let reader = zone.read();
        let apex_name = zone_name.clone();
        let min_expiration = Arc::new(MinTimestamp::new());
        let saved_min_expiration = min_expiration.clone();
        reader.walk(Box::new(move |name, rrset, _cut| {
            for r in rrset.data() {
                if let ZoneRecordData::Rrsig(rrsig) = r {
                    if name == apex_name
                        && (rrsig.type_covered() == Rtype::DNSKEY
                            || rrsig.type_covered() == Rtype::CDS
                            || rrsig.type_covered() == Rtype::CDNSKEY)
                    {
                        // These types come from the key manager.
                        continue;
                    }

                    min_expiration.add(rrsig.expiration());
                }
            }
        }));

        // Save the minimum of the expiration times.
        {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone = get_zone(&self.center, zone_name).unwrap();
            let mut zone_state = zone.state.lock().unwrap();

            // Save as next_min_expiration. After the signed zone is approved
            // this value should be move to min_expiration.
            zone_state.next_min_expiration = saved_min_expiration.get();
            zone.mark_dirty(&mut zone_state, &self.center);
        }

        let total_time = start.elapsed();

        {
            let mut status = self.signer_status.write().await;

            status.update(zone_name, |s| {
                s.rrsig_count = Some(total_signatures);
                s.rrsig_reused_count = Some(0); // Not implemented yet
                s.rrsig_time = Some(generation_time);
                s.insertion_time = Some(insertion_time);
                s.total_time = Some(total_time);
            });

            status.finish(zone_name);
        }

        // Log signing statistics.
        info!(
            "Signing statistics for {zone_name} serial: {zone_serial}:\n\
            Collected {unsigned_rr_count} records in {:.1}s, sorted in {:.1}s\n\
            Generated {denial_rr_count} NSEC(3) records in {:.1}s\n\
            Generated {total_signatures} signatures in {:.1}s ({generation_rate:.0}sig/s)
            Inserted signatures in {:.1}s ({insertion_rate:.0}sig/s)\n\
            Took {:.1}s in total, using {parallelism} threads",
            walk_time.as_secs_f64(),
            sort_time.as_secs_f64(),
            denial_time.as_secs_f64(),
            generation_time.as_secs_f64(),
            insertion_time.as_secs_f64(),
            total_time.as_secs_f64()
        );

        // Notify Central Command that we have finished.
        self.center
            .update_tx
            .send(Update::ZoneSignedEvent {
                zone_name: zone_name.clone(),
                zone_serial,
                trigger,
            })
            .unwrap();

        Ok(())
    }

    fn determine_signing_concurrency(&self, rr_count: usize) -> (usize, usize) {
        // TODO: Relevant user suggestion: "Misschien een tip voor NameShed:
        // Het aantal signerthreads dynamisch maken, zodat de signer zelf
        // extra threads kan opstarten als er geconstateerd wordt dat er veel
        // nieuwe sigs gemaakt moeten worden."
        let parallelism = if rr_count < 1024 {
            if rr_count >= 2 {
                2
            } else {
                1
            }
        } else {
            self.max_concurrent_rrsig_generation_tasks
        };
        let parallelism = std::cmp::min(parallelism, self.max_concurrent_rrsig_generation_tasks);
        let chunk_size = rr_count / parallelism;
        (parallelism, chunk_size)
    }

    fn get_or_insert_signed_zone(&self, zone_name: &StoredName) -> Zone {
        // Create an empty zone to sign into if no existing signed zone exists.
        let signed_zones = self.center.signed_zones.load();

        signed_zones
            .get_zone(zone_name, Class::IN)
            .cloned()
            .unwrap_or_else(move || {
                let mut new_zones = Arc::unwrap_or_clone(signed_zones.clone());

                let new_zone = if self.use_lightweight_zone_tree {
                    Zone::new(LightWeightZone::new(zone_name.clone(), false))
                } else {
                    ZoneBuilder::new(zone_name.clone(), Class::IN).build()
                };

                new_zones.insert_zone(new_zone.clone()).unwrap();
                self.center.signed_zones.store(Arc::new(new_zones));

                new_zone
            })
    }

    fn signing_config(&self, policy: &PolicyVersion) -> SigningConfig<Bytes, MultiThreadedSorter> {
        let denial = match &policy.signer.denial {
            SignerDenialPolicy::NSec => DenialConfig::Nsec(Default::default()),
            SignerDenialPolicy::NSec3 { opt_out } => {
                let first = parse_nsec3_config(*opt_out);
                DenialConfig::Nsec3(first)
            }
        };

        let now = Timestamp::now().into_int();
        let inception = now.wrapping_sub(policy.signer.sig_inception_offset.as_secs() as u32);
        let expiration = now.wrapping_add(policy.signer.sig_validity_time.as_secs() as u32);
        SigningConfig::new(denial, inception.into(), expiration.into())
    }

    fn next_resign_time(&self) -> Option<Instant> {
        let zone_tree = &self.center.unsigned_zones;
        let mut min_time = None;
        let now = SystemTime::now();
        for zone in zone_tree.load().iter_zones() {
            let zone_name = zone.apex_name();

            let min_expiration = {
                // Use a block to make sure that the mutex is clearly dropped.
                let state = self.center.state.lock().unwrap();
                let zone = state.zones.get(zone_name).unwrap();
                let zone_state = zone.0.state.lock().unwrap();

                zone_state.min_expiration
            };

            let Some(min_expiration) = min_expiration else {
                trace!("[ZS] resign: no min-expiration for zone {zone_name}");
                continue;
            };

            // Start a new block to make sure the mutex is released.
            {
                let mut resign_busy = self.center.resign_busy.lock().expect("should not fail");
                let opt_expiration = resign_busy.get(zone_name);
                if let Some(expiration) = opt_expiration {
                    if *expiration == min_expiration {
                        // This zone is busy.
                        trace!("[ZS]: resign: zone {zone_name} is busy");
                        continue;
                    }

                    // Zone has been resigned. Remove this entry.
                    resign_busy.remove(zone_name);
                }
            }

            // Ensure that the Mutexes are locked only in this block;
            let remain_time = {
                let state = self.center.state.lock().unwrap();
                let zone = state.zones.get(zone_name).unwrap();
                let zone_state = zone.0.state.lock().unwrap();
                // TODO: what if there is no policy?
                zone_state.policy.as_ref().unwrap().signer.sig_remain_time
            };

            let exp_time = min_expiration.to_system_time(now);
            let exp_time = exp_time - remain_time;

            min_time = if let Some(time) = min_time {
                Some(min(time, exp_time))
            } else {
                Some(exp_time)
            };
        }
        min_time.map(|t| {
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

    fn resign_zones(&self) {
        let zone_tree = &self.center.unsigned_zones;
        let now = SystemTime::now();
        for zone in zone_tree.load().iter_zones() {
            let zone_name = zone.apex_name();

            let min_expiration = {
                // Use a block to make sure that the mutex is clearly dropped.
                let state = self.center.state.lock().unwrap();
                let zone = state.zones.get(zone_name).unwrap();
                let zone_state = zone.0.state.lock().unwrap();

                zone_state.min_expiration
            };

            let Some(min_expiration) = min_expiration else {
                continue;
            };

            // Start a new block to make sure the mutex is released.
            {
                let resign_busy = self.center.resign_busy.lock().expect("should not fail");
                let opt_expiration = resign_busy.get(zone_name);
                if let Some(expiration) = opt_expiration {
                    if *expiration == min_expiration {
                        // This zone is busy.
                        continue;
                    }
                }
            }

            // Ensure that the Mutexes are locked only in this block;
            let remain_time = {
                let state = self.center.state.lock().unwrap();
                let zone = state.zones.get(zone_name).unwrap();
                let zone_state = zone.0.state.lock().unwrap();
                // What if there is no policy?
                zone_state.policy.as_ref().unwrap().signer.sig_remain_time
            };

            let exp_time = min_expiration.to_system_time(now);
            let exp_time = exp_time - remain_time;

            if exp_time < now {
                trace!("[ZS]: re-signing: request signing of zone {zone_name}");

                // Start a new block to make sure the mutex is released.
                {
                    let mut resign_busy = self.center.resign_busy.lock().expect("should not fail");
                    resign_busy.insert(zone_name.clone(), min_expiration);
                }
                self.center
                    .update_tx
                    .send(Update::ResignZoneEvent {
                        zone_name: zone_name.clone(),
                        trigger: SigningTrigger::SignatureExpiration,
                    })
                    .unwrap();
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

    pub dnskey_rrset: Vec<String>,
    pub ds_rrset: Vec<String>,
    pub cds_rrset: Vec<String>,
    pub ns_rrset: Vec<String>,
}

struct MinTimestamp(Mutex<Option<Timestamp>>);

impl MinTimestamp {
    fn new() -> Self {
        Self(Mutex::new(None))
    }
    fn add(&self, ts: Timestamp) {
        let mut min_ts = self.0.lock().expect("should not fail");
        if let Some(curr_min) = *min_ts {
            if ts < curr_min {
                *min_ts = Some(ts);
            }
        } else {
            *min_ts = Some(ts);
        }
    }
    fn get(&self) -> Option<Timestamp> {
        let min_ts = self.0.lock().expect("should not fail");
        *min_ts
    }
}

/// A signature record.
type SigRecord = Record<StoredName, Rrsig<Bytes, StoredName>>;

/// A task to sign a set of records.
#[derive(Clone)]
struct SignTask<'a> {
    /// The name of the zone.
    zone_name: &'a StoredName,

    /// The entire set of unsigned records.
    records: &'a [Record<StoredName, StoredRecordData>],

    /// The apparent range of records to work on.
    ///
    /// The true range is slightly different; it rounds forward to full RRsets.
    /// This means that some initial records might be skipped, and some records
    /// beyond the end might be included.
    range: Range<usize>,

    /// The signing configuration.
    config: &'a GenerateRrsigConfig,

    /// The set of keys to sign with.
    keys: &'a [&'a SigningKey<Bytes, KeyPair>],

    /// The zone updater to insert the records into.
    updater_tx: &'a std::sync::mpsc::Sender<Vec<SigRecord>>,
}

impl SignTask<'_> {
    /// The ideal batch size for signing records.
    ///
    /// Records will be signed when they are grouped into batches of this size
    /// or smaller.
    const BATCH_SIZE: usize = 4096;

    /// Execute this task.
    ///
    /// If the task is too big, it will be split into two and executed through
    /// Rayon.  This follows Rayon's concurrency paradigm, known as Cilk-style
    /// parallelism.  It's ideal for Rayon's work-stealing implementation.
    pub fn execute(self) -> Result<(), SigningError> {
        if self.range.len() <= Self::BATCH_SIZE {
            // This task should take little enough time that we'll do it all
            // on this thread, immediately.

            self.execute_now()
        } else {
            // Split the task into two and allow Rayon to execute them in
            // parallel if it can.

            let (a, b) = self.split();
            match rayon::join(|| a.execute(), || b.execute()) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(err), Ok(())) | (Ok(()), Err(err)) => Err(err),
                // TODO: Do we want to combine errors somehow?
                (Err(a), Err(_b)) => Err(a),
            }
        }
    }

    /// Split this task in two.
    fn split(self) -> (Self, Self) {
        debug_assert!(self.range.len() > Self::BATCH_SIZE);

        // Just split the apparent range in two.
        let midpoint = self.range.start + self.range.len() / 2;
        let left_range = self.range.start..midpoint;
        let right_range = midpoint..self.range.end;

        (
            Self {
                range: left_range,
                ..self.clone()
            },
            Self {
                range: right_range,
                ..self.clone()
            },
        )
    }

    /// Execute this task right here.
    fn execute_now(self) -> Result<(), SigningError> {
        // Determine the true range we want to sign.

        if self.range.is_empty() {
            return Ok(());
        }

        let start = if self.range.start > 0 {
            // The record immediately before our apparent range.
            let previous = &self.records[self.range.start - 1];

            self.records[self.range.clone()]
                .iter()
                .position(|r| r.owner() != previous.owner())
                .map_or(self.range.end, |p| self.range.start + p)
        } else {
            self.range.start
        };

        let end = {
            // The last record in our apparent range.
            let last = &self.records[self.range.end - 1];

            self.records[self.range.end..]
                .iter()
                .position(|r| r.owner() != last.owner())
                .map_or(self.records.len(), |p| self.range.end + p)
        };

        let range = start..end;

        if range.is_empty() {
            return Ok(());
        }

        // Perform the actual signing.
        let signatures = sign_sorted_zone_records(
            self.zone_name,
            RecordsIter::new(&self.records[range]),
            self.keys,
            self.config,
        )?;

        // Return the signatures.
        //
        // If this fails, then the receiver must have panicked; an error about
        // that will already be logged, so let's not pollute the logs further.
        let _ = self.updater_tx.send(signatures);

        Ok(())
    }
}

fn get_zone_soa(
    zone: Zone,
    zone_name: StoredName,
) -> Result<Record<StoredName, StoredRecordData>, String> {
    let answer = zone
        .read()
        .query(zone_name.clone(), Rtype::SOA)
        .map_err(|_| format!("SOA not found for zone '{zone_name}'"))?;
    let (soa_ttl, soa_data) = answer
        .content()
        .first()
        .ok_or_else(|| format!("SOA not found for zone '{zone_name}'"))?;
    if !matches!(soa_data, ZoneRecordData::Soa(_)) {
        return Err(format!("SOA not found for zone '{zone_name}'"));
    };
    Ok(Record::new(zone_name.clone(), Class::IN, soa_ttl, soa_data))
}

fn collect_zone(zone: Zone) -> Vec<StoredRecord> {
    // Temporary: Accumulate the zone into a vec as we can only sign over a
    // slice at the moment, not over an iterator yet (nor can we iterate over
    // a zone yet, only walk it ...).
    let records = Arc::new(std::sync::Mutex::new(vec![]));
    let passed_records = records.clone();

    trace!("SIGNER: Walking");
    zone.read()
        .walk(Box::new(move |owner, rrset, _at_zone_cut| {
            let mut unlocked_records = passed_records.lock().unwrap();

            // SKIP DNSSEC records that should be generated by the signing
            // process (these will be present if re-signing a published signed
            // zone rather than signing an unsigned zone). Skip The SOA as
            // well. A new SOA will be added later.
            if matches!(
                rrset.rtype(),
                Rtype::DNSKEY
                    | Rtype::RRSIG
                    | Rtype::NSEC
                    | Rtype::NSEC3
                    | Rtype::CDS
                    | Rtype::CDNSKEY
                    | Rtype::SOA
            ) {
                return;
            }

            unlocked_records.extend(
                rrset.data().iter().map(|rdata| {
                    Record::new(owner.clone(), Class::IN, rrset.ttl(), rdata.to_owned())
                }),
            );
        }));

    let records = Arc::into_inner(records).unwrap().into_inner().unwrap();

    trace!(
        "SIGNER: Walked: accumulated {} records for signing",
        records.len()
    );

    records
}

fn parse_nsec3_config(opt_out: bool) -> GenerateNsec3Config<Bytes, MultiThreadedSorter> {
    let mut params = Nsec3param::default();
    if opt_out {
        params.set_opt_out_flag()
    }

    // TODO: support other ttl_modes? Seems missing from the config right now
    let ttl_mode = Nsec3ParamTtlMode::Soa;
    GenerateNsec3Config::new(params).with_ttl_mode(ttl_mode)
}

impl std::fmt::Debug for ZoneSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneSigner").finish()
    }
}

//------------ ZoneSigningStatus ---------------------------------------------

#[derive(Copy, Clone, Serialize)]
struct RequestedStatus {
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    requested_at: tokio::time::Instant,
}

impl RequestedStatus {
    fn new() -> Self {
        Self {
            requested_at: Instant::now(),
        }
    }
}

#[derive(Copy, Clone, Serialize)]
struct InProgressStatus {
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    requested_at: tokio::time::Instant,
    zone_serial: Serial,
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    started_at: tokio::time::Instant,
    unsigned_rr_count: Option<usize>,
    #[serde(serialize_with = "serialize_opt_duration_as_secs")]
    walk_time: Option<Duration>,
    #[serde(serialize_with = "serialize_opt_duration_as_secs")]
    sort_time: Option<Duration>,
    denial_rr_count: Option<usize>,
    #[serde(serialize_with = "serialize_opt_duration_as_secs")]
    denial_time: Option<Duration>,
    rrsig_count: Option<usize>,
    rrsig_reused_count: Option<usize>,
    #[serde(serialize_with = "serialize_opt_duration_as_secs")]
    rrsig_time: Option<Duration>,
    #[serde(serialize_with = "serialize_opt_duration_as_secs")]
    insertion_time: Option<Duration>,
    #[serde(serialize_with = "serialize_opt_duration_as_secs")]
    total_time: Option<Duration>,
    threads_used: Option<usize>,
}

impl InProgressStatus {
    fn new(requested_status: RequestedStatus, zone_serial: Serial) -> Self {
        Self {
            requested_at: requested_status.requested_at,
            zone_serial,
            started_at: Instant::now(),
            unsigned_rr_count: None,
            walk_time: None,
            sort_time: None,
            denial_rr_count: None,
            denial_time: None,
            rrsig_count: None,
            rrsig_reused_count: None,
            rrsig_time: None,
            insertion_time: None,
            total_time: None,
            threads_used: None,
        }
    }
}

#[derive(Copy, Clone, Serialize)]
struct FinishedStatus {
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    requested_at: tokio::time::Instant,
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    started_at: tokio::time::Instant,
    zone_serial: Serial,
    unsigned_rr_count: usize,
    #[serde(serialize_with = "serialize_duration_as_secs")]
    walk_time: Duration,
    #[serde(serialize_with = "serialize_duration_as_secs")]
    sort_time: Duration,
    denial_rr_count: usize,
    #[serde(serialize_with = "serialize_duration_as_secs")]
    denial_time: Duration,
    rrsig_count: usize,
    rrsig_reused_count: usize,
    #[serde(serialize_with = "serialize_duration_as_secs")]
    rrsig_time: Duration,
    #[serde(serialize_with = "serialize_duration_as_secs")]
    insertion_time: Duration,
    #[serde(serialize_with = "serialize_duration_as_secs")]
    total_time: Duration,
    threads_used: usize,
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    finished_at: tokio::time::Instant,
}

impl FinishedStatus {
    fn new(in_progress_status: InProgressStatus) -> Self {
        Self {
            requested_at: in_progress_status.requested_at,
            zone_serial: in_progress_status.zone_serial,
            started_at: Instant::now(),
            unsigned_rr_count: in_progress_status.unsigned_rr_count.unwrap(),
            walk_time: in_progress_status.walk_time.unwrap(),
            sort_time: in_progress_status.sort_time.unwrap(),
            denial_rr_count: in_progress_status.denial_rr_count.unwrap(),
            denial_time: in_progress_status.denial_time.unwrap(),
            rrsig_count: in_progress_status.rrsig_count.unwrap(),
            rrsig_reused_count: in_progress_status.rrsig_reused_count.unwrap(),
            rrsig_time: in_progress_status.rrsig_time.unwrap(),
            insertion_time: in_progress_status.insertion_time.unwrap(),
            total_time: in_progress_status.total_time.unwrap(),
            threads_used: in_progress_status.threads_used.unwrap(),
            finished_at: Instant::now(),
        }
    }
}

#[derive(Copy, Clone, Serialize)]
enum ZoneSigningStatus {
    Requested(RequestedStatus),

    InProgress(InProgressStatus),

    Finished(FinishedStatus),
}

impl ZoneSigningStatus {
    fn new() -> Self {
        Self::Requested(RequestedStatus::new())
    }

    fn start(self, zone_serial: Serial) -> Self {
        match self {
            ZoneSigningStatus::Requested(s) => {
                Self::InProgress(InProgressStatus::new(s, zone_serial))
            }
            ZoneSigningStatus::InProgress(_) => self,
            ZoneSigningStatus::Finished(_) => {
                panic!("Cannot start a signing operation that already finished")
            }
        }
    }

    fn finish(self) -> Self {
        match self {
            ZoneSigningStatus::Requested(_) => {
                panic!("Cannot finish a signing operation that never started")
            }
            ZoneSigningStatus::InProgress(s) => Self::Finished(FinishedStatus::new(s)),
            ZoneSigningStatus::Finished(_) => self,
        }
    }
}

//------------ ZoneSignerStatus ----------------------------------------------

const MAX_SIGNING_HISTORY: usize = 100;

#[derive(Serialize)]
struct NamedZoneSigningStatus {
    zone_name: StoredName,
    status: ZoneSigningStatus,
}

#[derive(Serialize)]
struct ZoneSignerStatus {
    // Maps zone names to signing status, keeping records of previous signing.
    // Use VecDeque for its ability to act as a ring buffer: check size, if
    // at max desired capacity pop_front(), then in both cases push_back().
    zones_being_signed: VecDeque<NamedZoneSigningStatus>,
}

impl ZoneSignerStatus {
    #[allow(dead_code)]
    pub fn get(&self, wanted_zone_name: &StoredName) -> Option<&NamedZoneSigningStatus> {
        self.zones_being_signed
            .iter()
            .rfind(|v| v.zone_name == wanted_zone_name)
    }

    fn get_mut(&mut self, wanted_zone_name: &StoredName) -> Option<&mut NamedZoneSigningStatus> {
        self.zones_being_signed
            .iter_mut()
            .rfind(|v| v.zone_name == wanted_zone_name)
    }

    pub fn enqueue(&mut self, zone_name: StoredName) {
        if self.zones_being_signed.len() == self.zones_being_signed.capacity() {
            // Discard oldest.
            let _ = self.zones_being_signed.pop_front();
        }
        self.zones_being_signed.push_back(NamedZoneSigningStatus {
            zone_name,
            status: ZoneSigningStatus::new(),
        });
    }

    pub fn start(&mut self, zone_name: &StoredName, zone_serial: Serial) {
        let res = self.get_mut(zone_name);
        if matches!(
            res,
            Some(NamedZoneSigningStatus {
                status: ZoneSigningStatus::Requested(..),
                ..
            })
        ) {
            let named_status = res.unwrap();
            named_status.status = named_status.status.start(zone_serial);
        }
    }

    pub fn update<F: Fn(&mut InProgressStatus)>(&mut self, zone_name: &StoredName, cb: F) {
        if let Some(NamedZoneSigningStatus {
            status: ZoneSigningStatus::InProgress(in_progress_status),
            ..
        }) = self.get_mut(zone_name)
        {
            // Only an existing unfinished status can be updated.
            cb(in_progress_status)
        }
    }

    pub fn finish(&mut self, zone_name: &StoredName) {
        let res = self.get_mut(zone_name);
        if matches!(
            res,
            Some(NamedZoneSigningStatus {
                status: ZoneSigningStatus::InProgress(..),
                ..
            })
        ) {
            let named_status = res.unwrap();
            named_status.status = named_status.status.finish();
        }
    }
}

impl Default for ZoneSignerStatus {
    fn default() -> Self {
        Self {
            zones_being_signed: VecDeque::with_capacity(MAX_SIGNING_HISTORY),
        }
    }
}

//------------ MultiThreadedSorter -------------------------------------------

/// A parallelized sort implementation for use with [`SortedRecords`].
///
/// TODO: Should we add a `-j` (jobs) command line argument to override the
/// default Rayon behaviour of using as many threads as their are CPU cores?
struct MultiThreadedSorter;

impl domain::dnssec::sign::records::Sorter for MultiThreadedSorter {
    fn sort_by<N, D, F>(records: &mut Vec<Record<N, D>>, compare: F)
    where
        F: Fn(&Record<N, D>, &Record<N, D>) -> Ordering + Sync,
        Record<N, D>: CanonicalOrd + Send,
    {
        records.par_sort_by(compare);
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
            panic!("Use either but not both of: client certificate and key PEM file paths, or a PCKS#12 certficate file path");
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
