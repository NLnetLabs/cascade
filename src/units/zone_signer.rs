// Allow println! for now.
#![allow(clippy::disallowed_macros)]

use std::cmp::{Ordering, min};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::collections::{HashMap, VecDeque};
use std::env::{VarError, var};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use bytes::BytesMut;
use cascade_zonedata::{
    LoadedZoneReader, OldParsedRecord, OldRecord, RegularRecord, SignedZoneBuilder,
    SignedZonePatcher, SignedZoneReader, SoaRecord,
};
use domain::base::iana::{Class, SecurityAlgorithm, ZonemdAlgorithm, ZonemdScheme};
use domain::base::name::FlattenInto;
use domain::base::{
    CanonicalOrd, Name, NameBuilder, Record, Rtype, Serial as DomainSerial, ToName, Ttl,
};
use domain::crypto::sign::{SecretKeyBytes, SignRaw};
use domain::dnssec::common::{nsec3_hash, parse_from_bind};
use domain::dnssec::sign::SigningConfig;
use domain::dnssec::sign::denial::config::DenialConfig;
use domain::dnssec::sign::denial::nsec::{GenerateNsecConfig, generate_nsecs};
use domain::dnssec::sign::denial::nsec3::{
    GenerateNsec3Config, Nsec3ParamTtlMode, Nsec3Records, generate_nsec3s,
};
use domain::dnssec::sign::error::SigningError;
use domain::dnssec::sign::keys::SigningKey;
use domain::dnssec::sign::keys::keyset::{KeySet, KeyType, UnixTime};
use domain::dnssec::sign::records::{DefaultSorter, RecordsIter, Rrset};
use domain::dnssec::sign::signatures::rrsigs::{
    GenerateRrsigConfig, sign_rrset, sign_sorted_zone_records,
};
use domain::new::base::{RType, Serial};
use domain::new::rdata::RecordData;
use domain::rdata::dnssec::{RtypeBitmap, Timestamp};
use domain::rdata::nsec3::OwnerHash;
use domain::rdata::{Dnskey, Nsec, Nsec3, Nsec3param, Soa, ZoneRecordData, Zonemd};
use domain::utils::base32;
use domain::zonefile::inplace::{Entry, Zonefile};
use domain::zonetree::{StoredName, StoredRecord};
use domain_kmip::KeyUrl;
use domain_kmip::dep::kmip::client::pool::{ConnectionManager, KmipConnError, SyncConnPool};
use domain_kmip::{self, ClientCertificate, ConnectionSettings};
use jiff::tz::TimeZone;
use jiff::{Timestamp as JiffTimestamp, Zoned};
use octseq::OctetsFrom;
use rayon::iter::{
    IntoParallelIterator, IntoParallelRefIterator, ParallelExtend, ParallelIterator,
};
use rayon::slice::ParallelSliceMut;
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::Instant;
use tracing::{Level, debug, error, info, trace, warn};
use url::Url;

use crate::api::{
    SigningFinishedReport, SigningInProgressReport, SigningQueueReport, SigningReport,
    SigningRequestedReport, SigningStageReport,
};
use crate::center::Center;
use crate::manager::{Terminated, record_zone_event};
use crate::policy::{PolicyVersion, SignerDenialPolicy, SignerSerialPolicy};
use crate::signer::{ResigningTrigger, SigningTrigger};
use crate::units::http_server::KmipServerState;
use crate::units::key_manager::{
    KmipClientCredentialsFile, KmipServerCredentialsFileMode, mk_dnst_keyset_state_file_path,
};
use crate::util::{
    AbortOnDrop, serialize_duration_as_secs, serialize_instant_as_duration_secs,
    serialize_opt_duration_as_secs,
};
use crate::zone::{HistoricalEvent, HistoricalEventType, Zone, ZoneHandle};

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
    // TODO: Discuss whether this semaphore is necessary.
    max_concurrent_operations: usize,
    concurrent_operation_permits: Arc<Semaphore>,
    signer_status: ZoneSignerStatus,
    kmip_servers: Arc<Mutex<HashMap<String, SyncConnPool>>>,

    /// A live view of the next scheduled global resigning time.
    next_resign_time_tx: watch::Sender<Option<tokio::time::Instant>>,
    next_resign_time_rx: watch::Receiver<Option<tokio::time::Instant>>,
}

impl ZoneSigner {
    #[expect(clippy::new_without_default)]
    pub fn new() -> Self {
        let max_concurrent_operations = 1;
        let (next_resign_time_tx, next_resign_time_rx) = watch::channel(None);

        Self {
            max_concurrent_operations,
            concurrent_operation_permits: Arc::new(Semaphore::new(max_concurrent_operations)),
            signer_status: ZoneSignerStatus::new(),
            kmip_servers: Default::default(),
            next_resign_time_tx,
            next_resign_time_rx,
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

    fn mk_signing_report(
        &self,
        status: Arc<RwLock<SigningStatusPerZone>>,
    ) -> Option<SigningReport> {
        let status = status.read().unwrap();
        let now = Instant::now();
        let now_t = SystemTime::now();
        let stage_report = match status.status {
            ZoneSigningStatus::Requested(s) => {
                Some(SigningStageReport::Requested(SigningRequestedReport {
                    requested_at: now_t.checked_sub(now.duration_since(s.requested_at))?,
                }))
            }
            ZoneSigningStatus::InProgress(s) => {
                Some(SigningStageReport::InProgress(SigningInProgressReport {
                    requested_at: now_t.checked_sub(now.duration_since(s.requested_at))?,
                    zone_serial: domain::base::Serial(s.zone_serial.into()),
                    started_at: now_t.checked_sub(now.duration_since(s.started_at))?,
                    unsigned_rr_count: s.unsigned_rr_count,
                    walk_time: s.walk_time,
                    sort_time: s.sort_time,
                    denial_rr_count: s.denial_rr_count,
                    denial_time: s.denial_time,
                    rrsig_count: s.rrsig_count,
                    rrsig_reused_count: s.rrsig_reused_count,
                    rrsig_time: s.rrsig_time,
                    total_time: s.total_time,
                    threads_used: s.threads_used,
                }))
            }
            ZoneSigningStatus::Finished(s) => {
                Some(SigningStageReport::Finished(SigningFinishedReport {
                    requested_at: now_t.checked_sub(now.duration_since(s.requested_at))?,
                    zone_serial: domain::base::Serial(s.zone_serial.into()),
                    started_at: now_t.checked_sub(now.duration_since(s.started_at))?,
                    unsigned_rr_count: s.unsigned_rr_count,
                    walk_time: s.walk_time,
                    sort_time: s.sort_time,
                    denial_rr_count: s.denial_rr_count,
                    denial_time: s.denial_time,
                    rrsig_count: s.rrsig_count,
                    rrsig_reused_count: s.rrsig_reused_count,
                    rrsig_time: s.rrsig_time,
                    total_time: s.total_time,
                    threads_used: s.threads_used,
                    finished_at: now_t.checked_sub(now.duration_since(s.finished_at))?,
                    succeeded: s.succeeded,
                }))
            }
            ZoneSigningStatus::Aborted => None,
        };

        stage_report.map(|stage_report| SigningReport {
            current_action: status.current_action.clone(),
            stage_report,
        })
    }

    pub fn on_signing_report(&self, zone: &Arc<Zone>) -> Option<SigningReport> {
        self.signer_status
            .get(zone)
            .and_then(|status| self.mk_signing_report(status))
    }

    pub fn on_queue_report(&self, _center: &Arc<Center>) -> Vec<SigningQueueReport> {
        let mut report = vec![];
        let zone_signer_status = &self.signer_status;
        let q = zone_signer_status.zones_being_signed.read().unwrap();
        for q_item in q.iter().rev() {
            if let Some(stage_report) = self.mk_signing_report(q_item.clone()) {
                report.push(SigningQueueReport {
                    zone_name: q_item.read().unwrap().zone.name.clone(),
                    signing_report: stage_report,
                });
            }
        }
        report
    }

    pub fn on_publish_signed_zone(&self, center: &Arc<Center>) {
        trace!("[ZS]: a zone is published, recompute next time to re-sign");
        let _ = self.next_resign_time_tx.send(self.next_resign_time(center));
    }

    /// Enqueue a zone for signing, waiting until it can begin.
    pub async fn wait_to_sign(
        &self,
        zone: &Arc<Zone>,
    ) -> (Arc<RwLock<SigningStatusPerZone>>, [OwnedSemaphorePermit; 3]) {
        let zone_name = &zone.name;
        info!("[ZS]: Waiting to enqueue signing operation for zone '{zone_name}'.");

        self.signer_status.dump_queue();

        let (q_size, q_permit, zone_permit, status) = {
            let signer_status = &self.signer_status;
            // TODO: Propagate the error properly.
            signer_status
                .enqueue(zone)
                .await
                .unwrap_or_else(|err| panic!("{err}"))
        };

        let num_ops_in_progress =
            self.max_concurrent_operations - self.concurrent_operation_permits.available_permits();
        info!(
            "[ZS]: Waiting to start signing operation for zone '{zone_name}': {num_ops_in_progress} signing operations are in progress and {} operations are queued ahead of us.",
            q_size - 1
        );

        let permit = self
            .concurrent_operation_permits
            .clone()
            .acquire_owned()
            .await
            .unwrap();

        // TODO: Why do we need three different permits?
        (status, [q_permit, zone_permit, permit])
    }

    pub fn sign_zone(
        &self,
        center: &Arc<Center>,
        zone: &Arc<Zone>,
        builder: &mut SignedZoneBuilder,
        trigger: SigningTrigger,
        status: Arc<RwLock<SigningStatusPerZone>>,
    ) -> Result<(), SignerError> {
        let zone_name = &zone.name;

        if let Some(patcher) = builder.patch() {
            return self.sign_incrementally(patcher, zone, center, status);
        }

        info!("[ZS]: Starting signing operation for zone '{zone_name}'");
        let start = Instant::now();

        let (last_signed_serial, policy) = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone_state = zone.state.lock().unwrap();

            let last_signed_serial = zone_state
                .find_last_event(HistoricalEventType::SigningSucceeded, None)
                .and_then(|item| item.serial)
                .map(|serial| Serial::from(serial.0));
            (last_signed_serial, zone_state.policy.clone().unwrap())
        };

        let kmip_server_state_dir = &center.config.kmip_server_state_dir;
        let kmip_credentials_store_path = &center.config.kmip_credentials_store_path;

        //
        // Lookup the zone to sign.
        //
        let mut writer = builder.replace().unwrap();
        let mut new_records = Vec::new();
        let loaded = writer
            .next_loaded()
            .or(writer.curr_loaded())
            .expect("a non-empty loaded instance must exist");
        let loaded_serial = loaded.soa().rdata.serial;

        let serial = match policy.signer.serial_policy {
            SignerSerialPolicy::Keep => {
                if let Some(previous_serial) = last_signed_serial
                    && loaded_serial <= previous_serial
                {
                    // TODO Ignore this error until we can figure out how to
                    // return a soft error. Waits for new pipeline to
                    // land.
                    // return Err(SignerError::KeepSerialPolicyViolated);
                }

                loaded_serial
            }
            SignerSerialPolicy::Counter => {
                // Select the maximum of 'last_signed_serial + 1' and
                // 'loaded_serial'.
                //
                // TODO: This is a partial workaround to help users starting
                // out with counter mode. For ongoing discussion, see
                // <https://github.com/NLnetLabs/cascade/issues/495>.
                let mut serial = loaded_serial;
                if let Some(previous_serial) = last_signed_serial
                    && serial <= previous_serial
                {
                    serial = previous_serial.inc(1);
                }
                serial
            }
            SignerSerialPolicy::UnixTime => {
                let mut serial = Serial::unix_time();
                if let Some(previous_serial) = last_signed_serial
                    && serial <= previous_serial
                {
                    serial = previous_serial.inc(1);
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

                if let Some(previous_serial) = last_signed_serial
                    && serial <= previous_serial
                {
                    serial = previous_serial.inc(1);
                }

                serial
            }
        };
        let new_soa = {
            let mut soa = loaded.soa().clone();
            soa.rdata.serial = serial;
            soa
        };

        info!(
            "[ZS]: Serials for zone '{zone_name}': last signed={last_signed_serial:?}, current={loaded_serial}, serial policy={}, new={serial}",
            policy.signer.serial_policy
        );

        //
        // Record the start of signing for this zone.
        //
        {
            status
                .write()
                .unwrap()
                .status
                .start(loaded_serial)
                .map_err(|_| SignerError::InternalError("Invalid status".to_string()))?;
        }

        //
        // Create a signing configuration.
        //
        let signing_config = self.signing_config(&policy)?;
        let rrsig_cfg =
            GenerateRrsigConfig::new(signing_config.inception, signing_config.expiration);

        //
        // Convert zone records into a form we can sign.
        //
        status.write().unwrap().current_action = "Collecting records to sign".to_string();
        debug!("[ZS]: Collecting records to sign for zone '{zone_name}'.");
        let walk_start = Instant::now();
        // TODO: Filter out DNSSEC records from the loaded instance.
        let mut records = loaded
            .unsigned_records()
            .into_iter()
            .map(OldRecord::from)
            .collect::<Vec<_>>();
        records.push(new_soa.clone().into());
        let walk_time = walk_start.elapsed();
        let unsigned_rr_count = records.len();

        {
            let mut v = status.write().unwrap();
            let v2 = &mut v.status;
            if let ZoneSigningStatus::InProgress(s) = v2 {
                s.unsigned_rr_count = Some(unsigned_rr_count);
                s.walk_time = Some(walk_time);
            }
        }

        debug!("Reading dnst keyset DNSKEY RRs and RRSIG RRs");
        status.write().unwrap().current_action =
            "Fetching apex RRs from the key manager".to_string();
        // Read the DNSKEY RRs and DNSKEY RRSIG RR from the keyset state.
        let state_path = mk_dnst_keyset_state_file_path(&center.config.keys_dir, &zone.name);
        let state = std::fs::read_to_string(&state_path)
            .map_err(|_| SignerError::CannotReadStateFile(state_path.into_string()))?;
        let state: KeySetState = serde_json::from_str(&state).unwrap();
        for dnskey_rr in state.dnskey_rrset {
            let mut zonefile = Zonefile::new();
            zonefile.extend_from_slice(dnskey_rr.as_bytes());
            zonefile.extend_from_slice(b"\n");
            if let Ok(Some(Entry::Record(rec))) = zonefile.next_entry() {
                let record: OldRecord = rec.flatten_into();
                new_records.push(record.clone().into());
                records.push(record);
            }
        }

        debug!("Loading dnst keyset signing keys");
        status.write().unwrap().current_action = "Loading signing keys".to_string();
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

                        let private_key = ZoneSigner::load_private_key(Path::new(priv_key_path))
                            .map_err(|_| {
                                SignerError::CannotReadPrivateKeyFile(priv_key_path.to_string())
                            })?;

                        let pub_key_path = pub_url.path();
                        debug!("Attempting to load public key '{pub_key_path}'.");

                        let public_key = ZoneSigner::load_public_key(Path::new(pub_key_path))
                            .map_err(|_| {
                                SignerError::CannotReadPublicKeyFile(pub_key_path.to_string())
                            })?;

                        let key_pair = domain::crypto::sign::KeyPair::from_bytes(
                            &private_key,
                            public_key.data(),
                        )
                        .map_err(|err| SignerError::InvalidKeyPairComponents(err.to_string()))?;
                        let signing_key = SigningKey::new(
                            zone_name.clone(),
                            public_key.data().flags(),
                            KeyPair::Domain(key_pair),
                        );

                        signing_keys.push(signing_key);
                    }

                    ("kmip", "kmip") => {
                        let priv_key_url =
                            KeyUrl::try_from(priv_url).map_err(SignerError::InvalidPublicKeyUrl)?;
                        let pub_key_url =
                            KeyUrl::try_from(pub_url).map_err(SignerError::InvalidPrivateKeyUrl)?;

                        // TODO: Replace the connection pool if the persisted KMIP server settings
                        // were updated more recently than the pool was created.

                        let mut kmip_servers = self.kmip_servers.lock().unwrap();
                        let kmip_conn_pool = match kmip_servers
                            .entry(priv_key_url.server_id().to_string())
                        {
                            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                            std::collections::hash_map::Entry::Vacant(e) => {
                                // Try and load the KMIP server settings.
                                let p = kmip_server_state_dir.join(priv_key_url.server_id());
                                info!("Reading KMIP server state from '{p}'");
                                let f = std::fs::File::open(p).unwrap();
                                let kmip_server: KmipServerState =
                                    serde_json::from_reader(f).unwrap();
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
                                        KmipServerCredentialsFileMode::ReadOnly,
                                    )
                                    .unwrap();

                                    let creds = creds_file.get(&server_id).ok_or(
                                        SignerError::KmipServerCredentialsNeeded(server_id.clone()),
                                    )?;

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
                                    ca_cert: None,     // TODO
                                    connect_timeout: Some(connect_timeout),
                                    read_timeout: Some(read_timeout),
                                    write_timeout: Some(write_timeout),
                                    max_response_bytes: Some(max_response_bytes),
                                };

                                let cloned_status = status.clone();
                                let cloned_server_id = server_id.clone();
                                tokio::task::spawn(async move {
                                    cloned_status.write().unwrap().current_action =
                                        format!("Connecting to KMIP server '{cloned_server_id}");
                                });
                                let pool = ConnectionManager::create_connection_pool(
                                    server_id.clone(),
                                    Arc::new(conn_settings.clone()),
                                    10,
                                    Some(Duration::from_secs(60)),
                                    Some(Duration::from_secs(60)),
                                )
                                .map_err(|err| {
                                    SignerError::CannotCreateKmipConnectionPool(server_id, err)
                                })?;

                                e.insert(pool)
                            }
                        };

                        let _flags = priv_key_url.flags();

                        let cloned_status = status.clone();
                        let cloned_server_id = priv_key_url.server_id().to_string();
                        tokio::task::spawn(async move {
                            cloned_status.write().unwrap().current_action =
                                format!("Fetching keys from KMIP server '{cloned_server_id}'");
                        });

                        let key_pair = KeyPair::Kmip(
                            domain_kmip::sign::KeyPair::from_urls(
                                priv_key_url,
                                pub_key_url,
                                kmip_conn_pool.clone(),
                            )
                            .map_err(|err| {
                                SignerError::InvalidKeyPairComponents(err.to_string())
                            })?,
                        );

                        let signing_key =
                            SigningKey::new(zone_name.clone(), key_pair.dnskey().flags(), key_pair);

                        signing_keys.push(signing_key);
                    }

                    (other1, other2) => {
                        return Err(SignerError::InvalidKeyPairComponents(format!(
                            "Using different key URI schemes ({other1} vs {other2}) for a public/private key pair is not supported."
                        )));
                    }
                }

                debug!("Loaded key pair for zone {zone_name} from key pair");
            }
        }

        debug!("{} signing keys loaded", signing_keys.len());

        // TODO: If signing is disabled for a zone should we then allow the
        // unsigned zone to propagate through the pipeline?
        if signing_keys.is_empty() {
            warn!("No signing keys found for zone {zone_name}, aborting");
            return Err(SignerError::SigningError(
                "No signing keys found".to_string(),
            ));
        }

        //
        // Sort them into DNSSEC order ready for NSEC(3) generation.
        //
        debug!("[ZS]: Sorting collected records for zone '{zone_name}'.");
        status.write().unwrap().current_action = "Sorting records".to_string();
        let sort_start = Instant::now();
        // Note: This may briefly use lots of CPU and many CPU cores.
        records.par_sort_by(CanonicalOrd::canonical_cmp);
        let sort_time = sort_start.elapsed();
        let unsigned_rr_count = records.len();

        {
            let mut v = status.write().unwrap();
            let v2 = &mut v.status;
            if let ZoneSigningStatus::InProgress(s) = v2 {
                s.sort_time = Some(sort_time);
            }
        }

        //
        // Generate NSEC(3) RRs.
        //
        debug!("[ZS]: Generating denial records for zone '{zone_name}'.");
        status.write().unwrap().current_action = "Generating denial records".to_string();
        let denial_start = Instant::now();
        match &signing_config.denial {
            DenialConfig::AlreadyPresent => {}

            DenialConfig::Nsec(cfg) => {
                let nsecs = generate_nsecs(&zone.name, RecordsIter::new_from_owned(&records), cfg)
                    .map_err(|err: SigningError| {
                        SignerError::SigningError(format!("Failed to generate denial RRs: {err}"))
                    })?;

                new_records.par_extend(
                    nsecs
                        .par_iter()
                        .map(|r| OldRecord::from_record(r.clone()).into()),
                );
                records.par_extend(nsecs.into_par_iter().map(Record::from_record));
            }

            DenialConfig::Nsec3(cfg) => {
                // RFC 5155 7.1 step 5: "Sort the set of NSEC3 RRs into hash
                // order." We store the NSEC3s as we create them and sort them
                // afterwards.
                let Nsec3Records { nsec3s, nsec3param } =
                    generate_nsec3s(&zone.name, RecordsIter::new_from_owned(&records), cfg)
                        .map_err(|err: SigningError| {
                            SignerError::SigningError(format!(
                                "Failed to generate denial RRs: {err}"
                            ))
                        })?;

                // Add the generated NSEC3 records.
                new_records.par_extend(
                    nsec3s
                        .par_iter()
                        .map(|r| OldRecord::from_record(r.clone()).into()),
                );
                new_records.push(OldRecord::from_record(nsec3param.clone()).into());
                records.par_extend(nsec3s.into_par_iter().map(Record::from_record));
                records.push(Record::from_record(nsec3param));
            }
        }
        // Use a stable sort; the stable sort algorithm detects runs of sorted
        // elements ('records' contains two concatenated pre-sorted runs) and
        // can efficiently sort around them.
        records.par_sort();
        let unsigned_records = records;
        let denial_time = denial_start.elapsed();
        let denial_rr_count = unsigned_records.len() - unsigned_rr_count;

        {
            let mut v = status.write().unwrap();
            let v2 = &mut v.status;
            if let ZoneSigningStatus::InProgress(s) = v2 {
                s.denial_rr_count = Some(denial_rr_count);
                s.denial_time = Some(denial_time);
            }
        }

        //
        // Generate RRSIG RRs concurrently.
        //
        // Use N concurrent Rayon scoped threads to do blocking RRSIG
        // generation without interfering with Tokio task scheduling, and an
        // async task which receives generated RRSIGs via a Tokio
        // mpsc::channel and accumulates them into the signed zone.
        //
        debug!("[ZS]: Generating RRSIG records.");
        status.write().unwrap().current_action = "Generating signature records".to_string();

        // TODO: Configure Rayon's thread pool to set the number of threads. By
        // default, it relies on 'std::thread::available_parallelism()'.
        let parallelism = rayon::current_num_threads();

        {
            let mut v = status.write().unwrap();
            let v2 = &mut v.status;
            if let ZoneSigningStatus::InProgress(s) = v2 {
                s.threads_used = Some(parallelism);
            }
        }

        let generation_start = Instant::now();

        // Get the keys to sign with.  Domain's 'sign_sorted_zone_records()'
        // needs a slice of references, so we need to build that here.
        let keys = signing_keys.iter().collect::<Vec<_>>();

        // TODO: This generation code is incorrect; 'sign_sorted_zone_records'
        // looks for zone cuts, but zone cuts may need to be detected _across_
        // the segments we split the records into. Zone cut detection needs to
        // be re-implemented here with parallel execution in mind. This also
        // applies to NSEC(3) generation, but it is currently single-threaded.

        // Disable parallel signing for now. This may also split RRsets.
        let signatures = if false {
            // Split the records into segments.
            let segments = rayon::iter::split(0..unsigned_records.len(), |range| {
                // Always sign at least 1024 records at a time.
                if range.len() < 1024 {
                    return (range, None);
                }

                let midpoint = range.start + range.len() / 2;
                let left = range.start..midpoint;
                let right = midpoint..range.end;
                (left, Some(right))
            });

            // Generate signatures from each segment.
            let signatures = segments.map(|range| {
                sign_sorted_zone_records(
                    &zone.name,
                    RecordsIter::new_from_owned(&unsigned_records[range]),
                    &keys,
                    &rrsig_cfg,
                )
            });

            // Convert the signatures into new-base types and collect them together.
            // If errors occur, one error is arbitrarily chosen and returned.
            signatures
                .try_fold(Vec::new, |mut a, b| {
                    a.extend(b?.into_iter().map(|r| OldRecord::from_record(r).into()));
                    Ok::<_, SigningError>(a)
                })
                .try_reduce(Vec::new, |mut a, mut b| {
                    a.append(&mut b);
                    Ok(a)
                })
                .map_err(|err| SignerError::SigningError(err.to_string()))?
        } else {
            let signatures = sign_sorted_zone_records(
                &zone.name,
                RecordsIter::new_from_owned(&unsigned_records),
                &keys,
                &rrsig_cfg,
            )
            .map_err(|err| SignerError::SigningError(err.to_string()))?;
            let signatures: Vec<RegularRecord> = signatures
                .into_iter()
                .map(|s| {
                    let r = Record::new(
                        s.owner().clone(),
                        s.class(),
                        s.ttl(),
                        ZoneRecordData::Rrsig(s.data().clone()),
                    );
                    r.into()
                })
                .collect();
            signatures
        };

        let total_signatures = signatures.len();

        new_records.extend(signatures);
        new_records.par_sort();
        writer.set_records(new_records).unwrap();

        let generation_time = generation_start.elapsed();

        let generation_rate = total_signatures as f64 / generation_time.as_secs_f64().min(0.001);

        writer.set_soa(new_soa.clone()).unwrap();
        writer.apply().unwrap();

        debug!("SIGNER: Determining min expiration time");
        let reader = builder.next_signed().unwrap();
        let min_expiration = Arc::new(MinTimestamp::new());
        let saved_min_expiration = min_expiration.clone();
        for record in reader.generated_records() {
            let RecordData::RRSig(sig) = record.rdata.get() else {
                continue;
            };

            // Ignore RRSIG records for DNSKEY, CDS, and CDNSKEY records; these
            // are generated by the key manager, using KSKs.
            if sig.rtype == RType::DNSKEY
                || sig.rtype == RType::from(59)
                || sig.rtype == RType::from(60)
            {
                continue;
            }

            min_expiration.add(u32::from(sig.expiration).into());
        }

        // Save the minimum of the expiration times.
        {
            // Use a block to make sure that the mutex is clearly dropped.
            let mut zone_state = zone.state.lock().unwrap();

            // Save as next_min_expiration. After the signed zone is approved
            // this value should be move to min_expiration.
            zone_state.next_min_expiration = saved_min_expiration.get();
            debug!(
                "SIGNER: Determined min expiration time: {:?}",
                zone_state.next_min_expiration
            );

            zone.mark_dirty(&mut zone_state, center);
        }

        let total_time = start.elapsed();

        {
            let mut v = status.write().unwrap();
            let v2 = &mut v.status;
            if let ZoneSigningStatus::InProgress(s) = v2 {
                s.rrsig_count = Some(total_signatures);
                s.rrsig_reused_count = Some(0); // Not implemented yet
                s.rrsig_time = Some(generation_time);
                s.total_time = Some(total_time);
            }
            v.status.finish(true);
        }

        // Log signing statistics.
        info!(
            "Signing statistics for {zone_name} serial: {serial}:\n\
            Collected {unsigned_rr_count} records in {:.1}s, sorted in {:.1}s\n\
            Generated {denial_rr_count} NSEC(3) records in {:.1}s\n\
            Generated {total_signatures} signatures in {:.1}s ({generation_rate:.0}sig/s)
            Took {:.1}s in total, using {parallelism} threads",
            walk_time.as_secs_f64(),
            sort_time.as_secs_f64(),
            denial_time.as_secs_f64(),
            generation_time.as_secs_f64(),
            total_time.as_secs_f64()
        );

        record_zone_event(
            center,
            zone,
            HistoricalEvent::SigningSucceeded {
                trigger: trigger.into(),
            },
            Some(domain::base::Serial(serial.into())),
        );

        Ok(())
    }

    fn sign_incrementally(
        &self,
        patch: SignedZonePatcher,
        zone: &Arc<Zone>,
        center: &Arc<Center>,
        status: Arc<RwLock<SigningStatusPerZone>>,
    ) -> Result<(), SignerError> {
        // Check what work needs to be done. If the keyset state
        // changed then check if the APEX records change or if a
        // CSK or ZSK roll require resigning the zone.
        // If enough time has passed since the last time
        // signatures have been updated, then update signatures
        // and during a key roll, sign with the new key(s).
        // Ignore signer configuration changes, they will get picked up when
        // signatures need to be updated.
        // Resign using the unsigned zonefile when load_unsigned is true.

        let load_unsigned = patch.next_loaded().is_some();

        let origin = &zone.name;
        let state_path = mk_dnst_keyset_state_file_path(&center.config.keys_dir, origin);
        let state = std::fs::read_to_string(&state_path)
            .map_err(|_| SignerError::CannotReadStateFile(state_path.into_string()))?;
        let keyset_state: KeySetState = serde_json::from_str(&state).unwrap();

        let policy = {
            let zone_state = zone.state.lock().unwrap();
            zone_state.policy.clone().unwrap()
        };

        let use_nsec3 = match &policy.signer.denial {
            SignerDenialPolicy::NSec => false,
            SignerDenialPolicy::NSec3 { .. } => true,
        };

        let mut ws = WorkSpace {
            keyset_state,
            use_nsec3,
            verbose: true,
            policy: policy.clone(),
            zone: zone.clone(),
            center: center.clone(),
            patch,
            zonemd: HashSet::new(),
            pass_through_mode: PassThroughMode::Off,
        };

        let apex_changed = ws.handle_keyset_changed();

        if !matches!(ws.pass_through_mode, PassThroughMode::Off) {
            ws.sign_pass_through()?;
            return Ok(());
        }

        let mut refresh_signatures = false;
        let now = faketime_or_now();
        let curr_last_signature_refresh = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone_state = ws.zone.state.lock().unwrap();

            zone_state.last_signature_refresh.clone()
        };

        if now
            > curr_last_signature_refresh.clone()
                + Duration::from_secs(ws.policy.signer.signature_refresh_interval.into())
        {
            if ws.verbose {
                println!(
                    "refresh signatures: {now} > {curr_last_signature_refresh} + {:?}",
                    ws.policy.signer.signature_refresh_interval
                );
            }
            refresh_signatures = true;
        }

        if !load_unsigned && !apex_changed && !refresh_signatures {
            // Nothing to do.
            return Ok(());
        }

        let mut iss = IncrementalSigningState::new(
            origin.clone(),
            &policy,
            self,
            center,
            &ws.keyset_state,
            status,
        )?;

        let start = Instant::now();
        iss.load_signed_zone(&ws.patch.curr()).unwrap();
        if ws.verbose {
            println!("loading signed zone took {:?}", start.elapsed());
        }

        ws.handle_nsec_nsec3(&mut iss)?;

        if load_unsigned {
            let start = Instant::now();
            iss.load_unsigned_zone(&ws.patch.next_loaded().unwrap())
                .unwrap();
            if ws.verbose {
                println!("loading new unsigned zone took {:?}", start.elapsed());
            }
        } else {
            // Re-use the signed data.
            iss.load_signed_only();
        }

        let start = Instant::now();
        ws.load_apex_records(&mut iss)?;

        iss.initial_diffs()?;

        match policy.signer.denial {
            SignerDenialPolicy::NSec3 { .. } => iss.incremental_nsec3()?,
            SignerDenialPolicy::NSec => iss.incremental_nsec()?,
        }

        ws.new_nsec_nsec3_sigs(&mut iss)?;

        if !ws.zonemd.is_empty() {
            let start = Instant::now();
            ws.add_zonemd(&mut iss)?;
            if ws.verbose {
                println!("ZONEMD took {:?}", start.elapsed());
            }
        }

        if refresh_signatures {
            ws.refresh_some_signatures(&mut iss)?;

            let curr_key_roll = {
                // Use a block to make sure that the mutex is clearly dropped.
                let zone_state = ws.zone.state.lock().unwrap();

                zone_state.key_roll.clone()
            };

            if curr_key_roll.is_some() {
                ws.key_roll_signatures(&mut iss)?;
            }
        }
        if ws.verbose {
            println!("incremental signing took {:?}", start.elapsed());
        }

        ws.incremental_generate_diffs(&iss)?;

        ws.patch.apply().unwrap();
        Ok(())
    }

    fn signing_config(
        &self,
        policy: &PolicyVersion,
    ) -> Result<SigningConfig<Bytes, MultiThreadedSorter>, SignerError> {
        let denial = match &policy.signer.denial {
            SignerDenialPolicy::NSec => DenialConfig::Nsec(Default::default()),
            SignerDenialPolicy::NSec3 { opt_out } => {
                let first = parse_nsec3_config(*opt_out);
                DenialConfig::Nsec3(first)
            }
        };

        let now = match var("CASCADE_FAKETIME") {
            Ok(val) => val
                .parse::<u32>()
                .map_err(|e| SignerError::InternalError(format!("cannot parse {e} as u32")))?,
            Err(VarError::NotPresent) => Timestamp::now().into_int(),
            Err(e) => return Err(SignerError::InternalError(e.to_string())),
        };
        let inception = now.wrapping_sub(policy.signer.sig_inception_offset);
        let expiration = now.wrapping_add(policy.signer.sig_validity_time);
        Ok(SigningConfig::new(
            denial,
            inception.into(),
            expiration.into(),
        ))
    }

    fn next_resign_time(&self, center: &Arc<Center>) -> Option<Instant> {
        let mut min_time = None;
        let now = SystemTime::now();

        #[allow(clippy::mutable_key_type)]
        let zones = {
            let state = center.state.lock().unwrap();
            state.zones.clone()
        };

        // This the old expiration time based on the signature that
        // expires first. It should be removed.
        for zone in &zones {
            let zone = &zone.0;
            let zone_name = &zone.name;

            let min_expiration = {
                // Use a block to make sure that the mutex is clearly dropped.
                let zone_state = zone.state.lock().unwrap();
                zone_state.min_expiration
            };

            let Some(min_expiration) = min_expiration else {
                trace!("[ZS] resign: no min-expiration for zone {zone_name}");
                continue;
            };

            // Start a new block to make sure the mutex is released.
            {
                let mut resign_busy = center.resign_busy.lock().expect("should not fail");
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
                let zone_state = zone.state.lock().unwrap();
                // TODO: what if there is no policy?
                zone_state.policy.as_ref().unwrap().signer.sig_remain_time
            };

            let exp_time = min_expiration.to_system_time(now);
            let exp_time = exp_time - Duration::from_secs(remain_time as u64);

            min_time = if let Some(time) = min_time {
                Some(min(time, exp_time))
            } else {
                Some(exp_time)
            };
        }

        // Compute when to incrementally sign a zone again to refresh
        // signatures.
        for zone in zones {
            let zone = &zone.0;
            let zone_name = &zone.name;

            let last_signature_refresh = {
                // Use a block to make sure that the mutex is clearly dropped.
                let zone_state = zone.state.lock().unwrap();
                zone_state.last_signature_refresh.clone()
            };

            // Ensure that the Mutexes are locked only in this block;
            let signature_refresh_interval = {
                let zone_state = zone.state.lock().unwrap();
                // TODO: what if there is no policy?
                zone_state
                    .policy
                    .as_ref()
                    .unwrap()
                    .signer
                    .signature_refresh_interval
            };

            println!(
                "Got last_signature_refresh {last_signature_refresh:?} and signature_refresh_interval {signature_refresh_interval} for zone {zone_name}"
            );

            let curr_refresh_time = last_signature_refresh.clone()
                + Duration::from_secs(signature_refresh_interval as u64);

            // Start a new block to make sure the mutex is released.
            {
                let mut resign_busy2 = center.resign_busy2.lock().expect("should not fail");
                let opt_refresh_time = resign_busy2.get(zone_name);
                if let Some(saved_refresh_time) = opt_refresh_time {
                    if *saved_refresh_time == curr_refresh_time {
                        // This zone is busy.
                        trace!("[ZS]: resign: zone {zone_name} is busy");
                        continue;
                    }

                    // Zone has been resigned. Remove this entry.
                    resign_busy2.remove(zone_name);
                }
            }

            let refresh_time = UNIX_EPOCH + Duration::from(curr_refresh_time);

            println!("min_time {min_time:?} and refresh_time {refresh_time:?}");
            min_time = if let Some(time) = min_time {
                Some(min(time, refresh_time))
            } else {
                Some(refresh_time)
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

    fn resign_zones(&self, center: &Arc<Center>) {
        let now = SystemTime::now();

        #[allow(clippy::mutable_key_type)]
        let zones = {
            let state = center.state.lock().unwrap();
            state.zones.clone()
        };

        // Note: should be removed.
        for zone in &zones {
            let zone = &zone.0;
            let zone_name = &zone.name;

            let min_expiration = {
                // Use a block to make sure that the mutex is clearly dropped.
                let zone_state = zone.state.lock().unwrap();
                zone_state.min_expiration
            };

            let Some(min_expiration) = min_expiration else {
                continue;
            };

            // Start a new block to make sure the mutex is released.
            {
                let resign_busy = center.resign_busy.lock().expect("should not fail");
                let opt_expiration = resign_busy.get(zone_name);
                if let Some(expiration) = opt_expiration
                    && *expiration == min_expiration
                {
                    // This zone is busy.
                    continue;
                }
            }

            // Ensure that the Mutexes are locked only in this block;
            let remain_time = {
                let zone_state = zone.state.lock().unwrap();
                // What if there is no policy?
                zone_state.policy.as_ref().unwrap().signer.sig_remain_time
            };

            let exp_time = min_expiration.to_system_time(now);
            let exp_time = exp_time - Duration::from_secs(remain_time as u64);

            if exp_time < now {
                trace!("[ZS]: re-signing: request signing of zone {zone_name}");

                // Start a new block to make sure the mutex is released.
                {
                    let mut resign_busy = center.resign_busy.lock().expect("should not fail");
                    resign_busy.insert(zone_name.clone(), min_expiration);
                }
                let mut state = zone.state.lock().unwrap();
                ZoneHandle {
                    zone,
                    state: &mut state,
                    center,
                }
                .signer()
                .enqueue_resign(ResigningTrigger::SIGS_NEED_REFRESH);
            }
        }
        for zone in zones {
            let zone = &zone.0;
            let zone_name = &zone.name;

            let last_signature_refresh = {
                // Use a block to make sure that the mutex is clearly dropped.
                let zone_state = zone.state.lock().unwrap();
                zone_state.last_signature_refresh.clone()
            };

            // Ensure that the Mutexes are locked only in this block;
            let signature_refresh_interval = {
                let zone_state = zone.state.lock().unwrap();
                // What if there is no policy?
                zone_state
                    .policy
                    .as_ref()
                    .unwrap()
                    .signer
                    .signature_refresh_interval
            };

            let curr_refresh_time = last_signature_refresh.clone()
                + Duration::from_secs(signature_refresh_interval as u64);

            // Start a new block to make sure the mutex is released.
            {
                let resign_busy2 = center.resign_busy2.lock().expect("should not fail");
                let opt_refresh_time = resign_busy2.get(zone_name);
                if let Some(saved_refresh_time) = opt_refresh_time
                    && *saved_refresh_time == curr_refresh_time
                {
                    // This zone is busy.
                    continue;
                }
            }

            let refresh_time = UNIX_EPOCH + Duration::from(curr_refresh_time.clone());

            if refresh_time < now {
                trace!("[ZS]: re-signing: request signing of zone {zone_name}");

                // Start a new block to make sure the mutex is released.
                {
                    let mut resign_busy2 = center.resign_busy2.lock().expect("should not fail");
                    resign_busy2.insert(zone_name.clone(), curr_refresh_time);
                }
                let mut state = zone.state.lock().unwrap();
                ZoneHandle {
                    zone,
                    state: &mut state,
                    center,
                }
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
pub struct RequestedStatus {
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
pub struct InProgressStatus {
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    requested_at: tokio::time::Instant,
    zone_serial: domain::base::Serial,
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
    total_time: Option<Duration>,
    threads_used: Option<usize>,
}

impl InProgressStatus {
    fn new(requested_status: RequestedStatus, zone_serial: Serial) -> Self {
        Self {
            requested_at: requested_status.requested_at,
            zone_serial: domain::base::Serial(zone_serial.into()),
            started_at: Instant::now(),
            unsigned_rr_count: None,
            walk_time: None,
            sort_time: None,
            denial_rr_count: None,
            denial_time: None,
            rrsig_count: None,
            rrsig_reused_count: None,
            rrsig_time: None,
            total_time: None,
            threads_used: None,
        }
    }
}

#[derive(Copy, Clone, Serialize)]
pub struct FinishedStatus {
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    requested_at: tokio::time::Instant,
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    started_at: tokio::time::Instant,
    zone_serial: domain::base::Serial,
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
    total_time: Duration,
    threads_used: usize,
    #[serde(serialize_with = "serialize_instant_as_duration_secs")]
    finished_at: tokio::time::Instant,
    succeeded: bool,
}

impl FinishedStatus {
    fn new(in_progress_status: InProgressStatus, succeeded: bool) -> Self {
        Self {
            requested_at: in_progress_status.requested_at,
            zone_serial: in_progress_status.zone_serial,
            started_at: Instant::now(),
            unsigned_rr_count: in_progress_status.unsigned_rr_count.unwrap_or_default(),
            walk_time: in_progress_status.walk_time.unwrap_or_default(),
            sort_time: in_progress_status.sort_time.unwrap_or_default(),
            denial_rr_count: in_progress_status.denial_rr_count.unwrap_or_default(),
            denial_time: in_progress_status.denial_time.unwrap_or_default(),
            rrsig_count: in_progress_status.rrsig_count.unwrap_or_default(),
            rrsig_reused_count: in_progress_status.rrsig_reused_count.unwrap_or_default(),
            rrsig_time: in_progress_status.rrsig_time.unwrap_or_default(),
            total_time: in_progress_status.total_time.unwrap_or_default(),
            threads_used: in_progress_status.threads_used.unwrap_or_default(),
            finished_at: Instant::now(),
            succeeded,
        }
    }
}

#[derive(Copy, Clone, Serialize)]
pub enum ZoneSigningStatus {
    Requested(RequestedStatus),

    InProgress(InProgressStatus),

    Finished(FinishedStatus),

    Aborted,
}

impl ZoneSigningStatus {
    fn new() -> Self {
        Self::Requested(RequestedStatus::new())
    }

    fn start(&mut self, zone_serial: Serial) -> Result<(), ()> {
        match *self {
            ZoneSigningStatus::Requested(s) => {
                *self = Self::InProgress(InProgressStatus::new(s, zone_serial));
                Ok(())
            }
            ZoneSigningStatus::Aborted
            | ZoneSigningStatus::InProgress(_)
            | ZoneSigningStatus::Finished(_) => Err(()),
        }
    }

    pub fn finish(&mut self, succeeded: bool) {
        match *self {
            ZoneSigningStatus::Requested(_) => {
                *self = Self::Aborted;
            }
            ZoneSigningStatus::InProgress(status) => {
                *self = Self::Finished(FinishedStatus::new(status, succeeded))
            }
            ZoneSigningStatus::Finished(_) | ZoneSigningStatus::Aborted => { /* Nothing to do */ }
        }
    }
}

impl std::fmt::Display for ZoneSigningStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZoneSigningStatus::Requested(_) => f.write_str("Requested"),
            ZoneSigningStatus::InProgress(_) => f.write_str("InProgress"),
            ZoneSigningStatus::Finished(_) => f.write_str("Finished"),
            ZoneSigningStatus::Aborted => f.write_str("Aborted"),
        }
    }
}

//------------ ZoneSignerStatus ----------------------------------------------

const SIGNING_QUEUE_SIZE: usize = 100;

pub struct SigningStatusPerZone {
    pub zone: Arc<Zone>,
    pub current_action: String,
    pub status: ZoneSigningStatus,
}

struct ZoneSignerStatus {
    // Maps zone names to signing status, keeping records of previous signing.
    // Use VecDeque for its ability to act as a ring buffer: check size, if
    // at max desired capacity pop_front(), then in both cases push_back().
    //
    // TODO: Separate out signing request queuing from signing statistics
    // tracking.
    zones_being_signed: Arc<RwLock<VecDeque<Arc<RwLock<SigningStatusPerZone>>>>>,

    // Sign each zone only once at a time.
    zone_semaphores: Arc<RwLock<HashMap<StoredName, Arc<Semaphore>>>>,

    queue_semaphore: Arc<Semaphore>,
}

impl ZoneSignerStatus {
    pub fn new() -> Self {
        Self {
            zones_being_signed: Arc::new(std::sync::RwLock::new(VecDeque::with_capacity(
                SIGNING_QUEUE_SIZE,
            ))),
            zone_semaphores: Default::default(),
            queue_semaphore: Arc::new(Semaphore::new(SIGNING_QUEUE_SIZE)),
        }
    }

    pub fn get(&self, wanted_zone: &Arc<Zone>) -> Option<Arc<RwLock<SigningStatusPerZone>>> {
        self.dump_queue();

        let zones_being_signed = self.zones_being_signed.read().unwrap();
        for q_item in zones_being_signed.iter().rev() {
            let readable_q_item = q_item.read().unwrap();
            if Arc::ptr_eq(&readable_q_item.zone, wanted_zone)
                && !matches!(readable_q_item.status, ZoneSigningStatus::Aborted)
            {
                return Some(q_item.clone());
            }
        }
        None
    }

    fn dump_queue(&self) {
        if tracing::event_enabled!(Level::DEBUG) {
            let zones_being_signed = self.zones_being_signed.read().unwrap();
            for q_item in zones_being_signed.iter().rev() {
                let q_item = q_item.read().unwrap();
                match q_item.status {
                    ZoneSigningStatus::Requested(_) => {
                        debug!("[ZS]: Queue item: {} => requested", q_item.zone.name)
                    }
                    ZoneSigningStatus::InProgress(_) => {
                        debug!("[ZS]: Queue item: {} => in-progress", q_item.zone.name)
                    }
                    ZoneSigningStatus::Finished(_) => {
                        debug!("[ZS]: Queue item: {} => finished", q_item.zone.name)
                    }
                    ZoneSigningStatus::Aborted => {
                        debug!("[ZS]: Queue item: {} => aborted", q_item.zone.name)
                    }
                };
            }
        }
    }

    /// Enqueue a zone for signing.
    pub async fn enqueue(
        &self,
        zone: &Arc<Zone>,
    ) -> Result<
        (
            usize,
            OwnedSemaphorePermit,
            OwnedSemaphorePermit,
            Arc<RwLock<SigningStatusPerZone>>,
        ),
        SignerError,
    > {
        let zone_name = &zone.name;
        debug!("SIGNER[{zone_name}]: Adding to the queue");
        let status = Arc::new(RwLock::new(SigningStatusPerZone {
            zone: zone.clone(),
            current_action: "Waiting for any existing signing operation for this zone to finish"
                .to_string(),
            status: ZoneSigningStatus::new(),
        }));
        {
            let mut zones_being_signed = self.zones_being_signed.write().unwrap();
            zones_being_signed.push_back(status.clone());
        }

        let approx_q_size = SIGNING_QUEUE_SIZE - self.queue_semaphore.available_permits() + 1;
        debug!("SIGNER[{zone_name}]: Approx queue size = {approx_q_size}");

        debug!("SIGNER[{zone_name}]: Acquiring zone permit");
        let zone_semaphore = self
            .zone_semaphores
            .write()
            .unwrap()
            .entry(zone_name.clone())
            .or_insert(Arc::new(Semaphore::new(1)))
            .clone();
        let zone_permit = zone_semaphore.acquire_owned().await.map_err(|_| {
            SignerError::InternalError("Cannot acquire the zone semaphore".to_string())
        })?;
        debug!("SIGNER[{zone_name}]: Zone permit acquired");

        status.write().unwrap().current_action = "Waiting for a signing queue slot".to_string();

        debug!("SIGNER: Acquiring queue permit");
        let queue_permit = self
            .queue_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| SignerError::SignerNotReady)?;
        debug!("SIGNER[{zone_name}]: Queue permit acquired");

        // If we were able to acquire a permit that means that a signing operation completed
        // and so we are safe to remove one item from the ring buffer.
        let mut zones_being_signed = self.zones_being_signed.write().unwrap();
        if zones_being_signed.len() == zones_being_signed.capacity() {
            // Discard oldest.
            let signing_status = zones_being_signed.pop_front();
            if let Some(signing_status) = signing_status {
                // Old items in the queue should have reached a final state,
                // either finished or aborted. If not, something is wrong with
                // the queueing logic.
                if !matches!(
                    signing_status.read().unwrap().status,
                    ZoneSigningStatus::Finished(_) | ZoneSigningStatus::Aborted
                ) {
                    return Err(SignerError::InternalError(
                        "Signing queue not in the expected state".to_string(),
                    ));
                }
            }
        }

        status.write().unwrap().current_action = "Queued for signing".to_string();

        debug!("SIGNER[{zone_name}]: Enqueuing complete.");
        Ok((approx_q_size, queue_permit, zone_permit, status))
    }
}

//----------- KeyPair ----------------------------------------------------------

/// A cryptographic keypair for signing.
#[derive(Debug)]
enum KeyPair {
    /// A keypair provided by [`domain`].
    Domain(domain::crypto::sign::KeyPair),

    /// A KMIP keypair.
    Kmip(domain_kmip::sign::KeyPair),
}

impl SignRaw for KeyPair {
    fn algorithm(&self) -> SecurityAlgorithm {
        match self {
            KeyPair::Domain(k) => k.algorithm(),
            KeyPair::Kmip(k) => k.algorithm(),
        }
    }

    fn dnskey(&self) -> Dnskey<Vec<u8>> {
        match self {
            KeyPair::Domain(k) => k.dnskey(),
            KeyPair::Kmip(k) => k.dnskey(),
        }
    }

    fn sign_raw(
        &self,
        data: &[u8],
    ) -> Result<domain::crypto::sign::Signature, domain::crypto::sign::SignError> {
        match self {
            KeyPair::Domain(k) => k.sign_raw(data),
            KeyPair::Kmip(k) => k.sign_raw(data),
        }
    }
}

//------------ MultiThreadedSorter -------------------------------------------

/// A parallelized sort implementation for signing.
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

#[derive(Clone, Debug, Default, Deserialize, Serialize, clap::ValueEnum)]
enum PassThroughMode {
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

struct WorkSpace<'a> {
    keyset_state: KeySetState,
    use_nsec3: bool,
    verbose: bool,
    policy: Arc<PolicyVersion>,
    zone: Arc<Zone>,
    center: Arc<Center>,
    patch: SignedZonePatcher<'a>,

    // Extra fields that should go to policy.
    zonemd: HashSet<()>,
    pass_through_mode: PassThroughMode,
    // Extra fields that should go to state.
}

impl WorkSpace<'_> {
    fn refresh_some_signatures(
        &mut self,
        iss: &mut IncrementalSigningState,
    ) -> Result<(), SignerError> {
        let effective_lifetime = Duration::from_secs(
            (self.policy.signer.sig_validity_time - self.policy.signer.sig_remain_time) as u64,
        );
        let now = faketime_or_now();
        let now_system_time = UNIX_EPOCH + Duration::from(now.clone());
        let min_expire =
            now_system_time + Duration::from_secs(self.policy.signer.sig_remain_time as u64);

        let curr_last_signature_refresh = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone_state = self.zone.state.lock().unwrap();

            zone_state.last_signature_refresh.clone()
        };
        let mut since_last_time: Duration = if now >= curr_last_signature_refresh {
            <UnixTime as Into<Duration>>::into(now.clone())
                - <UnixTime as Into<Duration>>::into(curr_last_signature_refresh.clone())
        } else {
            // Use 60 seconds when times are weird. This should get things
            // back in sync.
            Duration::from_secs(60)
        };

        // Limit to effective_lifetime in case of weird values.
        if since_last_time > effective_lifetime {
            since_last_time = effective_lifetime;
        }

        let total_signatures = iss.rrsigs.len();

        let to_sign = since_last_time.as_secs_f64() * (total_signatures as f64)
            / effective_lifetime.as_secs_f64();
        let to_sign = to_sign.ceil() as usize;

        dbg!(to_sign);

        // Collect expiration times, owner names, and types to figure out what
        // to sign.
        let mut expire_sigs = vec![];
        for ((owner, rtype), r) in &iss.rrsigs {
            let min_expiration = r
                .iter()
                .map(|r| {
                    let ZoneRecordData::Rrsig(rrsig) = r.data() else {
                        panic!("Rrsig expected");
                    };
                    rrsig.expiration().to_system_time(now_system_time)
                })
                .min()
                .expect("minimum should exist");
            let v = (min_expiration, owner, rtype);
            expire_sigs.push(v);
        }

        expire_sigs.sort();

        let mut new_sigs = vec![];
        for (i, (expire, owner, rtype)) in expire_sigs.iter().enumerate() {
            if *expire > min_expire && i >= to_sign {
                break;
            }

            let key = ((*owner).clone(), **rtype);
            dbg!(&key);
            if **rtype == Rtype::NSEC {
                let record = iss.nsecs.get(&key.0).expect("NSEC record should exist");
                let records = [record.clone()];
                sign_records(
                    &iss.origin,
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else if **rtype == Rtype::NSEC3 {
                let record = iss.nsec3s.get(&key.0).expect("NSEC3 record should exist");
                let records = [record.clone()];
                sign_records(
                    &iss.origin,
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else {
                let records = if key.0 == iss.origin {
                    iss.new_apex.get(&key.1)
                } else {
                    iss.new_data.get(&key)
                }
                .expect("records should exist");
                sign_records(
                    &iss.origin,
                    records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            };
        }

        for (sigs, rtype) in new_sigs {
            let key = (sigs[0].owner().clone(), rtype);
            iss.rrsigs.insert(key, sigs);
        }

        if to_sign != 0 {
            // Only update last_signature_refresh when enough time has passed
            // that at least one record got signed.
            {
                // Use a block to make sure that the mutex is clearly dropped.
                let mut zone_state = self.zone.state.lock().unwrap();

                zone_state.last_signature_refresh = now;
                self.zone.mark_dirty(&mut zone_state, &self.center);
            }
        }
        Ok(())
    }

    fn key_roll_signatures(
        &mut self,
        iss: &mut IncrementalSigningState,
    ) -> Result<(), SignerError> {
        let key_roll_time = Duration::from_secs(self.policy.signer.key_roll_time as u64);

        let curr_key_roll = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone_state = self.zone.state.lock().unwrap();

            zone_state.key_roll.clone()
        };
        let key_roll_start = curr_key_roll.as_ref().expect("should be there");

        let now = faketime_or_now();

        let since_start: Duration = <UnixTime as Into<Duration>>::into(now.clone())
            - <UnixTime as Into<Duration>>::into(key_roll_start.clone());

        let curr_key_tags = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone_state = self.zone.state.lock().unwrap();

            zone_state.key_tags.clone()
        };

        if since_start > key_roll_time {
            // Full roll. Make sure all signatures are made using the new keys.
            // Clear key_roll when we are done.

            let mut new_sigs = vec![];
            for ((owner, rtype), r) in &iss.rrsigs {
                let key_tags: HashSet<u16> = r
                    .iter()
                    .map(|r| {
                        let ZoneRecordData::Rrsig(rrsig) = r.data() else {
                            panic!("Rrsig expected");
                        };
                        rrsig.key_tag()
                    })
                    .collect();
                if key_tags == curr_key_tags {
                    // Nothing to do.
                    continue;
                }

                let key = ((*owner).clone(), *rtype);
                if *rtype == Rtype::NSEC {
                    let record = iss.nsecs.get(&key.0).expect("NSEC record should exist");
                    let records = [record.clone()];
                    sign_records(
                        &iss.origin,
                        &records,
                        &iss.keys,
                        iss.inception,
                        iss.expiration,
                        &mut new_sigs,
                    )?;
                } else if *rtype == Rtype::NSEC3 {
                    let record = iss.nsec3s.get(&key.0).expect("NSEC3 record should exist");
                    let records = [record.clone()];
                    sign_records(
                        &iss.origin,
                        &records,
                        &iss.keys,
                        iss.inception,
                        iss.expiration,
                        &mut new_sigs,
                    )?;
                } else {
                    let records = iss.new_data.get(&key).expect("records should exist");
                    sign_records(
                        &iss.origin,
                        records,
                        &iss.keys,
                        iss.inception,
                        iss.expiration,
                        &mut new_sigs,
                    )?;
                };
            }

            for (sigs, rtype) in new_sigs {
                let key = (sigs[0].owner().clone(), rtype);
                iss.rrsigs.insert(key, sigs);
            }

            // Clear key_roll.
            {
                // Use a block to make sure that the mutex is clearly dropped.
                let mut zone_state = self.zone.state.lock().unwrap();

                zone_state.key_roll = None;
                self.zone.mark_dirty(&mut zone_state, &self.center);
            }
            return Ok(());
        }

        let total_signatures = iss.rrsigs.len();

        let to_sign =
            since_start.as_secs_f64() * (total_signatures as f64) / key_roll_time.as_secs_f64();
        let to_sign = to_sign.ceil() as usize;

        // owner names, types, and key tags to figure out what to sign.
        let mut sigs_key_tags = vec![];
        for ((owner, rtype), r) in &iss.rrsigs {
            let key_tags: Vec<u16> = r
                .iter()
                .map(|r| {
                    let ZoneRecordData::Rrsig(rrsig) = r.data() else {
                        panic!("Rrsig expected");
                    };
                    rrsig.key_tag()
                })
                .collect();
            let v = (owner, rtype, key_tags);
            sigs_key_tags.push(v);
        }

        sigs_key_tags.sort();

        let mut new_sigs = vec![];
        for (i, (owner, rtype, key_tags)) in sigs_key_tags.iter().enumerate() {
            if i >= to_sign {
                break;
            }

            if HashSet::<u16>::from_iter(key_tags.iter().copied()) == curr_key_tags {
                // Nothing to do.
                continue;
            }

            let key = ((*owner).clone(), **rtype);
            if **rtype == Rtype::NSEC {
                let record = iss.nsecs.get(&key.0).expect("NSEC record should exist");
                let records = [record.clone()];
                sign_records(
                    &iss.origin,
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else if **rtype == Rtype::NSEC3 {
                let record = iss.nsec3s.get(&key.0).expect("NSEC3 record should exist");
                let records = [record.clone()];
                sign_records(
                    &iss.origin,
                    &records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            } else {
                let records = if key.0 == iss.origin {
                    iss.new_apex.get(&key.1)
                } else {
                    iss.new_data.get(&key)
                }
                .expect("records should exist");
                sign_records(
                    &iss.origin,
                    records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            };
        }

        for (sigs, rtype) in new_sigs {
            let key = (sigs[0].owner().clone(), rtype);
            iss.rrsigs.insert(key, sigs);
        }
        Ok(())
    }

    fn handle_keyset_changed(&mut self) -> bool {
        let mut apex_changed = false;

        // Check the APEX RRtypes that need to be removed. We
        // should get that from keyset, but currently we don't.
        // Just have a fixed list.
        let apex_remove: HashSet<Rtype> = [Rtype::DNSKEY, Rtype::CDS, Rtype::CDNSKEY].into();

        let curr_apex_remove = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone_state = self.zone.state.lock().unwrap();

            zone_state.apex_remove.clone()
        };

        if apex_remove != curr_apex_remove {
            println!("APEX remove RRtypes changed: from {curr_apex_remove:?} to {apex_remove:?}",);

            // Save the new apex_remove set.
            {
                // Use a block to make sure that the mutex is clearly dropped.
                let mut zone_state = self.zone.state.lock().unwrap();

                zone_state.apex_remove = apex_remove;
                self.zone.mark_dirty(&mut zone_state, &self.center);
            }
            apex_changed = true;
        }

        // Check records that need to be added to the APEX.
        let mut apex_extra = vec![];
        apex_extra.extend_from_slice(&self.keyset_state.dnskey_rrset);
        apex_extra.extend_from_slice(&self.keyset_state.cds_rrset);
        apex_extra.sort();

        let curr_apex_extra = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone_state = self.zone.state.lock().unwrap();

            zone_state.apex_extra.clone()
        };

        if apex_extra != curr_apex_extra {
            println!("APEX extra changed: from {curr_apex_extra:?} to {apex_extra:?}",);

            // Save the new apex_extra list.
            {
                // Use a block to make sure that the mutex is clearly dropped.
                let mut zone_state = self.zone.state.lock().unwrap();

                zone_state.apex_extra = apex_extra;
                self.zone.mark_dirty(&mut zone_state, &self.center);
            }
            apex_changed = true;
        }

        // Check if a ZSK/CSK roll has started.
        let mut key_tags = HashSet::new();
        for v in self.keyset_state.keyset.keys().values() {
            let signer = match v.keytype() {
                KeyType::Ksk(_) => false,
                KeyType::Zsk(key_state) => key_state.signer(),
                KeyType::Csk(_, key_state) => key_state.signer(),
                KeyType::Include(_) => false,
            };

            if !signer {
                continue;
            }

            key_tags.insert(v.key_tag());
        }

        let curr_key_tags = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone_state = self.zone.state.lock().unwrap();

            zone_state.key_tags.clone()
        };

        if key_tags != curr_key_tags {
            println!("key tags changed: from {curr_key_tags:?} to {key_tags:?}",);

            // Save the new key tags set and key roll start time.
            {
                // Use a block to make sure that the mutex is clearly dropped.
                let mut zone_state = self.zone.state.lock().unwrap();

                zone_state.key_tags = key_tags;
                zone_state.key_roll = Some(faketime_or_now());
                self.zone.mark_dirty(&mut zone_state, &self.center);
            }
            apex_changed = true;
        }
        apex_changed
    }

    fn incremental_generate_diffs(
        &mut self,
        iss: &IncrementalSigningState,
    ) -> Result<(), SignerError> {
        /*
                // apex records that were deleted.
                for (k, old_rrs) in &iss.new_apex_saved {
                    if let Some(new_rrs) = iss.new_apex.get(k) {
                        if new_rrs == old_rrs {
                            // No change.
                            continue;
                        }
                        // Add the new records to a hash set and then check the old
                        // ones against the set to see which ones are removed.
                        let new_rrs: HashSet<&Zrd> = HashSet::from_iter(new_rrs.iter());
                        for r in old_rrs {
                            if new_rrs.contains(r) {
                                continue;
                            }
                            let r: RegularRecord = r.clone().into();
                            println!("apex patch.remove {r:?}");
                            self.patch.remove(r).unwrap();
                        }
                    } else {
                        for r in old_rrs {
                            let r: RegularRecord = r.clone().into();
                            println!("apex patch.remove {r:?}");
                            self.patch.remove(r).unwrap();
                        }
                    }
                }

                // apex records that were added.
                for (k, new_rrs) in &iss.new_apex {
                    if let Some(old_rrs) = iss.new_apex_saved.get(k) {
                        if new_rrs == old_rrs {
                            // No change.
                            continue;
                        }
                        // Add the old records to a hash set and then check the new
                        // ones against the set to see which ones are added.
                        let old_rrs: HashSet<&Zrd> = HashSet::from_iter(old_rrs.iter());
                        for r in new_rrs {
                            if old_rrs.contains(r) {
                                continue;
                            }
                            let r: RegularRecord = r.clone().into();
                            println!("apex patch.add {r:?}");
                            self.patch.add(r).unwrap();
                        }
                    } else {
                        for r in new_rrs {
                            let r: RegularRecord = r.clone().into();
                            println!("apex patch.add {r:?}");
                            self.patch.add(r).unwrap();
                        }
                    }
                }
        */

        // NSEC records that were deleted.
        for (k, old_nsec) in &iss.old_nsecs {
            if let Some(new_nsec) = iss.nsecs.get(k) {
                if new_nsec == old_nsec {
                    // No change.
                    continue;
                }
                let old_nsec: RegularRecord = old_nsec.clone().into();
                self.patch.remove(old_nsec).unwrap();
            } else {
                let old_nsec: RegularRecord = old_nsec.clone().into();
                self.patch.remove(old_nsec).unwrap();
            }
        }

        // NSEC records that were added.
        for (k, new_nsec) in &iss.nsecs {
            if let Some(old_nsec) = iss.old_nsecs.get(k) {
                if new_nsec == old_nsec {
                    // No change.
                    continue;
                }
                let new_nsec: RegularRecord = new_nsec.clone().into();
                self.patch.add(new_nsec).unwrap();
            } else {
                let new_nsec: RegularRecord = new_nsec.clone().into();
                self.patch.add(new_nsec).unwrap();
            }
        }

        // NSEC3 records that were deleted.
        for (k, old_nsec3) in &iss.old_nsec3s {
            if let Some(new_nsec3) = iss.nsec3s.get(k) {
                if new_nsec3 == old_nsec3 {
                    // No change.
                    continue;
                }
                let old_nsec3: RegularRecord = old_nsec3.clone().into();
                self.patch.remove(old_nsec3).unwrap();
            } else {
                let old_nsec3: RegularRecord = old_nsec3.clone().into();
                self.patch.remove(old_nsec3).unwrap();
            }
        }

        // NSEC3 records that were added.
        for (k, new_nsec3) in &iss.nsec3s {
            if let Some(old_nsec3) = iss.old_nsec3s.get(k) {
                if new_nsec3 == old_nsec3 {
                    // No change.
                    continue;
                }
                let new_nsec3: RegularRecord = new_nsec3.clone().into();
                self.patch.add(new_nsec3).unwrap();
            } else {
                let new_nsec3: RegularRecord = new_nsec3.clone().into();
                self.patch.add(new_nsec3).unwrap();
            }
        }

        // RRSIG records that were deleted.
        for (k, old_rrsigs) in &iss.old_rrsigs {
            if let Some(new_rrsigs) = iss.rrsigs.get(k) {
                if new_rrsigs == old_rrsigs {
                    // No change.
                    continue;
                }
                // Add the new RRSIGs to a hash set and then check the old
                // ones against the set to see which ones are removed.
                let new_rrsigs: HashSet<&Zrd> = HashSet::from_iter(new_rrsigs.iter());
                for r in old_rrsigs {
                    if new_rrsigs.contains(r) {
                        continue;
                    }
                    let r: RegularRecord = r.clone().into();
                    //println!("patch.remove {r:?}");
                    self.patch.remove(r).unwrap();
                }
            } else {
                for r in old_rrsigs {
                    let r: RegularRecord = r.clone().into();
                    //println!("patch.remove {r:?}");
                    self.patch.remove(r).unwrap();
                }
            }
        }

        // RRSIG records that were added.
        for (k, new_rrsigs) in &iss.rrsigs {
            if let Some(old_rrsigs) = iss.old_rrsigs.get(k) {
                if new_rrsigs == old_rrsigs {
                    // No change.
                    continue;
                }
                // Add the old RRSIGs to a hash set and then check the new
                // ones against the set to see which ones are added.
                let old_rrsigs: HashSet<&Zrd> = HashSet::from_iter(old_rrsigs.iter());
                for r in new_rrsigs {
                    if old_rrsigs.contains(r) {
                        continue;
                    }
                    let r: RegularRecord = r.clone().into();
                    //println!("patch.add {r:?}");
                    self.patch.add(r).unwrap();
                }
            } else {
                for r in new_rrsigs {
                    let r: RegularRecord = r.clone().into();
                    //println!("patch.add {r:?}");
                    self.patch.add(r).unwrap();
                }
            }
        }

        Ok(())
        /*
                let start = Instant::now();
                let mut writer = {
                    let filename = &self.config.zonefile_out;
                    let file = File::create(filename)
                        .map_err(|e| format!("unable to create file {}: {e}", filename.display()))?;
                    BufWriter::new(file)
                    // FileOrStdout::File(file)
                };

                for data in iss.new_data.values() {
                    for rr in data {
                        writer
                            .write_fmt(format_args!("{}\n", rr.display_zonefile(DISPLAY_KIND)))
                            .map_err(|e| format!("unable write signed zone: {e}"))?;
                    }
                }
                for rr in iss.nsecs.values() {
                    writer
                        .write_fmt(format_args!("{}\n", rr.display_zonefile(DISPLAY_KIND)))
                        .map_err(|e| format!("unable write signed zone: {e}"))?;
                }
                for rr in iss.nsec3s.values() {
                    writer
                        .write_fmt(format_args!("{}\n", rr.display_zonefile(DISPLAY_KIND)))
                        .map_err(|e| format!("unable write signed zone: {e}"))?;
                }
                for data in iss.rrsigs.values() {
                    for rr in data {
                        let ZoneRecordData::Rrsig(rrsig) = rr.data() else {
                            panic!("RRSIG expected");
                        };
                        let rr = Record::new(rr.owner(), rr.class(), rr.ttl(), YyyyMmDdHhMMSsRrsig(rrsig));
                        writer
                            .write_fmt(format_args!("{}\n", rr.display_zonefile(DISPLAY_KIND)))
                            .map_err(|e| format!("unable write signed zone: {e}"))?;
                    }
                }
                if self.verbose {
                    println!("writing output took {:?}", start.elapsed());
                }
                Ok(())
        */
    }

    /*
        fn load_pass_through_dnskey(&mut self, iss: &mut IncrementalSigningState) -> Result<(), Error> {
            // Assume that the APEX records have been copied from KeySetState to
            // SignerState. Now update the APEX in new_data.

            let mut dnskey_records = vec![];
            let mut rrsig_records = vec![];

            for r in &self.state.apex_extra {
                let zonefile =
                    domain::zonefile::inplace::Zonefile::from((r.to_string() + "\n").as_ref() as &str);
                for entry in zonefile {
                    let entry = entry.map_err::<Error, _>(|e| format!("bad entry: {e}\n").into())?;

                    // We only care about records in a zonefile
                    let Entry::Record(record) = entry else {
                        continue;
                    };

                    if record.rtype() != Rtype::DNSKEY && record.rtype() != Rtype::RRSIG {
                        continue;
                    }

                    let owner = record.owner().to_name::<Bytes>();
                    let data = record.data().clone().try_flatten_into().unwrap();
                    let r = Record::new(owner.clone(), record.class(), record.ttl(), data);

                    if r.rtype() == Rtype::RRSIG {
                        let ZoneRecordData::Rrsig(rrsig) = r.data() else {
                            panic!("RRSIG expected");
                        };
                        if rrsig.type_covered() != Rtype::DNSKEY {
                            continue;
                        }
                        rrsig_records.push(r);
                    } else {
                        dnskey_records.push(r);
                    }
                }
            }

            match self.config.pass_through_mode {
                PassThroughMode::Off => unreachable!(),
                PassThroughMode::CopyDnskeyRrset => {
                    let key = (
                        dnskey_records
                            .first()
                            .ok_or("at least one DNSKEY expected")?
                            .owner()
                            .clone(),
                        Rtype::DNSKEY,
                    );
                    iss.new_data.insert(key.clone(), dnskey_records);
                    iss.rrsigs.insert(key, rrsig_records);
                }
                PassThroughMode::MergeDnskeySignatures => {
                    // Make sure the old and new DNSKEY RRsets are the same.
                    let key = (iss.origin.clone(), Rtype::DNSKEY);
                    let Some(old_dnskey_records) = iss.old_data.get(&key) else {
                        return Err("A DNSKEY RRset should exist in the input zone".into());
                    };
                    let mut old_dnskey_records = old_dnskey_records.clone();
                    old_dnskey_records.sort();
                    dnskey_records.sort();
                    if *old_dnskey_records != dnskey_records {
                        return Err(
                            "DNSKEY RRset in input has to be same as the DNSKEY RRset in keyset".into(),
                        );
                    }
                    let Some(rrsigs) = iss.rrsigs.get(&key) else {
                        return Err("RRSIGs expected for DNSKEY RRset".into());
                    };
                    let mut rrsigs = rrsigs.clone();
                    rrsigs.append(&mut rrsig_records);
                    iss.rrsigs.insert(key, rrsigs);
                }
            }

            let key = (iss.origin.clone(), Rtype::ZONEMD);
            if iss.new_data.contains_key(&key) {
                return Err("Pass-through is not possible for zone input with ZONEMD".into());
            }

            Ok(())
        }
    */

    fn add_zonemd(&self, _iss: &mut IncrementalSigningState) -> Result<(), SignerError> {
        todo!();
        /*
                // Get the SOA record. We need that for the Serial and for the
                // TTL.
                let key = (iss.origin.clone(), Rtype::SOA);
                let soa_records = iss
                    .new_data
                    .get(&key)
                    .expect("SOA record should be present");
                let ZoneRecordData::Soa(soa) = soa_records[0].data() else {
                    panic!("SOA record expected");
                };

                let start = Instant::now();

                // Create a Vec with all records to be able to sort them in canonical
                // order. Ignore ZONEMD and RRSIGs of ZONEMD records.
                let mut all = vec![];

                let mut data: Vec<_> = iss
                    .new_data
                    .iter()
                    .filter_map(|((o, t), r)| {
                        if *o != iss.origin || *t != Rtype::ZONEMD {
                            Some(r)
                        } else {
                            None
                        }
                    })
                    .flatten()
                    .collect();
                all.append(&mut data);

                let mut data: Vec<_> = iss.nsecs.values().collect();
                all.append(&mut data);

                let mut data: Vec<_> = iss.nsec3s.values().collect();
                all.append(&mut data);

                let mut data: Vec<_> = iss
                    .rrsigs
                    .iter()
                    .filter_map(|((o, t), r)| {
                        if *o != iss.origin || *t != Rtype::ZONEMD {
                            Some(r)
                        } else {
                            None
                        }
                    })
                    .flatten()
                    .collect();
                all.append(&mut data);

                //all.sort_by(|e1, e2| CanonicalOrd::canonical_cmp(*e1, *e2));
                all.par_sort_by(|e1, e2| CanonicalOrd::canonical_cmp(*e1, *e2));

                if self.verbose {
                    println!("ZONEMD prepare and sort took {:?}", start.elapsed());
                }

                let start = Instant::now();

                let mut zonemd_records = vec![];
                for z in &self.config.zonemd {
                    if z.0 != ZonemdScheme::SIMPLE {
                        return Err("unsupported zonemd scheme (only SIMPLE is supported)".into());
                    }
                    let mut buf: Vec<u8> = Vec::new();
                    let mut ctx = match z.1 {
                        ZonemdAlgorithm::SHA384 => digest::Context::new(&digest::SHA384),
                        ZonemdAlgorithm::SHA512 => digest::Context::new(&digest::SHA512),
                        _ => unreachable!(),
                    };
                    for r in &all {
                        buf.clear();
                        with_infallible(|| r.compose_canonical(&mut buf));
                        ctx.update(&buf);
                    }
                    let digest = ctx.finish();
                    let zonemd = Zonemd::new(
                        soa.serial(),
                        z.0,
                        z.1,
                        Bytes::copy_from_slice(digest.as_ref()),
                    );
                    let record = Record::new(
                        iss.origin.clone(),
                        soa_records[0].class(),
                        soa_records[0].ttl(),
                        ZoneRecordData::Zonemd(zonemd),
                    );
                    zonemd_records.push(record);
                }

                if self.verbose {
                    println!("ZONEMD hash took {:?}", start.elapsed());
                }

                let key = (iss.origin.clone(), Rtype::ZONEMD);
                let mut new_sigs = vec![];
                sign_records(
                    &iss.origin,
                    &zonemd_records,
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
                iss.new_data.insert(key.clone(), zonemd_records);
                iss.rrsigs.insert(key, new_sigs[0].0.clone());
                Ok(())
        */
    }

    fn update_soa_serial(&mut self, old_soa: &Zrd) -> Result<Zrd, SignerError> {
        // Implement SOA serial policies. There are four policies:
        // 1) Keep. Copy the serial from the unsigned zone. Refuse to sign
        //    if the serial did not change.
        // 2) Increment. Copy the serial from the unsigned zone but increment
        //    the serial if the zone needs to be signed an the serial in
        //    the unsigned zone did not change.
        // 3) Unix timestamp. The current time in Unix seconds. Increment if
        //    that does not result in a higher serial.
        // 4) Broken down time (YYYYMMDDnn). The current day plus a serial
        //    number. Implies increment to generate different serial numbers
        //    over a day.

        let ZoneRecordData::Soa(zone_soa) = old_soa.data() else {
            unreachable!();
        };

        let curr_previous_serial = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone_state = self.zone.state.lock().unwrap();

            zone_state.previous_serial
        };

        match self.policy.signer.serial_policy {
            SignerSerialPolicy::Keep => {
                if let Some(previous_serial) = curr_previous_serial
                    && zone_soa.serial() <= previous_serial
                {
                    return Err(SignerError::SigningError(
                        "Serial policy is Keep but upstream serial did not increase".to_string(),
                    ));
                }

                // Save the new SOA serial.
                {
                    // Use a block to make sure that the mutex is clearly
                    // dropped.
                    let mut zone_state = self.zone.state.lock().unwrap();

                    zone_state.previous_serial = Some(zone_soa.serial());
                    self.zone.mark_dirty(&mut zone_state, &self.center);
                }
                Ok(old_soa.clone())
            }
            SignerSerialPolicy::Counter => {
                // Always increment the serial number, ignore the serial
                // number in the unsigned zone.
                let previous_serial = if let Some(serial) = curr_previous_serial {
                    serial
                } else {
                    DomainSerial::from(0)
                };

                let serial = previous_serial.add(1);

                // Save the new SOA serial.
                {
                    // Use a block to make sure that the mutex is clearly
                    // dropped.
                    let mut zone_state = self.zone.state.lock().unwrap();

                    zone_state.previous_serial = Some(serial);
                    self.zone.mark_dirty(&mut zone_state, &self.center);
                }

                let new_soa = ZoneRecordData::Soa(Soa::new(
                    zone_soa.mname().clone(),
                    zone_soa.rname().clone(),
                    serial,
                    zone_soa.refresh(),
                    zone_soa.retry(),
                    zone_soa.expire(),
                    zone_soa.minimum(),
                ));
                let record = Record::new(
                    old_soa.owner().clone(),
                    old_soa.class(),
                    old_soa.ttl(),
                    new_soa,
                );

                Ok(record)
            }
            SignerSerialPolicy::UnixTime => {
                let mut serial = DomainSerial::now();
                if let Some(previous_serial) = curr_previous_serial
                    && serial <= previous_serial
                {
                    serial = previous_serial.add(1);
                }

                // Save the new SOA serial.
                {
                    // Use a block to make sure that the mutex is clearly
                    // dropped.
                    let mut zone_state = self.zone.state.lock().unwrap();

                    zone_state.previous_serial = Some(serial);
                    self.zone.mark_dirty(&mut zone_state, &self.center);
                }

                let new_soa = ZoneRecordData::Soa(Soa::new(
                    zone_soa.mname().clone(),
                    zone_soa.rname().clone(),
                    serial,
                    zone_soa.refresh(),
                    zone_soa.retry(),
                    zone_soa.expire(),
                    zone_soa.minimum(),
                ));

                let record = Record::new(
                    old_soa.owner().clone(),
                    old_soa.class(),
                    old_soa.ttl(),
                    new_soa,
                );

                Ok(record)
            }
            SignerSerialPolicy::DateCounter => {
                let ts = JiffTimestamp::now();
                let zone = Zoned::new(ts, TimeZone::UTC);
                let serial = ((zone.year() as u32 * 100 + zone.month() as u32) * 100
                    + zone.day() as u32)
                    * 100;
                let mut serial: DomainSerial = serial.into();

                if let Some(previous_serial) = curr_previous_serial
                    && serial <= previous_serial
                {
                    serial = previous_serial.add(1);
                }

                // Save the new SOA serial.
                {
                    // Use a block to make sure that the mutex is clearly
                    // dropped.
                    let mut zone_state = self.zone.state.lock().unwrap();

                    zone_state.previous_serial = Some(serial);
                    self.zone.mark_dirty(&mut zone_state, &self.center);
                }

                let new_soa = ZoneRecordData::Soa(Soa::new(
                    zone_soa.mname().clone(),
                    zone_soa.rname().clone(),
                    serial,
                    zone_soa.refresh(),
                    zone_soa.retry(),
                    zone_soa.expire(),
                    zone_soa.minimum(),
                ));

                let record = Record::new(
                    old_soa.owner().clone(),
                    old_soa.class(),
                    old_soa.ttl(),
                    new_soa,
                );

                Ok(record)
            }
        }
    }

    /*
        fn run_notify_command(&self) -> Result<(), Error> {
            if self.config.notify_command.is_empty() {
                return Ok(()); // Nothing to do.
            }

            let output = Command::new(&self.config.notify_command[0])
                .args(&self.config.notify_command[1..])
                .output()
                .map_err(|e| {
                    format!(
                        "unable to create new Command for {}: {e}",
                        self.config.notify_command[0]
                    )
                })?;
            if !output.status.success() {
                println!("notify command failed with: {}", output.status);
                io::stdout()
                    .write_all(&output.stdout)
                    .map_err(|e| format!("unable to write to stdout: {e}"))?;
                io::stderr()
                    .write_all(&output.stderr)
                    .map_err(|e| format!("unable to write to stderr: {e}"))?;
            }
            Ok(())
        }
    */

    fn sign_pass_through(&mut self) -> Result<(), SignerError> {
        todo!();
        /*
                // Clear key_tags and key_roll to trigger resigning when
                // pass-through mode is turned off. Also clear keyset_state_modified
                // to trigger a reload of the keyset state when pass-through is
                // turned off.
                if !self.state.key_tags.is_empty() {
                    self.state.key_tags = HashSet::new();
                    self.state.keyset_state_modified = Timestamp::from(0).into();
                    self.state_changed = true;
                }
                if self.state.key_roll.is_some() {
                    self.state.key_roll = None;
                    self.state_changed = true;
                }

                let mut iss = IncrementalSigningState::new(self)?;

                let start = Instant::now();
                load_signed_zone(&mut iss, &self.config.zonefile_in).unwrap();
                if self.verbose {
                    println!("loading signed zone took {:?}", start.elapsed());
                }

                // Re-use the signed data.
                load_signed_only(&mut iss);

                self.load_pass_through_dnskey(&mut iss)?;

                self.incremental_write_output(&iss)?;
                Ok(())
        */
    }

    fn load_apex_records(&mut self, iss: &mut IncrementalSigningState) -> Result<(), SignerError> {
        // Assume that the APEX records have been copied from KeySetState to
        // state. Now update the APEX in new_data.

        // Delete all types in apex_remove.
        let curr_apex_remove = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone_state = self.zone.state.lock().unwrap();

            zone_state.apex_remove.clone()
        };

        for t in curr_apex_remove {
            let key = (iss.origin.clone(), t);
            iss.new_apex.remove(&t);
            iss.rrsigs.remove(&key);
        }

        let curr_apex_extra = {
            // Use a block to make sure that the mutex is clearly dropped.
            let zone_state = self.zone.state.lock().unwrap();

            zone_state.apex_extra.clone()
        };

        for r in curr_apex_extra {
            let zonefile =
                domain::zonefile::inplace::Zonefile::from((r.to_string() + "\n").as_ref() as &str);
            for entry in zonefile {
                let entry =
                    entry.map_err(|e| SignerError::SigningError(format!("bad entry: {e}\n")))?;

                // We only care about records in a zonefile
                let Entry::Record(record) = entry else {
                    continue;
                };

                let owner = record.owner().to_name::<Bytes>();
                let data = record.data().clone().try_flatten_into().unwrap();
                let r = Record::new(owner.clone(), record.class(), record.ttl(), data);

                if r.rtype() == Rtype::RRSIG {
                    let ZoneRecordData::Rrsig(rrsig) = r.data() else {
                        panic!("RRSIG expected");
                    };
                    let key = (owner, rrsig.type_covered());
                    let mut records = vec![r];
                    if let Some(v) = iss.rrsigs.get_mut(&key) {
                        v.append(&mut records);
                    } else {
                        iss.rrsigs.insert(key, records);
                    }
                } else {
                    let key = r.rtype();
                    let mut records = vec![r];
                    if let Some(v) = iss.new_apex.get_mut(&key) {
                        v.append(&mut records);
                    } else {
                        iss.new_apex.insert(key, records);
                    }
                }
            }
        }

        if self.use_nsec3 {
            // Copy the NSEC3PARAM record from the old_apex to the new_apex.
            // The reason is that the NSEC3PARAM gets lost when the unsigned
            // zone is loaded.
            let nsec3param_records = iss
                .old_apex
                .get(&Rtype::NSEC3PARAM)
                .expect("NSEC3PARAM should be present");
            iss.new_apex
                .insert(Rtype::NSEC3PARAM, nsec3param_records.to_vec());
        }

        if !self.zonemd.is_empty() {
            let zonemd = Zonemd::new(
                0.into(),
                ZonemdScheme::SIMPLE,
                ZonemdAlgorithm::SHA384,
                Bytes::new(),
            );
            let record = Record::new(
                iss.origin.clone(),
                Class::IN,
                Ttl::ZERO,
                ZoneRecordData::Zonemd(zonemd),
            );
            let records = vec![record];
            let key = (iss.origin.clone(), Rtype::ZONEMD);
            iss.new_data.insert(key, records);
        }

        // Update the SOA serial.
        let zone_soa_rr = &iss.new_apex.get(&Rtype::SOA).expect("SOA should exist")[0];
        let new_soa = self.update_soa_serial(zone_soa_rr)?;
        let new_rrset = vec![new_soa];
        iss.new_apex.insert(Rtype::SOA, new_rrset);

        let old_soa = iss.old_apex.get(&Rtype::SOA).unwrap();
        for r in old_soa {
            let r: SoaRecord = r.clone().into();
            self.patch.remove_soa(r).unwrap();
        }
        let new_soa = iss.new_apex.get(&Rtype::SOA).unwrap();
        for r in new_soa {
            let r: SoaRecord = r.clone().into();
            self.patch.add_soa(r).unwrap();
        }

        Ok(())
    }

    fn new_nsec_nsec3_sigs(&self, iss: &mut IncrementalSigningState) -> Result<(), SignerError> {
        let mut new_sigs = vec![];
        if self.use_nsec3 {
            for m in &iss.modified_nsecs {
                let Some(nsec3) = iss.nsec3s.get(m) else {
                    panic!("NSEC3 for {m} should exist");
                };

                let nsec3 = nsec3.clone();
                sign_records(
                    &iss.origin,
                    &[nsec3],
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            }
        } else {
            for m in &iss.modified_nsecs {
                let Some(nsec) = iss.nsecs.get(m) else {
                    panic!("NSEC for {m} should exist");
                };

                let nsec = nsec.clone();
                sign_records(
                    &iss.origin,
                    &[nsec],
                    &iss.keys,
                    iss.inception,
                    iss.expiration,
                    &mut new_sigs,
                )?;
            }
        }
        for (sig, rtype) in new_sigs {
            let key = (sig[0].owner().clone(), rtype);
            iss.rrsigs.insert(key, sig);
        }
        Ok(())
    }

    fn handle_nsec_nsec3(&mut self, iss: &mut IncrementalSigningState) -> Result<(), SignerError> {
        // Note that we could try to regenerate the NSEC(3). Assume that
        // switching between NSEC, NSEC3, and NSEC3 opt-out (or other NSEC3
        // parameter changes) is rare enough that we can just resign the full
        // zone.
        let opt_nsec3param = iss.old_apex.get(&Rtype::NSEC3PARAM);
        if let Some(nsec3param_records) = opt_nsec3param {
            // Zone was signed with NSEC3.
            if !self.use_nsec3 {
                // Zone is signed with NSEC3 but we want NSEC.
                let start = Instant::now();
                iss.remove_nsec_nsec3();
                iss.new_nsec_chain()?;
                println!("replacing NSEC3 with NSEC took {:?}", start.elapsed());
                return Ok(());
            }
            let ZoneRecordData::Nsec3param(nsec3param) = nsec3param_records[0].data() else {
                panic!("ZoneRecordData::Nsec3param expected");
            };
            if *nsec3param != iss.nsec3param {
                // Parameters changed, resign.
                let start = Instant::now();
                iss.remove_nsec_nsec3();
                iss.new_nsec3_chain()?;
                if self.verbose {
                    println!("updating NSEC3 parameters took {:?}", start.elapsed());
                }
                return Ok(());
            }
        } else {
            // Zone was signed with NSEC, check if that is also the target.
            if self.use_nsec3 {
                // Resign the full zone with NSEC3.
                let start = Instant::now();
                iss.remove_nsec_nsec3();
                iss.new_nsec3_chain()?;
                println!("replacing NSEC with NSEC3 took {:?}", start.elapsed());
                return Ok(());
            }
            // Stay with NSEC.
        }
        Ok(())
    }
}

type Zrd = Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>;
type RtypeSet = HashSet<Rtype>;
type ChangesValue = (RtypeSet, RtypeSet); // add set followed by delete set.

struct IncrementalSigningState {
    origin: Name<Bytes>,
    old_apex: HashMap<Rtype, Vec<Zrd>>,
    new_apex: HashMap<Rtype, Vec<Zrd>>,
    new_apex_saved: HashMap<Rtype, Vec<Zrd>>,
    old_data: HashMap<(Name<Bytes>, Rtype), Vec<Zrd>>,
    new_data: BTreeMap<(Name<Bytes>, Rtype), Vec<Zrd>>,
    old_nsecs: BTreeMap<Name<Bytes>, Zrd>,
    nsecs: BTreeMap<Name<Bytes>, Zrd>,
    old_nsec3s: BTreeMap<Name<Bytes>, Zrd>,
    nsec3s: BTreeMap<Name<Bytes>, Zrd>,
    old_rrsigs: HashMap<(Name<Bytes>, Rtype), Vec<Zrd>>,
    rrsigs: HashMap<(Name<Bytes>, Rtype), Vec<Zrd>>,

    changes: HashMap<Name<Bytes>, ChangesValue>,
    modified_nsecs: HashSet<Name<Bytes>>,
    keys: Vec<SigningKey<Bytes, KeyPair>>,
    inception: Timestamp,
    expiration: Timestamp,

    // NSEC3 paramters.
    nsec3param: Nsec3param<Bytes>,
}

impl IncrementalSigningState {
    fn new(
        origin: Name<Bytes>,
        policy: &PolicyVersion,
        zone_signer: &ZoneSigner,
        center: &Arc<Center>,
        keyset_state: &KeySetState,
        status: Arc<RwLock<SigningStatusPerZone>>,
    ) -> Result<Self, SignerError> {
        let keys = Self::load_keys(zone_signer, center, origin.clone(), keyset_state, status)?;

        let now = faketime_or_now();
        let now_u32 = Into::<Duration>::into(now.clone()).as_secs() as u32;
        let inception = (now_u32 - policy.signer.sig_inception_offset).into();
        let expiration = (now_u32 + policy.signer.sig_validity_time).into();

        // This is the only way to deal with opt-out. There is no data type
        // for flags or constant for opt-out. Creating an Nsec3param makes it
        // possible to set opt-out.
        let mut nsec3param = Nsec3param::default();
        match &policy.signer.denial {
            SignerDenialPolicy::NSec => (),
            SignerDenialPolicy::NSec3 { opt_out } => {
                if *opt_out {
                    nsec3param.set_opt_out_flag();
                }
            }
        }
        Ok(Self {
            origin,
            old_apex: HashMap::new(),
            new_apex: HashMap::new(),
            new_apex_saved: HashMap::new(),
            old_data: HashMap::new(),
            new_data: BTreeMap::new(),
            old_nsecs: BTreeMap::new(),
            nsecs: BTreeMap::new(),
            old_nsec3s: BTreeMap::new(),
            nsec3s: BTreeMap::new(),
            old_rrsigs: HashMap::new(),
            rrsigs: HashMap::new(),
            changes: HashMap::new(),
            modified_nsecs: HashSet::new(),
            keys,
            inception,
            expiration,
            nsec3param,
        })
    }

    fn load_keys(
        zone_signer: &ZoneSigner,
        center: &Arc<Center>,
        zone_name: Name<Bytes>,
        keyset_state: &KeySetState,
        status: Arc<RwLock<SigningStatusPerZone>>,
    ) -> Result<Vec<SigningKey<Bytes, KeyPair>>, SignerError> {
        debug!("Loading dnst keyset signing keys");

        let kmip_server_state_dir = &center.config.kmip_server_state_dir;
        let kmip_credentials_store_path = &center.config.kmip_credentials_store_path;

        debug!("Reading dnst keyset DNSKEY RRs and RRSIG RRs");
        status.write().unwrap().current_action =
            "Fetching apex RRs from the key manager".to_string();

        // Read the DNSKEY RRs and DNSKEY RRSIG RR from the keyset state.

        status.write().unwrap().current_action = "Loading signing keys".to_string();
        // Load the signing keys indicated by the keyset state.
        let mut signing_keys = vec![];
        for (pub_key_name, key_info) in keyset_state.keyset.keys() {
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

                        let private_key = ZoneSigner::load_private_key(Path::new(priv_key_path))
                            .map_err(|_| {
                                SignerError::CannotReadPrivateKeyFile(priv_key_path.to_string())
                            })?;

                        let pub_key_path = pub_url.path();
                        debug!("Attempting to load public key '{pub_key_path}'.");

                        let public_key = ZoneSigner::load_public_key(Path::new(pub_key_path))
                            .map_err(|_| {
                                SignerError::CannotReadPublicKeyFile(pub_key_path.to_string())
                            })?;

                        let key_pair = domain::crypto::sign::KeyPair::from_bytes(
                            &private_key,
                            public_key.data(),
                        )
                        .map_err(|err| SignerError::InvalidKeyPairComponents(err.to_string()))?;
                        let signing_key = SigningKey::new(
                            zone_name.clone(),
                            public_key.data().flags(),
                            KeyPair::Domain(key_pair),
                        );

                        signing_keys.push(signing_key);
                    }

                    ("kmip", "kmip") => {
                        let priv_key_url =
                            KeyUrl::try_from(priv_url).map_err(SignerError::InvalidPublicKeyUrl)?;
                        let pub_key_url =
                            KeyUrl::try_from(pub_url).map_err(SignerError::InvalidPrivateKeyUrl)?;

                        // TODO: Replace the connection pool if the persisted KMIP server settings
                        // were updated more recently than the pool was created.

                        let mut kmip_servers = zone_signer.kmip_servers.lock().unwrap();
                        let kmip_conn_pool = match kmip_servers
                            .entry(priv_key_url.server_id().to_string())
                        {
                            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                            std::collections::hash_map::Entry::Vacant(e) => {
                                // Try and load the KMIP server settings.
                                let p = kmip_server_state_dir.join(priv_key_url.server_id());
                                info!("Reading KMIP server state from '{p}'");
                                let f = std::fs::File::open(p).unwrap();
                                let kmip_server: KmipServerState =
                                    serde_json::from_reader(f).unwrap();
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
                                        KmipServerCredentialsFileMode::ReadOnly,
                                    )
                                    .unwrap();

                                    let creds = creds_file.get(&server_id).ok_or(
                                        SignerError::KmipServerCredentialsNeeded(server_id.clone()),
                                    )?;

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
                                    ca_cert: None,     // TODO
                                    connect_timeout: Some(connect_timeout),
                                    read_timeout: Some(read_timeout),
                                    write_timeout: Some(write_timeout),
                                    max_response_bytes: Some(max_response_bytes),
                                };

                                let cloned_status = status.clone();
                                let cloned_server_id = server_id.clone();
                                tokio::task::spawn(async move {
                                    cloned_status.write().unwrap().current_action =
                                        format!("Connecting to KMIP server '{cloned_server_id}");
                                });
                                let pool = ConnectionManager::create_connection_pool(
                                    server_id.clone(),
                                    Arc::new(conn_settings.clone()),
                                    10,
                                    Some(Duration::from_secs(60)),
                                    Some(Duration::from_secs(60)),
                                )
                                .map_err(|err| {
                                    SignerError::CannotCreateKmipConnectionPool(server_id, err)
                                })?;

                                e.insert(pool)
                            }
                        };

                        let _flags = priv_key_url.flags();

                        let cloned_status = status.clone();
                        let cloned_server_id = priv_key_url.server_id().to_string();
                        tokio::task::spawn(async move {
                            cloned_status.write().unwrap().current_action =
                                format!("Fetching keys from KMIP server '{cloned_server_id}'");
                        });

                        let key_pair = KeyPair::Kmip(
                            domain_kmip::sign::KeyPair::from_urls(
                                priv_key_url,
                                pub_key_url,
                                kmip_conn_pool.clone(),
                            )
                            .map_err(|err| {
                                SignerError::InvalidKeyPairComponents(err.to_string())
                            })?,
                        );

                        let signing_key =
                            SigningKey::new(zone_name.clone(), key_pair.dnskey().flags(), key_pair);

                        signing_keys.push(signing_key);
                    }

                    (other1, other2) => {
                        return Err(SignerError::InvalidKeyPairComponents(format!(
                            "Using different key URI schemes ({other1} vs {other2}) for a public/private key pair is not supported."
                        )));
                    }
                }

                debug!("Loaded key pair for zone {zone_name} from key pair");
            }
        }

        debug!("{} signing keys loaded", signing_keys.len());

        // TODO: If signing is disabled for a zone should we then allow the
        // unsigned zone to propagate through the pipeline?
        if signing_keys.is_empty() {
            warn!("No signing keys found for zone {zone_name}, aborting");
            return Err(SignerError::SigningError(
                "No signing keys found".to_string(),
            ));
        }

        Ok(signing_keys)
    }

    fn load_signed_zone(&mut self, signed_reader: &SignedZoneReader) -> Result<(), SignerError> {
        // Collect records for a
        // name/RRtype and store a complete RRset in a hash table.
        let mut records = Vec::<Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>>::new();
        let mut rrsig_records = vec![];
        let mut type_covered = Rtype::RRSIG;

        for entry in signed_reader.all_records() {
            let record: OldParsedRecord = entry.clone().into();
            let record: StoredRecord = record.flatten_into();

            match record.data() {
                ZoneRecordData::Rrsig(rrsig) => {
                    if rrsig_records.is_empty() {
                        type_covered = rrsig.type_covered();
                        rrsig_records.push(record);
                        continue;
                    }
                    if record.owner() == rrsig_records[0].owner()
                        && rrsig.type_covered() == type_covered
                    {
                        rrsig_records.push(record);
                        continue;
                    }

                    let key = (rrsig_records[0].owner().clone(), type_covered);
                    if let Some(v) = self.rrsigs.get_mut(&key) {
                        v.append(&mut rrsig_records);
                    } else {
                        self.rrsigs.insert(key, rrsig_records);
                    }
                    type_covered = rrsig.type_covered();
                    rrsig_records = vec![];
                    rrsig_records.push(record);
                }
                ZoneRecordData::Nsec(_) => {
                    // Assume (at most) one NSEC record per owner name.
                    // Directly insert into the btree map.
                    self.nsecs.insert(record.owner().clone(), record);
                }
                ZoneRecordData::Nsec3(_) => {
                    // Assume (at most) one NSEC3 record per owner name.
                    // Directly insert into the btree map.
                    self.nsec3s.insert(record.owner().clone(), record);
                }
                _ => {
                    if records.is_empty() {
                        records.push(record);
                        continue;
                    }
                    if record.owner() == records[0].owner() && record.rtype() == records[0].rtype()
                    {
                        records.push(record);
                        continue;
                    }
                    let key = (records[0].owner().clone(), records[0].rtype());
                    if key.0 == self.origin {
                        if let Some(v) = self.old_apex.get_mut(&key.1) {
                            v.append(&mut records);
                        } else {
                            self.old_apex.insert(key.1, records);
                        }
                    } else if let Some(v) = self.old_data.get_mut(&key) {
                        v.append(&mut records);
                    } else {
                        self.old_data.insert(key, records);
                    }
                    records = vec![];
                    records.push(record);
                }
            }
        }

        if !records.is_empty() {
            let key = (records[0].owner().clone(), records[0].rtype());
            if key.0 == self.origin {
                if let Some(v) = self.old_apex.get_mut(&key.1) {
                    v.append(&mut records);
                } else {
                    self.old_apex.insert(key.1, records);
                }
            } else if let Some(v) = self.old_data.get_mut(&key) {
                v.append(&mut records);
            } else {
                self.old_data.insert(key, records);
            }
        }
        if !rrsig_records.is_empty() {
            let key = (rrsig_records[0].owner().clone(), type_covered);
            if let Some(v) = self.rrsigs.get_mut(&key) {
                v.append(&mut rrsig_records);
            } else {
                self.rrsigs.insert(key, rrsig_records);
            }
        }
        self.old_nsecs = self.nsecs.clone();
        self.old_nsec3s = self.nsec3s.clone();
        self.old_rrsigs = self.rrsigs.clone();
        Ok(())
    }

    fn load_unsigned_zone(&mut self, reader: &LoadedZoneReader) -> Result<(), SignerError> {
        // Collect records for a
        // name/RRtype and store a complete RRset in a btree.
        let mut records = Vec::<Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>>::new();

        records.push(Into::<OldParsedRecord>::into(reader.soa().clone()).flatten_into());

        for entry in reader.regular_records() {
            let record: OldParsedRecord = entry.clone().into();
            let record: StoredRecord = record.flatten_into();

            let record: StoredRecord = record.flatten_into();

            if records.is_empty() {
                records.push(record);
                continue;
            }
            if record.owner() == records[0].owner() && record.rtype() == records[0].rtype() {
                records.push(record);
                continue;
            }
            let key = (records[0].owner().clone(), records[0].rtype());
            if key.0 == self.origin {
                if let Some(v) = self.new_apex.get_mut(&key.1) {
                    v.append(&mut records);
                } else {
                    self.new_apex.insert(key.1, records);
                }
            } else if let Some(v) = self.new_data.get_mut(&key) {
                v.append(&mut records);
            } else {
                self.new_data.insert(key, records);
            }
            records = vec![];
            records.push(record);
        }

        if !records.is_empty() {
            let key = (records[0].owner().clone(), records[0].rtype());
            if key.0 == self.origin {
                if let Some(v) = self.new_apex.get_mut(&key.1) {
                    v.append(&mut records);
                } else {
                    self.new_apex.insert(key.1, records);
                }
            } else if let Some(v) = self.new_data.get_mut(&key) {
                v.append(&mut records);
            } else {
                self.new_data.insert(key, records);
            }
        }

        // Save a copy of the loaded new_apex to createa diff later.
        for (k, v) in &self.new_apex {
            self.new_apex_saved.insert(*k, v.clone());
        }

        // Remove an NSEC3PARAM and ZONEMD that we got from the unsigned
        // zone.
        self.new_apex.remove(&Rtype::NSEC3PARAM);
        self.new_apex.remove(&Rtype::ZONEMD);
        Ok(())
    }

    fn load_signed_only(&mut self) {
        // Copy old data to new data.

        for (k, v) in &self.old_data {
            self.new_data.insert(k.clone(), v.clone());
        }
        for (k, v) in &self.old_apex {
            self.new_apex.insert(*k, v.clone());
            self.new_apex_saved.insert(*k, v.clone());
        }
    }

    fn initial_diffs(&mut self) -> Result<(), SignerError> {
        let mut new_sigs = vec![];
        for (_, new_rrset) in self.new_data.iter_mut() {
            let key = (new_rrset[0].owner().clone(), new_rrset[0].rtype());
            if let Some(mut old_rrset) = self.old_data.remove(&key) {
                let rtype = new_rrset[0].rtype();
                if (rtype == Rtype::DNSKEY || rtype == Rtype::CDS || rtype == Rtype::CDNSKEY)
                    && *new_rrset[0].owner() == self.origin
                {
                    // At apex, these types are signed by the key manager. No
                    // need to check for changes.
                    continue;
                }
                old_rrset.sort_by(|a, b| a.as_ref().data().canonical_cmp(b.as_ref().data()));
                new_rrset.sort_by(|a, b| a.as_ref().data().canonical_cmp(b.as_ref().data()));

                if *old_rrset != *new_rrset && self.rrsigs.remove(&key).is_some() {
                    sign_records(
                        &self.origin,
                        new_rrset,
                        &self.keys,
                        self.inception,
                        self.expiration,
                        &mut new_sigs,
                    )?;
                }
            } else if let Some((added, _)) = self.changes.get_mut(&key.0) {
                added.insert(new_rrset[0].rtype());
            } else {
                let mut added = HashSet::new();
                let removed = HashSet::new();
                added.insert(new_rrset[0].rtype());
                self.changes.insert(key.0, (added, removed));
            }
        }
        for (_, new_rrset) in self.new_apex.iter_mut() {
            let key = (new_rrset[0].owner().clone(), new_rrset[0].rtype());
            if let Some(mut old_rrset) = self.old_apex.remove(&key.1) {
                let rtype = new_rrset[0].rtype();
                if (rtype == Rtype::DNSKEY || rtype == Rtype::CDS || rtype == Rtype::CDNSKEY)
                    && *new_rrset[0].owner() == self.origin
                {
                    // At apex, these types are signed by the key manager. No
                    // need to check for changes.
                    continue;
                }
                old_rrset.sort_by(|a, b| a.as_ref().data().canonical_cmp(b.as_ref().data()));
                new_rrset.sort_by(|a, b| a.as_ref().data().canonical_cmp(b.as_ref().data()));

                if *old_rrset != *new_rrset && self.rrsigs.remove(&key).is_some() {
                    sign_records(
                        &self.origin,
                        new_rrset,
                        &self.keys,
                        self.inception,
                        self.expiration,
                        &mut new_sigs,
                    )?;
                }
            } else if let Some((added, _)) = self.changes.get_mut(&key.0) {
                added.insert(new_rrset[0].rtype());
            } else {
                let mut added = HashSet::new();
                let removed = HashSet::new();
                added.insert(new_rrset[0].rtype());
                self.changes.insert(key.0, (added, removed));
            }
        }
        for (sig, rtype) in new_sigs {
            let key = (sig[0].owner().clone(), rtype);
            self.rrsigs.insert(key, sig);
        }
        for old_rrset in self.old_data.values() {
            // What is left in old_data is removed.
            let rtype = old_rrset[0].rtype();
            let key = (old_rrset[0].owner().clone(), rtype);

            self.rrsigs.remove(&key);

            if let Some((_, removed)) = self.changes.get_mut(&key.0) {
                removed.insert(rtype);
            } else {
                let added = HashSet::new();
                let mut removed = HashSet::new();
                removed.insert(rtype);
                self.changes.insert(key.0, (added, removed));
            }
        }
        for old_rrset in self.old_apex.values() {
            // What is left in old_data is removed.
            let rtype = old_rrset[0].rtype();
            let key = (old_rrset[0].owner().clone(), rtype);

            self.rrsigs.remove(&key);

            if let Some((_, removed)) = self.changes.get_mut(&key.0) {
                removed.insert(rtype);
            } else {
                let added = HashSet::new();
                let mut removed = HashSet::new();
                removed.insert(rtype);
                self.changes.insert(key.0, (added, removed));
            }
        }
        Ok(())
    }

    fn incremental_nsec(&mut self) -> Result<(), SignerError> {
        // Should changes be sorted or not? If changes is sorted we will
        // process a new delegation before any glue. Which is more efficient.
        // Otherwise if glue comes first, the glue will be signed and inserted
        // in the NSEC chain only to be removed when the delegation is processed.
        // However, we removing a delegation, the situation is reversed. For now
        // assuming that sorting is not necessary.

        let set_nsec_rrsig: HashSet<_> = [Rtype::NSEC, Rtype::RRSIG].into();

        let changes = self.changes.clone();
        for (key, (add, delete)) in &changes {
            // The intersection between add and delete is empty.
            assert!(add.intersection(delete).next().is_none());

            if let Some(record_nsec) = self.nsecs.get(key) {
                let record_nsec = record_nsec.clone();
                let ZoneRecordData::Nsec(nsec) = record_nsec.data() else {
                    panic!("NSEC record expected");
                };

                // Convert the existing RRtype bitmap into a hash set.
                let mut curr = HashSet::new();
                for rtype in nsec.types() {
                    curr.insert(rtype);
                }

                // The intersection between curr and add is empty.
                assert!(curr.intersection(add).next().is_none());

                // delete is completely contained in curr. In other words the
                // difference between delete and curr is empty.
                assert!(delete.difference(&curr).next().is_none());

                if add.contains(&Rtype::NS) {
                    // Apex is special, but we can assume the NS RRset will not
                    // be added to apex.
                    assert!(*key != self.origin);

                    // Remove the signatures for the existing types.
                    for rtype in nsec.types().iter() {
                        // When NS is added, we should keep the signatures for
                        // DS and NSEC. The NSEC signature will be updated but
                        // there is no point in removing it first. Do not try to
                        // remove a signature for RRSIG because it does not exist.
                        if rtype == Rtype::DS || rtype == Rtype::NSEC || rtype == Rtype::RRSIG {
                            continue;
                        }
                        let key = (key.clone(), rtype);
                        self.rrsigs.remove(&key);
                    }

                    // Restrict curr and add to these types.
                    let mask: HashSet<Rtype> =
                        [Rtype::NS, Rtype::DS, Rtype::NSEC, Rtype::RRSIG].into();

                    let curr = curr.intersection(&mask).copied().collect();
                    let add = add.intersection(&mask).copied().collect();

                    // Update the NSEC record.
                    nsec_update_bitmap(
                        &record_nsec,
                        nsec,
                        &curr,
                        &add,
                        delete,
                        &set_nsec_rrsig,
                        self,
                    );

                    // Mark descendents as occluded after updating the bitmap.
                    // The reason is that nsec_update_bitmap uses the current
                    // next_name and nsec_set_occluded may change that.
                    nsec_set_occluded(key, self);

                    continue;
                }
                if delete.contains(&Rtype::NS) {
                    // Apex is special, but we can assume the NS RRset will not
                    // be removed from apex.
                    assert!(*key != self.origin);

                    // Curr does not include all types at this name. Add the
                    // missing types to curr.
                    let range_key = (key.clone(), 0.into());
                    let range = self.new_data.range(range_key..);
                    for ((r_name, r_type), _) in range {
                        if r_name != key {
                            break;
                        }
                        if add.contains(r_type) {
                            // Skip what we are trying to add.
                            continue;
                        }
                        curr.insert(*r_type);
                    }

                    let mut new = nsec_update_bitmap(
                        &record_nsec,
                        nsec,
                        &curr,
                        add,
                        delete,
                        &set_nsec_rrsig,
                        self,
                    );

                    // Sign the types at this name except for NSEC, and RRSIG.
                    new.remove(&Rtype::NSEC);
                    new.remove(&Rtype::RRSIG);
                    sign_rtype_set(key, &new, self)?;

                    // Names that were previously occluded are no longer.
                    nsec_clear_occluded(key, self)?;
                    continue;
                }
                if *key != self.origin && nsec.types().contains(Rtype::NS) {
                    // NS marks a delegation but only when the NS is not
                    // at the apex.

                    // If the add set contains DS then sign the DS RRset.
                    if add.contains(&Rtype::DS) {
                        let ds_set: HashSet<_> = [Rtype::DS].into();
                        sign_rtype_set(key, &ds_set, self)?;
                    }
                    nsec_update_bitmap(
                        &record_nsec,
                        nsec,
                        &curr,
                        add,
                        delete,
                        &set_nsec_rrsig,
                        self,
                    );
                    continue;
                }

                // The add types need to be signed.
                sign_rtype_set(key, add, self)?;

                nsec_update_bitmap(
                    &record_nsec,
                    nsec,
                    &curr,
                    add,
                    delete,
                    &set_nsec_rrsig,
                    self,
                );
            } else {
                if add.is_empty() {
                    assert!(!delete.is_empty());
                    // No need to do anything.
                    continue;
                }
                assert!(delete.is_empty());
                if is_occluded(key, self) {
                    // No need to do anything.
                    continue;
                }

                if add.contains(&Rtype::NS) {
                    // Create a new NSEC record and sign only DS records (if any).
                    let rtypebitmap = nsec_rtypebitmap_from_iterator(add.iter());
                    nsec_insert(key, rtypebitmap, self);
                    if add.contains(&Rtype::DS) {
                        let ds_set: HashSet<_> = [Rtype::DS].into();
                        sign_rtype_set(key, &ds_set, self)?;
                    }

                    // nsec_set_occluded expects the NSEC for key to exist.
                    // So call this after inserting the new NSEC record.
                    nsec_set_occluded(key, self);
                    continue;
                }
                // Create a new NSEC record and sign all records.
                let rtypebitmap = nsec_rtypebitmap_from_iterator(add.iter());
                nsec_insert(key, rtypebitmap, self);
                sign_rtype_set(key, add, self)?;
            }
        }
        Ok(())
    }

    fn incremental_nsec3(&mut self) -> Result<(), SignerError> {
        // Should changes be sorted or not? If changes is sorted we will
        // process a new delegation before any glue. Which is more efficient.
        // Otherwise if glue comes first, the glue will be signed and inserted
        // in the NSEC chain only to be removed when the delegation is processed.
        // However, we removing a delegation, the situation is reversed. For now
        // assuming that sorting is not necessary.

        let opt_out_flag = self.nsec3param.opt_out_flag();

        let changes = self.changes.clone();
        for (key, (add, delete)) in &changes {
            // The intersection between add and delete is empty.
            assert!(add.intersection(delete).next().is_none());

            let (nsec3_hash_octets, nsec3_name) = nsec3_hash_parts(key, self);

            if let Some(record_nsec3) = self.nsec3s.get(&nsec3_name) {
                let record_nsec3 = record_nsec3.clone();
                let ZoneRecordData::Nsec3(nsec3) = record_nsec3.data() else {
                    panic!("NSEC3 record expected");
                };

                // Convert the existing RRtype bitmap into a hash set.
                let mut curr = HashSet::new();
                for rtype in nsec3.types() {
                    curr.insert(rtype);
                }

                // The intersection between curr and add is empty.
                assert!(curr.intersection(add).next().is_none());

                // delete is completely contained in curr. In other words the
                // difference between delete and curr is empty.
                assert!(delete.difference(&curr).next().is_none());

                if add.contains(&Rtype::NS) {
                    // Apex is special, but we can assume the NS RRset will not
                    // be added to apex.
                    assert!(*key != self.origin);

                    // Remove the signatures for the existing types.
                    for rtype in nsec3.types().iter() {
                        // When NS is added, we should keep the signatures for
                        // DS. Do not try to remove a signature for RRSIG because
                        // it does not exist.
                        if rtype == Rtype::DS || rtype == Rtype::RRSIG {
                            continue;
                        }
                        let key = (key.clone(), rtype);
                        self.rrsigs.remove(&key);
                    }

                    // Restrict curr and add to these types.
                    let mask: HashSet<Rtype> = [Rtype::NS, Rtype::DS, Rtype::RRSIG].into();

                    let curr = curr.intersection(&mask).copied().collect();
                    let add = add.intersection(&mask).copied().collect();

                    // Update the NSEC3 record.
                    nsec3_update_bitmap(key, &record_nsec3, nsec3, &curr, &add, delete, self);

                    // Mark descendents as occluded after updating the bitmap.
                    // The reason is that nsec3_update_bitmap uses the current
                    // next_hash and nsec3_set_occluded may change that.
                    nsec3_set_occluded(key, self);

                    continue;
                }
                if delete.contains(&Rtype::NS) {
                    // Apex is special, but we can assume the NS RRset will not
                    // be removed from apex.
                    assert!(*key != self.origin);

                    // Curr does not include all types at this name. Add the
                    // missing types to curr.
                    let range_key = (key.clone(), 0.into());
                    let range = self.new_data.range(range_key..);
                    for ((r_name, r_type), _) in range {
                        if r_name != key {
                            break;
                        }
                        if add.contains(r_type) {
                            // Skip what we are trying to add.
                            continue;
                        }
                        curr.insert(*r_type);
                    }

                    let mut new =
                        nsec3_update_bitmap(key, &record_nsec3, nsec3, &curr, add, delete, self);

                    // Sign the types at this name except for NSEC, and RRSIG.
                    new.remove(&Rtype::RRSIG);
                    sign_rtype_set(key, &new, self)?;

                    // Names that were previously occluded are no longer.
                    nsec3_clear_occluded(key, self)?;
                    continue;
                }
                if *key != self.origin && nsec3.types().contains(Rtype::NS) {
                    // NS marks a delegation but only when the NS is not
                    // at the apex.

                    // If the add set contains DS then sign the DS RRset.
                    if add.contains(&Rtype::DS) {
                        let ds_set: HashSet<_> = [Rtype::DS].into();
                        sign_rtype_set(key, &ds_set, self)?;
                    }
                    nsec3_update_bitmap(key, &record_nsec3, nsec3, &curr, add, delete, self);
                    continue;
                }

                // The add types need to be signed.
                sign_rtype_set(key, add, self)?;

                nsec3_update_bitmap(key, &record_nsec3, nsec3, &curr, add, delete, self);
            } else {
                if add.is_empty() {
                    assert!(!delete.is_empty());

                    // Special magic for out-out. It is possible that an NS
                    // record got deleted. With opt-out there will not be an
                    // NSEC3 record if there is only a NS record and no DS record.
                    if opt_out_flag && delete.contains(&Rtype::NS) {
                        if is_occluded(key, self) {
                            // No need to do anything.
                            continue;
                        }
                        nsec3_clear_occluded(key, self)?;
                        continue;
                    }

                    // No need to do anything.
                    continue;
                }
                assert!(delete.is_empty());
                if is_occluded(key, self) {
                    // No need to do anything.
                    continue;
                }

                // Just copy add in case we need to change it.
                let mut add = add.clone();
                if opt_out_flag {
                    // We have a new record and no NSEC3 record exists. But in the
                    // case of opt-out there may already be an NS record.
                    // We are not at APEX because APEX always has an NSEC3
                    // record.
                    let tmpkey = (key.clone(), Rtype::NS);
                    if self.new_data.contains_key(&tmpkey) {
                        // Found an NS record. It is safe to add NS to the add
                        // set.
                        add.insert(Rtype::NS);
                    }
                }

                if add.contains(&Rtype::NS) {
                    if opt_out_flag {
                        // Check if this is just an NS record. If so, don't
                        // create an NSEC3 record.
                        if !add.iter().any(|r| *r != Rtype::NS) {
                            continue;
                        }
                    }
                    // Create a new NSEC3 record and sign only DS records (if any).
                    // If add contains DS then add RRSIG to add.

                    let mut add = add.clone(); // In case we need to add RRSIG.
                    if add.contains(&Rtype::DS) {
                        let ds_set: HashSet<_> = [Rtype::DS].into();
                        sign_rtype_set(key, &ds_set, self)?;
                        add.insert(Rtype::RRSIG);
                    }

                    let rtypebitmap = nsec3_rtypebitmap_from_iterator(add.iter());

                    nsec3_insert_full(key, nsec3_hash_octets, &nsec3_name, rtypebitmap, self);
                    nsec3_set_occluded(key, self);
                    continue;
                }
                // The new name is not a delegation. Add RRSIG to the set of
                // Rtypes.
                let mut add_with_rrsig = add.clone();
                add_with_rrsig.insert(Rtype::RRSIG);

                // Create a new NSEC3 record and sign all records.
                let rtypebitmap = nsec3_rtypebitmap_from_iterator(add_with_rrsig.iter());
                nsec3_insert_full(key, nsec3_hash_octets, &nsec3_name, rtypebitmap, self);
                sign_rtype_set(key, &add, self)?;
            }
        }
        Ok(())
    }

    fn remove_nsec_nsec3(&mut self) {
        for k in self.nsecs.keys() {
            let key = (k.clone(), Rtype::NSEC);
            self.rrsigs.remove(&key);
        }
        self.nsecs = BTreeMap::new();

        for k in self.nsec3s.keys() {
            let key = (k.clone(), Rtype::NSEC3);
            self.rrsigs.remove(&key);
        }
        self.nsec3s = BTreeMap::new();
    }

    fn new_nsec_chain(&mut self) -> Result<(), SignerError> {
        let records = self.get_unsigned_sorted();
        let records_iter = RecordsIter::new_from_refs(&records);
        let config = GenerateNsecConfig::new();
        let nsec_records = generate_nsecs(&self.origin, records_iter, &config)
            .map_err(|e| SignerError::SigningError(format!("new_nsec_chain failed: {e}")))?;

        // Collect signatures here.
        let mut new_sigs = vec![];

        for r in nsec_records {
            let record = Record::new(
                r.owner().clone(),
                r.class(),
                r.ttl(),
                ZoneRecordData::Nsec(r.data().clone()),
            );
            self.nsecs.insert(record.owner().clone(), record.clone());
            sign_records(
                &self.origin,
                &[record],
                &self.keys,
                self.inception,
                self.expiration,
                &mut new_sigs,
            )?;
        }
        for (sig, rtype) in new_sigs {
            let key = (sig[0].owner().clone(), rtype);
            self.rrsigs.insert(key, sig);
        }
        Ok(())
    }

    fn new_nsec3_chain(&mut self) -> Result<(), SignerError> {
        let records = self.get_unsigned_sorted();
        let records_iter = RecordsIter::new_from_refs(&records);
        let config = GenerateNsec3Config::<_, DefaultSorter>::new(self.nsec3param.clone())
            .with_ttl_mode(Nsec3ParamTtlMode::SoaMinimum);
        let nsec3_records = generate_nsec3s(&self.origin, records_iter, &config)
            .map_err(|e| SignerError::SigningError(format!("generate_nsec3s failed: {e}")))?;

        // Collect signatures here.
        let mut new_sigs = vec![];

        let r = nsec3_records.nsec3param;
        let record = Record::new(
            r.owner().clone(),
            r.class(),
            r.ttl(),
            ZoneRecordData::Nsec3param(r.data().clone()),
        );
        let key = (record.owner().clone(), Rtype::NSEC3PARAM);
        let records = vec![record.clone()];

        // Insert in both old and new data.
        sign_records(
            &self.origin,
            &[record],
            &self.keys,
            self.inception,
            self.expiration,
            &mut new_sigs,
        )?;
        self.old_data.insert(key.clone(), records.clone());
        self.new_data.insert(key, records);

        for r in nsec3_records.nsec3s {
            let record = Record::new(
                r.owner().clone(),
                r.class(),
                r.ttl(),
                ZoneRecordData::Nsec3(r.data().clone()),
            );
            self.nsec3s.insert(record.owner().clone(), record.clone());
            sign_records(
                &self.origin,
                &[record],
                &self.keys,
                self.inception,
                self.expiration,
                &mut new_sigs,
            )?;
        }
        for (sig, rtype) in new_sigs {
            let key = (sig[0].owner().clone(), rtype);
            self.rrsigs.insert(key, sig);
        }
        Ok(())
    }

    fn get_unsigned_sorted(&self) -> Vec<&Zrd> {
        // Create a Vec with all unsigned records to be able to sort them in
        // canonical order.

        let mut apex: Vec<_> = self.old_apex.values().flatten().collect();
        let mut data: Vec<_> = self.old_data.values().flatten().collect();
        data.append(&mut apex);
        data.par_sort_by(|e1, e2| CanonicalOrd::canonical_cmp(*e1, *e2));

        data
    }
}

fn is_occluded(name: &Name<Bytes>, iss: &IncrementalSigningState) -> bool {
    // We need to check if the parent of name is a delegation. Stop
    // when we reached origin.
    let Some(mut curr) = name.parent() else {
        // We asked for the parent of the root. That is weird. Just
        // return not occluded.
        return false;
    };
    loop {
        if curr == iss.origin {
            // We reached apex. The name was not occluded.
            return false;
        }
        if !curr.ends_with(&iss.origin) {
            // Something weird is going on. Return not occluded.
            return false;
        }
        if iss.new_data.contains_key(&(curr.clone(), Rtype::NS)) {
            // Name is occluded.
            return true;
        }
        let Some(parent) = curr.parent() else {
            // We asked for the parent of the root. That is weird. Just
            // return not occluded.
            return false;
        };
        curr = parent;
    }
}

fn sign_rtype_set(
    name: &Name<Bytes>,
    set: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) -> Result<(), SignerError> {
    let mut new_sigs = vec![];
    for rtype in set {
        let key = (name.clone(), *rtype);
        let Some(records) = (if *name == iss.origin {
            iss.new_apex.get(&key.1)
        } else {
            iss.new_data.get(&key)
        }) else {
            panic!("Expected something for {name}/{rtype}");
        };
        sign_records(
            &iss.origin,
            records,
            &iss.keys,
            iss.inception,
            iss.expiration,
            &mut new_sigs,
        )?;
    }
    for (sig, rtype) in new_sigs {
        let key = (sig[0].owner().clone(), rtype);
        iss.rrsigs.insert(key, sig);
    }
    Ok(())
}

fn sign_records(
    origin: &Name<Bytes>,
    records: &[Zrd],
    keys: &[SigningKey<Bytes, KeyPair>],
    inception: Timestamp,
    expiration: Timestamp,
    new_sigs: &mut Vec<(Vec<Zrd>, Rtype)>,
) -> Result<(), SignerError> {
    let rtype = records[0].rtype();
    if (rtype == Rtype::DNSKEY || rtype == Rtype::CDS || rtype == Rtype::CDNSKEY)
        && records[0].owner() == origin
    {
        // These records get signed with the KSK(s). Don't touch
        // the signatures.
        return Ok(());
    }

    let rrset = Rrset::new_from_owned(records)
        .map_err(|e| SignerError::SigningError(format!("Rrset::new failed: {e}")))?;
    let mut rrsig_records = vec![];
    for key in keys {
        let rrsig = sign_rrset(key, &rrset, inception, expiration)
            .map_err(|e| SignerError::SigningError(format!("signing failed: {e}")))?;
        let record = Record::new(
            rrsig.owner().clone(),
            rrsig.class(),
            rrsig.ttl(),
            ZoneRecordData::Rrsig(rrsig.data().clone()),
        );
        rrsig_records.push(record);
    }
    new_sigs.push((rrsig_records, rrset.rtype()));
    Ok(())
}

fn nsec_insert(
    name: &Name<Bytes>,
    rtypebitmap: RtypeBitmap<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    // Try to find the NSEC record that comes before the one we are trying
    // to insert. Assume that the APEX NSEC will always exist can sort
    // before anything else.
    let mut range = iss.nsecs.range::<Name<_>, _>(..name);
    let (previous_name, previous_record) = range
        .next_back()
        .expect("previous NSEC record should exist");
    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    drop(range);
    let ZoneRecordData::Nsec(previous_nsec) = previous_record.data() else {
        panic!("NSEC record expected");
    };
    let next = previous_nsec.next_name();
    let new_nsec = Nsec::new(next.clone(), rtypebitmap);
    let new_record = Record::new(
        name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec(new_nsec),
    );
    iss.nsecs.insert(name.clone(), new_record);
    iss.modified_nsecs.insert(name.clone());
    let previous_nsec = Nsec::new(name.clone(), previous_nsec.types().clone());
    let previous_record = Record::new(
        previous_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec(previous_nsec),
    );
    iss.nsecs.insert(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
}

fn nsec_remove(name: &Name<Bytes>, next_name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Try to find the NSEC record that comes before the one we are trying
    // to remove. Assume that the APEX NSEC will always exist can sort
    // before anything else.
    let mut range = iss.nsecs.range::<Name<_>, _>(..name);
    let (previous_name, previous_record) = range
        .next_back()
        .expect("previous NSEC record should exist");
    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    drop(range);
    let ZoneRecordData::Nsec(previous_nsec) = previous_record.data() else {
        panic!("NSEC record expected");
    };
    let previous_nsec = Nsec::new(next_name.clone(), previous_nsec.types().clone());
    let previous_record = Record::new(
        previous_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec(previous_nsec),
    );
    iss.nsecs.insert(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
    iss.nsecs.remove(name);
    iss.modified_nsecs.remove(name);
    let key = (name.clone(), Rtype::NSEC);
    iss.rrsigs.remove(&key);
}

// Return the effective result HashSet even when the NSEC record gets deleted.
fn nsec_update_bitmap(
    record: &Zrd,
    nsec: &Nsec<Bytes, Name<Bytes>>,
    curr: &HashSet<Rtype>,
    add: &HashSet<Rtype>,
    delete: &HashSet<Rtype>,
    set_nsec_rrsig: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) -> HashSet<Rtype> {
    // Update curr.
    let curr: HashSet<_> = curr.union(add).copied().collect();
    let curr = curr.difference(delete).copied().collect();

    let owner = record.owner();
    if curr == *set_nsec_rrsig {
        nsec_remove(owner, nsec.next_name(), iss);
        return curr;
    }

    let rtypebitmap = nsec_rtypebitmap_from_iterator(curr.iter());
    let nsec = Nsec::new(nsec.next_name().clone(), rtypebitmap);
    let record = Record::new(
        record.owner().clone(),
        record.class(),
        record.ttl(),
        ZoneRecordData::Nsec(nsec),
    );
    iss.nsecs.insert(owner.clone(), record);

    iss.modified_nsecs.insert(owner.clone());
    curr
}

fn nsec_set_occluded(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    let Some(nsec_record) = iss.nsecs.get(name) else {
        panic!("NSEC for {name} expected to exist");
    };
    let ZoneRecordData::Nsec(nsec) = nsec_record.data() else {
        panic!("NSEC record expected");
    };
    let nsec = nsec.clone();
    let mut next = nsec.next_name().clone();
    loop {
        if !next.ends_with(name) {
            break;
        }

        // For consistency, make sure next is not equal to name.
        if next == name {
            break;
        }
        let curr = next;
        let Some(nsec_record) = iss.nsecs.get(&curr) else {
            panic!("NSEC for {name} expected to exist");
        };
        let ZoneRecordData::Nsec(nsec) = nsec_record.data() else {
            panic!("NSEC record expected");
        };
        let nsec = nsec.clone();
        next = nsec.next_name().clone();

        nsec_remove(&curr, &next, iss);

        // Remove all signatures.
        for rtype in nsec.types().iter() {
            let key = (curr.clone(), rtype);
            iss.rrsigs.remove(&key);
        }
    }
}

fn nsec_clear_occluded(
    name: &Name<Bytes>,
    iss: &mut IncrementalSigningState,
) -> Result<(), SignerError> {
    let key = (name.clone(), Rtype::SOA);
    let range = iss.new_data.range(key..);
    let mut opt_curr_name: Option<&Name<Bytes>> = None;
    let mut curr_types: HashSet<Rtype> = HashSet::new();
    let mut work = vec![];

    // Keep track of delegations. Name below a delegation remain occluded.
    let mut delegation: Option<Name<Bytes>> = None;

    for ((key_name, key_rtype), _) in range {
        // There is no easy way to avoid name showing up in the range. Just
        // filter out name.
        if key_name == name {
            continue;
        }

        // Make sure curr_name is below name.
        if !key_name.ends_with(name) {
            break;
        }
        if let Some(d) = &delegation
            && key_name.ends_with(d)
            && key_name != d
        {
            // Skip.
            continue;
        }

        if *key_rtype == Rtype::NS {
            // Set key_name as a delegation.
            delegation = Some(key_name.clone());
        }
        if let Some(curr_name) = opt_curr_name {
            if key_name == curr_name {
                curr_types.insert(*key_rtype);
            } else {
                work.push((curr_name.clone(), curr_types));
                opt_curr_name = Some(key_name);
                curr_types = [*key_rtype].into();
            }
        } else {
            opt_curr_name = Some(key_name);
            curr_types.insert(*key_rtype);
        }
    }
    if let Some(curr_name) = opt_curr_name {
        work.push((curr_name.clone(), curr_types));
    }
    for (curr_name, curr_types) in work {
        let mut curr_types = if curr_types.contains(&Rtype::NS) {
            let has_ds = curr_types.contains(&Rtype::DS);
            let mut curr_types: HashSet<Rtype> = [Rtype::NS].into();
            if has_ds {
                curr_types.insert(Rtype::DS);
            }
            curr_types
        } else {
            curr_types
        };
        let rtypebitmap = nsec_rtypebitmap_from_iterator(curr_types.iter());

        // Make sure NS doesn't get signed.
        curr_types.remove(&Rtype::NS);
        sign_rtype_set(&curr_name, &curr_types, iss)?;
        nsec_insert(&curr_name, rtypebitmap, iss);
    }
    Ok(())
}

fn nsec_rtypebitmap_from_iterator<'a, I>(iter: I) -> RtypeBitmap<Bytes>
where
    I: Iterator<Item = &'a Rtype>,
{
    let mut rtypebitmap = RtypeBitmap::<Bytes>::builder();
    rtypebitmap.add(Rtype::NSEC).expect("should not fail");
    rtypebitmap.add(Rtype::RRSIG).expect("should not fail");
    for rtype in iter {
        rtypebitmap.add(*rtype).expect("should not fail");
    }
    rtypebitmap.finalize()
}

fn nsec3_update(
    owner: &Name<Bytes>,
    nsec3_record: &Zrd,
    nsec3: &Nsec3<Bytes>,
    rtypes: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) {
    // Just update an NSEC3 record without further logic.
    let rtypebitmap = nsec3_rtypebitmap_from_iterator(rtypes.iter());
    let nsec3 = Nsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt().clone(),
        nsec3.next_owner().clone(),
        rtypebitmap,
    );
    let record = Record::new(
        nsec3_record.owner().clone(),
        nsec3_record.class(),
        nsec3_record.ttl(),
        ZoneRecordData::Nsec3(nsec3),
    );
    iss.nsec3s.insert(owner.clone(), record);

    iss.modified_nsecs.insert(owner.clone());
}

fn nsec3_remove_full(
    name: &Name<Bytes>,
    nsec3_name: &Name<Bytes>,
    nsec3_next: &OwnerHash<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    nsec3_remove_one(nsec3_name, nsec3_next, iss);

    // Assume that we never remove the APEX. So the parent always exists.
    let name = name.parent().expect("should exist");
    nsec3_remove_et(&name, iss);
}

fn nsec3_remove_et(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Check if name is an ET. If so remove it and see if the parent is
    // also an ET.
    //
    // Take a simple approach to check if a name is an ET: first lookup
    // the NSEC3 record for name and check that the bitmap is empty. Then
    // check all descendent names and check that none of them has an
    // NSEC3 record.
    let mut name = name.clone();
    loop {
        if !name.ends_with(&iss.origin) {
            // This is weird, we should never be able to get beyond APEX.
            // Just ignore this.
            return;
        }
        if name == iss.origin {
            // Never remove the NSEC3 record for APEX.
            return;
        }

        let (_, nsec3_name) = nsec3_hash_parts(&name, iss);

        let Some(record_nsec3) = iss.nsec3s.get(&nsec3_name) else {
            // No NSEC3 record, nothing to do.
            return;
        };

        let ZoneRecordData::Nsec3(nsec3) = record_nsec3.data() else {
            panic!("NSEC3 record expected");
        };

        if !nsec3.types().is_empty() {
            // There are types here.
            return;
        }

        // Check the descendents.
        let key = (name.clone(), Rtype::SOA);
        let range = iss.new_data.range(key..);
        let mut opt_curr_name: Option<&Name<Bytes>> = None;

        for ((key_name, _), _) in range {
            // There is no easy way to avoid name showing up in the range. Just
            // filter out name.
            if *key_name == name {
                continue;
            }

            // Make sure curr_name is below name.
            if !key_name.ends_with(&name) {
                break;
            }

            if let Some(curr_name) = opt_curr_name
                && key_name == curr_name
            {
                // Already checked.
                continue;
            }

            opt_curr_name = Some(key_name);

            let (_, nsec3_name) = nsec3_hash_parts(key_name, iss);

            if iss.nsec3s.contains_key(&nsec3_name) {
                // NSEC3 record is found. Our target is not an ET.
                return;
            };
        }

        // No descendents with NSEC3 records are found. Delete this one.
        let next_owner = nsec3.next_owner().clone();
        nsec3_remove_one(&nsec3_name, &next_owner, iss);

        // We remove the NSEC3 record for the name. Get the parent. We should
        // be below APEX, so the parent has to exist.
        name = name.parent().expect("parent should exist");
    }
}

fn nsec3_remove_one(
    nsec3_name: &Name<Bytes>,
    nsec3_next: &OwnerHash<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    // Try to find the NSEC3 record that comes before the one we are trying
    // to remove.
    let mut range = iss.nsec3s.range::<Name<_>, _>(..nsec3_name);
    let (previous_name, previous_record) = if let Some(kv) = range.next_back() {
        kv
    } else {
        let mut range = iss.nsec3s.range::<Name<_>, _>(nsec3_name..);
        range
            .next_back()
            .expect("at least one element should exist")
    };

    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    drop(range);
    let ZoneRecordData::Nsec3(previous_nsec) = previous_record.data() else {
        panic!("NSEC3 record expected");
    };
    let previous_nsec3 = Nsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt().clone(),
        nsec3_next.clone(),
        previous_nsec.types().clone(),
    );
    let previous_record = Record::new(
        previous_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec3(previous_nsec3),
    );
    iss.nsec3s.insert(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
    iss.nsec3s.remove(nsec3_name);
    iss.modified_nsecs.remove(nsec3_name);
    let key = (nsec3_name.clone(), Rtype::NSEC3);
    iss.rrsigs.remove(&key);
}

fn nsec3_set_occluded(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Loop over all names below name, if there is an NSEC3 record then
    // delete all signatures and the NSEC3 record.

    let key = (name.clone(), Rtype::SOA);
    let range = iss.new_data.range(key..);
    let mut opt_curr_name: Option<&Name<Bytes>> = None;
    let mut work = vec![];

    for ((key_name, _), _) in range {
        // There is no easy way to avoid name showing up in the range. Just
        // filter out name.
        if key_name == name {
            continue;
        }

        // Make sure curr_name is below name.
        if !key_name.ends_with(name) {
            break;
        }

        if let Some(curr_name) = opt_curr_name
            && key_name == curr_name
        {
            // Looked at this name already.
            continue;
        }

        opt_curr_name = Some(key_name);

        let (_, nsec3_name) = nsec3_hash_parts(key_name, iss);

        let Some(record_nsec3) = iss.nsec3s.get(&nsec3_name) else {
            // No NSEC3 record, nothing to do.
            continue;
        };

        let ZoneRecordData::Nsec3(nsec3) = record_nsec3.data() else {
            panic!("NSEC3 record expected");
        };

        work.push((key_name.clone(), nsec3_name));

        // Remove all signatures.
        for rtype in nsec3.types().iter() {
            let key = (key_name.clone(), rtype);
            iss.rrsigs.remove(&key);
        }
    }
    for (key_name, nsec3_name) in work {
        let record_nsec3 = iss.nsec3s.get(&nsec3_name).expect("NSEC3 should exist");

        let ZoneRecordData::Nsec3(nsec3) = record_nsec3.data() else {
            panic!("NSEC3 record expected");
        };

        let nsec3_next = nsec3.next_owner().clone();
        nsec3_remove_full(&key_name, &nsec3_name, &nsec3_next, iss);
    }
}

fn nsec3_clear_occluded(
    name: &Name<Bytes>,
    iss: &mut IncrementalSigningState,
) -> Result<(), SignerError> {
    let key = (name.clone(), Rtype::SOA);
    let range = iss.new_data.range(key..);
    let mut opt_curr_name: Option<&Name<Bytes>> = None;
    let mut curr_types: HashSet<Rtype> = HashSet::new();
    let mut work = vec![];

    // Keep track of delegations. Name below a delegation remain occluded.
    let mut delegation: Option<Name<Bytes>> = None;

    for ((key_name, key_rtype), _) in range {
        // There is no easy way to avoid name showing up in the range. Just
        // filter out name.
        if key_name == name {
            continue;
        }

        // Make sure curr_name is below name.
        if !key_name.ends_with(name) {
            break;
        }
        if let Some(d) = &delegation
            && key_name.ends_with(d)
            && key_name != d
        {
            // Skip.
            continue;
        }

        if *key_rtype == Rtype::NS {
            // Set key_name as a delegation.
            delegation = Some(key_name.clone());
        }
        if let Some(curr_name) = opt_curr_name {
            if key_name == curr_name {
                curr_types.insert(*key_rtype);
            } else {
                work.push((curr_name.clone(), curr_types));
                opt_curr_name = Some(key_name);
                curr_types = [*key_rtype].into();
            }
        } else {
            opt_curr_name = Some(key_name);
            curr_types.insert(*key_rtype);
        }
    }
    if let Some(curr_name) = opt_curr_name {
        work.push((curr_name.clone(), curr_types));
    }
    for (curr_name, mut curr_types) in work {
        let mut curr_types = if curr_types.contains(&Rtype::NS) {
            let has_ds = curr_types.contains(&Rtype::DS);
            let mut curr_types: HashSet<Rtype> = [Rtype::NS].into();
            if has_ds {
                curr_types.insert(Rtype::DS);
                curr_types.insert(Rtype::RRSIG);
            }
            curr_types
        } else {
            curr_types.insert(Rtype::RRSIG);
            curr_types
        };
        let rtypebitmap = nsec3_rtypebitmap_from_iterator(curr_types.iter());

        // Make sure NS doesn't get signed. And avoid signing RRSIGs.
        curr_types.remove(&Rtype::NS);
        curr_types.remove(&Rtype::RRSIG);
        sign_rtype_set(&curr_name, &curr_types, iss)?;

        let (nsec3_hash_octets, nsec3_name) = nsec3_hash_parts(&curr_name, iss);

        nsec3_insert_full(&curr_name, nsec3_hash_octets, &nsec3_name, rtypebitmap, iss);
    }
    Ok(())
}

fn nsec3_insert_full(
    name: &Name<Bytes>,
    nsec3_hash: OwnerHash<Bytes>,
    nsec3_name: &Name<Bytes>,
    rtypebitmap: RtypeBitmap<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    nsec3_insert_one(nsec3_hash, nsec3_name, rtypebitmap, iss);

    // Assume that we never insert the APEX. So the parent always exists.
    let name = name.parent().expect("should exist");
    nsec3_insert_ent(&name, iss);
}

fn nsec3_insert_ent(name: &Name<Bytes>, iss: &mut IncrementalSigningState) {
    // Check if name has an NSEC3 record. If so, we are done. Otherwise,
    // insert an ENT and continue with the parent.
    let mut name = name.clone();
    loop {
        if !name.ends_with(&iss.origin) {
            // This is weird, we should never be able to get beyond APEX.
            // Just ignore this.
            return;
        }
        if name == iss.origin {
            // APEX exists by definition.
            return;
        }

        let (nsec3_hash_octets, nsec3_name) = nsec3_hash_parts(&name, iss);

        if iss.nsec3s.contains_key(&nsec3_name) {
            // Found something. We are done.
            return;
        }

        let rtypebitmap = RtypeBitmap::<Bytes>::builder();
        let rtypebitmap = rtypebitmap.finalize();
        nsec3_insert_one(nsec3_hash_octets, &nsec3_name, rtypebitmap, iss);

        // Get the parent. We should be below APEX, so the parent has to exist.
        name = name.parent().expect("parent should exist");
    }
}

fn nsec3_insert_one(
    nsec3_hash: OwnerHash<Bytes>,
    nsec3_name: &Name<Bytes>,
    rtypebitmap: RtypeBitmap<Bytes>,
    iss: &mut IncrementalSigningState,
) {
    // Try to find the NSEC3 record that comes before the one we are trying
    // to insert. It is possible that we try to insert before the first NSEC3
    // record. In that case, logically try to insert after the last NSEC3
    // record.
    let mut range = iss.nsec3s.range::<Name<_>, _>(..nsec3_name);
    let (previous_name, previous_record) = if let Some(kv) = range.next_back() {
        kv
    } else {
        let mut range = iss.nsec3s.range::<Name<_>, _>(nsec3_name..);
        range
            .next_back()
            .expect("at least one element should exist")
    };
    let previous_name = previous_name.clone();
    let previous_record = previous_record.clone();
    drop(range);
    let ZoneRecordData::Nsec3(previous_nsec3) = previous_record.data() else {
        panic!("NSEC3 record expected");
    };
    let next = previous_nsec3.next_owner();
    let new_nsec3 = Nsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt().clone(),
        next.clone(),
        rtypebitmap,
    );
    let new_record = Record::new(
        nsec3_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec3(new_nsec3),
    );
    iss.nsec3s.insert(nsec3_name.clone(), new_record);
    iss.modified_nsecs.insert(nsec3_name.clone());
    let previous_nsec3 = Nsec3::new(
        iss.nsec3param.hash_algorithm(),
        iss.nsec3param.flags(),
        iss.nsec3param.iterations(),
        iss.nsec3param.salt().clone(),
        nsec3_hash,
        previous_nsec3.types().clone(),
    );
    let previous_record = Record::new(
        previous_name.clone(),
        previous_record.class(),
        previous_record.ttl(),
        ZoneRecordData::Nsec3(previous_nsec3),
    );
    iss.nsec3s.insert(previous_name.clone(), previous_record);
    iss.modified_nsecs.insert(previous_name.clone());
}

// Return the effective result HashSet even when the NSEC3 record gets deleted.
fn nsec3_update_bitmap(
    name: &Name<Bytes>,
    nsec3_record: &Zrd,
    nsec3: &Nsec3<Bytes>,
    curr: &HashSet<Rtype>,
    add: &HashSet<Rtype>,
    delete: &HashSet<Rtype>,
    iss: &mut IncrementalSigningState,
) -> HashSet<Rtype> {
    // Update curr.
    let curr: HashSet<_> = curr.union(add).copied().collect();
    let mut curr: HashSet<_> = curr.difference(delete).copied().collect();
    let owner = nsec3_record.owner();

    // Check if we need to add or remove RRSIG. Assume that apex has a SOA
    // record.
    if curr.contains(&Rtype::NS) && !curr.contains(&Rtype::SOA) {
        // For an NS not at origin, there is an RRSIG if there is also a
        // DS record.
        if curr.contains(&Rtype::DS) {
            // Yes, add RRSIG.
            curr.insert(Rtype::RRSIG);
        } else {
            // No. Remove RRSIG.
            curr.remove(&Rtype::RRSIG);
        }
    } else {
        // Is there anything apart from RRSIG?
        if curr.iter().any(|r| *r != Rtype::RRSIG) {
            // Yes. Add RRSIG.
            curr.insert(Rtype::RRSIG);
        } else {
            // No. Remove RRSIG.
            curr.remove(&Rtype::RRSIG);
        }
    }

    if curr.is_empty() {
        // The NSEC3 bitmp will be empty, but this may now have become an
        // empty non-terminal. Our only option is to update the NSEC3 record
        // and then call nsec3_remove_et to see if it is empty can can be
        // removed.
        nsec3_update(owner, nsec3_record, nsec3, &curr, iss);
        nsec3_remove_et(name, iss);
        return curr;
    }

    if iss.nsec3param.opt_out_flag() && !curr.iter().any(|r| *r != Rtype::NS) {
        // The new bitmap has nothing except for NS. We would like to delete
        // the NSEC3. However there may still be descendents that need to be
        // removed with nsec3_set_occluded. Update this NSEC3 to be empty and
        // call nsec3_remove_et to remove it if there are no descendents.

        let empty_curr = HashSet::new();
        nsec3_update(owner, nsec3_record, nsec3, &empty_curr, iss);
        nsec3_remove_et(name, iss);
        return curr;
    }

    nsec3_update(owner, nsec3_record, nsec3, &curr, iss);
    curr
}

fn nsec3_rtypebitmap_from_iterator<'a, I>(iter: I) -> RtypeBitmap<Bytes>
where
    I: Iterator<Item = &'a Rtype>,
{
    let mut rtypebitmap = RtypeBitmap::<Bytes>::builder();
    for rtype in iter {
        rtypebitmap.add(*rtype).expect("should not fail");
    }
    rtypebitmap.finalize()
}

fn nsec3_hash_parts(
    name: &Name<Bytes>,
    iss: &IncrementalSigningState,
) -> (OwnerHash<Bytes>, Name<Bytes>) {
    let nsec3_hash_octets = OwnerHash::<Bytes>::octets_from(
        nsec3_hash::<_, _, BytesMut>(
            name,
            iss.nsec3param.hash_algorithm(),
            iss.nsec3param.iterations(),
            iss.nsec3param.salt(),
        )
        .expect("should not fail"),
    );
    let nsec3_hash_base32 = base32::encode_string_hex(&nsec3_hash_octets).to_ascii_lowercase();
    let mut builder = NameBuilder::<BytesMut>::new();
    builder
        .append_label(nsec3_hash_base32.as_bytes())
        .expect("should not fail");
    let nsec3_name = builder.append_origin(&iss.origin).expect("should not fail");
    (nsec3_hash_octets, nsec3_name)
}

pub fn faketime_or_now() -> UnixTime {
    match var("CASCADE_FAKETIME") {
        Ok(val) => val.parse::<Timestamp>().unwrap().into(),
        Err(VarError::NotPresent) => UnixTime::now(),
        Err(_e) => panic!("Cannot parse CASCADE_FAKETIME"),
    }
}

#[derive(Clone, Debug)]
pub enum SignerError {
    SoaNotFound,
    SignerNotReady,
    InternalError(String),
    KeepSerialPolicyViolated,
    CannotReadStateFile(String),
    CannotReadPrivateKeyFile(String),
    CannotReadPublicKeyFile(String),
    InvalidKeyPairComponents(String),
    InvalidPublicKeyUrl(String),
    InvalidPrivateKeyUrl(String),
    KmipServerCredentialsNeeded(String),
    CannotCreateKmipConnectionPool(String, KmipConnError),
    SigningError(String),
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerError::SoaNotFound => f.write_str("SOA not found"),
            SignerError::SignerNotReady => f.write_str("Signer not ready"),
            SignerError::InternalError(err) => write!(f, "Internal error: {err}"),
            SignerError::KeepSerialPolicyViolated => {
                f.write_str("Serial policy is Keep but upstream serial did not increase")
            }
            SignerError::CannotReadStateFile(path) => {
                write!(f, "Failed to read state file '{path}'")
            }
            SignerError::CannotReadPrivateKeyFile(path) => {
                write!(f, "Failed to read private key file '{path}'")
            }
            SignerError::CannotReadPublicKeyFile(path) => {
                write!(f, "Failed to read public key file '{path}'")
            }
            SignerError::InvalidKeyPairComponents(err) => {
                write!(
                    f,
                    "Failed to create a key pair from private and public keys: {err}"
                )
            }
            SignerError::InvalidPublicKeyUrl(err) => {
                write!(f, "Invalid public key URL: {err}")
            }
            SignerError::InvalidPrivateKeyUrl(err) => {
                write!(f, "Invalid private key URL: {err}")
            }
            SignerError::KmipServerCredentialsNeeded(server_id) => {
                write!(f, "No credentials available for KMIP server '{server_id}'")
            }
            SignerError::CannotCreateKmipConnectionPool(server_id, err) => {
                write!(
                    f,
                    "Cannot create connection pool for KMIP server '{server_id}': {err}"
                )
            }
            SignerError::SigningError(err) => write!(f, "Signing error: {err}"),
        }
    }
}
