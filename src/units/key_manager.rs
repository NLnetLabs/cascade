use crate::api;
use crate::api::{FileKeyImport, KeyImport, KmipKeyImport};
use crate::center::{Center, ZoneAddError};
use crate::manager::record_zone_event;
use crate::policy::{KeyParameters, PolicyVersion};
use crate::units::http_server::KmipServerState;
use crate::util::AbortOnDrop;
use crate::zone::{HistoricalEvent, SigningTrigger};
use bytes::Bytes;
use camino::{Utf8Path, Utf8PathBuf};
use cascade_api::keyset::{KeyRollCommand, KeyRollVariant};
use core::time::Duration;
use domain::base::Name;
use domain::base::iana::Class;
use domain::dnssec::sign::keys::keyset::{KeySet, UnixTime};
use domain::zonetree::StoredName;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::Formatter;
use std::fs::{File, OpenOptions, metadata};
use std::io::{BufReader, BufWriter, ErrorKind, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

//------------ KeyManager ----------------------------------------------------

/// The key manager.
#[derive(Debug)]
pub struct KeyManager {
    ks_info: Mutex<HashMap<String, KeySetInfo>>,
}

impl KeyManager {
    #[expect(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            ks_info: Default::default(),
        }
    }

    /// Launch the key manager.
    pub fn run(center: Arc<Center>) -> AbortOnDrop {
        // Perform periodic ticks in the background.
        AbortOnDrop::from(tokio::task::spawn({
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(5));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    center.key_manager.tick(&center).await;
                }
            }
        }))
    }

    pub async fn on_register_zone(
        &self,
        center: &Arc<Center>,
        name: Name<Bytes>,
        policy: String,
        key_imports: Vec<KeyImport>,
    ) -> Result<(), ZoneAddError> {
        let center = center.clone();
        let res = Self::register_zone(&center, name.clone(), policy, &key_imports).await;

        if let Err(err) = &res {
            error!("Registration of zone '{name}' failed: {err}");
        }

        res
    }

    pub async fn on_roll_key(
        &self,
        center: &Arc<Center>,
        zone: Name<Bytes>,
        roll_variant: KeyRollVariant,
        roll_cmd: KeyRollCommand,
    ) -> Result<(), String> {
        let center = center.clone();
        let mut cmd = Self::keyset_cmd(&center, zone, RecordingMode::Record);

        cmd.arg(match roll_variant {
            api::keyset::KeyRollVariant::Ksk => "ksk",
            api::keyset::KeyRollVariant::Zsk => "zsk",
            api::keyset::KeyRollVariant::Csk => "csk",
            api::keyset::KeyRollVariant::Algorithm => "algorithm",
        });

        match roll_cmd {
            api::keyset::KeyRollCommand::StartRoll => {
                cmd.arg("start-roll");
            }
            api::keyset::KeyRollCommand::Propagation1Complete { ttl } => {
                cmd.arg("propagation1-complete").arg(ttl.to_string());
            }
            api::keyset::KeyRollCommand::CacheExpired1 => {
                cmd.arg("cache-expired1");
            }
            api::keyset::KeyRollCommand::Propagation2Complete { ttl } => {
                cmd.arg("propagation2-complete").arg(ttl.to_string());
            }
            api::keyset::KeyRollCommand::CacheExpired2 => {
                cmd.arg("cache-expired2");
            }
            api::keyset::KeyRollCommand::RollDone => {
                cmd.arg("roll-done");
            }
        }

        if let Err(KeySetCommandError { err, output, .. }) = cmd.output().await {
            error!("key roll command failed: {err}");
            return Err(format_cmd_error(&err, output));
        }

        Ok(())
    }

    pub async fn on_remove_key(
        &self,
        center: &Arc<Center>,
        zone: StoredName,
        key: String,
        force: bool,
        continue_flag: bool,
    ) -> Result<(), String> {
        let center = center.clone();
        let mut cmd = Self::keyset_cmd(&center, zone, RecordingMode::Record);

        cmd.arg("remove-key").arg(key);

        if force {
            cmd.arg("--force");
        }

        if continue_flag {
            cmd.arg("--continue");
        }

        if let Err(KeySetCommandError { err, output, .. }) = cmd.output().await {
            error!("key removal command failed: {err}");
            return Err(format_cmd_error(&err, output));
        }

        Ok(())
    }

    pub async fn on_status(
        &self,
        center: &Arc<Center>,
        zone: StoredName,
    ) -> Result<String, String> {
        let center = center.clone();
        let res = Self::keyset_cmd(&center, zone, RecordingMode::RecordOnlyOnWarningOrError)
            .arg("status")
            .arg("-v")
            .output()
            .await;
        match res {
            Err(KeySetCommandError { err, output, .. }) => {
                // The dnst keyset status command failed.
                error!("key status command failed: {err}");
                Err(format_cmd_error(&err, output))
            }

            Ok(output) => {
                let mut status = String::from_utf8_lossy(&output.stdout).to_string();

                // Include any stderr output under a warning heading
                // in the status text that we send to the client.
                if !output.stderr.is_empty() {
                    status.push_str("Warning:\n");
                    status.push_str(&String::from_utf8_lossy(&output.stderr));
                }

                Ok(status)
            }
        }
    }

    pub fn on_zone_policy_changed(
        &self,
        center: &Arc<Center>,
        name: StoredName,
        old: Option<Arc<PolicyVersion>>,
        new: Arc<PolicyVersion>,
    ) {
        let center = center.clone();

        if let Some(old) = old
            && old.key_manager == new.key_manager
        {
            // Nothing changed.
            return;
        }

        tokio::spawn(async move {
            // Keep it simple, just send all config items to keyset even
            // if they didn't change.
            let config_commands = policy_to_commands(&new);
            for c in config_commands {
                let mut cmd = Self::keyset_cmd(&center, name.clone(), RecordingMode::Record);
                cmd.arg("set");

                for a in c {
                    cmd.arg(a);
                }

                let res = cmd.output().await;

                // Use match to make sure the pattern s exhaustive.
                #[allow(clippy::single_match)]
                match res {
                    Err(KeySetCommandError { err, output, .. }) => {
                        error!("{}", format_cmd_error(&err, output));
                        return;
                    }
                    Ok(_) => (),
                }
            }
        });
    }

    async fn register_zone(
        center: &Arc<Center>,
        name: Name<Bytes>,
        policy_name: String,
        key_imports: &[KeyImport],
    ) -> Result<(), ZoneAddError> {
        // Lookup the policy for the zone to see if it uses a KMIP
        // server.
        let policy;
        let kmip_server_id;
        {
            let state = center.state.lock().unwrap();
            policy = state
                .policies
                .get(policy_name.as_str())
                .ok_or(ZoneAddError::NoSuchPolicy)?
                .clone();
            kmip_server_id = policy.latest.key_manager.hsm_server_id.clone();
        };

        let kmip_server_state_dir = &center.config.kmip_server_state_dir;
        let kmip_credentials_store_path = &center.config.kmip_credentials_store_path;

        // Check if the zone already exist. If it does we should not be
        // here and panic. For the moment, assume there is a bug and
        // return an error.
        let zone_tree = &center.unsigned_zones.load();
        let zone = zone_tree.get_zone(&name, Class::IN);
        if zone.is_some() {
            return Err(ZoneAddError::Other(format!("zone {name} already exists")));
        }

        let state_path = mk_dnst_keyset_state_file_path(&center.config.keys_dir, &name);

        let mut cmd = Self::keyset_cmd(center, name.clone(), RecordingMode::Record);

        cmd.arg("create")
            .arg("-n")
            .arg(name.to_string())
            .arg("-s")
            .arg(&state_path)
            .output()
            .await
            .map_err(|err| ZoneAddError::Other(err.err))?;

        // TODO: If we fail after this point, what should we do with whatever
        // changes `dnst keyset create` made on disk? Will leaving them behind
        // mean that a subsequent attempt to again create the zone after
        // resolving whatever failure occurred below will then fail because
        // the `dnst keyset create`d state already exists?

        if let Some(kmip_server_id) = kmip_server_id {
            let kmip_server_state_path = kmip_server_state_dir.join(kmip_server_id);

            debug!("Reading KMIP server state from '{kmip_server_state_path}'");
            let f = File::open(&kmip_server_state_path)
                .map_err(|err| ZoneAddError::Other(format!("Unable to open KMIP server state file '{kmip_server_state_path}' for reading: {err}")))?;
            let kmip_server: KmipServerState = serde_json::from_reader(f).map_err(|err| {
                ZoneAddError::Other(format!(
                    "Unable to read KMIP server state from file '{kmip_server_state_path}': {err}"
                ))
            })?;

            let KmipServerState {
                server_id,
                ip_host_or_fqdn,
                port,
                insecure,
                connect_timeout,
                read_timeout,
                write_timeout,
                max_response_bytes,
                key_label_prefix,
                key_label_max_bytes,
                has_credentials,
            } = kmip_server;

            let mut cmd = Self::keyset_cmd(center, name.clone(), RecordingMode::Record);

            cmd.arg("kmip")
                .arg("add-server")
                .arg(server_id.clone())
                .arg(ip_host_or_fqdn)
                .arg("--port")
                .arg(port.to_string())
                .arg("--connect-timeout")
                .arg(format!("{}s", connect_timeout.as_secs()))
                .arg("--read-timeout")
                .arg(format!("{}s", read_timeout.as_secs()))
                .arg("--write-timeout")
                .arg(format!("{}s", write_timeout.as_secs()))
                .arg("--max-response-bytes")
                .arg(max_response_bytes.to_string())
                .arg("--key-label-max-bytes")
                .arg(key_label_max_bytes.to_string());

            if insecure {
                cmd.arg("--insecure");
            }

            if has_credentials {
                cmd.arg("--credential-store")
                    .arg(kmip_credentials_store_path.as_str());
            }

            if let Some(key_label_prefix) = key_label_prefix {
                cmd.arg("--key-label-prefix").arg(key_label_prefix);
            }

            // TODO: --client-cert, --client-key, --server-cert and --ca-cert
            cmd.output()
                .await
                .map_err(|err| ZoneAddError::Other(err.err))?;
        }

        // Pass `set` and `import` commands to `dnst keyset`.
        let config_commands = imports_to_commands(key_imports).into_iter().chain(
            policy_to_commands(&policy.latest).into_iter().map(|v| {
                let mut final_cmd = vec!["set".into()];
                final_cmd.extend(v);
                final_cmd
            }),
        );

        for c in config_commands {
            let mut cmd = Self::keyset_cmd(center, name.clone(), RecordingMode::Record);

            for a in c {
                cmd.arg(a);
            }

            cmd.output()
                .await
                .map_err(|err| ZoneAddError::Other(err.err))?;
        }

        // TODO: This should not happen immediately after
        // `keyset create` but only once the zone is enabled.
        // We currently do not have a good mechanism for that
        // so we init the key immediately.
        Self::keyset_cmd(center, name.clone(), RecordingMode::Record)
            .arg("init")
            .output()
            .await
            .map_err(|err| ZoneAddError::Other(err.err))?;

        Ok(())
    }

    /// Create a keyset command with the config file for the given zone.
    fn keyset_cmd(
        center: &Arc<Center>,
        name: StoredName,
        recording_mode: RecordingMode,
    ) -> KeySetCommand {
        KeySetCommand::new(
            name,
            center.clone(),
            center.config.keys_dir.clone(),
            center.config.dnst_binary_path.clone(),
            recording_mode,
        )
    }

    async fn tick(&self, center: &Arc<Center>) {
        let zone_tree = &center.unsigned_zones;
        let Ok(mut ks_info) = self.ks_info.try_lock() else {
            // An existing call to tick() is still busy, don't do anything.
            return;
        };
        for zone in zone_tree.load().iter_zones() {
            let apex_name = zone.apex_name().to_string();
            let state_path =
                mk_dnst_keyset_state_file_path(&center.config.keys_dir, zone.apex_name());
            if !state_path.exists() {
                continue;
            }

            let info = match ks_info.entry(apex_name.clone()) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    match KeySetInfo::try_from(&state_path) {
                        Ok(new_info) => entry.insert(new_info.clone()),
                        Err(err) => {
                            error!(
                                "[KM]: Failed to load key set state for zone '{apex_name}': {err}"
                            );
                            continue;
                        }
                    }
                }
            };

            let keyset_state_modified = match file_modified(&state_path) {
                Ok(modified) => modified,
                Err(err) => {
                    error!("[KM]: {err}");
                    continue;
                }
            };
            if keyset_state_modified != info.keyset_state_modified {
                // Keyset state file is modified. Update our data and
                // signal the signer to re-sign the zone.
                let new_info = match KeySetInfo::try_from(&state_path) {
                    Ok(info) => info,
                    Err(err) => {
                        error!("[KM]: {err}");
                        continue;
                    }
                };
                let _ = ks_info.insert(apex_name, new_info);
                info!("[CC]: Instructing zone signer to re-sign the zone");
                center.signer.on_sign_zone(
                    center,
                    zone.apex_name().clone(),
                    None,
                    SigningTrigger::ExternallyModifiedKeySetState,
                );
                continue;
            }

            let Some(ref cron_next) = info.cron_next else {
                continue;
            };

            if *cron_next < UnixTime::now() {
                // Note: The call to keyset cron can take a long time if
                // keyset times out trying to contact nameservers. This will
                // block the loop so we won't check the keyset state for the
                // next zone till after the call to cron finishes.
                let Ok(res) =
                    Self::keyset_cmd(center, zone.apex_name().clone(), RecordingMode::Record)
                        .arg("cron")
                        .output()
                        .await
                else {
                    info.clear_cron_next();
                    continue;
                };

                if res.status.success() {
                    // We expect cron to change the state file. If
                    // that is the case, get a new KeySetInfo and notify
                    // the signer.
                    let new_info = match KeySetInfo::try_from(&state_path) {
                        Ok(info) => info,
                        Err(err) => {
                            error!("[KM]: {err}");
                            continue;
                        }
                    };
                    if new_info.keyset_state_modified != info.keyset_state_modified {
                        // Something happened. Update ks_info and signal the
                        // signer.
                        // let new_info = get_keyset_info(&state_path);
                        let _ = ks_info.insert(apex_name, new_info);
                        info!("[CC]: Instructing zone signer to re-sign the zone");
                        center.signer.on_sign_zone(
                            center,
                            zone.apex_name().clone(),
                            None,
                            SigningTrigger::KeySetModifiedAfterCron,
                        );
                        continue;
                    }

                    // Nothing happened. Assume that the timing could be off.
                    // Try again in a minute. After a few tries log an error
                    // and give up.
                    info.retry_after(Duration::from_secs(60));
                    if info.retries >= CRON_MAX_RETRIES {
                        error!(
                            "The command 'dnst keyset cron' failed to update state file {state_path}",
                        );
                        info.clear_cron_next();
                    }
                } else {
                    info.clear_cron_next();
                }
            }
        }
    }
}

fn format_cmd_error(err: &str, output: Option<Output>) -> String {
    format!(
        "{err}:\nstdout:\n{}\nstderr:\n{}",
        output
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default(),
        output
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
            .unwrap_or_default()
    )
}

pub fn mk_dnst_keyset_cfg_file_path(keys_dir: &Utf8Path, name: &Name<Bytes>) -> Utf8PathBuf {
    // Note: Zone name to file name handling needs work as we shouldn't
    // have to lowercase this here (if we don't the dnst keyset state file
    // for an uppercase zone name won't be found) but also in general we
    // don't handle characters that are legal in zone names but not in
    // file names.
    keys_dir.join(format!("{}.cfg", name.to_string().to_lowercase()))
}

pub fn mk_dnst_keyset_state_file_path(keys_dir: &Utf8Path, name: &Name<Bytes>) -> Utf8PathBuf {
    // Note: Zone name to file name handling needs work as we shouldn't
    // have to lowercase this here (if we don't the dnst keyset state file
    // for an uppercase zone name won't be found) but also in general we
    // don't handle characters that are legal in zone names but not in
    // file names.
    keys_dir.join(format!("{}.state", name.to_string().to_lowercase()))
}

//------------ KeySetInfo ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct KeySetInfo {
    keyset_state_modified: UnixTime,
    cron_next: Option<UnixTime>,
    retries: u32,
}

impl KeySetInfo {
    fn clear_cron_next(&mut self) {
        self.cron_next = None;
        self.retries = 0;
    }

    fn retry_after(&mut self, after: Duration) {
        if let Some(cron_next) = self.cron_next.take() {
            self.cron_next = Some(cron_next + after);
        }
        self.retries += 1;
    }
}

impl TryFrom<&Utf8PathBuf> for KeySetInfo {
    type Error = String;

    fn try_from(state_path: &Utf8PathBuf) -> Result<Self, Self::Error> {
        // Get the modified time of the state file before we read
        // state file itself. This is safe if there is a concurrent
        // update.
        let keyset_state_modified = file_modified(state_path)?;

        /// Persistent state for the keyset command.
        /// Copied from the keyset branch of dnst.
        #[allow(dead_code)]
        #[derive(Deserialize)]
        struct KeySetState {
            /// Domain KeySet state.
            keyset: KeySet,

            dnskey_rrset: Vec<String>,
            ds_rrset: Vec<String>,
            cds_rrset: Vec<String>,
            ns_rrset: Vec<String>,
            cron_next: Option<UnixTime>,
        }

        let state = std::fs::read_to_string(state_path)
            .map_err(|err| format!("Failed to read file '{state_path}': {err}"))?;
        let state: KeySetState = serde_json::from_str(&state).map_err(|err| {
            format!("Failed to parse keyset JSON from file '{state_path}': {err}")
        })?;

        Ok(KeySetInfo {
            keyset_state_modified,
            cron_next: state.cron_next,
            retries: 0,
        })
    }
}

// Maximum number of times to try the cron command when the state file does
// not change.
const CRON_MAX_RETRIES: u32 = 5;

fn file_modified(filename: impl AsRef<Path>) -> Result<UnixTime, String> {
    let md = metadata(&filename).map_err(|err| {
        format!(
            "Failed to query metadata for file '{}': {err}",
            filename.as_ref().display()
        )
    })?;
    let modified = md.modified().map_err(|err| {
        format!(
            "Failed to query modified timestamp for file '{}': {err}",
            filename.as_ref().display()
        )
    })?;
    modified
        .try_into()
        .map_err(|err| format!("Failed to query modified timestamp for file '{}': unable to convert from SystemTime: {err}", filename.as_ref().display()))
}

macro_rules! strs {
    ($($e:expr),*$(,)?) => {
        vec![$($e.to_string()),*]
    };
}

fn policy_to_commands(policy: &PolicyVersion) -> Vec<Vec<String>> {
    let km = &policy.key_manager;

    let mut algorithm_cmd = vec!["algorithm".to_string()];
    match km.algorithm {
        KeyParameters::RsaSha256(bits) => {
            algorithm_cmd.extend(strs!["RSASHA256", "-b", bits]);
        }
        KeyParameters::RsaSha512(bits) => {
            algorithm_cmd.extend(strs!["RSASHA512", "-b", bits]);
        }
        KeyParameters::EcdsaP256Sha256
        | KeyParameters::EcdsaP384Sha384
        | KeyParameters::Ed25519
        | KeyParameters::Ed448 => algorithm_cmd.push(km.algorithm.to_string()),
    };

    let validity = |x| match x {
        Some(validity) => format!("{validity}s"),
        None => "off".to_string(),
    };

    let seconds = |x| format!("{x}s");

    vec![
        strs!["use-csk", km.use_csk],
        algorithm_cmd,
        strs!["ksk-validity", validity(km.ksk_validity)],
        strs!["zsk-validity", validity(km.zsk_validity)],
        strs!["csk-validity", validity(km.csk_validity)],
        strs![
            "auto-ksk",
            km.auto_ksk.start,
            km.auto_ksk.report,
            km.auto_ksk.expire,
            km.auto_ksk.done,
        ],
        strs![
            "auto-zsk",
            km.auto_zsk.start,
            km.auto_zsk.report,
            km.auto_zsk.expire,
            km.auto_zsk.done,
        ],
        strs![
            "auto-csk",
            km.auto_csk.start,
            km.auto_csk.report,
            km.auto_csk.expire,
            km.auto_csk.done,
        ],
        strs![
            "auto-algorithm",
            km.auto_algorithm.start,
            km.auto_algorithm.report,
            km.auto_algorithm.expire,
            km.auto_algorithm.done,
        ],
        strs![
            "dnskey-inception-offset",
            seconds(km.dnskey_inception_offset),
        ],
        strs!["dnskey-lifetime", seconds(km.dnskey_signature_lifetime),],
        strs!["dnskey-remain-time", seconds(km.dnskey_remain_time)],
        strs!["cds-inception-offset", seconds(km.cds_inception_offset)],
        strs!["cds-lifetime", seconds(km.cds_signature_lifetime)],
        strs!["cds-remain-time", seconds(km.cds_remain_time)],
        strs!["ds-algorithm", km.ds_algorithm],
        strs!["default-ttl".to_string(), km.default_ttl.as_secs(),],
        strs!["autoremove", km.auto_remove],
    ]
}

//============ KMIP Credential Management ====================================
// Copied from dnst keyset. TODO: Share the code via a separate Rust crate.

//------------ KmipClientCredentialsConfig -----------------------------------

/// Optional disk file based credentials for connecting to a KMIP server.
pub struct KmipClientCredentialsConfig {
    pub credentials_store_path: PathBuf,
    pub credentials: Option<KmipClientCredentials>,
}

//------------ KmipClientCredentials -----------------------------------------

/// Credentials for connecting to a KMIP server.
///
/// Intended to be read from a JSON file stored separately to the main
/// configuration so that separate security policy can be applied to sensitive
/// credentials.
#[derive(Debug, Deserialize, Serialize)]
pub struct KmipClientCredentials {
    /// KMIP username credential.
    ///
    /// Mandatory if the KMIP "Credential Type" is "Username and Password".
    ///
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613458
    pub username: String,

    /// KMIP password credential.
    ///
    /// Optional when KMIP "Credential Type" is "Username and Password".
    ///
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613458
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub password: Option<String>,
}

//------------ KmipClientCredentialSet ---------------------------------------

/// A set of KMIP server credentials.
#[derive(Debug, Default, Deserialize, Serialize)]
struct KmipClientCredentialsSet(HashMap<String, KmipClientCredentials>);

//------------ KmipClientCredentialsFileMode ---------------------------------

/// The access mode to use when accessing a credentials file.
#[derive(Debug)]
pub enum KmipServerCredentialsFileMode {
    /// Open an existing credentials file for reading. Saving will fail.
    ReadOnly,

    /// Open an existing credentials file for reading and writing.
    ReadWrite,

    /// Open or create the credentials file for reading and writing.
    CreateReadWrite,
}

//--- impl Display

impl std::fmt::Display for KmipServerCredentialsFileMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KmipServerCredentialsFileMode::ReadOnly => write!(f, "read-only"),
            KmipServerCredentialsFileMode::ReadWrite => write!(f, "read-write"),
            KmipServerCredentialsFileMode::CreateReadWrite => write!(f, "create-read-write"),
        }
    }
}

//------------ KmipServerCredentialsFile -------------------------------------

/// A KMIP server credential set file.
#[derive(Debug)]
pub struct KmipClientCredentialsFile {
    /// The file from which the credentials were loaded, and will be saved
    /// back to.
    file: File,

    /// The path from which the file was loaded. Used for generating error
    /// messages.
    path: PathBuf,

    /// The actual set of loaded credentials.
    credentials: KmipClientCredentialsSet,

    /// The read/write/create mode.
    #[allow(dead_code)]
    mode: KmipServerCredentialsFileMode,
}

impl KmipClientCredentialsFile {
    /// Load credentials from disk.
    ///
    /// Optionally:
    ///   - Create the file if missing.
    ///   - Keep the file open for writing back changes. See ['Self::save()`].
    pub fn new(path: &Path, mode: KmipServerCredentialsFileMode) -> Result<Self, String> {
        let read;
        let write;
        let create;

        match mode {
            KmipServerCredentialsFileMode::ReadOnly => {
                read = true;
                write = false;
                create = false;
            }
            KmipServerCredentialsFileMode::ReadWrite => {
                read = true;
                write = true;
                create = false;
            }
            KmipServerCredentialsFileMode::CreateReadWrite => {
                read = true;
                write = true;
                create = true;
            }
        }

        let file = OpenOptions::new()
            .read(read)
            .write(write)
            .create(create)
            .truncate(false)
            .open(path)
            .map_err(|e| {
                format!(
                    "unable to open KMIP credentials file {} in {mode} mode: {e}",
                    path.display()
                )
            })?;

        // Determine the length of the file as JSON parsing fails if the file
        // is completely empty.
        let len = file.metadata().map(|m| m.len()).map_err(|e| {
            format!(
                "unable to query metadata of KMIP credentials file {}: {e}",
                path.display()
            )
        })?;

        // Buffer reading as apparently JSON based file reading is extremely
        // slow without buffering, even for small files.
        let mut reader = BufReader::new(&file);

        // Load or create the credential set.
        let credentials: KmipClientCredentialsSet = if len > 0 {
            serde_json::from_reader(&mut reader).map_err(|e| {
                format!(
                    "error loading KMIP credentials file {:?}: {e}\n",
                    path.display()
                )
            })?
        } else {
            KmipClientCredentialsSet::default()
        };

        // Save the path for use in generating error messages.
        let path = path.to_path_buf();

        Ok(KmipClientCredentialsFile {
            file,
            path,
            credentials,
            mode,
        })
    }

    /// Write the credential set back to the file it was loaded from.
    pub fn save(&mut self) -> std::io::Result<()> {
        // Ensure that writing happens at the start of the file.
        self.file.seek(SeekFrom::Start(0))?;

        // Use a buffered writer as writing JSON to a file directly is
        // apparently very slow, even for small files.
        //
        // Enclose the use of the BufWriter in a block so that it is
        // definitely no longer using the file when we next act on it.
        {
            let mut writer = BufWriter::new(&self.file);
            serde_json::to_writer_pretty(&mut writer, &self.credentials).map_err(|e| {
                std::io::Error::other(format!(
                    "error writing KMIP credentials file {}: {e}",
                    self.path.display()
                ))
            })?;

            // Ensure that the BufWriter is flushed as advised by the
            // BufWriter docs.
            writer.flush()?;
        }

        // Truncate the file to the length of data we just wrote..
        let pos = self.file.stream_position()?;
        self.file.set_len(pos)?;

        // Ensure that any write buffers are flushed.
        self.file.flush()?;

        Ok(())
    }

    /// Does this credential set include credentials for the specified KMIP
    /// server.
    pub fn contains(&self, server_id: &str) -> bool {
        self.credentials.0.contains_key(server_id)
    }

    pub fn get(&self, server_id: &str) -> Option<&KmipClientCredentials> {
        self.credentials.0.get(server_id)
    }

    /// Add credentials for the specified KMIP server, replacing any that
    /// previously existed for the same server.-
    ///
    /// Returns any previous configuration if found.
    pub fn insert(
        &mut self,
        server_id: String,
        credentials: KmipClientCredentials,
    ) -> Option<KmipClientCredentials> {
        self.credentials.0.insert(server_id, credentials)
    }

    /// Remove any existing configuration for the specified KMIP server.
    ///
    /// Returns any previous configuration if found.
    pub fn remove(&mut self, server_id: &str) -> Option<KmipClientCredentials> {
        self.credentials.0.remove(server_id)
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.0.is_empty()
    }
}

/// A process command that doesn't block and records events in history.
struct AsyncHistoricalCommand {
    cmd: std::process::Command,
}

impl AsyncHistoricalCommand {
    fn new(cmd: std::process::Command) -> Self {
        Self { cmd }
    }

    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) {
        let _ = self.cmd.arg(arg);
    }

    pub async fn output(self) -> Result<KeySetCommandSuccess, KeySetCommandError> {
        // Remember the binary path and the entire command
        // string as these are only available until we convert
        // std::process::Command into tokio::process::Command while we
        // use them in error messages after that point.
        let binary_path = self.cmd.get_program().to_string_lossy().to_string();
        let cmd_string = format!(
            "{binary_path} {}",
            self.cmd
                .get_args()
                .map(|v| v.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );

        // Convert std::process::Command into tokio::process::Command so that
        // we can execute it without blocking the Tokio runtime.
        let mut cmd = tokio::process::Command::from(self.cmd);

        // Execute the command.
        debug!("Executing keyset command {cmd_string}");
        let output = cmd.output().await.map_err(|msg| {
            let mut err = format!("Keyset command '{cmd_string}' could not be executed: {msg}",);
            if matches!(msg.kind(), ErrorKind::NotFound) {
                err.push_str(&format!(" [path: {binary_path}]"));
            }
            error!("{err}");
            KeySetCommandError {
                cmd: cmd_string.clone(),
                err,
                output: None,
            }
        })?;

        if !output.status.success() {
            let err = format!(
                "Keyset command '{cmd_string}' returned non-zero exit code: {} [stdout={}, stderr={}]",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            error!("{err}");
            Err(KeySetCommandError {
                cmd: cmd_string,
                err,
                output: Some(output),
            })
        } else {
            let warning = match output.stderr.is_empty() {
                true => None,
                false => Some(String::from_utf8_lossy(&output.stderr).to_string()),
            };

            debug!(
                "Keyset command '{cmd_string}' stdout: {}",
                String::from_utf8_lossy(&output.stdout)
            );

            if let Some(warning) = &warning {
                warn!("Keyset command '{cmd_string}' stderr: {warning}");
            }

            Ok(KeySetCommandSuccess {
                cmd: cmd_string,
                output,
                warning,
            })
        }
    }
}

//------------ RecordingMode -------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordingMode {
    #[allow(dead_code)]
    DoNotRecord,
    Record,
    RecordOnlyOnWarningOrError,
}

pub struct KeySetCommand {
    cmd: Option<AsyncHistoricalCommand>,
    name: StoredName,
    center: Arc<Center>,
    recording_mode: RecordingMode,
}

pub struct KeySetCommandSuccess {
    cmd: String,
    output: Output,
    warning: Option<String>,
}

pub struct KeySetCommandError {
    cmd: String,
    err: String,
    output: Option<Output>,
}

impl From<KeySetCommandError> for String {
    fn from(err: KeySetCommandError) -> Self {
        err.err
    }
}

impl KeySetCommand {
    pub fn new(
        name: StoredName,
        center: Arc<Center>,
        #[allow(clippy::boxed_local)] keys_dir: Box<Utf8Path>,
        #[allow(clippy::boxed_local)] dnst_binary_path: Box<Utf8Path>,
        recording_mode: RecordingMode,
    ) -> Self {
        let cfg_path = mk_dnst_keyset_cfg_file_path(&keys_dir, &name);
        let mut cmd = std::process::Command::new(dnst_binary_path.as_std_path());
        cmd.arg("keyset").arg("-c").arg(&cfg_path);
        Self {
            cmd: Some(AsyncHistoricalCommand::new(cmd)),
            name,
            center,
            recording_mode,
        }
    }

    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut KeySetCommand {
        if let Some(c) = self.cmd.as_mut() {
            c.arg(arg)
        }
        self
    }

    pub async fn output(&mut self) -> Result<Output, KeySetCommandError> {
        let start = Instant::now();
        let res = self
            .cmd
            .take()
            .expect("Command has already been consumed")
            .output()
            .await;
        let elapsed = Instant::now().duration_since(start);

        let (res, history_event) = match res {
            Ok(KeySetCommandSuccess {
                cmd,
                output,
                warning,
            }) => {
                // Determine whether and what to record in zone history
                let record = match self.recording_mode {
                    RecordingMode::DoNotRecord => false,
                    RecordingMode::Record => true,
                    RecordingMode::RecordOnlyOnWarningOrError => warning.is_some(),
                };
                let history_event = record.then_some(HistoricalEvent::KeySetCommand {
                    cmd,
                    warning,
                    elapsed,
                });
                (Ok(output), history_event)
            }
            Err(err) => {
                let err_string = err.err.to_string();

                // Determine whether and what to record in zone history
                let record = match self.recording_mode {
                    RecordingMode::DoNotRecord => false,
                    RecordingMode::Record => true,
                    RecordingMode::RecordOnlyOnWarningOrError => true,
                };
                let history_event = record.then_some(HistoricalEvent::KeySetError {
                    cmd: err.cmd.clone(),
                    err: err_string,
                    elapsed,
                });
                (Err(err), history_event)
            }
        };

        if let Some(history_event) = history_event {
            // Record the error in the zone history
            record_zone_event(&self.center, &self.name, history_event, None);
        }

        res
    }
}

fn imports_to_commands(key_imports: &[KeyImport]) -> Vec<Vec<String>> {
    key_imports
        .iter()
        .map(|key| match key {
            KeyImport::PublicKey(path) => strs!["import", "public-key", path],
            KeyImport::Kmip(KmipKeyImport {
                key_type,
                server,
                public_id,
                private_id,
                algorithm,
                flags,
            }) => {
                strs![
                    "import", key_type, "kmip", server, public_id, private_id, algorithm, flags
                ]
            }
            KeyImport::File(FileKeyImport { key_type, path }) => {
                strs!["import", key_type, "file", path]
            }
        })
        .collect()
}
