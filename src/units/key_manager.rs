use crate::center::Center;
use crate::cli::commands::hsm::Error;
use crate::comms::{ApplicationCommand, Terminated};
use crate::payload::Update;
use crate::units::http_server::KmipServerState;
use bytes::Bytes;
use camino::Utf8Path;
use core::time::Duration;
use domain::base::Name;
use domain::dnssec::sign::keys::keyset::{KeySet, UnixTime};
use log::error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::{metadata, File, OpenOptions};
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use tokio::time::MissedTickBehavior;

#[derive(Debug)]
pub struct KeyManagerUnit {
    pub center: Arc<Center>,
}

impl KeyManagerUnit {
    pub async fn run(
        self,
        cmd_rx: mpsc::UnboundedReceiver<ApplicationCommand>,
    ) -> Result<(), Terminated> {
        // TODO: metrics and status reporting

        KeyManager::new(self.center).run(cmd_rx).await?;

        Ok(())
    }
}

//------------ KeyManager ----------------------------------------------------

struct KeyManager {
    center: Arc<Center>,
    ks_info: Mutex<HashMap<String, KeySetInfo>>,
    dnst_binary_path: Box<Utf8Path>,
    keys_dir: Box<Utf8Path>,
}

impl KeyManager {
    fn new(center: Arc<Center>) -> Self {
        let state = center.state.lock().unwrap();
        let dnst_binary_path = state.config.dnst_binary_path.clone();
        let keys_dir = state.config.keys_dir.clone();
        drop(state);

        Self {
            center,
            ks_info: Mutex::new(HashMap::new()),
            dnst_binary_path,
            keys_dir,
        }
    }

    async fn run(
        self,
        mut cmd_rx: mpsc::UnboundedReceiver<ApplicationCommand>,
    ) -> Result<(), crate::comms::Terminated> {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            select! {
                _ = interval.tick() => {
                    self.tick().await;
                }
                cmd = cmd_rx.recv() => {
                    self.run_cmd(cmd)?;
                }
            }
        }
    }

    fn run_cmd(&self, cmd: Option<ApplicationCommand>) -> Result<(), Terminated> {
        log::info!("[KM] Received command: {cmd:?}");

        match cmd {
            Some(ApplicationCommand::Terminate) | None => Err(Terminated),
            Some(ApplicationCommand::RegisterZone {
                register: crate::api::ZoneAdd { name, .. },
            }) => {
                let state_path = self.keys_dir.join(format!("{name}.state"));

                let mut cmd = self.keyset_cmd(&name);

                cmd.arg("create")
                    .arg("-n")
                    .arg(name.to_string())
                    .arg("-s")
                    .arg(&state_path);

                log::info!("Running {cmd:?}");

                let output = cmd.output().map_err(|e| {
                    error!("[KM]: Error creating keyset for {name}: {e}");
                    Terminated
                })?;
                if !output.status.success() {
                    error!("[KM]: Create command failed for {name}: {}", output.status);
                    error!(
                        "[KM]: Create stdout {}",
                        String::from_utf8_lossy(&output.stdout)
                    );
                    error!(
                        "[KM]: Create stderr {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    return Err(Terminated);
                }

                // Lookup the policy for the zone to see if it uses a KMIP
                // server.
                let (kmip_server_id, kmip_server_state_dir, kmip_credentials_store_path) = {
                    let state = self.center.state.lock().unwrap();
                    let zone = state.zones.get(&name).unwrap();
                    let zone_state = zone.0.state.lock().unwrap();
                    let kmip_server_id = if let Some(policy) = &zone_state.policy {
                        policy.key_manager.hsm_server_id.clone()
                    } else {
                        None
                    };
                    let kmip_server_state_dir = state.config.kmip_server_state_dir.clone();
                    let kmip_credentials_store_path =
                        state.config.kmip_credentials_store_path.clone();
                    (
                        kmip_server_id,
                        kmip_server_state_dir,
                        kmip_credentials_store_path,
                    )
                };

                if let Some(kmip_server_id) = kmip_server_id {
                    let p = kmip_server_state_dir.join(kmip_server_id);
                    log::info!("Reading KMIP server state from '{p}'");
                    let f = std::fs::File::open(p).unwrap();
                    let kmip_server: KmipServerState = serde_json::from_reader(f).unwrap();
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

                    let mut cmd = self.keyset_cmd(&name);

                    // TODO: This command should get issued _after_ keyset create
                    // but _before_ keyset init, both of which are issued above.
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

                    log::info!("Running {cmd:?}");

                let output = cmd.output().map_err(|e| {
                    error!("[KM]: Error adding KMIP server '{server_id}' for {name}: {e}");
                    Terminated
                })?;
                if !output.status.success() {
                    error!("[KM]: Add KMIP server command failed for {name}: {}", output.status);
                    error!(
                        "[KM]: Create stdout {}",
                        String::from_utf8_lossy(&output.stdout)
                    );
                    error!(
                        "[KM]: Create stderr {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    return Err(Terminated);
                }
                }

                // Set config
                let config_commands = policy_to_commands(&self.center, &name);
                for c in config_commands {
                    let mut cmd = self.keyset_cmd(&name);

                    cmd.arg("set");
                    for a in c {
                        cmd.arg(a);
                    }

                    log::info!("Running {cmd:?}");

                    let output = cmd.output().map_err(|e| {
                        error!("[KM]: keyset command failed for {name}: {e}");
                        Terminated
                    })?;
                    if !output.status.success() {
                        error!("[KM]: set command failed for {name}: {}", output.status);
                        error!(
                            "[KM]: Create stdout {}",
                            String::from_utf8_lossy(&output.stdout)
                        );
                        error!(
                            "[KM]: Create stderr {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        return Err(Terminated);
                    }
                }

                // TODO: This should not happen immediately after
                // `keyset create` but only once the zone is enabled.
                // We currently do not have a good mechanism for that
                // so we init the key immediately.
                let mut cmd = self.keyset_cmd(&name);
                cmd.arg("init");

                log::info!("Running {cmd:?}");

                let output = cmd.output().map_err(|e| {
                    error!("[KM]: Error initializing keyset for {name}: {e}");
                    Terminated
                })?;
                if !output.status.success() {
                    error!("[KM]: init command failed for {name}: {}", output.status);
                    error!(
                        "[KM]: Create stdout {}",
                        String::from_utf8_lossy(&output.stdout)
                    );
                    error!(
                        "[KM]: Create stderr {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    return Err(Terminated);
                }

                Ok(())
            }
            Some(_) => Ok(()), // not for us
        }
    }

    /// Create a keyset command with the config file for the given zone
    fn keyset_cmd(&self, name: impl Display) -> Command {
        let cfg_path = self.keys_dir.join(format!("{name}.cfg"));
        let mut cmd = Command::new(self.dnst_binary_path.as_std_path());
        cmd.arg("keyset").arg("-c").arg(&cfg_path);
        cmd
    }

    async fn tick(&self) {
        let zone_tree = &self.center.unsigned_zones;
        let mut ks_info = self.ks_info.lock().await;
        for zone in zone_tree.load().iter_zones() {
            let apex_name = zone.apex_name().to_string();
            let state_path = self.keys_dir.join(format!("{apex_name}.state"));
            if !state_path.exists() {
                continue;
            }

            let info = ks_info.get(&apex_name);
            let Some(info) = info else {
                let value = get_keyset_info(state_path);
                let _ = ks_info.insert(apex_name, value);
                continue;
            };

            let keyset_state_modified = file_modified(&state_path).unwrap();
            if keyset_state_modified != info.keyset_state_modified {
                // Keyset state file is modified. Update our data and
                // signal the signer to re-sign the zone.
                let new_info = get_keyset_info(&state_path);
                let _ = ks_info.insert(apex_name, new_info);
                self.center
                    .update_tx
                    .send(Update::ResignZoneEvent {
                        zone_name: zone.apex_name().clone(),
                    })
                    .unwrap();
                continue;
            }

            let Some(ref cron_next) = info.cron_next else {
                continue;
            };

            if *cron_next < UnixTime::now() {
                println!("Invoking keyset cron for zone {apex_name}");
                let Ok(res) = self.keyset_cmd(&apex_name).arg("cron").output() else {
                    error!(
                        "Failed to invoke keyset binary at '{}",
                        self.dnst_binary_path
                    );

                    // Clear cron_next.
                    let info = KeySetInfo {
                        cron_next: None,
                        keyset_state_modified: info.keyset_state_modified.clone(),
                        retries: 0,
                    };
                    let _ = ks_info.insert(apex_name, info);
                    continue;
                };

                if res.status.success() {
                    println!("CRON OUT: {}", String::from_utf8_lossy(&res.stdout));

                    // We expect cron to change the state file. If
                    // that is the case, get a new KeySetInfo and notify
                    // the signer.
                    let new_info = get_keyset_info(&state_path);
                    if new_info.keyset_state_modified != info.keyset_state_modified {
                        // Something happened. Update ks_info and signal the
                        // signer.
                        let new_info = get_keyset_info(&state_path);
                        let _ = ks_info.insert(apex_name, new_info);
                        self.center
                            .update_tx
                            .send(Update::ResignZoneEvent {
                                zone_name: zone.apex_name().clone(),
                            })
                            .unwrap();
                        continue;
                    }

                    // Nothing happened. Assume that the timing could be off.
                    // Try again in a minute. After a few tries log an error
                    // and give up.
                    let cron_next = cron_next.clone() + Duration::from_secs(60);
                    let new_info = KeySetInfo {
                        cron_next: Some(cron_next),
                        keyset_state_modified: info.keyset_state_modified.clone(),
                        retries: info.retries + 1,
                    };
                    if new_info.retries >= CRON_MAX_RETRIES {
                        error!(
                            "The command 'dnst keyset cron' failed to update state file {state_path}", 
                        );

                        // Clear cron_next.
                        let info = KeySetInfo {
                            cron_next: None,
                            keyset_state_modified: info.keyset_state_modified.clone(),
                            retries: 0,
                        };
                        let _ = ks_info.insert(apex_name, info);
                        continue;
                    }
                    let _ = ks_info.insert(apex_name, new_info);
                    continue;
                } else {
                    println!("CRON ERR: {}", String::from_utf8_lossy(&res.stderr));
                    // Clear cron_next.
                    let info = KeySetInfo {
                        cron_next: None,
                        keyset_state_modified: info.keyset_state_modified.clone(),
                        retries: 0,
                    };
                    let _ = ks_info.insert(apex_name, info);
                }
            }
        }
    }
}

//------------ KeySetInfo ----------------------------------------------------

#[derive(Clone)]
pub struct KeySetInfo {
    keyset_state_modified: UnixTime,
    cron_next: Option<UnixTime>,
    retries: u32,
}

// Maximum number of times to try the cron command when the state file does
// not change.
const CRON_MAX_RETRIES: u32 = 5;

fn file_modified(filename: impl AsRef<Path>) -> Result<UnixTime, String> {
    let md = metadata(filename).unwrap();
    let modified = md.modified().unwrap();
    modified
        .try_into()
        .map_err(|e| format!("unable to convert from SystemTime: {e}"))
}

fn get_keyset_info(state_path: impl AsRef<Path>) -> KeySetInfo {
    // Get the modified time of the state file before we read
    // state file itself. This is safe if there is a concurrent
    // update.
    let keyset_state_modified = file_modified(&state_path).unwrap();

    /// Persistent state for the keyset command.
    /// Copied frmo the keyset branch of dnst.
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

    let state = std::fs::read_to_string(state_path).unwrap();
    let state: KeySetState = serde_json::from_str(&state).unwrap();

    KeySetInfo {
        keyset_state_modified,
        cron_next: state.cron_next,
        retries: 0,
    }
}

fn policy_to_commands(center: &Center, zone_name: &Name<Bytes>) -> Vec<Vec<String>> {
    // Ensure that the mutexes are locked only in this block;
    let policy = {
        let state = center.state.lock().unwrap();
        let zone = state.zones.get(zone_name).unwrap();
        let zone_state = zone.0.state.lock().unwrap();
        zone_state.policy.clone()
    }
    .unwrap();

    let km = &policy.key_manager;

    vec![
        vec!["use-csk".to_string(), km.use_csk.to_string()],
        vec!["algorithm".to_string(), km.algorithm.to_string()],
        vec![
            "ksk-validity".to_string(),
            if let Some(validity) = km.ksk_validity {
                validity.to_string() + "s"
            } else {
                "off".to_string()
            },
        ],
        vec![
            "zsk-validity".to_string(),
            if let Some(validity) = km.zsk_validity {
                validity.to_string() + "s"
            } else {
                "off".to_string()
            },
        ],
        vec![
            "csk-validity".to_string(),
            if let Some(validity) = km.csk_validity {
                validity.to_string() + "s"
            } else {
                "off".to_string()
            },
        ],
        vec![
            "auto-ksk".to_string(),
            km.auto_ksk.start.to_string(),
            km.auto_ksk.report.to_string(),
            km.auto_ksk.expire.to_string(),
            km.auto_ksk.done.to_string(),
        ],
        vec![
            "auto-zsk".to_string(),
            km.auto_zsk.start.to_string(),
            km.auto_zsk.report.to_string(),
            km.auto_zsk.expire.to_string(),
            km.auto_zsk.done.to_string(),
        ],
        vec![
            "auto-csk".to_string(),
            km.auto_csk.start.to_string(),
            km.auto_csk.report.to_string(),
            km.auto_csk.expire.to_string(),
            km.auto_csk.done.to_string(),
        ],
        vec![
            "auto-algorithm".to_string(),
            km.auto_algorithm.start.to_string(),
            km.auto_algorithm.report.to_string(),
            km.auto_algorithm.expire.to_string(),
            km.auto_algorithm.done.to_string(),
        ],
        vec![
            "dnskey-inception-offset".to_string(),
            km.dnskey_inception_offset.to_string() + "s",
        ],
        vec![
            "dnskey-lifetime".to_string(),
            km.dnskey_signature_lifetime.to_string() + "s",
        ],
        vec![
            "dnskey-remain-time".to_string(),
            km.dnskey_remain_time.to_string() + "s",
        ],
        vec![
            "cds-inception-offset".to_string(),
            km.cds_inception_offset.to_string() + "s",
        ],
        vec![
            "cds-lifetime".to_string(),
            km.cds_signature_lifetime.to_string() + "s",
        ],
        vec![
            "cds-remain-time".to_string(),
            km.cds_remain_time.to_string() + "s",
        ],
        vec!["ds-algorithm".to_string(), km.ds_algorithm.to_string()],
        vec![
            "default-ttl".to_string(),
            km.default_ttl.as_secs().to_string(),
        ],
        vec!["autoremove".to_string(), km.auto_remove.to_string()],
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
    pub fn new(path: &Path, mode: KmipServerCredentialsFileMode) -> Result<Self, Error> {
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
            .map_err::<Error, _>(|e| {
                format!(
                    "unable to open KMIP credentials file {} in {mode} mode: {e}",
                    path.display()
                )
                .into()
            })?;

        // Determine the length of the file as JSON parsing fails if the file
        // is completely empty.
        let len = file.metadata().map(|m| m.len()).map_err::<Error, _>(|e| {
            format!(
                "unable to query metadata of KMIP credentials file {}: {e}",
                path.display()
            )
            .into()
        })?;

        // Buffer reading as apparently JSON based file reading is extremely
        // slow without buffering, even for small files.
        let mut reader = BufReader::new(&file);

        // Load or create the credential set.
        let credentials: KmipClientCredentialsSet = if len > 0 {
            serde_json::from_reader(&mut reader).map_err::<Error, _>(|e| {
                format!(
                    "error loading KMIP credentials file {:?}: {e}\n",
                    path.display()
                )
                .into()
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
    pub fn save(&mut self) -> Result<(), Error> {
        // Ensure that writing happens at the start of the file.
        self.file.seek(SeekFrom::Start(0))?;

        // Use a buffered writer as writing JSON to a file directly is
        // apparently very slow, even for small files.
        //
        // Enclose the use of the BufWriter in a block so that it is
        // definitely no longer using the file when we next act on it.
        {
            let mut writer = BufWriter::new(&self.file);
            serde_json::to_writer_pretty(&mut writer, &self.credentials).map_err::<Error, _>(
                |e| {
                    format!(
                        "error writing KMIP credentials file {}: {e}",
                        self.path.display()
                    )
                    .into()
                },
            )?;

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
