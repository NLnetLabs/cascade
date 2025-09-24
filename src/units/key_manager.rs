use crate::api::{FileKeyImport, KeyImport, KmipKeyImport};
use crate::center::Center;
use crate::comms::{ApplicationCommand, Terminated};
use crate::payload::Update;
use crate::policy::KeyParameters;
use bytes::Bytes;
use camino::Utf8Path;
use core::time::Duration;
use domain::base::Name;
use domain::dnssec::sign::keys::keyset::{KeySet, UnixTime};
use log::error;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::metadata;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tokio::select;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::MissedTickBehavior;

#[derive(Debug)]
pub struct KeyManagerUnit {
    pub center: Arc<Center>,
}

impl KeyManagerUnit {
    pub async fn run(
        self,
        cmd_rx: mpsc::UnboundedReceiver<ApplicationCommand>,
        ready_tx: oneshot::Sender<bool>,
    ) -> Result<(), Terminated> {
        // TODO: metrics and status reporting

        let km = KeyManager::new(self.center);

        // Notify the manager that we are ready.
        ready_tx.send(true).map_err(|_| Terminated)?;

        km.run(cmd_rx).await?;

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
                register:
                    crate::api::ZoneAdd {
                        name,
                        source: _,
                        policy: _,
                        key_imports,
                    },
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

                // Set config
                let config_commands = imports_to_commands(&key_imports)
                    .into_iter()
                    .chain(policy_to_commands(&self.center, &name));

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

macro_rules! strs {
    ($($e:expr),*$(,)?) => {
        vec![$($e.to_string()),*]
    };
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

    let mut algorithm_cmd = vec!["algorithm".to_string()];
    match km.algorithm {
        KeyParameters::RsaSha256(bits) => {
            algorithm_cmd.extend(strs!["RSASHA256", "-b", bits,]);
        }
        KeyParameters::RsaSha512(bits) => {
            algorithm_cmd.extend(strs!["RSASHA512", "-b", bits,]);
        }
        KeyParameters::EcdsaP256Sha256
        | KeyParameters::EcdsaP384Sha384
        | KeyParameters::Ed25519
        | KeyParameters::Ed448 => algorithm_cmd.push(km.algorithm.to_string()),
    }

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
        strs![
            "default-ttl".to_string(),
            seconds(km.default_ttl.as_secs() as u64),
        ],
        strs!["autoremove", km.auto_remove],
    ]
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
                strs!["import", key_type, "kmip", server, public_id, private_id, algorithm, flags]
            }
            KeyImport::File(FileKeyImport { key_type, path }) => {
                strs!["import", key_type, "file", path]
            }
        })
        .collect()
}
