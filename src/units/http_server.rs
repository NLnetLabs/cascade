use std::collections::HashMap;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;

use axum::extract::OriginalUri;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::routing::post;
use axum::Json;
use axum::Router;
use bytes::Bytes;
use domain::base::iana::Class;
use domain::base::Name;
use domain::base::Serial;
use domain::crypto::kmip::ConnectionSettings;
use domain::dep::kmip::client::pool::ConnectionManager;
use domain::dnssec::sign::keys::keyset::KeyType;
use log::warn;
use log::{debug, error, info};
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::api;
use crate::api::keyset::*;
use crate::api::KeyInfo;
use crate::api::*;
use crate::center;
use crate::center::get_zone;
use crate::center::Center;
use crate::comms::{ApplicationCommand, Terminated};
use crate::daemon::SocketProvider;
use crate::policy::SignerDenialPolicy;
use crate::policy::SignerSerialPolicy;
use crate::units::key_manager::KmipClientCredentials;
use crate::units::key_manager::KmipClientCredentialsFile;
use crate::units::key_manager::KmipServerCredentialsFileMode;
use crate::units::zone_loader::ZoneLoaderReport;
use crate::units::zone_signer::KeySetState;
use crate::zone::HistoricalEvent;
use crate::zone::HistoricalEventType;
use crate::zone::ZoneLoadSource;
use crate::zonemaintenance::maintainer::read_soa;
use crate::zonemaintenance::types::ZoneReportDetails;

const HTTP_UNIT_NAME: &str = "HS";

// NOTE: To send data back from a unit, send them an app command with
// a transmitter they can use to send the reply

pub struct HttpServer {
    pub center: Arc<Center>,
}

struct HttpServerState {
    pub center: Arc<Center>,
}

impl HttpServer {
    pub async fn run(
        self,
        mut cmd_rx: mpsc::UnboundedReceiver<ApplicationCommand>,
        ready_tx: oneshot::Sender<bool>,
        socket_provider: Arc<Mutex<SocketProvider>>,
    ) -> Result<(), Terminated> {
        // Spawn the application command handler
        tokio::task::spawn(async move {
            loop {
                let cmd = cmd_rx.recv().await;
                let Some(cmd) = cmd else {
                    return Result::<(), Terminated>::Err(Terminated);
                };
                info!("[{HTTP_UNIT_NAME}] Received command: {cmd:?}");
                match &cmd {
                    ApplicationCommand::Terminate => {
                        return Err(Terminated);
                    }
                    // ...
                    _ => { /* not for us */ }
                }
            }
        });

        let state = Arc::new(HttpServerState {
            center: self.center,
        });

        let unit_router = Router::new()
            .route("/review-unsigned/{action}/{token}", get(Self::handle_rs))
            .route("/review-signed/{action}/{token}", get(Self::handle_rs2));

        let app = Router::new()
            .route("/", get(|| async { "Hello, World!" }))
            .nest("/hook", unit_router)
            .route("/status", get(Self::status))
            .route("/config/reload", post(Self::config_reload))
            .route("/zone/", get(Self::zones_list))
            .route("/zone/add", post(Self::zone_add))
            // TODO: .route("/zone/{name}/", get(Self::zone_get))
            .route("/zone/{name}/remove", post(Self::zone_remove))
            .route("/zone/{name}/status", get(Self::zone_status))
            .route("/zone/{name}/history", get(Self::zone_history))
            .route("/zone/{name}/reload", post(Self::zone_reload))
            .route("/policy/", get(Self::policy_list))
            .route("/policy/reload", post(Self::policy_reload))
            .route("/policy/{name}", get(Self::policy_show))
            .route("/kmip", get(Self::kmip_server_list))
            .route("/kmip", post(Self::kmip_server_add))
            .route("/kmip/{server_id}", get(Self::hsm_server_get))
            .route("/key/{zone}/roll", post(Self::key_roll))
            .route("/key/{zone}/remove", post(Self::key_remove))
            .with_state(state.clone());

        // Setup listen sockets
        let mut socks = vec![];
        {
            let state = state.center.state.lock().unwrap();
            for addr in &state.config.remote_control.servers {
                let sock = socket_provider
                    .lock()
                    .unwrap()
                    .take_tcp(addr)
                    .ok_or_else(|| {
                        error!("[{HTTP_UNIT_NAME}]: No socket available for TCP {addr}");
                        Terminated
                    })?;
                socks.push(sock);
            }
        }

        // Notify the manager that we are ready.
        ready_tx.send(true).map_err(|_| Terminated)?;

        // Serve our HTTP endpoints on each listener that has been configured.
        let mut set = JoinSet::new();
        for sock in socks {
            let app = app.clone();
            set.spawn(async move { axum::serve(sock, app).await });
        }

        // Wait for each future in the order they complete.
        while let Some(res) = set.join_next().await {
            if let Err(err) = res {
                error!("[{HTTP_UNIT_NAME}]: {err}");
                return Err(Terminated);
            }
        }

        Ok(())
    }

    /// Reload the configuration file.
    async fn config_reload(
        State(state): State<Arc<HttpServerState>>,
        Json(command): Json<ConfigReload>,
    ) -> Json<ConfigReloadResult> {
        let ConfigReload {} = command;

        let path = {
            let state = state.center.state.lock().unwrap();
            state.config.daemon.config_file.value().clone()
        }
        .into_path_buf();

        match crate::config::reload(&state.center) {
            Ok(()) => Json(Ok(ConfigReloadOutput {})),

            Err(crate::config::file::FileError::Load(error)) => {
                Json(Err(ConfigReloadError::Load(path, error.to_string())))
            }

            Err(crate::config::file::FileError::Parse(error)) => {
                Json(Err(ConfigReloadError::Parse(path, error.to_string())))
            }
        }
    }

    async fn zone_add(
        State(state): State<Arc<HttpServerState>>,
        Json(zone_register): Json<ZoneAdd>,
    ) -> Json<Result<ZoneAddResult, ZoneAddError>> {
        let res = center::add_zone(
            &state.center,
            zone_register.name.clone(),
            zone_register.policy.into(),
            zone_register.source,
            zone_register.key_imports,
        )
        .await;

        match res {
            Ok(_) => Json(Ok(ZoneAddResult {
                name: zone_register.name,
                status: "Submitted".to_string(),
            })),
            Err(err) => Json(Err(err.into())),
        }
    }

    async fn zone_remove(
        State(state): State<Arc<HttpServerState>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<Result<ZoneRemoveResult, ZoneRemoveError>> {
        // TODO: Use the result.
        Json(
            center::remove_zone(&state.center, name.clone())
                .map(|_| ZoneRemoveResult { name })
                .map_err(|e| e.into()),
        )
    }

    async fn zones_list(State(http_state): State<Arc<HttpServerState>>) -> Json<ZonesListResult> {
        let state = http_state.center.state.lock().unwrap();
        let zones = state
            .zones
            .iter()
            .map(|z| z.0.name.clone())
            .collect::<Vec<_>>();
        Json(ZonesListResult { zones })
    }

    async fn zone_status(
        State(state): State<Arc<HttpServerState>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<Result<ZoneStatus, ZoneStatusError>> {
        Json(Self::get_zone_status(state, name).await)
    }

    async fn get_zone_status(
        state: Arc<HttpServerState>,
        name: Name<Bytes>,
    ) -> Result<ZoneStatus, ZoneStatusError> {
        let mut zone_loaded_at = None;
        let mut zone_loaded_in = None;
        let mut zone_loaded_bytes = 0;
        let dnst_binary_path;
        let cfg_path;
        let state_path;
        let app_cmd_tx;
        let policy;
        let mut source;
        let unsigned_review_addr;
        let signed_review_addr;
        let publish_addr;
        let unsigned_review_status;
        let signed_review_status;
        let pipeline_mode;
        {
            let locked_state = state.center.state.lock().unwrap();
            dnst_binary_path = locked_state.config.dnst_binary_path.clone();
            let keys_dir = &locked_state.config.keys_dir;
            cfg_path = keys_dir.join(format!("{name}.cfg"));
            state_path = keys_dir.join(format!("{name}.state"));
            app_cmd_tx = state.center.app_cmd_tx.clone();
            let zone = locked_state
                .zones
                .get(&name)
                .ok_or(ZoneStatusError::ZoneDoesNotExist)?;
            let zone_state = zone.0.state.lock().unwrap();
            pipeline_mode = zone_state.pipeline_mode.clone();
            policy = zone_state
                .policy
                .as_ref()
                .map_or("<none>".into(), |p| p.name.to_string());
            // TODO: Needs some info from the zone loader?
            source = match zone_state.source.clone() {
                ZoneLoadSource::None => api::ZoneSource::None,
                ZoneLoadSource::Zonefile { path } => api::ZoneSource::Zonefile { path },
                ZoneLoadSource::Server { addr, tsig_key: _ } => api::ZoneSource::Server {
                    addr,
                    tsig_key: None,
                    xfr_status: Default::default(),
                },
            };
            unsigned_review_addr = locked_state
                .config
                .loader
                .review
                .servers
                .first()
                .map(|v| v.addr());
            signed_review_addr = locked_state
                .config
                .signer
                .review
                .servers
                .first()
                .map(|v| v.addr());
            publish_addr = locked_state
                .config
                .server
                .servers
                .first()
                .expect("Server must have a publish address")
                .addr();

            unsigned_review_status = zone_state
                .find_last_event(HistoricalEventType::UnsignedZoneReview, None)
                .map(|item| {
                    let HistoricalEvent::UnsignedZoneReview { status } = item.event else {
                        unreachable!()
                    };
                    TimestampedZoneReviewStatus {
                        status,
                        when: item.when,
                    }
                });

            signed_review_status = zone_state
                .find_last_event(HistoricalEventType::SignedZoneReview, None)
                .map(|item| {
                    let HistoricalEvent::SignedZoneReview { status } = item.event else {
                        unreachable!()
                    };
                    TimestampedZoneReviewStatus {
                        status,
                        when: item.when,
                    }
                });
        }

        // TODO: We need to show multiple versions here
        let unsigned_zones = state.center.unsigned_zones.load();
        let signed_zones = state.center.signed_zones.load();
        let published_zones = state.center.published_zones.load();
        let unsigned_zone = unsigned_zones.get_zone(&name, Class::IN);
        let signed_zone = signed_zones.get_zone(&name, Class::IN);
        let published_zone = published_zones.get_zone(&name, Class::IN);

        // Determine the highest stage the zone has progressed to.
        let stage = if published_zone.is_some() {
            ZoneStage::Published
        } else if signed_zone.is_some() {
            ZoneStage::Signed
        } else {
            ZoneStage::Unsigned
        };

        // Query key status
        let key_status = {
            // TODO: Move this into key manager as that is the component that knows
            // about dnst?
            if let Some(stdout) = Command::new(dnst_binary_path.as_std_path())
                .arg("keyset")
                .arg("-c")
                .arg(cfg_path)
                .arg("status")
                .arg("-v")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            {
                // Invoke dnst to get status information about the keys for the
                // zone. Strip out lines that would be correct for a dnst user but
                // confusing for a cascade user, and rewrite advice to invoke dnst
                // to be equivalent advice to invoke cascade.
                let mut sanitized_output = String::new();
                for line in stdout.lines() {
                    if line.contains("Next time to run the 'cron' subcommand") {
                        continue;
                    }

                    if line.contains("dnst keyset -c") {
                        // The config file path after -c should NOT contain a
                        // space as it is based on a zone name, and zone names
                        // cannot contain spaces. Find the config file path so
                        // that we can strip it out (as users of the cascade
                        // CLI should not need to know or care what internal
                        // dnst config files are being used).
                        let mut parts = line.split(' ');
                        if parts.any(|part| part == "-c") {
                            if let Some(dnst_config_path) = parts.next() {
                                let sanitized_line = line.replace(
                                    &format!("dnst keyset -c {dnst_config_path}"),
                                    &format!("cascade keyset {name}"),
                                );
                                sanitized_output.push_str(&sanitized_line);
                                sanitized_output.push('\n');
                                continue;
                            }
                        }
                    }

                    sanitized_output.push_str(line);
                    sanitized_output.push('\n');
                }
                Some(sanitized_output)
            } else {
                None
            }
        };

        // Query XFR status
        let (tx, rx) = oneshot::channel();
        app_cmd_tx
            .send((
                "ZL".to_owned(),
                ApplicationCommand::GetZoneReport {
                    zone_name: name.clone(),
                    report_tx: tx,
                },
            ))
            .ok();
        if let Ok((zone_maintainer_report, zone_loader_report)) = rx.await {
            match zone_maintainer_report.details() {
                ZoneReportDetails::Primary => {
                    if let Some(report) = zone_loader_report {
                        if let Ok(duration) = report.finished_at.duration_since(report.started_at) {
                            zone_loaded_in = Some(duration);
                            zone_loaded_at = Some(report.finished_at);
                            zone_loaded_bytes = report.byte_count;
                        }
                    }
                }
                ZoneReportDetails::PendingSecondary(s) | ZoneReportDetails::Secondary(s) => {
                    let api::ZoneSource::Server { xfr_status, .. } = &mut source else {
                        unreachable!("A secondary must have been configured from a server source");
                    };
                    *xfr_status = s.status();
                    let metrics = s.metrics();
                    let now = Instant::now();
                    let now_t = SystemTime::now();
                    if let (Some(checked_at), Some(refreshed_at)) = (
                        metrics.last_soa_serial_check_succeeded_at,
                        metrics.last_refreshed_at,
                    ) {
                        zone_loaded_in = Some(refreshed_at.duration_since(checked_at));
                        zone_loaded_at = now_t.checked_sub(now.duration_since(refreshed_at));
                        zone_loaded_bytes = metrics.last_refresh_succeeded_bytes.unwrap();
                    }
                }
            }
        }

        // Query zone keys
        let mut keys = vec![];
        match std::fs::read_to_string(&state_path) {
            Ok(json) => {
                let keyset_state: KeySetState = serde_json::from_str(&json).unwrap();
                for (pubref, key) in keyset_state.keyset.keys() {
                    let (key_type, signer) = match key.keytype() {
                        KeyType::Ksk(s) => (api::KeyType::Ksk, s.signer()),
                        KeyType::Zsk(s) => (api::KeyType::Zsk, s.signer()),
                        KeyType::Csk(s1, s2) => (api::KeyType::Csk, s1.signer() || s2.signer()),
                        KeyType::Include(_) => continue,
                    };
                    keys.push(KeyInfo {
                        pubref: pubref.clone(),
                        key_type,
                        key_tag: key.key_tag(),
                        signer,
                    });
                }
            }
            Err(err) => {
                error!("Unable to read `dnst keyset` state file '{state_path}' while querying status of zone {name} for the API: {err}");
            }
        }

        // Query signing status
        let mut signing_report = None;
        if stage >= ZoneStage::Signed {
            let (report_tx, rx) = oneshot::channel();
            app_cmd_tx
                .send((
                    "ZS".to_owned(),
                    ApplicationCommand::GetSigningReport {
                        zone_name: name.clone(),
                        report_tx,
                    },
                ))
                .ok();
            if let Ok(report) = rx.await {
                signing_report = Some(report);
            }
        }

        let receipt_report =
            if let (Some(finished_at), Some(zone_loaded_in)) = (zone_loaded_at, zone_loaded_in) {
                let started_at = finished_at.checked_sub(zone_loaded_in).unwrap();
                Some(ZoneLoaderReport {
                    started_at,
                    finished_at,
                    byte_count: zone_loaded_bytes,
                })
            } else {
                None
            };

        // Query zone serials
        let mut unsigned_serial = None;
        if let Some(zone) = unsigned_zone {
            if let Ok(Some((soa, _ttl))) = read_soa(&zone.read(), name.clone()).await {
                unsigned_serial = Some(soa.serial());
            }
        }
        let mut signed_serial = None;
        if let Some(zone) = signed_zone {
            if let Ok(Some((soa, _ttl))) = read_soa(&zone.read(), name.clone()).await {
                signed_serial = Some(soa.serial());
            }
        }
        let mut published_serial = None;
        if let Some(zone) = published_zone {
            if let Ok(Some((soa, _ttl))) = read_soa(&zone.read(), name.clone()).await {
                published_serial = Some(soa.serial());
            }
        }

        // If the timing were unlucky we may have a published serial but not
        // signed serial as the signed zone may have just been removed. Use
        // the published serial as the signed serial in this case.
        if signed_serial.is_none() && published_serial.is_some() {
            signed_serial = published_serial;
        }

        Ok(ZoneStatus {
            name,
            source,
            policy,
            stage,
            keys,
            key_status,
            receipt_report,
            unsigned_serial,
            unsigned_review_status,
            unsigned_review_addr,
            signed_serial,
            signed_review_status,
            signed_review_addr,
            signing_report,
            published_serial,
            publish_addr,
            pipeline_mode,
        })
    }

    async fn zone_history(
        State(state): State<Arc<HttpServerState>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<Result<ZoneHistory, ZoneHistoryError>> {
        let zone = match get_zone(&state.center, &name) {
            Some(zone) => zone,
            None => return Json(Err(ZoneHistoryError::ZoneDoesNotExist)),
        };
        let zone_state = zone.state.lock().unwrap();
        Json(Ok(ZoneHistory {
            history: zone_state.history.clone(),
        }))
    }

    async fn zone_reload(
        State(api_state): State<Arc<HttpServerState>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<Result<ZoneReloadResult, ZoneReloadError>> {
        Json(Self::do_zone_reload(api_state, name))
    }

    fn do_zone_reload(
        api_state: Arc<HttpServerState>,
        name: Name<Bytes>,
    ) -> Result<ZoneReloadResult, ZoneReloadError> {
        let the_state = api_state.center.state.lock().unwrap();
        let zone = the_state
            .zones
            .get(&name)
            .ok_or(ZoneReloadError::ZoneDoesNotExist)?;
        let zone_state = zone.0.state.lock().unwrap();
        if let Some(reason) = zone_state.halted(true) {
            return Err(ZoneReloadError::ZoneHalted(reason));
        }

        let source = zone_state.source.clone();
        match zone_state.source.clone() {
            crate::zone::ZoneLoadSource::None => Err(ZoneReloadError::ZoneWithoutSource),
            _ => {
                api_state
                    .center
                    .app_cmd_tx
                    .send((
                        "ZL".into(),
                        ApplicationCommand::ReloadZone {
                            zone_name: name.clone(),
                            source,
                        },
                    ))
                    .unwrap();
                Ok(ZoneReloadResult { name })
            }
        }
    }

    async fn policy_list(State(state): State<Arc<HttpServerState>>) -> Json<PolicyListResult> {
        let state = state.center.state.lock().unwrap();

        let mut policies: Vec<String> = state
            .policies
            .keys()
            .map(|s| String::from(s.as_ref()))
            .collect();

        // We don't _have_ to sort, but seems useful for consistent output
        policies.sort();

        Json(PolicyListResult { policies })
    }

    async fn policy_reload(
        State(state): State<Arc<HttpServerState>>,
    ) -> Json<Result<PolicyChanges, PolicyReloadError>> {
        let mut state = state.center.state.lock().unwrap();

        // TODO: This clone is a bit unfortunate. Looks like that's necessary because of the
        // mutex guard. We could make `reload_all` a function that takes the whole state to fix
        // this.
        let mut policies = state.policies.clone();
        let res = crate::policy::reload_all(&mut policies, &state.config);
        let changes = match res {
            Ok(c) => c,
            Err(e) => {
                return Json(Err(e));
            }
        };
        let mut changes: Vec<_> = changes.into_iter().map(|(p, c)| (p.into(), c)).collect();
        changes.sort_by_key(|x: &(String, _)| x.0.clone());

        state.policies = policies;

        Json(Ok(PolicyChanges { changes }))
    }

    async fn policy_show(
        State(state): State<Arc<HttpServerState>>,
        Path(name): Path<Box<str>>,
    ) -> Json<Result<PolicyInfo, PolicyInfoError>> {
        let state = state.center.state.lock().unwrap();
        let Some(p) = state.policies.get(&name) else {
            return Json(Err(PolicyInfoError::PolicyDoesNotExist));
        };

        let zones = p.zones.iter().cloned().collect();
        let loader = LoaderPolicyInfo {
            review: ReviewPolicyInfo {
                required: p.latest.loader.review.required,
                cmd_hook: p.latest.loader.review.cmd_hook.clone(),
            },
        };

        let signer = SignerPolicyInfo {
            serial_policy: match p.latest.signer.serial_policy {
                SignerSerialPolicy::Keep => SignerSerialPolicyInfo::Keep,
                SignerSerialPolicy::Counter => SignerSerialPolicyInfo::Counter,
                SignerSerialPolicy::UnixTime => SignerSerialPolicyInfo::UnixTime,
                SignerSerialPolicy::DateCounter => SignerSerialPolicyInfo::DateCounter,
            },
            sig_inception_offset: p.latest.signer.sig_inception_offset,
            sig_validity_offset: p.latest.signer.sig_validity_time,
            denial: match p.latest.signer.denial {
                SignerDenialPolicy::NSec => SignerDenialPolicyInfo::NSec,
                SignerDenialPolicy::NSec3 { opt_out } => SignerDenialPolicyInfo::NSec3 { opt_out },
            },
            review: ReviewPolicyInfo {
                required: p.latest.signer.review.required,
                cmd_hook: p.latest.signer.review.cmd_hook.clone(),
            },
        };

        let key_manager = KeyManagerPolicyInfo {
            hsm_server_id: p.latest.key_manager.hsm_server_id.clone(),
        };

        let p_outbound = &p.latest.server.outbound;
        let server = ServerPolicyInfo {
            outbound: OutboundPolicyInfo {
                accept_xfr_requests_from: p_outbound
                    .accept_xfr_requests_from
                    .iter()
                    .map(|v| NameserverCommsPolicyInfo { addr: v.addr })
                    .collect(),
                send_notify_to: p_outbound
                    .send_notify_to
                    .iter()
                    .map(|v| NameserverCommsPolicyInfo { addr: v.addr })
                    .collect(),
            },
        };

        Json(Ok(PolicyInfo {
            name: p.latest.name.clone(),
            zones,
            loader,
            key_manager,
            signer,
            server,
        }))
    }

    async fn status() -> Json<ServerStatusResult> {
        Json(ServerStatusResult {})
    }

    async fn key_roll(
        State(state): State<Arc<HttpServerState>>,
        Path(zone): Path<Name<Bytes>>,
        Json(key_roll): Json<KeyRoll>,
    ) -> Json<Result<KeyRollResult, KeyRollError>> {
        let (tx, mut rx) = mpsc::channel(10);
        state
            .center
            .app_cmd_tx
            .send((
                "KM".into(),
                ApplicationCommand::RollKey {
                    zone: zone.clone(),
                    key_roll,
                    http_tx: tx,
                },
            ))
            .unwrap();

        let res = rx.recv().await;
        let Some(res) = res else {
            return Json(Err(KeyRollError::RxError));
        };

        if let Err(e) = res {
            return Json(Err(e));
        }

        Json(Ok(KeyRollResult { zone }))
    }

    async fn key_remove(
        State(state): State<Arc<HttpServerState>>,
        Path(zone): Path<Name<Bytes>>,
        Json(key_remove): Json<KeyRemove>,
    ) -> Json<Result<KeyRemoveResult, KeyRemoveError>> {
        let (tx, mut rx) = mpsc::channel(10);
        state
            .center
            .app_cmd_tx
            .send((
                "KM".into(),
                ApplicationCommand::RemoveKey {
                    zone: zone.clone(),
                    key_remove,
                    http_tx: tx,
                },
            ))
            .unwrap();

        let res = rx.recv().await;
        let Some(res) = res else {
            return Json(Err(KeyRemoveError::RxError));
        };

        if let Err(e) = res {
            return Json(Err(e));
        }

        Json(Ok(KeyRemoveResult { zone }))
    }
}

//------------ HttpServer Handler for /kmip ----------------------------------

/// Non-sensitive KMIP server settings to be persisted.
///
/// Sensitive details such as certificates and credentials should be stored
/// separately.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct KmipServerState {
    pub server_id: String,
    pub ip_host_or_fqdn: String,
    pub port: u16,
    pub insecure: bool,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub max_response_bytes: u32,
    pub key_label_prefix: Option<String>,
    pub key_label_max_bytes: u8,
    pub has_credentials: bool,
}

impl From<HsmServerAdd> for KmipServerState {
    fn from(srv: HsmServerAdd) -> Self {
        KmipServerState {
            server_id: srv.server_id,
            ip_host_or_fqdn: srv.ip_host_or_fqdn,
            port: srv.port,
            insecure: srv.insecure,
            connect_timeout: srv.connect_timeout,
            read_timeout: srv.read_timeout,
            write_timeout: srv.write_timeout,
            max_response_bytes: srv.max_response_bytes,
            key_label_prefix: srv.key_label_prefix,
            key_label_max_bytes: srv.key_label_max_bytes,
            has_credentials: srv.username.is_some(),
        }
    }
}

impl From<HsmServerAdd> for ConnectionSettings {
    fn from(
        HsmServerAdd {
            ip_host_or_fqdn,
            port,
            username,
            password,
            insecure,
            connect_timeout,
            read_timeout,
            write_timeout,
            max_response_bytes,
            ..
        }: HsmServerAdd,
    ) -> Self {
        ConnectionSettings {
            host: ip_host_or_fqdn,
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
        }
    }
}

impl HttpServer {
    async fn kmip_server_add(
        State(state): State<Arc<HttpServerState>>,
        Json(req): Json<HsmServerAdd>,
    ) -> Json<Result<HsmServerAddResult, HsmServerAddError>> {
        // TODO: Write the given certificates to disk.
        // TODO: Create a single common way to store secrets.
        let server_id = req.server_id.clone();
        let state = state.center.state.lock().unwrap();
        let kmip_server_state_file = state.config.kmip_server_state_dir.join(server_id.clone());
        let kmip_credentials_store_path = state.config.kmip_credentials_store_path.clone();
        drop(state);

        // Test the connection before using the HSM.
        let conn_settings = ConnectionSettings::from(req.clone());

        let pool = match ConnectionManager::create_connection_pool(
            server_id.clone(),
            Arc::new(conn_settings.clone()),
            10,
            Some(Duration::from_secs(60)),
            Some(Duration::from_secs(60)),
        ) {
            Ok(pool) => pool,
            Err(err) => {
                return Json(Err(HsmServerAddError::UnableToConnect {
                    server_id,
                    host: conn_settings.host,
                    port: conn_settings.port,
                    err: format!("Error creating connection pool: {err}"),
                }))
            }
        };

        // Test the connectivity (but not the HSM capabilities).
        let conn = match pool.get() {
            Ok(conn) => conn,
            Err(err) => {
                return Json(Err(HsmServerAddError::UnableToConnect {
                    server_id,
                    host: conn_settings.host,
                    port: conn_settings.port,
                    err: format!("Error retrieving connection from pool: {err}"),
                }));
            }
        };

        let query_res = match conn.query() {
            Ok(query_res) => query_res,
            Err(err) => {
                return Json(Err(HsmServerAddError::UnableToQuery {
                    server_id,
                    host: conn_settings.host,
                    port: conn_settings.port,
                    err: err.to_string(),
                }));
            }
        };

        let vendor_id = query_res
            .vendor_identification
            .unwrap_or("Anonymous HSM vendor".to_string());

        // Copy the username and password as we consume the req object below.
        let username = req.username.clone();
        let password = req.password.clone();

        // Add any credentials to the credentials store.
        if let Some(username) = username {
            let creds = KmipClientCredentials { username, password };
            let mut creds_file = match KmipClientCredentialsFile::new(
                kmip_credentials_store_path.as_std_path(),
                KmipServerCredentialsFileMode::CreateReadWrite,
            ) {
                Ok(creds_file) => creds_file,
                Err(err) => {
                    return Json(Err(
                        HsmServerAddError::CredentialsFileCouldNotBeOpenedForWriting {
                            err: err.to_string(),
                        },
                    ))
                }
            };
            let _ = creds_file.insert(server_id, creds);
            if let Err(err) = creds_file.save() {
                return Json(Err(HsmServerAddError::CredentialsFileCouldNotBeSaved {
                    err: err.to_string(),
                }));
            }
        }

        // Extract just the settings that do not need to be
        // stored separately.
        let kmip_state = KmipServerState::from(req);

        info!("Writing to KMIP server file '{kmip_server_state_file}");
        let f = match std::fs::File::create_new(kmip_server_state_file.clone()) {
            Ok(f) => f,
            Err(err) => {
                return Json(Err(
                    HsmServerAddError::KmipServerStateFileCouldNotBeCreated {
                        path: kmip_server_state_file.into_string(),
                        err: err.to_string(),
                    },
                ))
            }
        };
        if let Err(err) = serde_json::to_writer_pretty(&f, &kmip_state) {
            return Json(Err(HsmServerAddError::KmipServerStateFileCouldNotBeSaved {
                path: kmip_server_state_file.into_string(),
                err: err.to_string(),
            }));
        }

        Json(Ok(HsmServerAddResult { vendor_id }))
    }

    async fn kmip_server_list(
        State(state): State<Arc<HttpServerState>>,
    ) -> Json<HsmServerListResult> {
        let state = state.center.state.lock().unwrap();
        let kmip_server_state_dir = state.config.kmip_server_state_dir.clone();
        drop(state);

        let mut servers = Vec::<String>::new();

        if let Ok(entries) = std::fs::read_dir(kmip_server_state_dir.as_std_path()) {
            for entry in entries {
                let Ok(entry) = entry else { continue };

                if let Ok(f) = std::fs::File::open(entry.path()) {
                    if let Ok(server) = serde_json::from_reader::<_, KmipServerState>(f) {
                        servers.push(server.server_id);
                    }
                }
            }
        }

        // We don't _have_ to sort, but seems useful for consistent output
        servers.sort();

        Json(HsmServerListResult { servers })
    }

    async fn hsm_server_get(
        State(state): State<Arc<HttpServerState>>,
        Path(name): Path<Box<str>>,
    ) -> Json<Result<HsmServerGetResult, ()>> {
        let state = state.center.state.lock().unwrap();
        let kmip_server_state_dir = state.config.kmip_server_state_dir.clone();
        drop(state);

        let p = kmip_server_state_dir.as_std_path().join(&*name);
        if let Ok(f) = std::fs::File::open(p) {
            if let Ok(server) = serde_json::from_reader::<_, KmipServerState>(f) {
                return Json(Ok(HsmServerGetResult { server }));
            }
        }

        Json(Err(()))
    }
}

//------------ HttpServer Handler for /<unit>/ -------------------------------

impl HttpServer {
    async fn handle_rs(
        uri: OriginalUri,
        State(state): State<Arc<HttpServerState>>,
        Path((action, token)): Path<(String, String)>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Result<(), StatusCode> {
        Self::zone_server_unit_api_common("RS", uri, state, action, token, params).await
    }

    async fn handle_rs2(
        uri: OriginalUri,
        State(state): State<Arc<HttpServerState>>,
        Path((action, token)): Path<(String, String)>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Result<(), StatusCode> {
        Self::zone_server_unit_api_common("RS2", uri, state, action, token, params).await
    }

    //--- common api implementations

    // All ZoneServerUnit's have the same review API
    //
    // API: GET /{approve,reject}/<approval token>?zone=<zone name>&serial=<zone serial>
    //
    // NOTE: We use query parameters for the zone details because dots that appear in zone names
    // are decoded specially by HTTP standards compliant libraries, especially occurences of
    // handling of /./ are problematic as that gets collapsed to /.
    async fn zone_server_unit_api_common(
        unit: &str,
        uri: OriginalUri,
        state: Arc<HttpServerState>,
        action: String,
        token: String,
        params: HashMap<String, String>,
    ) -> Result<(), StatusCode> {
        let uri = uri.path_and_query().map(|p| p.as_str()).unwrap_or_default();
        debug!("[{HTTP_UNIT_NAME}]: Got HTTP approval hook request: {uri}");

        let Some(zone_name) = params.get("zone") else {
            warn!("[{HTTP_UNIT_NAME}]: Invalid HTTP request: {uri}");
            return Err(StatusCode::BAD_REQUEST);
        };

        let Some(zone_serial) = params.get("serial") else {
            warn!("[{HTTP_UNIT_NAME}]: Invalid HTTP request: {uri}");
            return Err(StatusCode::BAD_REQUEST);
        };

        if token.is_empty() || !["approve", "reject"].contains(&action.as_ref()) {
            warn!("[{HTTP_UNIT_NAME}]: Invalid HTTP request: {uri}");
            return Err(StatusCode::BAD_REQUEST);
        }

        let Ok(zone_name) = Name::<Bytes>::from_str(zone_name) else {
            warn!("[{HTTP_UNIT_NAME}]: Invalid zone name '{zone_name}' in request.");
            return Err(StatusCode::BAD_REQUEST);
        };

        let Ok(zone_serial) = Serial::from_str(zone_serial) else {
            warn!("[{HTTP_UNIT_NAME}]: Invalid zone serial '{zone_serial}' in request.");
            return Err(StatusCode::BAD_REQUEST);
        };

        let (tx, mut rx) = mpsc::channel(10);
        state
            .center
            .app_cmd_tx
            .send((
                unit.into(),
                ApplicationCommand::HandleZoneReviewApi {
                    zone_name,
                    zone_serial,
                    approval_token: token,
                    operation: action,
                    http_tx: tx,
                },
            ))
            .unwrap();

        let res = rx.recv().await;
        let Some(res) = res else {
            // Failed to receive response... When would that happen?
            error!("[{HTTP_UNIT_NAME}]: Failed to receive response from unit {unit} while handling HTTP request: {uri}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };

        let ret = match res {
            Ok(_) => Ok(()),
            Err(_) => Err(StatusCode::BAD_REQUEST),
        };

        debug!("[{HTTP_UNIT_NAME}]: Handled HTTP request: {uri} :: {ret:?}");

        ret
    }
}
