use std::collections::HashMap;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;

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
use log::warn;
use log::{debug, error, info};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinSet;

use crate::api;
use crate::api::KeyManagerPolicyInfo;
use crate::api::LoaderPolicyInfo;
use crate::api::PolicyChanges;
use crate::api::PolicyInfo;
use crate::api::PolicyInfoError;
use crate::api::PolicyListResult;
use crate::api::PolicyReloadError;
use crate::api::ReviewPolicyInfo;
use crate::api::ServerPolicyInfo;
use crate::api::ServerStatusResult;
use crate::api::SignerDenialPolicyInfo;
use crate::api::SignerPolicyInfo;
use crate::api::SignerSerialPolicyInfo;
use crate::api::ZoneAdd;
use crate::api::ZoneAddError;
use crate::api::ZoneAddResult;
use crate::api::ZoneApprovalStatus;
use crate::api::ZoneReloadResult;
use crate::api::ZoneRemoveResult;
use crate::api::ZoneStage;
use crate::api::ZoneStatus;
use crate::api::ZoneStatusError;
use crate::api::ZonesListResult;
use crate::center;
use crate::center::Center;
use crate::comms::{ApplicationCommand, Terminated};
use crate::daemon::SocketProvider;
use crate::policy::SignerDenialPolicy;
use crate::policy::SignerSerialPolicy;
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

        // For now, only implemented the ZoneReviewApi for the Units:
        // "RS"   ZoneServerUnit
        // "RS2"  ZoneServerUnit
        // "PS"   ZoneServerUnit
        //
        // Skipping SigningHistoryApi and ZoneListApi's for
        // "ZL"   ZoneLoader
        // "ZS"   ZoneSignerUnit
        // "CC"   CentralCommand
        //
        // Noting them down, but without a previously existing API:
        // "HS"   HttpServer
        // "KM"   KeyManagerUnit

        let unit_router = Router::new()
            .route("/rs/{action}/{token}", get(Self::handle_rs))
            .route("/rs2/{action}/{token}", get(Self::handle_rs2));

        let app = Router::new()
            .route("/", get(|| async { "Hello, World!" }))
            // Using the /_unit sub-path to not clutter the rest of the API
            .nest("/_unit", unit_router)
            .route("/status", get(Self::status))
            .route("/zones/list", get(Self::zones_list))
            .route("/zone/add", post(Self::zone_add))
            .route("/zone/{name}/remove", post(Self::zone_remove))
            .route("/zone/{name}/status", get(Self::zone_status))
            .route("/zone/{name}/reload", post(Self::zone_reload))
            .route("/policy/reload", post(Self::policy_reload))
            .route("/policy/list", get(Self::policy_list))
            .route("/policy/{name}", get(Self::policy_show))
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

    async fn zone_add(
        State(state): State<Arc<HttpServerState>>,
        Json(zone_register): Json<ZoneAdd>,
    ) -> Json<Result<ZoneAddResult, ZoneAddError>> {
        if let Err(e) = center::add_zone(
            &state.center,
            zone_register.name.clone(),
            zone_register.policy.clone().into(),
            zone_register.source.clone(),
        ) {
            return Json(Err(e.into()));
        }

        let zone_name = zone_register.name.clone();
        state
            .center
            .app_cmd_tx
            .send((
                "KM".into(),
                ApplicationCommand::RegisterZone {
                    register: zone_register,
                },
            ))
            .unwrap();

        Json(Ok(ZoneAddResult {
            name: zone_name,
            status: "Submitted".to_string(),
        }))
    }

    async fn zone_remove(
        State(state): State<Arc<HttpServerState>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<ZoneRemoveResult> {
        // TODO: Use the result.
        let _ = center::remove_zone(&state.center, name);

        Json(ZoneRemoveResult {})
    }

    async fn zones_list(State(http_state): State<Arc<HttpServerState>>) -> Json<ZonesListResult> {
        let names;
        {
            let state = http_state.center.state.lock().unwrap();
            names = state
                .zones
                .iter()
                .map(|z| z.0.name.clone())
                .collect::<Vec<_>>();
        }

        let mut zones = Vec::with_capacity(names.len());
        for name in names {
            if let Ok(zone_status) = Self::get_zone_status(http_state.clone(), name.clone()).await {
                zones.push(zone_status);
            }
        }

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
        let dnst_binary_path;
        let cfg_path;
        let app_cmd_tx;
        let policy;
        let mut source;
        let unsigned_review_addr;
        let signed_review_addr;
        let publish_addr;
        {
            let locked_state = state.center.state.lock().unwrap();
            dnst_binary_path = locked_state.config.dnst_binary_path.clone();
            let keys_dir = &locked_state.config.keys_dir;
            cfg_path = keys_dir.join(format!("{name}.cfg"));
            app_cmd_tx = state.center.app_cmd_tx.clone();
            let zone = locked_state
                .zones
                .get(&name)
                .ok_or(ZoneStatusError::ZoneDoesNotExist)?;
            let zone_state = zone.0.state.lock().unwrap();
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
            unsigned_review_addr = locked_state.config.loader.review.servers.get(0).map(|v| v.addr());
            signed_review_addr = locked_state.config.signer.review.servers.get(0).map(|v| v.addr());
            publish_addr = locked_state.config.server.servers.get(0).expect("Server must have a publish address").addr();
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

        // Query key status
        let key_status = {
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
                        if let Some(_) = parts.find(|part| *part == "-c") {
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
        if let Ok(zone_loader_report) = rx.await {
            match zone_loader_report.details() {
                ZoneReportDetails::Primary => { /* Nothing to do */ }
                ZoneReportDetails::PendingSecondary(s) | ZoneReportDetails::Secondary(s) => {
                    match &mut source {
                        api::ZoneSource::None|api::ZoneSource::Zonefile { .. } => { /* Nothing to do */ }
                        api::ZoneSource::Server { xfr_status, .. } => *xfr_status = s.status(),
                    }
                }
            }
        }

        // Query approval status
        let mut approval_status = None;
        let (tx, rx) = oneshot::channel();
        app_cmd_tx
            .send((
                "RS".to_owned(),
                ApplicationCommand::IsZonePendingApproval {
                    zone_name: name.clone(),
                    tx,
                },
            ))
            .ok();
        if matches!(rx.await, Ok(true)) {
            approval_status = Some(ZoneApprovalStatus::PendingUnsignedApproval);
        }

        let (tx, rx) = oneshot::channel();
        app_cmd_tx
            .send((
                "RS2".to_owned(),
                ApplicationCommand::IsZonePendingApproval {
                    zone_name: name.clone(),
                    tx,
                },
            ))
            .ok();
        if matches!(rx.await, Ok(true)) {
            approval_status = Some(ZoneApprovalStatus::PendingSignedApproval);
        }

        Ok(ZoneStatus {
            name: name.clone(),
            source,
            policy,
            stage,
            key_status,
            approval_status,
            unsigned_serial,
            signed_serial,
            published_serial,
            unsigned_review_addr,
            signed_review_addr,
            publish_addr,
        })
    }

    async fn zone_reload(
        Path(payload): Path<Name<Bytes>>,
    ) -> Result<Json<ZoneReloadResult>, String> {
        Ok(Json(ZoneReloadResult { name: payload }))
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
        let server = ServerPolicyInfo {};

        Json(Ok(PolicyInfo {
            name: p.latest.name.clone(),
            zones,
            loader,
            key_manager: KeyManagerPolicyInfo {},
            signer,
            server,
        }))
    }

    async fn status() -> Json<ServerStatusResult> {
        Json(ServerStatusResult {})
    }
}

//------------ HttpServer Handler for /<unit>/ -------------------------------

impl HttpServer {
    //--- /rs/
    async fn handle_rs(
        uri: OriginalUri,
        State(state): State<Arc<HttpServerState>>,
        Path((action, token)): Path<(String, String)>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Result<(), StatusCode> {
        Self::zone_server_unit_api_common("RS", uri, state, action, token, params).await
    }

    //--- /rs2/
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
