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
use crate::api::keyset::*;
use crate::api::*;
use crate::center;
use crate::center::Center;
use crate::comms::{ApplicationCommand, Terminated};
use crate::daemon::SocketProvider;
use crate::policy::SignerDenialPolicy;
use crate::policy::SignerSerialPolicy;

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
        let state = http_state.center.state.lock().unwrap();
        let names: Vec<_> = state.zones.iter().map(|z| z.0.name.clone()).collect();
        drop(state);

        let zones = names
            .iter()
            .filter_map(|z| Self::get_zone_status(http_state.clone(), z).ok())
            .collect();

        Json(ZonesListResult { zones })
    }

    async fn zone_status(
        State(state): State<Arc<HttpServerState>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<Result<ZoneStatus, ZoneStatusError>> {
        Json(Self::get_zone_status(state, &name))
    }

    fn get_zone_status(
        state: Arc<HttpServerState>,
        name: &Name<Bytes>,
    ) -> Result<ZoneStatus, ZoneStatusError> {
        let center = &state.center;

        let state = center.state.lock().unwrap();
        let zone = state
            .zones
            .get(name)
            .ok_or(ZoneStatusError::ZoneDoesNotExist)?;
        let zone_state = zone.0.state.lock().unwrap();

        // TODO: Needs some info from the zone loader?
        let source = match zone_state.source.clone() {
            crate::zone::ZoneLoadSource::None => api::ZoneSource::None,
            crate::zone::ZoneLoadSource::Zonefile { path } => api::ZoneSource::Zonefile { path },
            crate::zone::ZoneLoadSource::Server { addr, tsig_key: _ } => api::ZoneSource::Server {
                addr,
                tsig_key: None,
            },
        };

        let policy = zone_state
            .policy
            .as_ref()
            .map_or("<none>".into(), |p| p.name.to_string());

        // TODO: We need to show multiple versions here
        let stage = if center
            .published_zones
            .load()
            .get_zone(&name, Class::IN)
            .is_some()
        {
            ZoneStage::Published
        } else if center
            .signed_zones
            .load()
            .get_zone(&name, Class::IN)
            .is_some()
        {
            ZoneStage::Signed
        } else {
            ZoneStage::Unsigned
        };

        let dnst_binary = &state.config.dnst_binary_path;
        let keys_dir = &state.config.keys_dir;
        let cfg = keys_dir.join(format!("{name}.cfg"));
        let key_status = Command::new(dnst_binary.as_std_path())
            .arg("keyset")
            .arg("-c")
            .arg(cfg)
            .arg("status")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string());

        Ok(ZoneStatus {
            name: name.clone(),
            source,
            policy,
            stage,
            key_status,
        })
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
