use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::OriginalUri;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Html;
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
use log::warn;
use log::{debug, error, info};
use serde::Deserialize;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::api;
use crate::api::HsmServerAdd;
use crate::api::HsmServerAddError;
use crate::api::HsmServerAddResult;
use crate::api::HsmServerGetResult;
use crate::api::HsmServerListResult;
use crate::api::KeyManagerPolicyInfo;
use crate::api::LoaderPolicyInfo;
use crate::api::Nsec3OptOutPolicyInfo;
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
use crate::api::ZoneReloadResult;
use crate::api::ZoneRemoveResult;
use crate::api::ZoneStage;
use crate::api::ZoneStatus;
use crate::api::ZoneStatusError;
use crate::api::ZonesListResult;
use crate::center;
use crate::center::Center;
use crate::comms::{ApplicationCommand, Terminated};
use crate::policy::Nsec3OptOutPolicy;
use crate::policy::SignerDenialPolicy;
use crate::policy::SignerSerialPolicy;
use crate::units::key_manager::KmipClientCredentials;
use crate::units::key_manager::KmipClientCredentialsFile;
use crate::units::key_manager::KmipServerCredentialsFileMode;

const HTTP_UNIT_NAME: &str = "HS";

// NOTE: To send data back from a unit, send them an app command with
// a transmitter they can use to send the reply

pub struct HttpServer {
    pub center: Arc<Center>,
    pub listen_addr: SocketAddr,
}

struct HttpServerState {
    pub center: Arc<Center>,
}

impl HttpServer {
    pub async fn run(
        self,
        mut cmd_rx: mpsc::UnboundedReceiver<ApplicationCommand>,
    ) -> Result<(), Terminated> {
        // Setup listener
        let sock = TcpListener::bind(self.listen_addr).await.map_err(|e| {
            error!("[{HTTP_UNIT_NAME}]: {e}");
            Terminated
        })?;

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
            .route("/ps/", get(Self::handle_ps_base))
            .route("/ps/{action}/{token}", get(Self::handle_ps))
            .route("/rs/", get(Self::handle_rs_base))
            .route("/rs/{action}/{token}", get(Self::handle_rs))
            .route("/rs2/", get(Self::handle_rs2_base))
            .route("/rs2/{action}/{token}", get(Self::handle_rs2));
        // .route("/zl/", get(Self::handle_zl_base))
        // .route("/zs/", get(Self::handle_zs_base));

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
            .route("/kmip", post(Self::kmip_server_add))
            .route("/kmip", get(Self::kmip_server_list))
            .route("/kmip/{server_id}", get(Self::hsm_server_get))
            .with_state(state);

        axum::serve(sock, app).await.map_err(|e| {
            error!("[{HTTP_UNIT_NAME}]: {e}");
            Terminated
        })
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
                SignerDenialPolicy::NSec3 { opt_out } => SignerDenialPolicyInfo::NSec3 {
                    opt_out: match opt_out {
                        Nsec3OptOutPolicy::Disabled => Nsec3OptOutPolicyInfo::Disabled,
                        Nsec3OptOutPolicy::FlagOnly => Nsec3OptOutPolicyInfo::FlagOnly,
                        Nsec3OptOutPolicy::Enabled => Nsec3OptOutPolicyInfo::Enabled,
                    },
                },
            },
            review: ReviewPolicyInfo {
                required: p.latest.signer.review.required,
                cmd_hook: p.latest.signer.review.cmd_hook.clone(),
            },
        };

        let key_manager = KeyManagerPolicyInfo {
            hsm_server_id: p.latest.key_manager.hsm_server_id.clone(),
        };

        let server = ServerPolicyInfo {};

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
            Err(_err) => return Json(Err(HsmServerAddError::UnableToConnect)),
        };

        // Test the connectivity (but not the HSM capabilities).
        let Ok(conn) = pool.get() else {
            return Json(Err(HsmServerAddError::UnableToConnect));
        };

        let Ok(query_res) = conn.query() else {
            return Json(Err(HsmServerAddError::UnableToQuery));
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
                Err(_err) => {
                    return Json(Err(
                        HsmServerAddError::CredentialsFileCouldNotBeOpenedForWriting,
                    ))
                }
            };
            let _ = creds_file.insert(server_id, creds);
            if creds_file.save().is_err() {
                return Json(Err(HsmServerAddError::CredentialsFileCouldNotBeSaved));
            }
        }

        // Extract just the settings that do not need to be
        // stored separately.
        let kmip_state = KmipServerState::from(req);

        info!("Writing to KMIP server file '{kmip_server_state_file}");
        let f = match std::fs::File::create_new(kmip_server_state_file) {
            Ok(f) => f,
            Err(_err) => return Json(Err(HsmServerAddError::KmipServerStateFileCouldNotBeCreated)),
        };
        if let Err(_err) = serde_json::to_writer_pretty(&f, &kmip_state) {
            return Json(Err(HsmServerAddError::KmipServerStateFileCouldNotBeSaved));
        }
        drop(f);

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
    //--- /ps/
    async fn handle_ps_base(
        uri: OriginalUri,
        State(state): State<Arc<HttpServerState>>,
    ) -> Result<Html<String>, StatusCode> {
        Self::zone_server_unit_api_base_common("PS", uri, state).await
    }

    async fn handle_ps(
        uri: OriginalUri,
        State(state): State<Arc<HttpServerState>>,
        Path((action, token)): Path<(String, String)>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Result<(), StatusCode> {
        Self::zone_server_unit_api_common("PS", uri, state, action, token, params).await
    }

    // //--- /zs/
    // async fn handle_zs_base(
    //     uri: OriginalUri,
    //     State(state): State<Arc<HttpServerState>>,
    // ) -> Result<Html<String>, StatusCode> {
    //     Self::zone_server_unit_api_base_common("ZS", uri, state).await
    // }

    // async fn handle_zs(
    //     uri: OriginalUri,
    //     State(state): State<Arc<HttpServerState>>,
    //     Path((action, token)): Path<(String, String)>,
    //     Query(params): Query<HashMap<String, String>>,
    // ) -> Result<(), StatusCode> {
    //     Self::zone_server_unit_api_common("ZS", uri, state, action, token, params).await
    // }

    // //--- /zl/
    // async fn handle_zl_base(
    //     uri: OriginalUri,
    //     State(state): State<Arc<HttpServerState>>,
    // ) -> Result<Html<String>, StatusCode> {
    //     Self::zone_server_unit_api_base_common("ZL", uri, state).await
    // }

    // async fn handle_zl(
    //     uri: OriginalUri,
    //     State(state): State<Arc<HttpServerState>>,
    //     Path((action, token)): Path<(String, String)>,
    //     Query(params): Query<HashMap<String, String>>,
    // ) -> Result<(), StatusCode> {
    //     Self::zone_server_unit_api_common("ZL", uri, state, action, token, params).await
    // }

    //--- /rs2/
    async fn handle_rs2_base(
        uri: OriginalUri,
        State(state): State<Arc<HttpServerState>>,
    ) -> Result<Html<String>, StatusCode> {
        Self::zone_server_unit_api_base_common("RS2", uri, state).await
    }

    async fn handle_rs2(
        uri: OriginalUri,
        State(state): State<Arc<HttpServerState>>,
        Path((action, token)): Path<(String, String)>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Result<(), StatusCode> {
        Self::zone_server_unit_api_common("RS2", uri, state, action, token, params).await
    }

    //--- /rs/
    async fn handle_rs_base(
        uri: OriginalUri,
        State(state): State<Arc<HttpServerState>>,
    ) -> Result<Html<String>, StatusCode> {
        Self::zone_server_unit_api_base_common("RS", uri, state).await
    }

    async fn handle_rs(
        uri: OriginalUri,
        State(state): State<Arc<HttpServerState>>,
        Path((action, token)): Path<(String, String)>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Result<(), StatusCode> {
        Self::zone_server_unit_api_common("RS", uri, state, action, token, params).await
    }

    //--- common api implementations
    async fn zone_server_unit_api_base_common(
        unit: &str,
        uri: OriginalUri,
        state: Arc<HttpServerState>,
    ) -> Result<Html<String>, StatusCode> {
        let (tx, mut rx) = mpsc::channel(10);
        state
            .center
            .app_cmd_tx
            .send((
                unit.into(),
                ApplicationCommand::HandleZoneReviewApiStatus { http_tx: tx },
            ))
            .unwrap();

        let res = rx.recv().await;
        let Some(res) = res else {
            // Failed to receive response... When would that happen?
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };

        debug!(
            "[{HTTP_UNIT_NAME}]: Handled HTTP request: {}",
            uri.path_and_query()
                .map(|p| { p.as_str() })
                .unwrap_or_default()
        );

        Ok(Html(res))
    }

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
