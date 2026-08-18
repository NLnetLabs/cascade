//! Controlling Cascade.

use std::{
    collections::HashMap,
    fmt::{self, Debug},
    io::Write,
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    time::{Duration, SystemTime},
};

use bollard::{
    Docker,
    container::LogOutput,
    exec::StartExecResults,
    plugin::{ExecConfig, PortBinding},
};
use cascade_api as api;
use futures_util::{Stream, StreamExt};
use serde::{Serialize, de::DeserializeOwned};
use tracing::Instrument;

use super::{ExposedDnsPort, ExposedPort, strs};

//----------- Cascade ----------------------------------------------------------

/// A running Cascade instance.
pub struct Cascade {
    /// The Docker exec ID.
    exec_id: String,

    /// The configuration with which Cascade was launched.
    #[expect(dead_code)]
    config: CascadeConfig,

    /// Exposed ports.
    #[expect(dead_code)]
    ports: CascadePorts,

    /// An HTTP client for communicating with Cascade.
    control: CascadeControl,
}

impl Cascade {
    /// The maximum time Cascade startup is allowed to take.
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

    /// The interval between pings to check Cascade's health.
    const HEALTH_PING_INTERVAL: Duration = Duration::from_millis(100);

    /// Start Cascade.
    pub async fn start(client: &Docker, container_id: &str) -> Self {
        Self::start_with(client, container_id, CascadeConfig::default()).await
    }

    /// Start Cascade with the given configuration.
    pub async fn start_with(client: &Docker, container_id: &str, config: CascadeConfig) -> Self {
        tracing::info!("Starting Cascade");

        let (exec_id, ports) = tokio::join!(self::start(client, container_id, &config), async {
            let response = client.inspect_container(container_id, None).await.unwrap();
            let ports = response.network_settings.unwrap().ports.unwrap();
            CascadePorts::get(&ports)
        });

        let control = CascadeControl::new(&ports);

        let this = Self {
            exec_id,
            config,
            ports,
            control,
        };

        // Wait until the daemon appears ready.
        let ready = tokio::time::timeout(Self::STARTUP_TIMEOUT, async {
            loop {
                tokio::time::sleep(Self::HEALTH_PING_INTERVAL).await;
                if this.health().await.is_ok_and(|h| h.healthy) {
                    break;
                }
            }
        })
        .await;
        if ready.is_err() {
            tracing::error!("Cascade did not appear ready in time.");
            let stream = client.export_container(container_id);
            let mut stream = std::pin::pin!(stream);
            let mut file = std::fs::File::create("dump.tar").unwrap();
            while let Some(chunk) = stream.next().await {
                file.write_all(&chunk.unwrap()).unwrap();
            }
            tracing::info!("Container dumped to `dump.tar`");
            panic!("Cascade did not appear ready in time")
        }

        this
    }

    // Stop Cascade.
}

//--- Debugging

impl fmt::Debug for Cascade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cascade")
            .field("exec_id", &self.exec_id)
            .finish_non_exhaustive()
    }
}

//----------- CascadeControl ---------------------------------------------------

/// An HTTP client controlling Cascade.
pub struct CascadeControl {
    /// The underlying HTTP client.
    inner: reqwest::Client,

    /// The base URL for all requests.
    base: url::Url,
}

impl CascadeControl {
    /// Prepare a new [`CascadeControl`].
    fn new(ports: &CascadePorts) -> Self {
        let inner = reqwest::ClientBuilder::new()
            .user_agent(Self::USER_AGENT)
            .timeout(Self::REQUEST_TIMEOUT)
            .http2_prior_knowledge()
            .build()
            .unwrap();

        let base = reqwest::Url::parse(&format!(
            "http://{}/",
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, ports.remote_control.on_ipv4)
        ))
        .unwrap();

        Self { inner, base }
    }

    /// The user agent for HTTP requests.
    const USER_AGENT: &str = concat!(
        env!("CARGO_PKG_NAME"),
        "-testing/",
        env!("CARGO_PKG_VERSION"),
    );

    /// The maximum time an HTTP request is expected to take.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// Decode a JSON response.
    ///
    /// ## Panics
    ///
    /// Panics if the response cannot be deserialized.
    async fn decode_json<T: DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, CascadeControlError> {
        response
            .error_for_status()
            .map_err(|err| CascadeControlError::BadStatusCode(err.status().unwrap()))?
            .json()
            .await
            .map_err(CascadeControlError::Receive)
    }

    /// Make a GET request, receiving JSON data.
    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn get_json<T>(&self, url: &str) -> Result<T, CascadeControlError>
    where
        T: Debug + DeserializeOwned,
    {
        let url = self.base.join(url).unwrap();
        let response = self
            .inner
            .get(url.clone())
            .send()
            .await
            .map_err(CascadeControlError::Send)?;
        let result = Self::decode_json(response).await;
        tracing::trace!("GET {url:?} -> {result:?}");
        result
    }

    /// Make a POST request, sending and receiving JSON data.
    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn post_json<T, P>(&self, url: &str, payload: P) -> Result<T, CascadeControlError>
    where
        T: Debug + DeserializeOwned,
        P: Debug + Serialize,
    {
        let url = self.base.join(url).unwrap();
        let response = self
            .inner
            .post(url.clone())
            .json(&payload)
            .send()
            .await
            .map_err(CascadeControlError::Send)?;
        let result = Self::decode_json(response).await;
        tracing::trace!("POST {url:?} with {payload:?} -> {result:?}");
        result
    }

    /// Make a POST request, receiving JSON data.
    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn post_recv_json<T>(&self, url: &str) -> Result<T, CascadeControlError>
    where
        T: Debug + DeserializeOwned,
    {
        let url = self.base.join(url).unwrap();
        let response = self
            .inner
            .post(url.clone())
            .send()
            .await
            .map_err(CascadeControlError::Send)?;
        let result = Self::decode_json(response).await;
        tracing::trace!("POST {url:?} -> {result:?}");
        result
    }
}

/// # Overall Control
impl Cascade {
    /// Overall health.
    #[tracing::instrument(level = "trace", skip(self), ret)]
    pub async fn health(&self) -> Result<api::Health, CascadeControlError> {
        self.control.get_json("health").await
    }
}

/// # Policy Control
#[expect(dead_code)]
impl Cascade {
    /// The names of all known policies.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn policy_names(&self) -> Vec<String> {
        self.control
            .get_json::<api::PolicyListResult>("policy/")
            .await
            .unwrap()
            .policies
    }

    /// Information about a policy.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn policy_info(&self, name: &str) -> api::PolicyInfo {
        self.control
            .get_json::<api::PolicyInfo>(&format!("policy/{name}"))
            .await
            .unwrap()
    }

    /// Reload all policies.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn reload_policies(&self) -> Result<api::PolicyChanges, api::PolicyReloadError> {
        self.control.post_recv_json("policy/reload").await.unwrap()
    }
}

/// # Zones Control
#[expect(dead_code)]
impl Cascade {
    /// The names of all known zones.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn zone_names(&self) -> Vec<api::ZoneName> {
        self.control
            .get_json::<api::ZonesListResult>("zone/")
            .await
            .unwrap()
            .zones
    }

    /// The status of a zone.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn zone_status(&self, name: &str) -> Result<api::ZoneStatus, api::ZoneStatusError> {
        self.control
            .get_json(&format!("zone/{name}/status"))
            .await
            .unwrap()
    }

    /// The history of important events for a zone.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn zone_history(
        &self,
        name: &str,
    ) -> Result<api::ZoneHistory, api::ZoneHistoryError> {
        self.control
            .get_json(&format!("zone/{name}/history"))
            .await
            .unwrap()
    }

    /// Add a new zone.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn add_zone(
        &self,
        cmd: api::ZoneAdd,
    ) -> Result<api::ZoneAddResult, api::ZoneAddError> {
        self.control.post_json("zone/add", cmd).await.unwrap()
    }

    /// Remove a zone.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn remove_zone(
        &self,
        name: &str,
    ) -> Result<api::ZoneRemoveResult, api::ZoneRemoveError> {
        self.control
            .post_recv_json(&format!("zone/{name}/remove"))
            .await
            .unwrap()
    }

    /// Reload a zone.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn reload_zone(
        &self,
        name: &str,
    ) -> Result<api::ZoneReloadResult, api::ZoneReloadError> {
        self.control
            .post_recv_json(&format!("zone/{name}/reload"))
            .await
            .unwrap()
    }

    /// Start moving a zone to maintenance mode.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn start_maintenance_for_zone(&self, name: &str) -> api::ZoneMaintenanceModeResult {
        self.control
            .post_recv_json(&format!("zone/{name}/maintenance/enable"))
            .await
            .unwrap()
    }

    /// Restore a zone from (moving to) maintenance mode.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn stop_maintenance_for_zone(&self, name: &str) -> api::ZoneMaintenanceModeResult {
        self.control
            .post_recv_json(&format!("zone/{name}/maintenance/disable"))
            .await
            .unwrap()
    }

    /// Reset the pipeline for a zone.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn reset_pipeline(&self, name: &str) -> api::ZoneResetResult {
        self.control
            .post_recv_json(&format!("zone/{name}/reset"))
            .await
            .unwrap()
    }

    /// Override a unsigned hard-halt for a zone.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn override_unsigned_hard_halt(&self, name: &str) -> api::ZoneOverrideResult {
        self.control
            .post_recv_json(&format!("zone/{name}/unsigned/override"))
            .await
            .unwrap()
    }

    /// Override a signed hard-halt for a zone.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn override_signed_hard_halt(&self, name: &str) -> api::ZoneOverrideResult {
        self.control
            .post_recv_json(&format!("zone/{name}/signed/override"))
            .await
            .unwrap()
    }

    /// Manually approve an unsigned zone instance pending review.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn approve_unsigned(&self, name: &str, serial: api::Serial) -> api::ZoneReviewResult {
        self.control
            .post_recv_json(&format!("zone/{name}/unsigned/{serial}/approve"))
            .await
            .unwrap()
    }

    /// Manually approve a signed zone instance pending review.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn approve_signed(&self, name: &str, serial: api::Serial) -> api::ZoneReviewResult {
        self.control
            .post_recv_json(&format!("zone/{name}/signed/{serial}/approve"))
            .await
            .unwrap()
    }

    /// Manually reject an unsigned zone instance pending review.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn reject_unsigned(&self, name: &str, serial: api::Serial) -> api::ZoneReviewResult {
        self.control
            .post_recv_json(&format!("zone/{name}/unsigned/{serial}/reject"))
            .await
            .unwrap()
    }

    /// Manually reject a signed zone instance pending review.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub async fn reject_signed(&self, name: &str, serial: api::Serial) -> api::ZoneReviewResult {
        self.control
            .post_recv_json(&format!("zone/{name}/signed/{serial}/reject"))
            .await
            .unwrap()
    }
}

//----------- Starting Cascade -------------------------------------------------

/// Start Cascade and return the Docker exec ID.
async fn start(client: &Docker, container_id: &str, config: &CascadeConfig) -> String {
    let command = strs![
        "/test/bin/cascaded",
        "--config",
        "/test/cascade/config.toml",
        "--state",
        "/test/cascade/state.db",
    ];

    let mut env = None::<Vec<_>>;
    if let Some(time) = &config.faketime {
        // Set to seconds since Unix epoch.
        let unixtime = time.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        let unixtime = unixtime.as_secs();
        env.get_or_insert_default()
            .push(format!("CASCADE_FAKETIME={unixtime}"));
    }

    let exec_cfg = ExecConfig {
        cmd: Some(command),
        working_dir: Some("/test/cascade".into()),
        env,
        ..Default::default()
    };

    let exec_id = client.create_exec(container_id, exec_cfg).await.unwrap().id;

    let StartExecResults::Attached { output, input: _ } =
        client.start_exec(&exec_id, None).await.unwrap()
    else {
        unreachable!("Did not enable `detached`")
    };

    tokio::spawn(log_exec_output(container_id, &exec_id, output));

    exec_id
}

type LogOutputResult = Result<LogOutput, bollard::errors::Error>;

/// Log unexpected output from Docker exec.
fn log_exec_output(
    container_id: &str,
    exec_id: &str,
    mut output: Pin<Box<dyn Stream<Item = LogOutputResult> + Send>>,
) -> impl Future<Output = ()> + Send + use<> {
    let span = tracing::debug_span!(
        parent: tracing::Span::none(),
        "cascade_output",
        container = container_id,
        exec_id);

    async move {
        while let Some(event) = output.next().await {
            match event {
                Ok(LogOutput::StdOut { message }) => {
                    if let Ok(text) = std::str::from_utf8(&message) {
                        tracing::debug!(text, "stdout");
                    } else {
                        tracing::debug!(text = ?message.utf8_chunks(), "stdout");
                    }
                }
                Ok(LogOutput::StdErr { message }) => {
                    if let Ok(text) = std::str::from_utf8(&message) {
                        tracing::debug!(text, "stderr");
                    } else {
                        tracing::debug!(text = ?message.utf8_chunks(), "stderr");
                    }
                }
                Ok(other) => {
                    tracing::debug!(?other);
                }
                Err(error) => {
                    tracing::error!("Listening failed: {error}")
                }
            }
        }
    }
    .instrument(span)
}

//------------------------------------------------------------------------------

/// Configuration for launching Cascade.
#[derive(Debug, Default)]
pub struct CascadeConfig {
    /// The fake time to set.
    pub faketime: Option<SystemTime>,
}

/// Exposed ports from Cascade.
#[derive(Clone, Debug)]
pub struct CascadePorts {
    /// The remote control server.
    pub remote_control: ExposedPort,

    /// The loaded review server.
    #[expect(dead_code)]
    pub loaded_review: ExposedDnsPort,

    /// The signed review server.
    #[expect(dead_code)]
    pub signed_review: ExposedDnsPort,

    /// The publication server.
    #[expect(dead_code)]
    pub publication: ExposedDnsPort,
}

impl CascadePorts {
    /// Look up the exposed Cascade ports.
    fn get(ports: &HashMap<String, Option<Vec<PortBinding>>>) -> Self {
        Self {
            remote_control: ExposedPort::get_tcp(ports, super::ports::REMOTE_CONTROL),
            loaded_review: ExposedDnsPort::get(ports, super::ports::LOADED_REVIEW),
            signed_review: ExposedDnsPort::get(ports, super::ports::SIGNED_REVIEW),
            publication: ExposedDnsPort::get(ports, super::ports::PUBLICATION),
        }
    }
}

/// An error controlling Cascade.
#[derive(Debug)]
pub enum CascadeControlError {
    /// Could not send the request.
    Send(reqwest::Error),

    /// A bad status code was received.
    BadStatusCode(reqwest::StatusCode),

    /// Could not fetch or decode a body.
    Receive(reqwest::Error),
}

impl fmt::Display for CascadeControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CascadeControlError::Send(error) => {
                write!(f, "Could not send an HTTP request: {error}")
            }
            CascadeControlError::BadStatusCode(status_code) => {
                write!(f, "HTTP request failed with status code {status_code}")
            }
            CascadeControlError::Receive(error) => {
                write!(f, "Could not receive HTTP response: {error}")
            }
        }
    }
}
