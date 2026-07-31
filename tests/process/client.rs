use std::time::Duration;

use cascade_api as api;
use domain::base::Serial;
use serde::{Serialize, de::DeserializeOwned};

use crate::process::DaemonSockets;

/// An HTTP client for controlling a [`Daemon`].
///
/// [`Daemon`]: super::Daemon
#[derive(Debug)]
pub struct DaemonClient {
    /// The underlying HTTP client.
    inner: reqwest::blocking::Client,

    /// The base URL for all requests.
    base: reqwest::Url,
}

//--- Initialization and configuration

impl DaemonClient {
    /// The user agent.
    const USER_AGENT: &str = concat!(
        env!("CARGO_PKG_NAME"),
        "-testing/",
        env!("CARGO_PKG_VERSION"),
    );

    /// The maximum time an HTTP request is expected to take.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// Construct a new [`DaemonClient`].
    pub fn new(base: reqwest::Url) -> Self {
        let inner = reqwest::blocking::ClientBuilder::new()
            .user_agent(Self::USER_AGENT)
            .timeout(Self::REQUEST_TIMEOUT)
            .build()
            .unwrap();

        Self { inner, base }
    }

    /// Construct a new [`DaemonClient`].
    pub fn for_sockets(sockets: &DaemonSockets) -> Self {
        let addr = sockets.remote_control.local_addr().unwrap();
        let base = reqwest::Url::parse(&format!("http://{addr}/")).unwrap();
        Self::new(base)
    }
}

//--- Generic request methods

impl DaemonClient {
    /// Decode a JSON response.
    ///
    /// ## Panics
    ///
    /// Panics if the response cannot be deserialized.
    fn decode_json<T: DeserializeOwned>(response: reqwest::blocking::Response) -> T {
        response
            .error_for_status()
            .unwrap_or_else(|err| {
                panic!(
                    "HTTP request failed with status code {}",
                    err.status().unwrap()
                )
            })
            .json()
            .unwrap_or_else(|err| panic!("Could not decode JSON: {err}"))
    }

    /// Make a GET request, receiving JSON data.
    pub fn get_json<T: DeserializeOwned>(&self, url: &str) -> T {
        let url = self.base.join(url).unwrap();
        let response = self.inner.get(url).send().unwrap();
        Self::decode_json(response)
    }

    /// Make a POST request, sending and receiving JSON data.
    pub fn post_json<T: DeserializeOwned, P: Serialize>(&self, url: &str, payload: P) -> T {
        let url = self.base.join(url).unwrap();
        let response = self.inner.post(url).json(&payload).send().unwrap();
        Self::decode_json(response)
    }

    /// Make a POST request, receiving JSON data.
    pub fn post_recv_json<T: DeserializeOwned>(&self, url: &str) -> T {
        let url = self.base.join(url).unwrap();
        let response = self.inner.post(url).send().unwrap();
        Self::decode_json(response)
    }
}

//--- Concrete client functionality

/// # Policies
impl DaemonClient {
    /// The names of all known policies.
    pub fn policy_names(&self) -> Vec<String> {
        self.get_json::<api::PolicyListResult>("policy/").policies
    }

    /// Information about a policy.
    pub fn policy_info(&self, name: &str) -> api::PolicyInfo {
        self.get_json::<api::PolicyInfo>(&format!("policy/{name}"))
    }

    /// Reload all policies.
    pub fn reload_policies(&self) -> Result<api::PolicyChanges, api::PolicyReloadError> {
        self.post_recv_json("policy/reload")
    }
}

/// # Zones
impl DaemonClient {
    /// The names of all known zones.
    pub fn zone_names(&self) -> Vec<api::ZoneName> {
        self.get_json::<api::ZonesListResult>("zone/").zones
    }

    /// The status of a zone.
    pub fn zone_status(&self, name: &str) -> api::ZoneStatus {
        self.get_json(&format!("zone/{name}/status"))
    }

    /// The history of important events for a zone.
    pub fn zone_history(&self, name: &str) -> api::ZoneHistory {
        self.get_json(&format!("zone/{name}/history"))
    }

    /// Add a new zone.
    pub fn add_zone(&self, cmd: api::ZoneAdd) -> Result<api::ZoneAddResult, api::ZoneAddError> {
        self.post_json("zone/add", cmd)
    }

    /// Remove a zone.
    pub fn remove_zone(&self, name: &str) -> Result<api::ZoneRemoveResult, api::ZoneRemoveError> {
        self.post_recv_json(&format!("zone/{name}/remove"))
    }

    /// Reload a zone.
    pub fn reload_zone(&self, name: &str) -> Result<api::ZoneReloadResult, api::ZoneReloadError> {
        self.post_recv_json(&format!("zone/{name}/reload"))
    }

    /// Start moving a zone to maintenance mode.
    pub fn start_maintenance_for_zone(&self, name: &str) -> api::ZoneMaintenanceModeResult {
        self.post_recv_json(&format!("zone/{name}/maintenance/enable"))
    }

    /// Restore a zone from (moving to) maintenance mode.
    pub fn stop_maintenance_for_zone(&self, name: &str) -> api::ZoneMaintenanceModeResult {
        self.post_recv_json(&format!("zone/{name}/maintenance/disable"))
    }

    /// Reset the pipeline for a zone.
    pub fn reset_pipeline(&self, name: &str) -> api::ZoneResetResult {
        self.post_recv_json(&format!("zone/{name}/reset"))
    }

    /// Override a unsigned hard-halt for a zone.
    pub fn override_unsigned_hard_halt(&self, name: &str) -> api::ZoneOverrideResult {
        self.post_recv_json(&format!("zone/{name}/unsigned/override"))
    }

    /// Override a signed hard-halt for a zone.
    pub fn override_signed_hard_halt(&self, name: &str) -> api::ZoneOverrideResult {
        self.post_recv_json(&format!("zone/{name}/signed/override"))
    }

    /// Manually approve an unsigned zone instance pending review.
    pub fn approve_unsigned(&self, name: &str, serial: Serial) -> api::ZoneReviewResult {
        self.post_recv_json(&format!("zone/{name}/unsigned/{serial}/approve"))
    }

    /// Manually approve a signed zone instance pending review.
    pub fn approve_signed(&self, name: &str, serial: Serial) -> api::ZoneReviewResult {
        self.post_recv_json(&format!("zone/{name}/signed/{serial}/approve"))
    }

    /// Manually reject an unsigned zone instance pending review.
    pub fn reject_unsigned(&self, name: &str, serial: Serial) -> api::ZoneReviewResult {
        self.post_recv_json(&format!("zone/{name}/unsigned/{serial}/reject"))
    }

    /// Manually reject a signed zone instance pending review.
    pub fn reject_signed(&self, name: &str, serial: Serial) -> api::ZoneReviewResult {
        self.post_recv_json(&format!("zone/{name}/signed/{serial}/reject"))
    }
}
