//! Hardware Security Modules (HSMs).

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use camino::Utf8PathBuf;
use cascade_api::HsmServerAdd;
use serde::{Deserialize, Serialize};

use crate::api;

//----------- HsmStore ---------------------------------------------------------

/// A store of known [`Hsm`]s.
#[derive(Clone, Debug, Default)]
pub struct HsmStore {
    /// A map of known HSMs by name.
    pub map: foldhash::HashMap<Box<str>, Arc<Hsm>>,
}

impl HsmStore {
    /// Construct a new [`HsmStore`].
    pub fn new() -> Self {
        Self::default()
    }

    // TODO: Methods to get, modify, add, remove HSMs?

    pub fn server_exists(&self, hsm_server_id: &str) -> bool {
        self.map.contains_key(hsm_server_id)
    }
}

//----------- Hsm --------------------------------------------------------------

/// A Hardware Security Module (HSM).
#[derive(Debug)]
pub struct Hsm {
    /// The state of the HSM.
    pub state: Mutex<HsmState>,
}

//----------- HsmState ---------------------------------------------------------

/// The state of an [`Hsm`].
#[derive(Debug)]
pub struct HsmState {
    pub kmip: KmipServerState,
}

/// Non-sensitive KMIP server settings to be persisted.
///
/// Sensitive details such as certificates and credentials should be stored
/// separately.
//
// TODO: Prefix all TLS related fields with tls_ or move them into a child
// structure?
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct KmipServerState {
    pub server_id: String,
    pub ip_host_or_fqdn: String,
    pub port: u16,
    pub insecure: bool,
    pub client_cert_path: Option<Utf8PathBuf>,
    pub client_key_path: Option<Utf8PathBuf>,
    pub server_cert_path: Option<Utf8PathBuf>,
    pub server_name: Option<String>,
    pub ca_cert_path: Option<Utf8PathBuf>,
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
            server_name: srv.server_name,
            connect_timeout: srv.connect_timeout,
            read_timeout: srv.read_timeout,
            write_timeout: srv.write_timeout,
            max_response_bytes: srv.max_response_bytes,
            key_label_prefix: srv.key_label_prefix,
            key_label_max_bytes: srv.key_label_max_bytes,
            has_credentials: srv.username.is_some(),

            // mTLS certificate/key paths cannot be set as HsmServerAdd has
            // their byte content, not file paths. These should be filled in
            // once the bytes have been written to disk and the paths to the
            // resulting files are known, so we set them to None for now.
            client_cert_path: None,
            client_key_path: None,
            server_cert_path: None,
            ca_cert_path: None,
        }
    }
}

impl From<KmipServerState> for api::KmipServerState {
    fn from(value: KmipServerState) -> Self {
        let KmipServerState {
            server_id,
            ip_host_or_fqdn,
            port,
            insecure,
            server_name,
            connect_timeout,
            read_timeout,
            write_timeout,
            max_response_bytes,
            key_label_prefix,
            key_label_max_bytes,
            has_credentials,
            ..
        } = value;

        Self {
            server_id,
            ip_host_or_fqdn,
            port,
            insecure,
            server_name,
            connect_timeout,
            read_timeout,
            write_timeout,
            max_response_bytes,
            key_label_prefix,
            key_label_max_bytes,
            has_credentials,
        }
    }
}
