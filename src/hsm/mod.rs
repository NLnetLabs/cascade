//! Hardware Security Modules (HSMs).

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

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

impl From<api::HsmServerAdd> for KmipServerState {
    fn from(srv: api::HsmServerAdd) -> Self {
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

impl From<KmipServerState> for api::KmipServerState {
    fn from(value: KmipServerState) -> Self {
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
        } = value;

        Self {
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
        }
    }
}
