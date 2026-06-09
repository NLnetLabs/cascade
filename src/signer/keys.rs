//! Handling signing keys.

use core::fmt;
use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use camino::Utf8Path;
use domain::{
    base::{Name, Record, iana::SecurityAlgorithm},
    crypto::sign::{BindFormatError, SecretKeyBytes, SignError, SignRaw, Signature},
    dnssec::{
        common::{ParseDnskeyTextError, parse_from_bind},
        sign::keys::{SigningKey, keyset::KeyType},
    },
    rdata::Dnskey,
};
use domain_kmip::{
    ConnectionSettings, KeyUrl,
    dep::kmip::client::pool::{ConnectionManager, KmipConnError},
};
use tracing::{debug, error, warn};
use url::Url;

use crate::{
    center::Center,
    units::{
        http_server::KmipServerState,
        key_manager::{KmipClientCredentialsFile, KmipServerCredentialsFileMode},
        zone_signer::KeySetState,
    },
    zone::Zone,
};

//----------- ZoneSigningKeys --------------------------------------------------

/// A set of keys for signing a zone.
///
/// These are zone signing keys (ZSKs) and combined signing keys (CSKs) that the
/// key manager indicates should be used for signing a zone.
#[derive(Debug)]
pub struct ZoneSigningKeys {
    /// The underlying list of keys.
    ///
    /// This list should be non-empty.
    pub list: Vec<SigningKey<Bytes, KeyPair>>,
}

impl ZoneSigningKeys {
    /// Load the keys that should be used to sign a zone.
    ///
    /// ## Panics
    ///
    /// Panics if `keyset_state` is malformed (e.g. contains invalid URLs).
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(zone = %zone.name),
    )]
    pub fn load(
        center: &Center,
        zone: &Zone,
        keyset_state: &KeySetState,
    ) -> Result<Self, Box<LoadError>> {
        let mut list = Vec::new();

        for (pub_key_name, key_info) in keyset_state.keyset.keys() {
            let (KeyType::Zsk(key_state) | KeyType::Csk(_, key_state)) = key_info.keytype() else {
                debug!("Ignoring key {pub_key_name:?}: Not a ZSK or CSK");
                continue;
            };

            if !key_state.signer() {
                debug!("Ignoring key {pub_key_name:?}: Not enabled by keyset");
                continue;
            }

            let Some(priv_key_name) = key_info.privref() else {
                debug!("Ignoring key {pub_key_name:?}: Don't have a private key");
                continue;
            };

            let priv_url = Url::parse(priv_key_name).expect("valid URL expected");
            let pub_url = Url::parse(pub_key_name).expect("valid URL expected");

            if priv_url.scheme() != pub_url.scheme() {
                return Err(Box::new(LoadError::MultipleSchemesInKey {
                    pub_url,
                    priv_url,
                }));
            }

            let keypair = match priv_url.scheme() {
                "file" => KeyPair::load_from_disk(
                    zone,
                    priv_url.path().as_ref(),
                    pub_url.path().as_ref(),
                )?,
                "kmip" => {
                    let priv_url = KeyUrl::try_from(priv_url.clone()).map_err(|error| {
                        Box::new(LoadError::MalformedKmipKeyUrl {
                            url: priv_url.clone(),
                            error,
                        })
                    })?;
                    let pub_url = KeyUrl::try_from(pub_url.clone()).map_err(|error| {
                        Box::new(LoadError::MalformedKmipKeyUrl {
                            url: pub_url.clone(),
                            error,
                        })
                    })?;
                    KeyPair::load_kmip(center, priv_url, pub_url)?
                }
                _ => {
                    return Err(Box::new(LoadError::UnsupportedScheme { url: pub_url }));
                }
            };

            let key = SigningKey::new(zone.name.clone(), keypair.dnskey().flags(), keypair);

            debug!("Successfully loaded key '{priv_url}' + '{pub_url}'");
            list.push(key);
        }

        debug!("Loaded {} signing key(s).", list.len());

        // TODO: If signing is disabled for a zone should we then allow the
        // unsigned zone to propagate through the pipeline?
        if list.is_empty() {
            error!("No applicable signing keys were found");
            return Err(Box::new(LoadError::NoKeysFound));
        }

        Ok(Self { list })
    }
}

//----------- KeyPair ----------------------------------------------------------

/// A cryptographic keypair for signing.
#[derive(Debug)]
pub enum KeyPair {
    /// A keypair provided by [`domain`].
    Domain(domain::crypto::sign::KeyPair),

    /// A KMIP keypair.
    Kmip(domain_kmip::sign::KeyPair),
}

//--- Signing

impl SignRaw for KeyPair {
    fn algorithm(&self) -> SecurityAlgorithm {
        match self {
            KeyPair::Domain(k) => k.algorithm(),
            KeyPair::Kmip(k) => k.algorithm(),
        }
    }

    fn dnskey(&self) -> Dnskey<Vec<u8>> {
        match self {
            KeyPair::Domain(k) => k.dnskey(),
            KeyPair::Kmip(k) => k.dnskey(),
        }
    }

    fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError> {
        match self {
            KeyPair::Domain(k) => k.sign_raw(data),
            KeyPair::Kmip(k) => k.sign_raw(data),
        }
    }
}

//--- Loading from disk

impl KeyPair {
    /// Load a key-pair from the disk.
    pub fn load_from_disk(
        zone: &Zone,
        priv_key_path: &Utf8Path,
        pub_key_path: &Utf8Path,
    ) -> Result<Self, Box<LoadError>> {
        debug!("Loading the on-disk private key '{priv_key_path}'");
        let priv_key = Self::load_priv_from_file(priv_key_path)?;

        debug!("Loading the on-disk public key '{pub_key_path}'");
        let pub_key = Self::load_pub_from_file(pub_key_path)?;

        let key_pair = domain::crypto::sign::KeyPair::from_bytes(&priv_key, pub_key.data())
            .map_err(|error| {
                Box::new(LoadError::MalformedOnDiskKeyPair {
                    priv_key_path: priv_key_path.into(),
                    pub_key_path: pub_key_path.into(),
                    error,
                })
            })?;

        if pub_key.owner() != &zone.name {
            let encoded_owner = pub_key.owner();
            let zone_name = &zone.name;
            warn!(
                "The public key at '{pub_key_path}' \
                encodes the owner name '{encoded_owner}', \
                but this will be ignored in favor of \
                the name of the zone, '{zone_name}'"
            );
        }

        Ok(Self::Domain(key_pair))
    }

    /// Load a private key from a file.
    fn load_priv_from_file(path: &Utf8Path) -> Result<SecretKeyBytes, Box<LoadError>> {
        let encoded = std::fs::read_to_string(path).map_err(|error| {
            Box::new(LoadError::UnreadableKeyFile {
                path: path.into(),
                error,
            })
        })?;

        // TODO: Compared to the original ldns-signzone there is a minor
        // regression here because at the time of writing the error returned
        // from parsing indicates broadly the type of parsing failure but does
        // note indicate the line number at which parsing failed.
        let secret_key = SecretKeyBytes::parse_from_bind(&encoded).map_err(|error| {
            Box::new(LoadError::MalformedPrivateKeyFile {
                path: path.into(),
                error,
            })
        })?;

        Ok(secret_key)
    }

    /// Load a public key from a file.
    fn load_pub_from_file(
        path: &Utf8Path,
    ) -> Result<Record<Name<Bytes>, Dnskey<Bytes>>, Box<LoadError>> {
        let encoded = std::fs::read_to_string(path).map_err(|error| {
            Box::new(LoadError::UnreadableKeyFile {
                path: path.into(),
                error,
            })
        })?;

        // TODO: Compared to the original ldns-signzone there is a minor
        // regression here because at the time of writing the error returned
        // from parsing indicates broadly the type of parsing failure but does
        // note indicate the line number at which parsing failed.
        let public_key = parse_from_bind(&encoded).map_err(|error| {
            Box::new(LoadError::MalformedPublicKeyFile {
                path: path.into(),
                error,
            })
        })?;

        Ok(public_key)
    }
}

//--- Loading from KMIP

impl KeyPair {
    /// Load a KMIP key-pair.
    pub fn load_kmip(
        center: &Center,
        priv_key_url: KeyUrl,
        pub_key_url: KeyUrl,
    ) -> Result<Self, Box<LoadError>> {
        // TODO: Replace the connection pool if the persisted KMIP server settings
        // were updated more recently than the pool was created.

        let mut kmip_servers = center.signer.kmip_servers.lock().unwrap();
        let kmip_conn_pool = match kmip_servers.entry(priv_key_url.server_id().to_string()) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                // Try and load the KMIP server settings.
                let server_state_path = center
                    .config
                    .kmip_server_state_dir
                    .join(priv_key_url.server_id());
                debug!("Reading KMIP server state from '{server_state_path}'");
                let f = std::fs::File::open(&server_state_path).map_err(|error| {
                    Box::new(LoadError::UnreadableKmipServerState {
                        path: server_state_path.clone().into(),
                        error,
                    })
                })?;
                let kmip_server: KmipServerState = serde_json::from_reader(f).map_err(|error| {
                    Box::new(LoadError::MalformedKmipServerState {
                        path: server_state_path.clone().into(),
                        error,
                    })
                })?;
                let KmipServerState {
                    server_id,
                    ip_host_or_fqdn: host,
                    port,
                    insecure,
                    connect_timeout,
                    read_timeout,
                    write_timeout,
                    max_response_bytes,
                    has_credentials,
                    ..
                } = kmip_server;

                let mut username = None;
                let mut password = None;
                if has_credentials {
                    let creds_path = &center.config.kmip_credentials_store_path;
                    let creds_file = KmipClientCredentialsFile::new(
                        creds_path.as_std_path(),
                        KmipServerCredentialsFileMode::ReadOnly,
                    )
                    .unwrap();

                    let creds = creds_file.get(&server_id).ok_or_else(|| {
                        Box::new(LoadError::MissingKmipClientCredentials {
                            server_id: server_id.clone().into(),
                            path: creds_path.clone(),
                        })
                    })?;

                    username = Some(creds.username.clone());
                    password = creds.password.clone();
                }

                let conn_settings = ConnectionSettings {
                    host,
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
                };

                debug!("Connecting to KMIP server '{server_id}'");
                let pool = ConnectionManager::create_connection_pool(
                    server_id.clone(),
                    Arc::new(conn_settings.clone()),
                    10,
                    Some(Duration::from_secs(60)),
                    Some(Duration::from_secs(60)),
                )
                .map_err(|error| {
                    Box::new(LoadError::KmipConnection {
                        server_id: server_id.into(),
                        error,
                    })
                })?;

                e.insert(pool)
            }
        };

        let priv_key_url_inner = (*priv_key_url).clone();
        let pub_key_url_inner = (*pub_key_url).clone();

        let key_pair = Self::Kmip(
            domain_kmip::sign::KeyPair::from_urls(
                priv_key_url,
                pub_key_url,
                kmip_conn_pool.clone(),
            )
            .map_err(|error| {
                Box::new(LoadError::MalformedKmipKeypair {
                    priv_key_url: priv_key_url_inner,
                    pub_key_url: pub_key_url_inner,
                    error: error.to_string(),
                })
            })?,
        );

        Ok(key_pair)
    }
}

//============ Errors ==========================================================

//----------- LoadError --------------------------------------------------------

/// An error loading [`ZoneSigningKeys`].
#[derive(Debug)]
pub enum LoadError {
    /// No applicable zone signing keys were found.
    NoKeysFound,

    /// A key uses multiple key URI schemes.
    MultipleSchemesInKey {
        /// The URL of the public key.
        pub_url: Url,

        /// The URL of the private key.
        priv_url: Url,
    },

    /// A public/private key uses an unsupported URI scheme.
    UnsupportedScheme {
        /// The URL of the key.
        url: Url,
    },

    /// A public/private key could not be read from a file.
    UnreadableKeyFile {
        /// The path to the key.
        path: Box<Utf8Path>,

        /// The underlying I/O error.
        error: std::io::Error,
    },

    /// An on-disk private key could not be parsed.
    MalformedPrivateKeyFile {
        /// The path to the key.
        path: Box<Utf8Path>,

        /// The underlying error.
        error: BindFormatError,
    },

    /// An on-disk public key could not be parsed.
    MalformedPublicKeyFile {
        /// The path to the key.
        path: Box<Utf8Path>,

        /// The underlying error.
        error: ParseDnskeyTextError,
    },

    /// An on-disk key-pair was malformed.
    MalformedOnDiskKeyPair {
        /// The path to the private key.
        priv_key_path: Box<Utf8Path>,

        /// The path to the public key.
        pub_key_path: Box<Utf8Path>,

        /// The underlying error.
        error: domain::crypto::sign::FromBytesError,
    },

    /// A KMIP key URL was malformed.
    MalformedKmipKeyUrl {
        /// The URL of the key.
        url: Url,

        /// The underlying error.
        error: String,
    },

    /// Could not read the KMIP server state.
    UnreadableKmipServerState {
        /// The path to the state file.
        path: Box<Utf8Path>,

        /// The underlying error.
        error: std::io::Error,
    },

    /// Could not parse the KMIP server state.
    MalformedKmipServerState {
        /// The path to the state file.
        path: Box<Utf8Path>,

        /// The underlying error.
        error: serde_json::Error,
    },

    /// Could not load the KMIP client credentials file.
    KmipClientCredentials {
        /// The path to the credentials file.
        path: Box<Utf8Path>,

        /// The underlying error.
        error: String,
    },

    /// Missing credentials for a KMIP server.
    MissingKmipClientCredentials {
        /// The name of the KMIP server.
        server_id: Box<str>,

        /// The path to the credentials file.
        path: Box<Utf8Path>,
    },

    /// Could not connect to a KMIP server.
    KmipConnection {
        /// The name of the KMIP server.
        server_id: Box<str>,

        /// The underlying error.
        error: KmipConnError,
    },

    /// A KMIP key-pair was malformed.
    MalformedKmipKeypair {
        /// The URL of the private key.
        priv_key_url: Url,

        /// The URL of the public key.
        pub_key_url: Url,

        /// The underlying error.
        error: String,
    },
}

impl core::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::NoKeysFound => None,
            Self::MultipleSchemesInKey { .. } => None,
            Self::UnsupportedScheme { .. } => None,
            Self::UnreadableKeyFile { error, .. } => Some(error),
            Self::MalformedPrivateKeyFile { error, .. } => Some(error),
            Self::MalformedPublicKeyFile { error, .. } => Some(error),
            Self::MalformedOnDiskKeyPair { error, .. } => Some(error),
            Self::MalformedKmipKeyUrl { .. } => None, // TODO
            Self::UnreadableKmipServerState { error, .. } => Some(error),
            Self::MalformedKmipServerState { error, .. } => Some(error),
            Self::KmipClientCredentials { .. } => None, // TODO
            Self::MissingKmipClientCredentials { .. } => None,
            Self::KmipConnection { .. } => None,       // TODO
            Self::MalformedKmipKeypair { .. } => None, // TODO
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKeysFound => f.write_str("no applicable zone signing keys were found"),
            Self::MultipleSchemesInKey { pub_url, priv_url } => {
                let pub_scheme = pub_url.scheme();
                let priv_scheme = priv_url.scheme();
                write!(
                    f,
                    "Multiple key URI schemes \
                    ({pub_scheme:?} and {priv_scheme:?}) \
                    as used by key '{pub_url}' are not supported"
                )
            }
            Self::UnsupportedScheme { url } => {
                let scheme = url.scheme();
                write!(
                    f,
                    "The key URI scheme '{scheme}', \
                    as used by key '{url}', \
                    is not supported"
                )
            }
            Self::UnreadableKeyFile { path, error } => {
                write!(f, "Could not load a key from '{path}': {error}")
            }
            Self::MalformedPrivateKeyFile { path, error } => {
                write!(
                    f,
                    "The on-disk private key at '{path}' could not be parsed: {error}"
                )
            }
            Self::MalformedPublicKeyFile { path, error } => {
                write!(
                    f,
                    "The on-disk public key at '{path}' could not be parsed: {error}"
                )
            }
            Self::MalformedOnDiskKeyPair {
                priv_key_path,
                pub_key_path,
                error,
            } => {
                write!(
                    f,
                    "An on-disk key-pair \
                    (private key '{priv_key_path}', public key '{pub_key_path}') \
                    was malformed: {error}"
                )
            }
            Self::MalformedKmipKeyUrl { url, error } => {
                write!(f, "The KMIP key URL '{url}' is malformed: {error}")
            }
            Self::UnreadableKmipServerState { path, error } => {
                write!(
                    f,
                    "The KMIP server state file '{path}' could not be read: {error}"
                )
            }
            Self::MalformedKmipServerState { path, error } => {
                write!(
                    f,
                    "The KMIP server state file '{path}' was malformed: {error}"
                )
            }
            Self::KmipClientCredentials { path, error } => {
                write!(
                    f,
                    "The KMIP client credentials store \
                    (at '{path}') could not be loaded: {error}"
                )
            }
            Self::MissingKmipClientCredentials { server_id, path } => {
                write!(
                    f,
                    "The KMIP server '{server_id}' requires client credentials, \
                    but the client credentials store (at '{path}') does not provide any"
                )
            }
            Self::KmipConnection { server_id, error } => {
                write!(f, "Could not connect to KMIP server '{server_id}': {error}")
            }
            Self::MalformedKmipKeypair {
                priv_key_url,
                pub_key_url,
                error,
            } => {
                write!(
                    f,
                    "A KMIP key-pair \
                    (private key '{priv_key_url}', public key '{pub_key_url}') \
                    was malformed: {error}"
                )
            }
        }
    }
}
