use std::{
    collections::HashMap,
    fmt::{self, Display},
};

use bytes::Bytes;
use serde::{
    de::{self, Visitor},
    Deserializer, Serialize, Serializer,
};
use tokio::time::Instant;
use tracing::trace;

use core::time::Duration;
use domain::{
    base::{Name, Serial, Ttl},
    rdata::Soa,
    tsig::{Algorithm, Key, KeyName},
};

use crate::api;

//------------ Type Aliases --------------------------------------------------

/// A store of TSIG keys index by key name and algorithm.
#[allow(dead_code)]
pub type ZoneMaintainerKeyStore = HashMap<(KeyName, Algorithm), Key>;

//------------ ZoneStatus ----------------------------------------------------

#[derive(Copy, Clone, Debug, Default, PartialEq)]
enum ZoneRefreshStatus {
    /// Refreshing according to the SOA REFRESH interval.
    #[default]
    RefreshPending,

    RefreshInProgress(usize),

    /// Periodically retrying according to the SOA RETRY interval.
    RetryPending,

    RetryInProgress,

    /// Refresh triggered by NOTIFY currently in progress.
    NotifyInProgress,
}

//--- Display

impl Display for ZoneRefreshStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZoneRefreshStatus::RefreshPending => f.write_str("refresh pending"),
            ZoneRefreshStatus::RefreshInProgress(n) => {
                f.write_fmt(format_args!("refresh in progress ({n} updates applied)"))
            }
            ZoneRefreshStatus::RetryPending => f.write_str("retrying"),
            ZoneRefreshStatus::RetryInProgress => f.write_str("retry in progress"),
            ZoneRefreshStatus::NotifyInProgress => f.write_str("notify in progress"),
        }
    }
}

//--- Conversion

impl From<ZoneRefreshStatus> for api::ZoneRefreshStatus {
    fn from(value: ZoneRefreshStatus) -> Self {
        match value {
            ZoneRefreshStatus::RefreshPending => Self::RefreshPending,
            ZoneRefreshStatus::RefreshInProgress(p) => Self::RefreshInProgress(p),
            ZoneRefreshStatus::RetryPending => Self::RetryPending,
            ZoneRefreshStatus::RetryInProgress => Self::RetryInProgress,
            ZoneRefreshStatus::NotifyInProgress => Self::NotifyInProgress,
        }
    }
}

//------------ ZoneRefreshMetrics --------------------------------------------

pub fn instant_to_duration_secs(instant: Instant) -> u64 {
    match Instant::now().checked_duration_since(instant) {
        Some(d) => d.as_secs(),
        None => 0,
    }
}

pub fn serialize_instant_as_duration_secs<S>(
    instant: &Instant,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u64(instant_to_duration_secs(*instant))
}

pub fn serialize_duration_as_secs<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u64(duration.as_secs())
}

pub fn serialize_opt_duration_as_secs<S>(
    instant: &Option<Duration>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match instant {
        Some(v) => serialize_duration_as_secs(v, serializer),
        None => serializer.serialize_str("null"),
    }
}

pub fn deserialize_duration_from_secs<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    struct U64Visitor;
    impl<'de> Visitor<'de> for U64Visitor {
        type Value = u64;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a u64 unsigned integer value")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value)
        }
    }
    Ok(Duration::from_secs(
        deserializer.deserialize_u64(U64Visitor)?,
    ))
}
