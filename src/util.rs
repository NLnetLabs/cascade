//! Miscellaneous utilities for Cascade.

use std::{
    fmt, fs,
    io::{self, Write},
    time::Duration,
};

use camino::Utf8Path;
use serde::{
    de::{self, Visitor},
    Deserializer, Serializer,
};
use tokio::time::Instant;

/// Atomically write a file.
///
/// # Panics
///
/// Panics if 'path' does not have a containing directory.
pub fn write_file(path: &Utf8Path, contents: &[u8]) -> io::Result<()> {
    // Ensure such a path _can_ exist.
    let dir = path
        .parent()
        .expect("'path' must be a file, so it must have a parent");
    fs::create_dir_all(dir)?;

    // Obtain a temporary file in the same directory.
    let mut tmp_file = tempfile::Builder::new().tempfile_in(dir)?;

    // Fill up the temporary file.
    tmp_file.as_file_mut().write_all(contents)?;

    // Replace the target path with the temporary file.
    let _ = tmp_file.persist(path)?;

    Ok(())
}

/// Update a value.
#[inline]
pub fn update_value<T: Eq>(dst: &mut T, value: T, changed: &mut bool) {
    if *dst != value {
        *changed = true;
        *dst = value;
    }
}

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
