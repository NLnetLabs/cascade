use std::{fmt, str::FromStr, time::Duration};

use domain::base::Ttl;
use jiff::{Span, SpanRelativeTo};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize,
};

/// A wrapper around [`Duration`] with fancier (de)serialization
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimeSpan(u32);

impl TimeSpan {
    pub fn as_secs(&self) -> u32 {
        self.0
    }

    pub fn as_ttl(&self) -> Ttl {
        Ttl::from_secs(self.0)
    }

    pub fn from_secs(x: u32) -> Self {
        Self(x)
    }

    pub fn from_ttl(x: Ttl) -> Self {
        Self(x.as_secs())
    }
}

struct TimeSpanVisitor;

impl<'de> Visitor<'de> for TimeSpanVisitor {
    type Value = TimeSpan;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("string or int")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        FromStr::from_str(value).map_err(E::custom)
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(TimeSpan::from_secs(value.try_into().map_err(|_| {
            E::custom(format!("duration value must be between 0 and {}", u32::MAX))
        })?))
    }
}

impl<'de> Deserialize<'de> for TimeSpan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(TimeSpanVisitor)
    }
}

impl Serialize for TimeSpan {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_secs().serialize(serializer)
    }
}

impl TryFrom<Span> for TimeSpan {
    type Error = String;

    fn try_from(value: Span) -> Result<Self, Self::Error> {
        let signeddur = value
            .to_duration(SpanRelativeTo::days_are_24_hours())
            .map_err(|e| format!("unable to convert duration: {e}\n"))?;

        let duration = Duration::try_from(signeddur)
            .map_err(|e| format!("unable to convert duration: {e}\n"))?;

        let secs = duration
            .as_secs()
            .try_into()
            .map_err(|_| format!("duration value must be between 0 and {}", u32::MAX))?;

        Ok(Self(secs))
    }
}

impl FromStr for TimeSpan {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Handle a small edge case to treat the string "10" as 10 seconds.
        if let Ok(secs) = s.parse() {
            return Ok(Self::from_secs(secs));
        }
        let span: Span = s
            .parse()
            .map_err(|e| format!("unable to parse {s} as timespan: {e}\n"))?;

        Self::try_from(span)
    }
}

#[cfg(test)]
mod tests {
    use super::TimeSpan;
    use serde::Deserialize;

    #[test]
    fn parse() {
        #[derive(Debug, Deserialize)]
        struct Foo {
            val: Vec<TimeSpan>,
        }

        let foo: Foo = toml::from_str(
            r#"
            val = [
              10,
              "10",
              "10s",
              "10m",
              "10h",
              "10d",
              "10w",
              "2h 3m 4s",
              "P35DT2H30M"
            ]
            "#,
        )
        .unwrap();
        assert_eq!(
            foo.val,
            vec![
                TimeSpan::from_secs(10),
                TimeSpan::from_secs(10),
                TimeSpan::from_secs(10),
                TimeSpan::from_secs(10 * 60),
                TimeSpan::from_secs(10 * 60 * 60),
                TimeSpan::from_secs(10 * 60 * 60 * 24),
                TimeSpan::from_secs(10 * 60 * 60 * 24 * 7),
                TimeSpan::from_secs((2 * 60 * 60) + (3 * 60) + 4),
                TimeSpan::from_secs(
                    (35 * 60 * 60 * 24) // days
                    + (2 * 60 * 60) // hours
                    + (30 * 60) // minutes
                ),
            ]
        );

        toml::from_str::<Foo>(
            r#"
            val = ["10y"]
            "#,
        )
        .unwrap_err();
    }
}
