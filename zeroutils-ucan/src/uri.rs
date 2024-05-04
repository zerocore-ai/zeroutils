use std::{ops::Deref, str::FromStr};

use serde::Serialize;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// TODO
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Uri(fluent_uri::Uri);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<fluent_uri::Uri> for Uri {
    fn from(uri: fluent_uri::Uri) -> Self {
        Uri(uri)
    }
}

impl Deref for Uri {
    type Target = fluent_uri::Uri;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for Uri {
    type Err = fluent_uri::uri::InvalidUri;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fluent_uri::Uri::from_str(s).map(Uri)
    }
}

impl Serialize for Uri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> Result<Uri, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Uri::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl PartialOrd for Uri {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.to_string().partial_cmp(&other.to_string())
    }
}

impl Ord for Uri {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_string().cmp(&other.to_string())
    }
}
