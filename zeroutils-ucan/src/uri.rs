use std::{ops::Deref, str::FromStr};

use serde::Serialize;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents a Uniform Resource Identifier (URI) specifically tailored for use in UCAN tokens.
///
/// This struct wraps a `fluent_uri::Uri<String>`, providing a standardized way to reference resources.
/// URIs are fundamental in specifying the target of an ability within UCAN, distinguishing between
/// different resources and actions across various services and platforms.
#[derive(Debug, Clone)]
pub struct Uri(fluent_uri::Uri<String>);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<fluent_uri::Uri<String>> for Uri {
    fn from(uri: fluent_uri::Uri<String>) -> Self {
        Uri(uri)
    }
}

impl Deref for Uri {
    type Target = fluent_uri::Uri<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for Uri {
    type Err = fluent_uri::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fluent_uri::Uri::parse(s).map(|x| Uri(x.to_owned()))
    }
}

impl Serialize for Uri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
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
        Some(self.cmp(other))
    }
}

impl Ord for Uri {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialEq for Uri {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Uri {}
