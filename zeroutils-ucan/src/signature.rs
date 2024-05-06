use std::{fmt::Display, str::FromStr};

use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::UcanError;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents the digital signature of a UCAN token.
///
/// This signature verifies the integrity and authenticity of the UCAN, confirming it has not been
/// tampered with and was indeed issued by the holder of the private key corresponding to the public
/// key specified in the UCAN header.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UcanSignature(Vec<u8>);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Serialize for UcanSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UcanSignature {
    fn deserialize<D>(deserializer: D) -> Result<UcanSignature, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let signature = Vec::<u8>::deserialize(deserializer)?;
        Ok(UcanSignature(signature))
    }
}

impl Display for UcanSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(&self.0);
        write!(f, "{}", encoded)
    }
}

impl FromStr for UcanSignature {
    type Err = UcanError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(s.as_bytes())?;
        Ok(UcanSignature(decoded))
    }
}

impl From<Vec<u8>> for UcanSignature {
    fn from(signature: Vec<u8>) -> Self {
        Self(signature)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test]
    fn test_signature_serde() {
        let signature = UcanSignature::from(vec![1, 2, 3, 4, 5]);

        let serialized = serde_json::to_string(&signature).unwrap();
        tracing::debug!(?serialized);
        assert_eq!(serialized, "[1,2,3,4,5]");

        let deserialized: UcanSignature = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, signature);
    }

    #[test_log::test]
    fn test_signature_display() {
        let signature = UcanSignature::from(vec![1, 2, 3, 4, 5]);

        let displayed = signature.to_string();
        tracing::debug!(?displayed);
        assert_eq!(displayed, "AQIDBAU");

        let parsed = UcanSignature::from_str(&displayed).unwrap();
        assert_eq!(parsed, signature);
    }
}
