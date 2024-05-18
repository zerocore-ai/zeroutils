use std::{fmt::Display, str::FromStr};

use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use zeroutils_key::JwsAlgorithm;

use crate::UcanError;

//--------------------------------------------------------------------------------------------------
// Constant
//--------------------------------------------------------------------------------------------------

/// Defines the type of the token as a JSON Web Token (JWT).
pub const TYPE: &str = "JWT";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents the header part of a UCAN token, specifically defining the cryptographic algorithm used for signing.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UcanHeader {
    /// The algorithm used for signing the token.
    alg: JwsAlgorithm,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl UcanHeader {
    /// Returns the algorithm used for signing the token.
    pub fn alg(&self) -> JwsAlgorithm {
        self.alg
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Serialize for UcanHeader {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_json::json!({
            "typ": TYPE,
            "alg": self.alg,
        })
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UcanHeader {
    fn deserialize<D>(deserializer: D) -> Result<UcanHeader, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Header {
            alg: JwsAlgorithm,
            typ: String,
        }

        let header = Header::deserialize(deserializer)?;

        if header.typ != TYPE {
            return Err(serde::de::Error::custom(UcanError::UnsupportedTokenType(
                header.typ,
            )));
        }

        Ok(UcanHeader { alg: header.alg })
    }
}

impl Display for UcanHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(json.as_bytes());
        write!(f, "{}", encoded)
    }
}

impl FromStr for UcanHeader {
    type Err = UcanError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(s.as_bytes())?;
        serde_json::from_slice(&decoded).map_err(UcanError::from)
    }
}

impl Default for UcanHeader {
    fn default() -> Self {
        Self {
            alg: JwsAlgorithm::EdDSA,
        }
    }
}

impl From<JwsAlgorithm> for UcanHeader {
    fn from(alg: JwsAlgorithm) -> Self {
        Self { alg }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test]
    fn test_header_serde() {
        let header = UcanHeader::default();

        let serialized = serde_json::to_string(&header).unwrap();
        tracing::debug!(?serialized);
        assert_eq!(serialized, r#"{"alg":"EdDSA","typ":"JWT"}"#);

        let deserialized: UcanHeader = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, header);
    }

    #[test_log::test]
    fn test_header_display() {
        let header = UcanHeader::default();

        let displayed = header.to_string();
        tracing::debug!(?displayed);
        assert_eq!(displayed, "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9");

        let parsed = UcanHeader::from_str(&displayed).unwrap();
        assert_eq!(parsed, header);

        let header = UcanHeader::from(JwsAlgorithm::ES256);

        let displayed = header.to_string();
        tracing::debug!(?displayed);
        assert_eq!(displayed, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9");

        let parsed = UcanHeader::from_str(&displayed).unwrap();
        assert_eq!(parsed, header);

        let header = UcanHeader::from(JwsAlgorithm::ES256K);
        let displayed = header.to_string();
        tracing::debug!(?displayed);
        assert_eq!(displayed, "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ");

        let parsed = UcanHeader::from_str(&displayed).unwrap();
        assert_eq!(parsed, header);
    }
}
