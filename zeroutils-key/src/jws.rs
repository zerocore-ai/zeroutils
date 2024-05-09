use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::KeyError;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// JSON Web Signature (JWS) algorithm.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum JwsAlgorithm {
    /// EdDSA algorithm.
    #[serde(rename = "EdDSA")]
    EdDSA,

    /// ECDSA using P-256 and SHA-256.
    #[serde(rename = "ES256")]
    ES256,

    /// ECDSA using secp256k1 and SHA-256.
    #[serde(rename = "ES256K")]
    ES256K,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Display for JwsAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwsAlgorithm::EdDSA => write!(f, "EdDSA"),
            JwsAlgorithm::ES256 => write!(f, "ES256"),
            JwsAlgorithm::ES256K => write!(f, "ES256K"),
        }
    }
}

impl FromStr for JwsAlgorithm {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "EdDSA" => Ok(JwsAlgorithm::EdDSA),
            "ES256" => Ok(JwsAlgorithm::ES256),
            "ES256K" => Ok(JwsAlgorithm::ES256K),
            s => Err(KeyError::UnsupportedJwsAlgName(s.to_string())),
        }
    }
}
