use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::{Ed25519PubKey, P256PubKey, Secp256k1PubKey};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A key pair with a public and private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsymmetricKey<'a, P, S>
where
    P: Clone,
{
    pub(crate) public: Cow<'a, P>,
    pub(crate) private: S,
}

/// A public key.
pub type PubKey<'a, P> = AsymmetricKey<'a, P, ()>;

/// Supported key types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyType {
    /// An `ed25519` key
    #[serde(rename = "ed25519")]
    Ed25519,

    /// A `NIST P-256` key
    #[serde(rename = "p256")]
    P256,

    /// A `secp256k1` key
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

/// Supported public key types.
pub enum PubKeyType<'a> {
    /// `ed25519` public key.
    Ed25519(Ed25519PubKey<'a>),

    /// `NIST P-256` public key.
    P256(P256PubKey<'a>),

    /// `secp256k1` public key.
    Secp256k1(Secp256k1PubKey<'a>),
}
