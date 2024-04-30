//! TODO: Add description
//!
//! This module currently only support just three (3) asymmetric key types:
//! - Ed25519
//! - P-256
//! - Secp256k1

use std::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    str::FromStr,
};

use crate::key::{Ed25519KeyPair, KeyError, KeyPairType, KeyResult, P256KeyPair, Secp256k1KeyPair};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// TODO
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
// #[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DidWebKey {
    key_pair: KeyPair,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KeyPair {
    Ed25519(Ed25519KeyPair),
    P256(P256KeyPair),
    Secp256k1(Secp256k1KeyPair),
}

// pub struct _Ed25519KeyPair {
//     pub_key: Vec<u8>,
//     priv_key: std::cell::OnceCell<Vec<u8>>,
// }

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DidWebKey {
    pub fn generate(kind: KeyPairType) -> KeyResult<Self> {
        unimplemented!()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FromStr for DidWebKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        unimplemented!()
    }
}

impl From<KeyPair> for DidWebKey {
    fn from(key_pair: KeyPair) -> Self {
        unimplemented!()
    }
}

impl PartialEq for DidWebKey {
    fn eq(&self, other: &Self) -> bool {
        unimplemented!()
    }
}

impl Eq for DidWebKey {}

impl Hash for DidWebKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        unimplemented!()
    }
}

impl Display for DidWebKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unimplemented!()
    }
}

impl Debug for DidWebKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unimplemented!()
    }
}

impl From<KeyPair> for KeyPairType {
    fn from(key_pair: KeyPair) -> Self {
        unimplemented!()
    }
}
