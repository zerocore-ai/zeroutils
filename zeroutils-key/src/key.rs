use std::{any::Any, borrow::Cow};

use serde::{Deserialize, Serialize};

use crate::{
    Ed25519KeyPair, Ed25519PubKey, GetPublicKey, IntoOwned, KeyError, KeyPairBytes, KeyResult,
    P256KeyPair, P256PubKey, PublicKeyBytes, Secp256k1KeyPair, Secp256k1PubKey, Sign, Verify,
};

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

/// Represents a public key in any of the supported key types.
///
/// Unlike [`PubKey`], this type is not generic over the public key component and only supports certain types of publc keys.
///
/// `WrappedPubKey` is useful when you just want to work with public keys without any of the generic type business,
/// for example, in `struct`s with multiple public key fields.
///
/// Key types supported:
/// - `ed25519`
/// - `NIST P-256`
/// - `secp256k1`
pub enum WrappedPubKey<'a> {
    /// `ed25519` public key.
    Ed25519(Ed25519PubKey<'a>),

    /// `NIST P-256` public key.
    P256(P256PubKey<'a>),

    /// `secp256k1` public key.
    Secp256k1(Secp256k1PubKey<'a>),
}

/// Represents a key pair in any of the supported key types.
///
/// Unlike [`AsymmetricKey`], this type is not generic over the public and private key components.
/// It only supports certain types of keys.
///
/// `WrappedDidWebKey` is useful when you just want to work with public keys without any of the generic type business,
/// for example, in `struct`s with multiple public key fields.
///
/// Key types supported:
/// - `ed25519`
/// - `NIST P-256`
/// - `secp256k1`
#[allow(clippy::large_enum_variant)]
pub enum WrappedKeyPair<'a> {
    /// `ed25519` public key.
    Ed25519(Ed25519KeyPair<'a>),

    /// `NIST P-256` public key.
    P256(P256KeyPair<'a>),

    /// `secp256k1` public key.
    Secp256k1(Secp256k1KeyPair<'a>),
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: AsymmetricKey
//--------------------------------------------------------------------------------------------------

impl<'a, P, S> IntoOwned for AsymmetricKey<'a, P, S>
where
    P: Clone + 'static,
    S: 'static,
{
    type Owned = AsymmetricKey<'static, P, S>;

    fn into_owned(self) -> Self::Owned {
        AsymmetricKey {
            public: Cow::Owned(self.public.into_owned()),
            private: self.private,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: WrappedPubKey
//--------------------------------------------------------------------------------------------------

impl Verify for WrappedPubKey<'_> {
    fn verify(&self, data: &[u8], signature: &[u8]) -> KeyResult<()> {
        match self {
            WrappedPubKey::Ed25519(wk) => wk.verify(data, signature),
            WrappedPubKey::P256(wk) => wk.verify(data, signature),
            WrappedPubKey::Secp256k1(wk) => wk.verify(data, signature),
        }
    }
}

impl PublicKeyBytes for WrappedPubKey<'_> {
    fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            WrappedPubKey::Ed25519(wk) => wk.public_key_bytes(),
            WrappedPubKey::P256(wk) => wk.public_key_bytes(),
            WrappedPubKey::Secp256k1(wk) => wk.public_key_bytes(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: WrappedKeyPair
//--------------------------------------------------------------------------------------------------

impl Verify for WrappedKeyPair<'_> {
    fn verify(&self, data: &[u8], signature: &[u8]) -> KeyResult<()> {
        match self {
            WrappedKeyPair::Ed25519(wk) => wk.verify(data, signature),
            WrappedKeyPair::P256(wk) => wk.verify(data, signature),
            WrappedKeyPair::Secp256k1(wk) => wk.verify(data, signature),
        }
    }
}

impl Sign for WrappedKeyPair<'_> {
    fn sign(&self, data: &[u8]) -> KeyResult<Vec<u8>> {
        match self {
            WrappedKeyPair::Ed25519(wk) => wk.sign(data),
            WrappedKeyPair::P256(wk) => wk.sign(data),
            WrappedKeyPair::Secp256k1(wk) => wk.sign(data),
        }
    }
}

impl PublicKeyBytes for WrappedKeyPair<'_> {
    fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            WrappedKeyPair::Ed25519(wk) => wk.public_key_bytes(),
            WrappedKeyPair::P256(wk) => wk.public_key_bytes(),
            WrappedKeyPair::Secp256k1(wk) => wk.public_key_bytes(),
        }
    }
}

impl KeyPairBytes for WrappedKeyPair<'_> {
    fn private_key_bytes(&self) -> Vec<u8> {
        match self {
            WrappedKeyPair::Ed25519(wk) => wk.private_key_bytes(),
            WrappedKeyPair::P256(wk) => wk.private_key_bytes(),
            WrappedKeyPair::Secp256k1(wk) => wk.private_key_bytes(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> WrappedPubKey<'a> {
    /// Consumes the [`WrappedPubKey`] and returns the inner [`PubKey`].
    pub fn into_inner<T>(self) -> KeyResult<T>
    where
        T: Clone + 'static,
        'a: 'static,
    {
        let any = match self {
            WrappedPubKey::Ed25519(wk) => Box::new(wk) as Box<dyn Any>,
            WrappedPubKey::P256(wk) => Box::new(wk) as Box<dyn Any>,
            WrappedPubKey::Secp256k1(wk) => Box::new(wk) as Box<dyn Any>,
        };

        let t = any
            .downcast::<T>()
            .map_err(|t| KeyError::CastingFailed((*t).type_id()))?;

        Ok(*t)
    }

    /// Converts the [`WrappedPubKey`] into an owned version.
    pub fn into_owned(self) -> WrappedPubKey<'static> {
        match self {
            WrappedPubKey::Ed25519(wk) => WrappedPubKey::Ed25519(wk.into_owned()),
            WrappedPubKey::P256(wk) => WrappedPubKey::P256(wk.into_owned()),
            WrappedPubKey::Secp256k1(wk) => WrappedPubKey::Secp256k1(wk.into_owned()),
        }
    }
}

impl<'a> WrappedKeyPair<'a> {
    /// Consumes the [`WrappedKeyPair`] and returns the inner [`PubKey`].
    pub fn into_inner<T>(self) -> KeyResult<T>
    where
        T: Clone + 'static,
        'a: 'static,
    {
        let any = match self {
            WrappedKeyPair::Ed25519(wk) => Box::new(wk) as Box<dyn Any>,
            WrappedKeyPair::P256(wk) => Box::new(wk) as Box<dyn Any>,
            WrappedKeyPair::Secp256k1(wk) => Box::new(wk) as Box<dyn Any>,
        };

        let t = any
            .downcast::<T>()
            .map_err(|t| KeyError::CastingFailed((*t).type_id()))?;

        Ok(*t)
    }

    /// Returns the public key of the key pair.
    pub fn public_key(&'a self) -> WrappedPubKey<'a> {
        match self {
            WrappedKeyPair::Ed25519(wk) => WrappedPubKey::Ed25519(wk.public_key()),
            WrappedKeyPair::P256(wk) => WrappedPubKey::P256(wk.public_key()),
            WrappedKeyPair::Secp256k1(wk) => WrappedPubKey::Secp256k1(wk.public_key()),
        }
    }
}
