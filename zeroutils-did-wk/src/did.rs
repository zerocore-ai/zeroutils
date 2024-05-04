use std::{fmt::Display, str::FromStr};

use zeroutils_key::{AsymmetricKey, Ed25519PubKey, P256PubKey, PubKey, Secp256k1PubKey};

use super::{
    Base, Did, DidError, DidResult, DidWebKeyBuilder, KeyDecode, KeyEncode, LocatorComponent,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// This is a generic type that represents a decentralized identifier (DID) using the `did:wk` method,
///
/// [`did:wk` method][did-wk] is designed for decentralized user-managed authentication. It encapsulates the
/// `public_key` part and optionally includes a `locator_component` for finding the DID document. Without the
/// locator component, it functions similarly as a [`did:key`][did-key] identifier.
///
/// [did-wk]: https://github.com/zerocore-ai/did-wk
/// [did-key]: https://w3c-ccg.github.io/did-method-key/
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DidWebKey<P> {
    /// Copy-on-write reference to the public key
    pub(crate) public_key: P,

    /// Optional component that specifies the web location (host and path) where the DID document can be resolved.
    pub(crate) locator_component: Option<LocatorComponent>,
}

/// This type implements the supported key types for the `did:wk` method.
///
/// [`did:wk` method][did-wk] is designed for decentralized user-managed authentication. It encapsulates the
/// `public_key` part and optionally includes a `locator_component` for finding the DID document. Without the
/// locator component, it functions similarly as a [`did:key`][did-key] identifier.
///
/// Key types supported:
/// - `ed25519`
/// - `NIST P-256`
/// - `secp256k1`
///
/// Several base encodings are supported, some of which include:
/// - `base58btc`
/// - `base64url`
/// - `base64`
/// - `base32`
/// - `base16`
///
/// [did-wk]: https://github.com/zerocore-ai/did-wk
/// [did-key]: https://w3c-ccg.github.io/did-method-key/
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DidWebKeyType<'a> {
    /// `ed25519` public key.
    Ed25519(Ed25519DidWebKey<'a>),

    /// `NIST P-256` public key.
    P256(P256DidWebKey<'a>),

    /// `secp256k1` public key.
    Secp256k1(Secp256k1DidWebKey<'a>),
}

/// A `DID Web Key` ([`did:wk`][ref]) with an `ed25519` public key.
///
/// The type represents a decentralized identifier (DID) using the [`did:wk` method][ref], which is designed
/// for decentralized systems with web key authentication. It encapsulates the `public_key`, optionally includes
/// a `locator_component` for resolving to a specific URL.
///
/// [ref]: https://github.com/zerocore-ai/did-wk
pub type Ed25519DidWebKey<'a> = DidWebKey<Ed25519PubKey<'a>>;

/// A `DID Web Key` ([`did:wk`][ref]) with a `NIST P-256` public key.
///
/// The type represents a decentralized identifier (DID) using the [`did:wk` method][ref], which is designed
/// for decentralized systems with web key authentication. It encapsulates the `public_key`, optionally includes
/// a `locator_component` for resolving to a specific URL.
///
/// [ref]: https://github.com/zerocore-ai/did-wk
pub type P256DidWebKey<'a> = DidWebKey<P256PubKey<'a>>;

/// A `DID Web Key` ([`did:wk`][ref]) with a `secp256k1` public key.
///
/// The type represents a decentralized identifier (DID) using the [`did:wk` method][ref], which is designed
/// for decentralized systems with web key authentication. It encapsulates the `public_key`, optionally includes
/// a `locator_component` for resolving to a specific URL.
///
/// [ref]: https://github.com/zerocore-ai/did-wk
pub type Secp256k1DidWebKey<'a> = DidWebKey<Secp256k1PubKey<'a>>;

/// Supported public key types.
pub enum PubKeyType<'a> {
    /// `ed25519` public key.
    Ed25519(Ed25519PubKey<'a>),

    /// `NIST P-256` public key.
    P256(P256PubKey<'a>),

    /// `secp256k1` public key.
    Secp256k1(Secp256k1PubKey<'a>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<P> DidWebKey<P> {
    /// Creates a new `DidWebKey` builder.
    pub fn builder() -> DidWebKeyBuilder {
        DidWebKeyBuilder::default()
    }

    /// Gets the public key.
    pub fn public_key(&self) -> &P {
        &self.public_key
    }

    /// Gets the locator component.
    pub fn locator_component(&self) -> Option<&LocatorComponent> {
        self.locator_component.as_ref()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: DidWebKeyType
//--------------------------------------------------------------------------------------------------

impl<'a> FromStr for DidWebKeyType<'a> {
    type Err = DidError;

    fn from_str(did: &str) -> DidResult<Self> {
        let wk = if let Ok(wk) = Ed25519DidWebKey::from_str(did) {
            DidWebKeyType::Ed25519(wk)
        } else if let Ok(wk) = P256DidWebKey::from_str(did) {
            DidWebKeyType::P256(wk)
        } else if let Ok(wk) = Secp256k1DidWebKey::from_str(did) {
            DidWebKeyType::Secp256k1(wk)
        } else {
            return Err(DidError::InvalidMethod);
        };

        Ok(wk)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: DidWebKey
//--------------------------------------------------------------------------------------------------

impl<P> Display for DidWebKey<P>
where
    P: KeyEncode,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_encoded = self.public_key.encode(Base::Base58Btc);
        let locator_component_encoded = self
            .locator_component
            .as_ref()
            .map_or("".to_string(), |lc| format!("@{}", lc.encode()));

        write!(f, "did:web{}{}", key_encoded, locator_component_encoded)
            .map_err(|_| std::fmt::Error)
    }
}

impl<P> FromStr for DidWebKey<P>
where
    P: KeyDecode,
    DidError: From<P::Error>,
{
    type Err = DidError;

    fn from_str(did: &str) -> Result<Self, Self::Err> {
        let Some(s) = did.strip_prefix("did:wk:") else {
            return Err(DidError::InvalidMethod);
        };

        let at_split = s.splitn(2, '@').collect::<Vec<&str>>();

        let public_key = P::decode(at_split[0])?;
        let locator_component = if at_split.len() == 2 {
            Some(LocatorComponent::from_str(at_split[1])?)
        } else {
            None
        };

        Ok(DidWebKey {
            public_key,
            locator_component,
        })
    }
}

impl<P> Did for DidWebKey<P>
where
    P: KeyEncode + KeyDecode,
    DidError: From<P::Error>,
{
}

impl<'a, P, S> From<&'a AsymmetricKey<'a, P, S>> for DidWebKey<PubKey<'a, P>>
where
    P: Clone,
    PubKey<'a, P>: From<&'a AsymmetricKey<'a, P, S>>,
{
    fn from(public_key: &'a AsymmetricKey<'a, P, S>) -> Self {
        Self {
            public_key: PubKey::from(public_key),
            locator_component: None,
        }
    }
}

impl<'a, P, S> From<AsymmetricKey<'a, P, S>> for DidWebKey<PubKey<'a, P>>
where
    P: Clone,
    PubKey<'a, P>: From<AsymmetricKey<'a, P, S>>,
{
    fn from(public_key: AsymmetricKey<'a, P, S>) -> Self {
        Self {
            public_key: PubKey::from(public_key),
            locator_component: None,
        }
    }
}

// //--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::Host;

    use super::*;

    #[test]
    fn test_did_web_key_type_from_str() -> anyhow::Result<()> {
        let did_string = "did:wk:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq";
        let did_web_key = DidWebKeyType::from_str(did_string)?;

        assert_eq!(
            did_web_key,
            DidWebKeyType::Ed25519(Ed25519DidWebKey {
                public_key: Ed25519PubKey::decode(
                    "z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq"
                )?,
                locator_component: None,
            })
        );

        // With locator component
        let did_string =
            "did:wk:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq@steve.zerocore.ai:8080/public";
        let did_web_key = DidWebKeyType::from_str(did_string)?;

        assert_eq!(
            did_web_key,
            DidWebKeyType::Ed25519(Ed25519DidWebKey {
                public_key: Ed25519PubKey::decode(
                    "z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq"
                )?,
                locator_component: Some(LocatorComponent::new(
                    Host::Domain("steve.zerocore.ai".to_owned()),
                    Some(8080),
                    Some("/public".into())
                )),
            })
        );

        // Invalid method
        let did_string = "did:xyz:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq";
        let did_web_key = DidWebKeyType::from_str(did_string);

        assert!(did_web_key.is_err());

        Ok(())
    }
}
