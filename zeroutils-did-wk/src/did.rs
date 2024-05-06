use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroutils_key::{AsymmetricKey, Ed25519PubKey, P256PubKey, PubKey, Secp256k1PubKey};

use super::{
    Base, Did, DidError, DidResult, DidWebKeyBuilder, KeyDecode, KeyEncode, LocatorComponent,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// This is a type that implements the [DID Web Key (`did-wk`)][did-wk] method and is generic over the public key type.
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

    /// The base encoding to use for the public key.
    pub(crate) base: Base,

    /// Optional component that specifies the web location (host and path) where the DID document can be resolved.
    pub(crate) locator_component: Option<LocatorComponent>,
}

/// This is a type that implements the [DID Web Key (`did-wk`)][did-wk] method and only supports a few key types.
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
/// - ...
///
/// See [`Base`] for the full list of supported encodings.
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

    /// Encodes the `DidWebKey` into a did string representation.
    ///
    /// `base` specifies the encoding to use for the public key.
    pub fn encode(&self, base: Base) -> String
    where
        P: KeyEncode,
    {
        let key_encoded = self.public_key.encode(base);
        let locator_component_encoded = self
            .locator_component
            .as_ref()
            .map_or(String::new(), |lc| format!("@{}", lc));

        format!("did:wk:{}{}", key_encoded, locator_component_encoded)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: DidWebKeyType
//--------------------------------------------------------------------------------------------------

impl<'a> Display for DidWebKeyType<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DidWebKeyType::Ed25519(wk) => write!(f, "{}", wk),
            DidWebKeyType::P256(wk) => write!(f, "{}", wk),
            DidWebKeyType::Secp256k1(wk) => write!(f, "{}", wk),
        }
    }
}

impl<'a> FromStr for DidWebKeyType<'a> {
    type Err = DidError;

    fn from_str(did: &str) -> DidResult<Self> {
        match Ed25519DidWebKey::from_str(did) {
            Err(DidError::ExpectedKeyType(_)) => {}
            Ok(wk) => return Ok(DidWebKeyType::Ed25519(wk)),
            Err(e) => return Err(e),
        }

        match P256DidWebKey::from_str(did) {
            Err(DidError::ExpectedKeyType(_)) => {}
            Ok(wk) => return Ok(DidWebKeyType::P256(wk)),
            Err(e) => return Err(e),
        }

        match Secp256k1DidWebKey::from_str(did) {
            Err(DidError::ExpectedKeyType(_)) => {}
            Ok(wk) => return Ok(DidWebKeyType::Secp256k1(wk)),
            Err(e) => return Err(e),
        }

        Err(DidError::UnsupportedKeyType(did.to_string()))
    }
}

impl<'a> From<&str> for DidWebKeyType<'a> {
    fn from(did: &str) -> Self {
        DidWebKeyType::from_str(did).unwrap()
    }
}

impl<'a> Serialize for DidWebKeyType<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let did_string = self.to_string();
        serializer.serialize_str(&did_string)
    }
}

impl<'de, 'a> Deserialize<'de> for DidWebKeyType<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let did_string = String::deserialize(deserializer)?;
        DidWebKeyType::from_str(&did_string).map_err(serde::de::Error::custom)
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
        write!(f, "{}", self.encode(self.base))
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

        let (public_key, base) = P::decode(at_split[0])?;
        let locator_component = if at_split.len() == 2 {
            Some(LocatorComponent::from_str(at_split[1])?)
        } else {
            None
        };

        Ok(DidWebKey {
            public_key,
            base,
            locator_component,
        })
    }
}

impl<P> From<&str> for DidWebKey<P>
where
    P: KeyDecode,
    DidError: From<P::Error>,
{
    fn from(did: &str) -> Self {
        DidWebKey::from_str(did).unwrap()
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
            base: Base::Base58Btc,
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
            base: Base::Base58Btc,
            locator_component: None,
        }
    }
}

impl<P> Serialize for DidWebKey<P>
where
    P: KeyEncode,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let did_string = self.to_string();
        serializer.serialize_str(&did_string)
    }
}

impl<'de, P> Deserialize<'de> for DidWebKey<P>
where
    P: KeyDecode,
    DidError: From<P::Error>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let did_string = String::deserialize(deserializer)?;
        DidWebKey::from_str(&did_string).map_err(serde::de::Error::custom)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use zeroutils_key::{Ed25519KeyPair, KeyPairGenerate, P256KeyPair, Secp256k1KeyPair};

    use crate::Host;

    use super::*;

    #[test]
    fn test_did_web_key_type_from_str() -> anyhow::Result<()> {
        let did_string = "did:wk:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq";
        let did_web_key = DidWebKeyType::from_str(did_string)?;

        let (public_key, base) =
            Ed25519PubKey::decode("z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq")?;

        assert_eq!(
            did_web_key,
            DidWebKeyType::Ed25519(Ed25519DidWebKey {
                public_key,
                base,
                locator_component: None,
            })
        );

        // With locator component
        let did_string =
            "did:wk:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq@steve.zerocore.ai:8080/public";
        let did_web_key = DidWebKeyType::from_str(did_string)?;

        let (public_key, base) =
            Ed25519PubKey::decode("z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq")?;
        assert_eq!(
            did_web_key,
            DidWebKeyType::Ed25519(Ed25519DidWebKey {
                public_key,
                base,
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

    #[test]
    fn test_did_web_key_display() -> anyhow::Result<()> {
        let did_string = "did:wk:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq";
        let did_web_key = DidWebKeyType::from_str(did_string)?;

        assert_eq!(did_web_key.to_string(), did_string);

        // With locator component
        let did_string =
            "did:wk:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq@steve.zerocore.ai:8080/public";
        let did_web_key = DidWebKeyType::from_str(did_string)?;

        assert_eq!(did_web_key.to_string(), did_string);

        Ok(())
    }

    #[test_log::test]
    fn test_did_web_key_serde() -> anyhow::Result<()> {
        let rng = &mut rand::thread_rng();

        let public_key = Ed25519PubKey::from(Ed25519KeyPair::generate(rng)?);
        let did_web_key = DidWebKey {
            public_key,
            base: Base::Base58Btc,
            locator_component: Some(LocatorComponent::new(
                Host::Domain("steve.zerocore.ai".to_owned()),
                Some(8080),
                Some("/public".into()),
            )),
        };

        let serialized = serde_json::to_string(&did_web_key)?;
        tracing::debug!(?serialized);
        let deserialized = serde_json::from_str(&serialized)?;
        assert_eq!(did_web_key, deserialized);

        let public_key = P256PubKey::from(P256KeyPair::generate(rng)?);
        let did_web_key = DidWebKey {
            public_key,
            base: Base::Base64,
            locator_component: None,
        };

        let serialized = serde_json::to_string(&did_web_key)?;
        tracing::debug!(?serialized);
        let deserialized = serde_json::from_str(&serialized)?;
        assert_eq!(did_web_key, deserialized);

        let public_key = Secp256k1PubKey::from(Secp256k1KeyPair::generate(rng)?);
        let did_web_key = DidWebKey {
            public_key,
            base: Base::Base32Z,
            locator_component: Some(LocatorComponent::new(
                Host::Domain("steve.zerocore.ai".to_owned()),
                Some(8080),
                Some("/public".into()),
            )),
        };

        let serialized = serde_json::to_string(&did_web_key)?;
        tracing::debug!(?serialized);
        let deserialized = serde_json::from_str(&serialized)?;
        assert_eq!(did_web_key, deserialized);

        Ok(())
    }

    #[test_log::test]
    fn test_did_web_key_type_serde() -> anyhow::Result<()> {
        let did_string = "did:wk:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq";
        let did_web_key = DidWebKeyType::from_str(did_string)?;

        let serialized = serde_json::to_string(&did_web_key)?;
        tracing::debug!(?serialized);

        let deserialized = serde_json::from_str(&serialized)?;
        assert_eq!(did_web_key, deserialized);

        Ok(())
    }
}
