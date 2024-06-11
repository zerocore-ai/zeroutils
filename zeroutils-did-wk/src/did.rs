use std::{any::Any, fmt::Display, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroutils_key::{
    Ed25519PubKey, GetPublicKey, IntoOwned, P256PubKey, Secp256k1PubKey, WrappedKeyPair,
    WrappedPubKey,
};

use super::{
    Base, Did, DidError, DidResult, DidWebKeyBuilder, KeyDecode, KeyEncode, LocatorComponent,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// This is a type that implements the [DID Web Key (`did:wk`)][did-wk] method and is generic over the
/// public key type.
///
/// [`did:wk` method][did-wk] is designed for decentralized user-managed authentication. It encapsulates the
/// `public_key` part and optionally includes a `locator_component` for finding the DID document. Without the
/// locator component, it functions similarly as a [`did:key`][did-key] identifier.
///
/// [did-wk]: https://github.com/zerocore-ai/did-wk
/// [did-key]: https://w3c-ccg.github.io/did-method-key/
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DidWebKey<P = ()> {
    /// The public key.
    pub(crate) public_key: P,

    /// The base encoding to use for the public key.
    pub(crate) base: Base,

    /// Optional component that specifies the web location (host and path) where the DID document can be resolved.
    pub(crate) locator_component: Option<LocatorComponent>,
}

/// This is a type that implements the [DID Web Key (`did:wk`)][did-wk] method and only supports a few key types.
///
/// [`did:wk` method][did-wk] is designed for decentralized user-managed authentication. It encapsulates the
/// `public_key` part and optionally includes a `locator_component` for finding the DID document. Without the
/// locator component, it functions similarly as a [`did:key`][did-key] identifier.
///
/// Unlike [`DidWebKey`], this type is not generic over the public key type and only supports a few key types.
/// It will fail to parse if the key type is not supported.
///
/// `WrappedDidWebKey` is useful when you are deserializing from a did string representation but you are unsure of the
/// exact key type to expect or when you just want to work with `did:wk` without any of the generic type business,
/// for example, in `struct`s with multiple `did:wk` fields.
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
/// - ...
///
/// See [`Base`] for the full list of supported encodings.
///
/// [did-wk]: https://github.com/zerocore-ai/did-wk
/// [did-key]: https://w3c-ccg.github.io/did-method-key/
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WrappedDidWebKey<'a> {
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
// Methods: DidWebKey
//--------------------------------------------------------------------------------------------------

impl DidWebKey {
    /// Creates a new [`DidWebKey`] from a key and base encoding.
    pub fn from_key<K>(key: &K, base: Base) -> DidWebKey<<K as GetPublicKey>::PublicKey<'_>>
    where
        K: GetPublicKey,
    {
        DidWebKey {
            public_key: key.public_key(),
            locator_component: None,
            base,
        }
    }

    /// Tries to create a new [`DidWebKey`] from a [`WrappedDidWebKey`].
    pub fn from_wrapped_did_web_key<'a, P>(
        wrapped_dwk: WrappedDidWebKey<'a>,
    ) -> DidResult<DidWebKey<P>>
    where
        P: Clone + 'static,
        'a: 'static,
    {
        wrapped_dwk.into_inner()
    }
}

impl<P> DidWebKey<P> {
    /// Creates a new [`DidWebKey`] builder.
    pub fn builder() -> DidWebKeyBuilder {
        DidWebKeyBuilder::default()
    }

    /// Gets the public key.
    pub fn public_key(&self) -> &P {
        &self.public_key
    }

    /// Gets the base encoding.
    pub fn base(&self) -> Base {
        self.base
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
// Methods: WrappedDidWebKey
//--------------------------------------------------------------------------------------------------

impl<'a> WrappedDidWebKey<'a> {
    /// Creates a new [`WrappedDidWebKey`] from a [`WrappedPubKey`] and base encoding.
    pub fn from_wrapped_pub_key(
        pub_key: &'a WrappedPubKey<'a>,
        base: Base,
    ) -> WrappedDidWebKey<'a> {
        match pub_key {
            WrappedPubKey::Ed25519(wk) => WrappedDidWebKey::Ed25519(DidWebKey::from_key(wk, base)),
            WrappedPubKey::P256(wk) => WrappedDidWebKey::P256(DidWebKey::from_key(wk, base)),
            WrappedPubKey::Secp256k1(wk) => {
                WrappedDidWebKey::Secp256k1(DidWebKey::from_key(wk, base))
            }
        }
    }

    /// Creates a new [`WrappedDidWebKey`] from a [`WrappedKeyPair`] and base encoding.
    pub fn from_wrapped_key_pair(
        key_pair: &'a WrappedKeyPair<'a>,
        base: Base,
    ) -> WrappedDidWebKey<'a> {
        match key_pair {
            WrappedKeyPair::Ed25519(kp) => WrappedDidWebKey::Ed25519(DidWebKey::from_key(kp, base)),
            WrappedKeyPair::P256(kp) => WrappedDidWebKey::P256(DidWebKey::from_key(kp, base)),
            WrappedKeyPair::Secp256k1(kp) => {
                WrappedDidWebKey::Secp256k1(DidWebKey::from_key(kp, base))
            }
        }
    }

    /// Tries to create a [`WrappedDidWebKey`] from a key, _`K`_ and a base encoding.
    pub fn from_key<K>(key: &K, base: Base) -> DidResult<Self>
    where
        K: GetPublicKey,
    {
        let public_key = key.public_key().into_owned();
        let did_wk = DidWebKey {
            public_key,
            base,
            locator_component: None,
        };
        Self::from_did_web_key(did_wk)
    }

    /// Tries to create a [`WrappedDidWebKey`] from [`DidWebKey`] with some arbitrary public key, _`P`_.
    pub fn from_did_web_key<P>(
        DidWebKey {
            public_key,
            base,
            locator_component,
        }: DidWebKey<P>,
    ) -> DidResult<Self>
    where
        P: 'static,
    {
        let any: Box<dyn Any> = Box::new(public_key);
        let v = if any.downcast_ref::<Ed25519PubKey>().is_some() {
            let public_key = any.downcast::<Ed25519PubKey>().unwrap();
            let did_wk = DidWebKey {
                public_key: *public_key,
                base,
                locator_component,
            };
            WrappedDidWebKey::Ed25519(did_wk)
        } else if any.downcast_ref::<P256PubKey>().is_some() {
            let public_key = any.downcast::<P256PubKey>().unwrap();
            let did_wk = DidWebKey {
                public_key: *public_key,
                base,
                locator_component,
            };
            WrappedDidWebKey::P256(did_wk)
        } else if any.downcast_ref::<Secp256k1PubKey>().is_some() {
            let public_key = any.downcast::<Secp256k1PubKey>().unwrap();
            let did_wk = DidWebKey {
                public_key: *public_key,
                base,
                locator_component,
            };
            WrappedDidWebKey::Secp256k1(did_wk)
        } else {
            return Err(DidError::CastingFailed((*any).type_id()));
        };

        Ok(v)
    }

    /// Consumes the [`WrappedDidWebKey`] and returns the inner [`DidWebKey`].
    pub fn into_inner<T>(self) -> DidResult<T>
    where
        T: Clone + 'static,
        'a: 'static,
    {
        let any_wk: Box<dyn Any> = match self {
            WrappedDidWebKey::Ed25519(wk) => Box::new(wk),
            WrappedDidWebKey::P256(wk) => Box::new(wk),
            WrappedDidWebKey::Secp256k1(wk) => Box::new(wk),
        };

        let t = any_wk
            .downcast::<T>()
            .map_err(|t| DidError::CastingFailed((*t).type_id()))?;

        Ok(*t)
    }

    /// Gets the public key.
    pub fn public_key(&'a self) -> WrappedPubKey<'a> {
        match self {
            WrappedDidWebKey::Ed25519(wk) => WrappedPubKey::Ed25519(wk.public_key().clone()),
            WrappedDidWebKey::P256(wk) => WrappedPubKey::P256(wk.public_key().clone()),
            WrappedDidWebKey::Secp256k1(wk) => WrappedPubKey::Secp256k1(wk.public_key().clone()),
        }
    }

    /// Gets the locator component.
    pub fn locator_component(&self) -> Option<&LocatorComponent> {
        match self {
            WrappedDidWebKey::Ed25519(wk) => wk.locator_component(),
            WrappedDidWebKey::P256(wk) => wk.locator_component(),
            WrappedDidWebKey::Secp256k1(wk) => wk.locator_component(),
        }
    }

    /// Encodes the `WrappedDidWebKey` into a did string representation.
    ///
    /// `base` specifies the encoding to use for the public key.
    pub fn encode(&self, base: Base) -> String {
        match self {
            WrappedDidWebKey::Ed25519(wk) => wk.encode(base),
            WrappedDidWebKey::P256(wk) => wk.encode(base),
            WrappedDidWebKey::Secp256k1(wk) => wk.encode(base),
        }
    }

    /// Gets the base encoding.
    pub fn base(&self) -> Base {
        match self {
            WrappedDidWebKey::Ed25519(wk) => wk.base(),
            WrappedDidWebKey::P256(wk) => wk.base(),
            WrappedDidWebKey::Secp256k1(wk) => wk.base(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: WrappedDidWebKey
//--------------------------------------------------------------------------------------------------

impl<'a> Display for WrappedDidWebKey<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WrappedDidWebKey::Ed25519(wk) => write!(f, "{}", wk),
            WrappedDidWebKey::P256(wk) => write!(f, "{}", wk),
            WrappedDidWebKey::Secp256k1(wk) => write!(f, "{}", wk),
        }
    }
}

impl<'a> FromStr for WrappedDidWebKey<'a> {
    type Err = DidError;

    fn from_str(did: &str) -> DidResult<Self> {
        match Ed25519DidWebKey::from_str(did) {
            Err(DidError::ExpectedKeyType(_)) => {}
            Ok(wk) => return Ok(WrappedDidWebKey::Ed25519(wk)),
            Err(e) => return Err(e),
        }

        match P256DidWebKey::from_str(did) {
            Err(DidError::ExpectedKeyType(_)) => {}
            Ok(wk) => return Ok(WrappedDidWebKey::P256(wk)),
            Err(e) => return Err(e),
        }

        match Secp256k1DidWebKey::from_str(did) {
            Err(DidError::ExpectedKeyType(_)) => {}
            Ok(wk) => return Ok(WrappedDidWebKey::Secp256k1(wk)),
            Err(e) => return Err(e),
        }

        Err(DidError::UnsupportedKeyType(did.to_string()))
    }
}

impl<'a> From<&str> for WrappedDidWebKey<'a> {
    fn from(did: &str) -> Self {
        WrappedDidWebKey::from_str(did).unwrap()
    }
}

impl<'a> From<String> for WrappedDidWebKey<'a> {
    fn from(did: String) -> Self {
        WrappedDidWebKey::from_str(&did).unwrap()
    }
}

impl<'a> From<&String> for WrappedDidWebKey<'a> {
    fn from(did: &String) -> Self {
        WrappedDidWebKey::from_str(did).unwrap()
    }
}

impl<'a> From<Ed25519DidWebKey<'a>> for WrappedDidWebKey<'a> {
    fn from(did: Ed25519DidWebKey<'a>) -> Self {
        WrappedDidWebKey::Ed25519(did)
    }
}

impl<'a> From<P256DidWebKey<'a>> for WrappedDidWebKey<'a> {
    fn from(did: P256DidWebKey<'a>) -> Self {
        WrappedDidWebKey::P256(did)
    }
}

impl<'a> From<Secp256k1DidWebKey<'a>> for WrappedDidWebKey<'a> {
    fn from(did: Secp256k1DidWebKey<'a>) -> Self {
        WrappedDidWebKey::Secp256k1(did)
    }
}

impl<'a> Serialize for WrappedDidWebKey<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let did_string = self.to_string();
        serializer.serialize_str(&did_string)
    }
}

impl<'de, 'a> Deserialize<'de> for WrappedDidWebKey<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let did_string = String::deserialize(deserializer)?;
        WrappedDidWebKey::from_str(&did_string).map_err(serde::de::Error::custom)
    }
}

impl IntoOwned for WrappedDidWebKey<'_> {
    type Owned = WrappedDidWebKey<'static>;

    fn into_owned(self) -> Self::Owned {
        match self {
            WrappedDidWebKey::Ed25519(wk) => WrappedDidWebKey::Ed25519(wk.into_owned()),
            WrappedDidWebKey::P256(wk) => WrappedDidWebKey::P256(wk.into_owned()),
            WrappedDidWebKey::Secp256k1(wk) => WrappedDidWebKey::Secp256k1(wk.into_owned()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: DidWebKey
//--------------------------------------------------------------------------------------------------

impl<P> Did for DidWebKey<P>
where
    P: KeyEncode + KeyDecode,
    DidError: From<P::Error>,
{
}

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

impl<P> From<String> for DidWebKey<P>
where
    P: KeyDecode,
    DidError: From<P::Error>,
{
    fn from(did: String) -> Self {
        DidWebKey::from_str(&did).unwrap()
    }
}

impl<P> From<&String> for DidWebKey<P>
where
    P: KeyDecode,
    DidError: From<P::Error>,
{
    fn from(did: &String) -> Self {
        DidWebKey::from_str(did).unwrap()
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

impl<P> IntoOwned for DidWebKey<P>
where
    P: IntoOwned,
{
    type Owned = DidWebKey<P::Owned>;

    fn into_owned(self) -> Self::Owned {
        DidWebKey {
            public_key: self.public_key.into_owned(),
            base: self.base,
            locator_component: self.locator_component,
        }
    }
}

impl<P> PartialOrd for DidWebKey<P>
where
    P: KeyEncode + PartialEq,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.to_string().cmp(&other.to_string()))
    }
}

impl<P> Ord for DidWebKey<P>
where
    P: KeyEncode + Eq,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use zeroutils_key::{Ed25519KeyPair, KeyPairGenerate, P256KeyPair, Secp256k1KeyPair};

    use crate::Path;

    use super::*;

    #[test]
    fn test_did_web_key_from_key() -> anyhow::Result<()> {
        let rng = &mut rand::thread_rng();

        let key_pair = Ed25519KeyPair::generate(rng)?;
        let did_web_key = DidWebKey::from_key(&key_pair, Base::Base58Btc);

        assert_eq!(did_web_key.public_key(), &key_pair.public_key());

        let key_pair = P256KeyPair::generate(rng)?;
        let did_web_key = DidWebKey::from_key(&key_pair, Base::Base64);

        assert_eq!(did_web_key.public_key(), &key_pair.public_key());

        let key_pair = Secp256k1KeyPair::generate(rng)?;
        let did_web_key = DidWebKey::from_key(&key_pair, Base::Base32Z);

        assert_eq!(did_web_key.public_key(), &key_pair.public_key());

        Ok(())
    }

    #[test]
    fn test_wrapped_did_web_key_from_str() -> anyhow::Result<()> {
        let did_string = "did:wk:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq";
        let did_web_key = WrappedDidWebKey::from_str(did_string)?;

        let (public_key, base) =
            Ed25519PubKey::decode("z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq")?;

        assert_eq!(
            did_web_key,
            WrappedDidWebKey::Ed25519(Ed25519DidWebKey {
                public_key,
                base,
                locator_component: None,
            })
        );

        // With locator component
        let did_string =
            "did:wk:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq@steve.zerocore.ai:8080/public";
        let did_web_key = WrappedDidWebKey::from_str(did_string)?;

        let (public_key, base) =
            Ed25519PubKey::decode("z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq")?;
        assert_eq!(
            did_web_key,
            WrappedDidWebKey::Ed25519(Ed25519DidWebKey {
                public_key,
                base,
                locator_component: Some(LocatorComponent::new(
                    "steve.zerocore.ai",
                    8080,
                    Path::from("/public")
                )),
            })
        );

        // Invalid method
        let did_string = "did:xyz:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq";
        let did_web_key = WrappedDidWebKey::from_str(did_string);

        assert!(did_web_key.is_err());

        Ok(())
    }

    #[test]
    fn test_did_web_key_display() -> anyhow::Result<()> {
        let did_string = "did:wk:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq";
        let did_web_key = WrappedDidWebKey::from_str(did_string)?;

        assert_eq!(did_web_key.to_string(), did_string);

        // With locator component
        let did_string =
            "did:wk:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq@steve.zerocore.ai:8080/public";
        let did_web_key = WrappedDidWebKey::from_str(did_string)?;

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
                "steve.zerocore.ai",
                8080,
                Path::from("/public"),
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
                "steve.zerocore.ai",
                8080,
                Path::from("/public"),
            )),
        };

        let serialized = serde_json::to_string(&did_web_key)?;
        tracing::debug!(?serialized);
        let deserialized = serde_json::from_str(&serialized)?;
        assert_eq!(did_web_key, deserialized);

        Ok(())
    }

    #[test_log::test]
    fn test_wrapped_did_web_key_serde() -> anyhow::Result<()> {
        let did_string = "did:wk:z6Mkiyk3sxtq4QAR9etUibQAfj2FU1PU4jAw8Hd4ivHxYzAq";
        let did_web_key = WrappedDidWebKey::from_str(did_string)?;

        let serialized = serde_json::to_string(&did_web_key)?;
        tracing::debug!(?serialized);

        let deserialized = serde_json::from_str(&serialized)?;
        assert_eq!(did_web_key, deserialized);

        Ok(())
    }

    #[test]
    fn test_did_web_key_wrap_into_inner() -> anyhow::Result<()> {
        let rng = &mut rand::thread_rng();

        let public_key = Ed25519PubKey::from(Ed25519KeyPair::generate(rng)?);
        let did_web_key = DidWebKey {
            public_key,
            base: Base::Base58Btc,
            locator_component: Some(LocatorComponent::new(
                "steve.zerocore.ai",
                8080,
                Path::from("/public"),
            )),
        };

        let owned_did_web_key = did_web_key.into_owned();

        let wrapped_did_web_key = WrappedDidWebKey::from(owned_did_web_key.clone());
        let unwrapped_did_web_key: Ed25519DidWebKey = wrapped_did_web_key.into_inner()?;

        assert_eq!(owned_did_web_key, unwrapped_did_web_key);

        let wrapped_did_web_key = WrappedDidWebKey::try_from(owned_did_web_key.clone())?;
        let unwrapped_did_web_key: Ed25519DidWebKey = wrapped_did_web_key.into_inner()?;

        assert_eq!(owned_did_web_key, unwrapped_did_web_key);

        Ok(())
    }
}
