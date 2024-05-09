use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
};

use libsecp256k1::{Message, PublicKey, SecretKey, Signature};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AsymmetricKey, GetPublicKey, JwsAlgName, JwsAlgorithm, KeyPairBytes, KeyPairGenerate,
    KeyResult, PubKey, PublicKeyBytes, PublicKeyGenerate, Sign, Verify, WrappedKeyPair,
    WrappedPubKey,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A [`secp256k1`][ref] public key.
///
/// [ref]: https://en.bitcoin.it/wiki/Secp256k1
pub type Secp256k1PubKey<'a> = PubKey<'a, PublicKey>;

/// A [`secp256k1`][ref] key pair with a signing key.
///
/// [ref]: https://en.bitcoin.it/wiki/Secp256k1
pub type Secp256k1KeyPair<'a> = Secp256k1Key<'a, SecretKey>;

pub(crate) type Secp256k1Key<'a, S> = AsymmetricKey<'a, PublicKey, S>;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<S> Verify for Secp256k1Key<'_, S> {
    fn verify(&self, data: &[u8], signature: &[u8]) -> crate::KeyResult<()> {
        let signature = Signature::parse_standard_slice(signature)?;
        let hash = Sha256::digest(data);
        let message = Message::parse_slice(&hash)?;
        if libsecp256k1::verify(&message, &signature, &self.public) {
            Ok(())
        } else {
            Err(libsecp256k1::Error::InvalidSignature.into())
        }
    }
}

impl Sign for Secp256k1KeyPair<'_> {
    fn sign(&self, data: &[u8]) -> KeyResult<Vec<u8>> {
        let hash = Sha256::digest(data);
        let message = Message::parse_slice(&hash)?;
        let (signature, _) = libsecp256k1::sign(&message, &self.private);
        Ok(signature.serialize().to_vec())
    }
}

impl PublicKeyGenerate for Secp256k1PubKey<'_> {
    fn from_public_key(bytes: &[u8]) -> KeyResult<Self> {
        let public_key = PublicKey::parse_slice(bytes, None)?;
        Ok(Self {
            public: Cow::Owned(public_key),
            private: (),
        })
    }
}

impl KeyPairGenerate for Secp256k1KeyPair<'_> {
    fn generate(rng: &mut impl CryptoRngCore) -> KeyResult<Self> {
        let private_key = SecretKey::random(rng);
        let public_key = PublicKey::from_secret_key(&private_key);
        Ok(Self {
            public: Cow::Owned(public_key),
            private: private_key,
        })
    }

    fn from_private_key(bytes: &[u8]) -> KeyResult<Self> {
        let private_key = SecretKey::parse_slice(bytes)?;
        let public_key = PublicKey::from_secret_key(&private_key);
        Ok(Self {
            public: Cow::Owned(public_key),
            private: private_key,
        })
    }
}

impl<'a, S> GetPublicKey for Secp256k1Key<'a, S> {
    type OwnedPublicKey = Secp256k1PubKey<'static>;
    type PublicKey<'b> = Secp256k1PubKey<'b> where 'a: 'b, S: 'b;

    fn public_key(&self) -> Self::PublicKey<'_> {
        Secp256k1PubKey::from(self)
    }
}

impl<S> PublicKeyBytes for Secp256k1Key<'_, S> {
    /// Returns the compressed public key bytes.
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public.serialize_compressed().to_vec()
    }
}

impl KeyPairBytes for Secp256k1KeyPair<'_> {
    fn private_key_bytes(&self) -> Vec<u8> {
        self.private.serialize().to_vec()
    }
}

impl<'a> From<Secp256k1KeyPair<'a>> for Secp256k1PubKey<'a> {
    fn from(key_pair: Secp256k1KeyPair<'a>) -> Self {
        Self {
            public: key_pair.public,
            private: (),
        }
    }
}

impl<'a, S> From<&'a Secp256k1Key<'a, S>> for Secp256k1PubKey<'a> {
    fn from(key_pair: &'a Secp256k1Key<'a, S>) -> Self {
        Self {
            public: Cow::Borrowed(&key_pair.public),
            private: (),
        }
    }
}

impl Hash for Secp256k1PubKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.public_key_bytes().hash(state);
    }
}

impl Serialize for Secp256k1PubKey<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.public_key_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Secp256k1PubKey<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Secp256k1PubKey<'static>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Secp256k1PubKey::from_public_key(&bytes).map_err(serde::de::Error::custom)
    }
}

impl<S> JwsAlgName for Secp256k1Key<'_, S> {
    fn alg(&self) -> JwsAlgorithm {
        JwsAlgorithm::ES256K
    }
}

impl<'a> From<Secp256k1PubKey<'a>> for WrappedPubKey<'a> {
    fn from(pub_key: Secp256k1PubKey<'a>) -> Self {
        WrappedPubKey::Secp256k1(pub_key)
    }
}

impl<'a> From<Secp256k1KeyPair<'a>> for WrappedKeyPair<'a> {
    fn from(key_pair: Secp256k1KeyPair<'a>) -> Self {
        WrappedKeyPair::Secp256k1(key_pair)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use anyhow::Ok;

    use crate::IntoOwned;

    use super::*;

    #[test]
    fn test_secp256k1_generate() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let key_pair = Secp256k1KeyPair::generate(&mut rng)?;

        let public_key_bytes = key_pair.public_key_bytes();
        let public_key = Secp256k1PubKey::from_public_key(&public_key_bytes).unwrap();

        assert_eq!(Secp256k1PubKey::from(key_pair.clone()), public_key);

        let private_key_bytes = key_pair.private_key_bytes();
        let key_pair2 = Secp256k1KeyPair::from_private_key(&private_key_bytes)?;

        assert_eq!(key_pair, key_pair2);

        let public_key2 = key_pair2.public_key();

        assert_eq!(public_key, public_key2);

        Ok(())
    }

    #[test]
    fn test_secp256k1_sign_and_verify() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let key_pair = Secp256k1KeyPair::generate(&mut rng)?;

        let data = include_bytes!("../fixtures/data.txt");
        let signature = key_pair.sign(data)?;

        key_pair.verify(data, &signature)?;

        Ok(())
    }

    #[test_log::test]
    fn test_secp256k1_pub_key_serde() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let pub_key = Secp256k1PubKey::from(Secp256k1KeyPair::generate(&mut rng)?);

        let serialized = serde_json::to_string(&pub_key)?;
        tracing::debug!(?serialized);
        let deserialized = serde_json::from_str(&serialized)?;
        assert_eq!(pub_key, deserialized);

        Ok(())
    }

    #[test]
    fn test_secp256k1_wrap_into_inner() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let key_pair = Secp256k1KeyPair::generate(&mut rng)?;

        let keypair_wrapped = WrappedKeyPair::from(key_pair.clone());
        let keypair_unwrapped = keypair_wrapped.into_inner()?;
        assert_eq!(key_pair, keypair_unwrapped);

        let public_key = key_pair.public_key().into_owned();
        let wrapped_pub_key = WrappedPubKey::from(public_key.clone());
        let unwrapped_pub_key = wrapped_pub_key.into_inner::<Secp256k1PubKey>()?;

        assert_eq!(public_key, unwrapped_pub_key);

        Ok(())
    }
}
