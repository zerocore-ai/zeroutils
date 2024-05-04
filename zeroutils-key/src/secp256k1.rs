use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
};

use libsecp256k1::{Message, PublicKey, SecretKey, Signature};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

use crate::{
    AsymmetricKey, KeyPairBytes, KeyPairGenerate, KeyResult, PubKey, PublicKeyBytes,
    PublicKeyGenerate, Sign, Verify,
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use anyhow::Ok;

    use super::*;

    #[test]
    fn test_secp256k1_generate_and_serialize_roundtrip() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let key_pair = Secp256k1KeyPair::generate(&mut rng)?;

        let public_key_bytes = key_pair.public_key_bytes();
        let public_key = Secp256k1PubKey::from_public_key(&public_key_bytes).unwrap();

        assert_eq!(Secp256k1PubKey::from(key_pair.clone()), public_key);

        let private_key_bytes = key_pair.private_key_bytes();
        let key_pair2 = Secp256k1KeyPair::from_private_key(&private_key_bytes)?;

        assert_eq!(key_pair, key_pair2);

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
}
