use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;

use crate::{
    AsymmetricKey, KeyPairBytes, KeyPairGenerate, KeyResult, PubKey, PublicKeyBytes,
    PublicKeyGenerate, Sign, Verify,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An [`ed25519`][ref] verifying key.
///
/// [ref]: https://en.wikipedia.org/wiki/EdDSA
pub type Ed25519PubKey<'a> = PubKey<'a, VerifyingKey>;

/// An [`ed25519`][ref] key pair with a signing key.
///
/// [ref]: https://en.wikipedia.org/wiki/EdDSA
pub type Ed25519KeyPair<'a> = Ed25519Key<'a, SigningKey>;

pub(crate) type Ed25519Key<'a, S> = AsymmetricKey<'a, VerifyingKey, S>;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<S> Verify for Ed25519Key<'_, S> {
    fn verify(&self, data: &[u8], signature: &[u8]) -> KeyResult<()> {
        self.public
            .verify_strict(data, &Signature::try_from(signature)?)
            .map_err(Into::into)
    }
}

impl Sign for Ed25519KeyPair<'_> {
    fn sign(&self, data: &[u8]) -> KeyResult<Vec<u8>> {
        let signature = self.private.try_sign(data)?;
        Ok(signature.to_vec())
    }
}

impl PublicKeyGenerate for Ed25519PubKey<'_> {
    fn from_public_key(bytes: &[u8]) -> KeyResult<Self> {
        Ok(Self {
            public: Cow::Owned(VerifyingKey::try_from(bytes)?),
            private: (),
        })
    }
}

impl KeyPairGenerate for Ed25519KeyPair<'_> {
    fn generate(rng: &mut impl CryptoRngCore) -> KeyResult<Self> {
        let signing_key = SigningKey::generate(rng);
        Ok(Self {
            public: Cow::Owned(signing_key.verifying_key()),
            private: signing_key,
        })
    }

    fn from_private_key(bytes: &[u8]) -> KeyResult<Self> {
        let signing_key = SigningKey::try_from(bytes)?;
        Ok(Self {
            public: Cow::Owned(signing_key.verifying_key()),
            private: signing_key,
        })
    }
}

impl<S> PublicKeyBytes for Ed25519Key<'_, S> {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public.to_bytes().to_vec()
    }
}

impl KeyPairBytes for Ed25519KeyPair<'_> {
    fn private_key_bytes(&self) -> Vec<u8> {
        self.private.to_bytes().to_vec()
    }
}

impl<'a> From<Ed25519KeyPair<'a>> for Ed25519PubKey<'a> {
    fn from(key_pair: Ed25519KeyPair<'a>) -> Self {
        Self {
            public: key_pair.public,
            private: (),
        }
    }
}

impl<'a, S> From<&'a Ed25519Key<'a, S>> for Ed25519PubKey<'a> {
    fn from(key_pair: &'a Ed25519Key<'a, S>) -> Self {
        Self {
            public: Cow::Borrowed(&key_pair.public),
            private: (),
        }
    }
}

impl Hash for Ed25519PubKey<'_> {
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
    fn test_ed25519_generate_and_serialize_roundtrip() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let key_pair = Ed25519KeyPair::generate(&mut rng)?;

        let public_key_bytes = key_pair.public_key_bytes();
        let public_key = Ed25519PubKey::from_public_key(&public_key_bytes)?;

        assert_eq!(Ed25519PubKey::from(key_pair.clone()), public_key);

        let private_key_bytes = key_pair.private_key_bytes();
        let private_key = Ed25519KeyPair::from_private_key(&private_key_bytes)?;

        assert_eq!(key_pair, private_key);

        Ok(())
    }

    #[test]
    fn test_ed25519_sign_and_verify() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let key_pair = Ed25519Key::generate(&mut rng)?;

        let data = include_bytes!("../fixtures/data.txt");
        let signature = key_pair.sign(data)?;

        key_pair.verify(data, &signature)?;

        Ok(())
    }
}
