use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
};

use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    AsymmetricKey, GetPublicKey, JwsAlgName, JwsAlgorithm, KeyPairBytes, KeyPairGenerate,
    KeyResult, PubKey, PublicKeyBytes, PublicKeyGenerate, Sign, Verify, WrappedKeyPair,
    WrappedPubKey,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A [`NIST P-256`][ref] public key.
///
/// [ref]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
pub type P256PubKey<'a> = PubKey<'a, VerifyingKey>;

/// A [`NIST P-256`][ref] key pair with a signing key.
///
/// [ref]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
pub type P256KeyPair<'a> = P256Key<'a, SigningKey>;

pub(crate) type P256Key<'a, S> = AsymmetricKey<'a, VerifyingKey, S>;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<S> Verify for P256Key<'_, S> {
    fn verify(&self, data: &[u8], signature: &[u8]) -> KeyResult<()> {
        self.public
            .verify(data, &Signature::try_from(signature)?)
            .map_err(Into::into)
    }
}

impl Sign for P256KeyPair<'_> {
    fn sign(&self, data: &[u8]) -> KeyResult<Vec<u8>> {
        let signature: Signature = self.private.try_sign(data)?;
        Ok(signature.to_vec())
    }
}

impl PublicKeyGenerate for P256PubKey<'_> {
    /// Generates a public key from the given bytes from the [`Elliptic-Curve-Point-to-Octet-String` encoding][ref]
    /// described in SEC 1: Elliptic Curve Cryptography (Version 2.0).
    ///
    /// [ref]: http://www.secg.org/sec1-v2.pdf
    fn from_public_key(bytes: &[u8]) -> KeyResult<Self> {
        Ok(Self {
            public: Cow::Owned(VerifyingKey::from_sec1_bytes(bytes)?),
            private: (),
        })
    }
}

impl KeyPairGenerate for P256KeyPair<'_> {
    fn generate(rng: &mut impl CryptoRngCore) -> KeyResult<Self> {
        let signing_key = SigningKey::random(rng);
        Ok(Self {
            public: Cow::Owned(*signing_key.verifying_key()),
            private: signing_key,
        })
    }

    fn from_private_key(bytes: &[u8]) -> KeyResult<Self> {
        let signing_key = SigningKey::try_from(bytes)?;
        Ok(Self {
            public: Cow::Owned(*signing_key.verifying_key()),
            private: signing_key,
        })
    }
}

impl<'a, S> GetPublicKey for P256Key<'a, S> {
    type OwnedPublicKey = P256PubKey<'static>;
    type PublicKey<'b> = P256PubKey<'b> where 'a: 'b, S: 'b;

    fn public_key(&self) -> Self::PublicKey<'_> {
        P256PubKey::from(self)
    }
}

impl<S> PublicKeyBytes for P256Key<'_, S> {
    /// Returns the public key bytes in the [`Elliptic-Curve-Point-to-Octet-String` encoding][ref] described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0).
    ///
    /// [ref]: http://www.secg.org/sec1-v2.pdf
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public.to_encoded_point(true).as_bytes().to_vec()
    }
}

impl KeyPairBytes for P256KeyPair<'_> {
    fn private_key_bytes(&self) -> Vec<u8> {
        self.private.to_bytes().to_vec()
    }
}

impl<'a> From<P256KeyPair<'a>> for P256PubKey<'a> {
    fn from(key_pair: P256KeyPair<'a>) -> Self {
        Self {
            public: key_pair.public,
            private: (),
        }
    }
}

impl<'a, S> From<&'a P256Key<'a, S>> for P256PubKey<'a> {
    fn from(key_pair: &'a P256Key<'a, S>) -> Self {
        Self {
            public: Cow::Borrowed(&key_pair.public),
            private: (),
        }
    }
}

impl Hash for P256PubKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.public_key_bytes().hash(state);
    }
}

impl Serialize for P256PubKey<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.public_key_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for P256PubKey<'_> {
    fn deserialize<D>(deserializer: D) -> Result<P256PubKey<'static>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        P256PubKey::from_public_key(&bytes).map_err(serde::de::Error::custom)
    }
}

impl<S> JwsAlgName for P256Key<'_, S> {
    fn alg(&self) -> JwsAlgorithm {
        JwsAlgorithm::ES256
    }
}

impl<'a> From<P256PubKey<'a>> for WrappedPubKey<'a> {
    fn from(pub_key: P256PubKey<'a>) -> Self {
        WrappedPubKey::P256(pub_key)
    }
}

impl<'a> From<P256KeyPair<'a>> for WrappedKeyPair<'a> {
    fn from(key_pair: P256KeyPair<'a>) -> Self {
        WrappedKeyPair::P256(key_pair)
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
    fn test_p256_generate() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let key_pair = P256KeyPair::generate(&mut rng)?;

        let public_key_bytes = key_pair.public_key_bytes();
        let public_key = P256PubKey::from_public_key(&public_key_bytes)?;

        assert_eq!(P256PubKey::from(key_pair.clone()), public_key);

        let private_key_bytes = key_pair.private_key_bytes();
        let private_key = P256KeyPair::from_private_key(&private_key_bytes)?;

        assert_eq!(key_pair, private_key);

        let public_key2 = key_pair.public_key();

        assert_eq!(public_key, public_key2);

        Ok(())
    }

    #[test]
    fn test_p256_sign_and_verify() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let key_pair = P256KeyPair::generate(&mut rng)?;

        let data = include_bytes!("../fixtures/data.txt");
        let signature = key_pair.sign(data)?;

        key_pair.verify(data, &signature)?;

        Ok(())
    }

    #[test_log::test]
    fn test_p256_pub_key_serde() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let pub_key = P256PubKey::from(P256KeyPair::generate(&mut rng)?);

        let serialized = serde_json::to_string(&pub_key)?;
        tracing::debug!(?serialized);
        let deserialized = serde_json::from_str(&serialized)?;
        assert_eq!(pub_key, deserialized);

        Ok(())
    }

    #[test]
    fn test_p256_wrap_into_inner() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let key_pair = P256KeyPair::generate(&mut rng)?;

        let keypair_wrapped = WrappedKeyPair::from(key_pair.clone());
        let keypair_unwrapped = keypair_wrapped.into_inner()?;
        assert_eq!(key_pair, keypair_unwrapped);

        let public_key = key_pair.public_key().into_owned();
        let wrapped_pub_key = WrappedPubKey::from(public_key.clone());
        let unwrapped_pub_key = wrapped_pub_key.into_inner::<P256PubKey>()?;

        assert_eq!(public_key, unwrapped_pub_key);

        Ok(())
    }
}
