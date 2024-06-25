use rand_core::CryptoRngCore;

use crate::{JwsAlgorithm, KeyResult};

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// A trait for keys that can verify signatures.
pub trait Verify {
    /// Verifies a signature against data with a verifying key.
    fn verify(&self, data: &[u8], signature: &[u8]) -> KeyResult<()>;
}

/// A trait for keys that can sign data.
pub trait Sign: Verify {
    /// Signs data with a signing key.
    fn sign(&self, data: &[u8]) -> KeyResult<Vec<u8>>;
}

/// A trait for keys that can encrypt and decrypt data.
pub trait Cipher {
    /// Encrypts data with a key.
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;

    /// Decrypts data with a key.
    fn decrypt(&self, data: &[u8]) -> KeyResult<Vec<u8>>;
}

/// A trait for constructing a public key.
pub trait PublicKeyGenerate {
    /// Generates a public key from its bytes.
    fn from_public_key(bytes: &[u8]) -> KeyResult<Self>
    where
        Self: Sized;
}

/// A trait for constructing a key pair.
pub trait KeyPairGenerate {
    /// Generates a key pair from a cryptographically secure random number generator.
    fn generate(rng: &mut impl CryptoRngCore) -> KeyResult<Self>
    where
        Self: Sized;

    /// Constructs a key pair from its private key bytes.
    fn from_private_key(bytes: &[u8]) -> KeyResult<Self>
    where
        Self: Sized;
}

/// A trait for getting the public key of a key pair.
pub trait GetPublicKey {
    /// The type of the owned public key.
    type OwnedPublicKey: GetPublicKey + PublicKeyBytes + Verify + 'static;

    /// The type of the public key.
    type PublicKey<'b>: IntoOwned<Owned = Self::OwnedPublicKey> + PublicKeyBytes + Verify
    where
        Self: 'b;

    /// Returns the public key.
    fn public_key(&self) -> Self::PublicKey<'_>;
}

/// A trait for converting a type into an owned type.
pub trait IntoOwned {
    /// The type that is owned.
    type Owned: 'static;

    /// Converts the type into an owned type.
    fn into_owned(self) -> Self::Owned;
}

/// A trait for getting the public key bytes.
pub trait PublicKeyBytes {
    /// Returns the public key bytes.
    fn public_key_bytes(&self) -> Vec<u8>;
}

/// A trait for getting the key pair bytes.
pub trait KeyPairBytes: PublicKeyBytes {
    /// Returns the private key bytes.
    fn private_key_bytes(&self) -> Vec<u8>;
}

/// A trait for performing an elliptic-curve base Diffie-Hellman key exchange.
pub trait ECDHKeyExchange {
    /// The type of key that is exchanged.
    ///
    /// It represents the key agreed upon by both parties after the exchange.
    type SharedKey;

    /// Executes a key exchange operation using the provided public key of
    /// another party.
    ///
    /// RECCOMENDATION: The shared key should be further derived using a key derivation function like
    /// HKDF with a salt and info.
    fn exchange(&self, public_key: &[u8]) -> KeyResult<Self::SharedKey>;
}

/// A trait for getting the algorithm name of a JWS key.
pub trait JwsAlgName {
    /// Returns the algorithm name of a JWS key.
    fn alg(&self) -> JwsAlgorithm;
}
