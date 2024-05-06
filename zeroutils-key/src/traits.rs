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

/// A trait for performing key exchange operations, such as those used in Diffie-Hellman
/// key agreement protocols.
pub trait DiffieHellmanExchange {
    /// The type of key that is exchanged. This could be a session key, shared secret, or
    /// any other form of key material used in cryptographic operations.
    type SessionKey;

    /// Executes a key exchange operation using the provided public key of
    /// another party.
    fn exchange(&self, public_key: &[u8]) -> KeyResult<Self::SessionKey>;
}

/// A trait for getting the algorithm name of a JWS key.
pub trait JwsAlgName {
    /// Returns the algorithm name of a JWS key.
    fn alg(&self) -> JwsAlgorithm;
}
