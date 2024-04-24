//! DID key module.

use async_trait::async_trait;
use did_key::{CoreSign, DIDCore, Fingerprint, Generate, PatchedKeyPair, ECDH};
use ucan::crypto::KeyMaterial;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A key pair.
pub struct KeyPair<T>
where
    T: Generate + ECDH + DIDCore + Fingerprint + Into<did_key::KeyPair>,
{
    inner: PatchedKeyPair,
    phantom: std::marker::PhantomData<T>,
}

/// An Ed25519 key pair.
pub type Ed25516KeyPair = KeyPair<did_key::Ed25519KeyPair>;

/// A P-256 key pair.
pub type P256KeyPair = KeyPair<did_key::P256KeyPair>;

/// A secp256k1 key pair.
pub type Secp256k1KeyPair = KeyPair<did_key::Secp256k1KeyPair>;

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// A trait for getting the JWS algorithm name of a key pair.
pub trait JwsAlgName {
    /// Get the JWS algorithm name.
    fn get_jws_algorithm_name() -> String;
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<T> KeyPair<T>
where
    T: Generate + ECDH + DIDCore + Fingerprint + Into<did_key::KeyPair>,
{
    /// Generates a new key pair.
    pub fn generate(seed: Option<&[u8]>) -> Self {
        let key = did_key::generate::<T>(seed);
        Self {
            inner: key,
            phantom: std::marker::PhantomData,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[async_trait]
impl<T> KeyMaterial for KeyPair<T>
where
    T: Generate + ECDH + DIDCore + Fingerprint + Into<did_key::KeyPair> + Send + Sync + JwsAlgName,
{
    fn get_jwt_algorithm_name(&self) -> String {
        T::get_jws_algorithm_name()
    }

    async fn get_did(&self) -> anyhow::Result<String> {
        let did = format!("did:key:{}", self.inner.fingerprint());
        println!("DID: {}", did);
        Ok(did)
    }

    async fn sign(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let signature = self.inner.sign(payload);
        Ok(signature)
    }

    async fn verify(&self, payload: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        self.inner
            .verify(payload, signature)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;

        Ok(())
    }
}

impl JwsAlgName for did_key::Ed25519KeyPair {
    fn get_jws_algorithm_name() -> String {
        "EdDSA".to_string()
    }
}

impl JwsAlgName for did_key::P256KeyPair {
    fn get_jws_algorithm_name() -> String {
        "ES256".to_string()
    }
}

impl JwsAlgName for did_key::Secp256k1KeyPair {
    fn get_jws_algorithm_name() -> String {
        "ES256K".to_string()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ed25519_key_pair() {
        let key = Ed25516KeyPair::generate(None);
        let did = key.get_did().await.unwrap();

        assert!(did.starts_with("did:key:z6Mk"));

        let payload = b"hello world";
        let signature = key.sign(payload).await.unwrap();

        assert!(key.verify(payload, &signature).await.is_ok());
    }

    #[tokio::test]
    async fn test_p256_key_pair() {
        let key = P256KeyPair::generate(None);
        let did = key.get_did().await.unwrap();

        assert!(did.starts_with("did:key:zDna"));

        let payload = b"hello world";
        let signature = key.sign(payload).await.unwrap();

        assert!(key.verify(payload, &signature).await.is_ok());
    }

    #[tokio::test]
    async fn test_secp256k1_key_pair() {
        let key = Secp256k1KeyPair::generate(None);
        let did = key.get_did().await.unwrap();

        assert!(did.starts_with("did:key:zQ3s"));

        let payload = b"hello world";
        let signature = key.sign(payload).await.unwrap();

        assert!(key.verify(payload, &signature).await.is_ok());
    }
}
