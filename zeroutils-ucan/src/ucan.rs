use std::{
    fmt::{Debug, Display},
    marker::PhantomData,
};

use async_once_cell::OnceCell;
use libipld::Cid;
use serde::{
    de::{self, DeserializeSeed},
    Deserialize, Deserializer, Serialize,
};
use zeroutils_did_wk::WrappedDidWebKey;
use zeroutils_key::{GetPublicKey, JwsAlgName, JwsAlgorithm, Sign, Verify};
use zeroutils_store::{
    IpldStore, IpldStoreExt, PlaceholderStore, Storable, StoreError, StoreResult,
};

use crate::{
    DefaultUcanBuilder, ResolvedCapabilities, ResolvedCapabilityTuple, UcanBuilder, UcanError,
    UcanHeader, UcanPayload, UcanPayloadSerializable, UcanResult, UcanSignature,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents a [UCAN (User-Controlled Authorization Network)][ucan] token.
///
/// UCANs are a decentralized authorization scheme that offers fine-grained, user-centric
/// control over permissions. Unlike traditional access tokens, UCANs can be chained for
/// delegation, enabling complex authorization scenarios without a central authority.
///
/// NOTE: This implementation currently only supports the `did:wk` DID method.
///
/// [ucan]: https://github.com/ucan-wg/spec
pub struct Ucan<'a, S, H = (), V = (), R = ()>
where
    S: IpldStore,
{
    /// The header of the UCAN, containing metadata and cryptographic information.
    pub(crate) header: H,

    /// The payload of the UCAN, containing the actual authorization data and claims.
    pub(crate) payload: UcanPayload<'a, S>,

    /// The signature of the UCAN, proving its authenticity.
    pub(crate) signature: V,

    /// Cached resolved capabilities for the UCAN.
    pub(crate) resolved_capabilities: R,
}

/// Represents a signed [UCAN (User-Controlled Authorization Network)][ucan] token with a header and signature.
///
/// UCANs are a decentralized authorization scheme that offers fine-grained, user-centric
/// control over permissions. Unlike traditional access tokens, UCANs can be chained for
/// delegation, enabling complex authorization scenarios without a central authority.
///
/// ## Important
///
/// This implementation currently only supports the `did:wk` DID method.
///
/// [ucan]: https://github.com/ucan-wg/spec
pub type SignedUcan<'a, S> = Ucan<'a, S, UcanHeader, UcanSignature, CachedResolvedCapabilities>;

/// Represents a cached resolved capabilities for a signed UCAN.
pub type CachedResolvedCapabilities = OnceCell<ResolvedCapabilities>;

/// Represents an unsigned [UCAN (User-Controlled Authorization Network)][ucan] token without a signature.
///
/// UCANs are a decentralized authorization scheme that offers fine-grained, user-centric
/// control over permissions. Unlike traditional access tokens, UCANs can be chained for
/// delegation, enabling complex authorization scenarios without a central authority.
///
/// ## Important
///
/// This implementation currently only supports the `did:wk` DID method.
///
/// [ucan]: https://github.com/ucan-wg/spec
pub type UnsignedUcan<'a, S, H = ()> = Ucan<'a, S, H>;

//--------------------------------------------------------------------------------------------------
// Types: Serializable
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct UnsignedUcanSerializable<'a, H> {
    header: H,
    payload: UcanPayloadSerializable<'a>,
}

struct UnsignedUcanDeserializeSeed<'a, S, H> {
    store: S,
    phantom: PhantomData<&'a H>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a, S, H> UnsignedUcanDeserializeSeed<'a, S, H> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            phantom: PhantomData,
        }
    }
}

impl Ucan<'_, PlaceholderStore> {
    /// Creates a convenience builder for constructing a new UCAN.
    pub fn builder() -> DefaultUcanBuilder {
        UcanBuilder::default()
    }
}

impl<'a, S, H, V, R> Ucan<'a, S, H, V, R>
where
    S: IpldStore,
{
    /// Returns the header of the UCAN.
    pub fn header(&self) -> &H {
        &self.header
    }

    /// Returns the payload of the UCAN.
    pub fn payload(&self) -> &UcanPayload<'a, S> {
        &self.payload
    }

    /// Returns the signature of the UCAN.
    pub fn signature(&self) -> &V {
        &self.signature
    }

    /// Checks if the UCAN is addressed to the specified DID.
    pub fn addressed_to(&self, did: &WrappedDidWebKey) -> bool {
        self.payload.audience() == did
    }
}

impl<'a, S, H, V> Ucan<'a, S, H, V>
where
    S: IpldStore,
{
    /// Constructs a UCAN from its individual components.
    pub fn from_parts(header: H, payload: UcanPayload<'a, S>, signature: impl Into<V>) -> Self {
        Self {
            header,
            payload,
            signature: signature.into(),
            resolved_capabilities: (),
        }
    }

    /// Updates the UCAN to use a specified JWS algorithm.
    pub fn use_alg(self, alg: JwsAlgorithm) -> Ucan<'a, S, UcanHeader, V> {
        Ucan {
            header: alg.into(),
            payload: self.payload,
            signature: self.signature,
            resolved_capabilities: self.resolved_capabilities,
        }
    }
}

impl<'a, S, H> UnsignedUcan<'a, S, H>
where
    S: IpldStore,
{
    /// Signs an unsigned UCAN using the provided keypair.
    pub fn sign<K>(self, keypair: &K) -> UcanResult<SignedUcan<'a, S>>
    where
        K: Sign + JwsAlgName,
    {
        let ucan = self.use_alg(keypair.alg());
        let encoded = ucan.to_string();
        let signature = keypair.sign(encoded.as_bytes())?;

        Ok(Ucan {
            payload: ucan.payload,
            header: ucan.header,
            signature: signature.into(),
            resolved_capabilities: OnceCell::new(),
        })
    }

    /// Validates the UCAN, ensuring that it is well-formed.
    pub fn validate(&self) -> UcanResult<()> {
        self.payload.validate_time_bounds()
    }

    /// Deserializes to UnsignedUcan using an arbitrary deserializer and store.
    pub fn deserialize_with<'de>(
        deserializer: impl Deserializer<'de, Error: Into<UcanError>>,
        store: S,
    ) -> UcanResult<Self>
    where
        H: Deserialize<'de> + 'a,
    {
        UnsignedUcanDeserializeSeed::new(store)
            .deserialize(deserializer)
            .map_err(Into::into)
    }

    fn try_from_serializable(ucan: UnsignedUcanSerializable<'a, H>, store: S) -> UcanResult<Self> {
        let payload = UcanPayload::try_from_serializable(ucan.payload, store)?;
        Ok(Self {
            header: ucan.header,
            payload,
            signature: (),
            resolved_capabilities: (),
        })
    }
}

impl<'a, S> UnsignedUcan<'a, S, UcanHeader>
where
    S: IpldStore,
{
    /// Attempts to create a `UnsignedUcan` instance by parsing provided Base64 encoded string.
    pub fn try_from_str(string: impl AsRef<str>, store: S) -> UcanResult<Self> {
        let parts: Vec<&str> = string.as_ref().split('.').collect();

        if parts.len() != 2 {
            return Err(UcanError::UnableToParse);
        }

        let header = parts[0].parse()?;
        let payload = UcanPayload::try_from_str(parts[1], store)?;

        Ok(Self {
            header,
            payload,
            signature: (),
            resolved_capabilities: (),
        })
    }
}

impl<'a, S> SignedUcan<'a, S>
where
    S: IpldStore,
{
    /// Resolves the capabilities to their final forms and checks if the UCAN permits the specified capability.
    pub async fn permits(
        &self,
        capability: impl Into<ResolvedCapabilityTuple>,
        root_key: &impl GetPublicKey,
    ) -> UcanResult<bool> {
        let resolved = self.resolve_capabilities(root_key).await?;
        Ok(resolved.permits(capability))
    }

    /// Attempts to create a `SignedUcan` instance by parsing provided Base64 encoded string.
    pub fn try_from_str(string: impl AsRef<str>, store: S) -> UcanResult<Self> {
        let parts: Vec<&str> = string.as_ref().split('.').collect();

        if parts.len() != 3 {
            return Err(UcanError::UnableToParse);
        }

        let header = parts[0].parse()?;
        let payload = UcanPayload::try_from_str(parts[1], store)?;
        let signature = parts[2].parse()?;

        Ok(Self {
            header,
            payload,
            signature,
            resolved_capabilities: OnceCell::new(),
        })
    }

    /// Validates the UCAN, ensuring that it is well-formed.
    pub fn validate(&self) -> UcanResult<()> {
        self.payload.validate_time_bounds()?;
        self.verify_signature()
    }

    /// Checks if the UCAN does not exceed the constraints of the proof UCAN.
    pub fn validate_proof_constraints<'b>(
        &self,
        proof_ucan: &'b SignedUcan<'b, S>,
    ) -> UcanResult<()> {
        // Check if their `aud` field matches our `iss` field
        if self.payload.issuer != proof_ucan.payload.audience {
            return Err(UcanError::PrincipalAlignmentFailed(
                self.payload.issuer.to_string(),
                proof_ucan.payload.audience.to_string(),
            ));
        }

        // Check time bound constraints.
        if self.payload.expiration > proof_ucan.payload.expiration {
            return Err(UcanError::ExpirationConstraintViolated(
                self.payload.expiration,
                proof_ucan.payload.expiration,
            ));
        }

        if self.payload.not_before < proof_ucan.payload.not_before {
            return Err(UcanError::NotBeforeConstraintViolated(
                self.payload.not_before,
                proof_ucan.payload.not_before,
            ));
        }

        Ok(())
    }

    /// Verifies the signature is truly signed by the issuer.
    pub fn verify_signature(&self) -> UcanResult<()> {
        let unsigned_ucan = UnsignedUcan::from_parts(self.header.clone(), self.payload.clone(), ());

        self.payload
            .issuer
            .public_key()
            .verify(unsigned_ucan.to_string().as_bytes(), self.signature())?;

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'a, S> Display for UnsignedUcan<'a, S, UcanHeader>
where
    S: IpldStore,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.header, self.payload)
    }
}

impl<'a, S> Display for SignedUcan<'a, S>
where
    S: IpldStore,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.header, self.payload, self.signature)
    }
}

impl<'a, H> Serialize for UnsignedUcan<'a, PlaceholderStore, H>
where
    H: Serialize + Clone,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let parts = UnsignedUcanSerializable {
            header: self.header.clone(),
            payload: UcanPayloadSerializable::from(&self.payload),
        };

        parts.serialize(serializer)
    }
}

impl<'a, 'de, S, H> DeserializeSeed<'de> for UnsignedUcanDeserializeSeed<'a, S, H>
where
    S: IpldStore,
    H: Deserialize<'de>,
{
    type Value = Ucan<'a, S, H>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let payload = UnsignedUcanSerializable::deserialize(deserializer)?;
        UnsignedUcan::try_from_serializable(payload, self.store).map_err(de::Error::custom)
    }
}

impl<S> PartialEq for SignedUcan<'_, S>
where
    S: IpldStore,
{
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && self.payload == other.payload
            && self.signature == other.signature
    }
}

impl<S, H> PartialEq for UnsignedUcan<'_, S, H>
where
    S: IpldStore,
    H: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.payload == other.payload
    }
}

impl<'a, S, H, V, R> Debug for Ucan<'a, S, H, V, R>
where
    S: IpldStore,
    H: Debug,
    V: Debug,
    R: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ucan")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .field("signature", &self.signature)
            .field("resolved_capabilities", &self.resolved_capabilities)
            .finish()
    }
}

impl<'a, S, H, V> Clone for Ucan<'a, S, H, V>
where
    S: IpldStore + Clone,
    H: Clone,
    V: Clone,
{
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            payload: self.payload.clone(),
            signature: self.signature.clone(),
            resolved_capabilities: (),
        }
    }
}

impl<'a, S, H, V> Clone for Ucan<'a, S, H, V, OnceCell<ResolvedCapabilities>>
where
    S: IpldStore + Clone,
    H: Clone,
    V: Clone,
{
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            payload: self.payload.clone(),
            signature: self.signature.clone(),
            resolved_capabilities: OnceCell::new(),
        }
    }
}

impl<'a, S> Storable<S> for SignedUcan<'a, S>
where
    S: IpldStore,
{
    async fn store(&self) -> StoreResult<Cid> {
        let encoded = self.to_string();
        self.payload.store.put_bytes(encoded.as_bytes()).await
    }

    async fn load(cid: &Cid, store: S) -> StoreResult<Self> {
        let bytes = store.read_all(cid).await?;
        let encoded = std::str::from_utf8(&bytes).map_err(StoreError::custom)?;
        SignedUcan::try_from_str(encoded, store).map_err(StoreError::custom)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use zeroutils_did_wk::Base;
    use zeroutils_key::{Ed25519KeyPair, KeyPairGenerate};
    use zeroutils_store::MemoryStore;

    use crate::caps;

    use super::*;

    #[test_log::test]
    fn test_ucan_serde() -> anyhow::Result<()> {
        // Unsigned UCAN
        let ucan = Ucan::builder()
            .store(PlaceholderStore)
            .issuer("did:wk:m5wECtxi2kxRme2uhswu46BwzRtqvhEznWKucFrrph0I7+uo")
            .audience("did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti")
            .expiration(UNIX_EPOCH + Duration::from_secs(3_600_000_000)) // TODO: Change to chrono date
            .not_before(UNIX_EPOCH)
            .nonce("1100263a4012")
            .facts(vec![])
            .capabilities(caps!()?)
            .proofs(vec![])
            .build();

        let serialized = serde_json::to_string(&ucan)?;
        tracing::debug!(?serialized);
        assert_eq!(
            serialized,
            r#"{"header":null,"payload":{"ucv":"0.10.0-alpha.1","iss":"did:wk:m5wECtxi2kxRme2uhswu46BwzRtqvhEznWKucFrrph0I7+uo","aud":"did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti","exp":3600000000,"nbf":0,"nnc":"1100263a4012","fct":{},"cap":{}}}"#
        );

        let deserialized = UnsignedUcan::deserialize_with(
            &mut serde_json::Deserializer::from_str(&serialized),
            PlaceholderStore,
        )?;
        assert_eq!(deserialized, ucan);

        Ok(())
    }

    #[test_log::test]
    fn test_ucan_display() -> anyhow::Result<()> {
        // Signed UCAN
        let keypair = Ed25519KeyPair::from_private_key(&vec![
            190, 244, 147, 155, 83, 151, 225, 133, 7, 166, 15, 183, 157, 168, 142, 25, 128, 4, 106,
            34, 199, 60, 60, 9, 190, 179, 2, 196, 179, 179, 64, 134,
        ])?;

        let signed_ucan = Ucan::builder()
            .store(PlaceholderStore)
            .issuer("did:wk:m5wECtxi2kxRme2uhswu46BwzRtqvhEznWKucFrrph0I7+uo")
            .audience("did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti")
            .expiration(UNIX_EPOCH + Duration::from_secs(3_600_000_000)) // TODO: Change to chrono date
            .not_before(UNIX_EPOCH)
            .nonce("1100263a4012")
            .facts(vec![])
            .capabilities(caps! {
                "zerofs://public/photos/dogs/": {
                    "entity/read": [{}],
                    "entity/write": [{}],
                },
            }?)
            .proofs(vec![])
            .sign(&keypair)?;

        let encoded = signed_ucan.to_string();
        tracing::debug!(?encoded);
        assert_eq!(
            encoded,
            "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ1Y3YiOiIwLjEwLjAtYWxwaGEuMSIsImlzcyI6ImRpZDp3azptNXdFQ3R4aTJreFJtZTJ1aHN3dTQ2Qnd6UnRxdmhFem5XS3VjRnJycGgwSTcrdW8iLCJhdWQiOiJkaWQ6d2s6YjV1YTVsNHdnY3A0NnpydG4zaWhqam11NWdieWh1c215dDViaWFubDVvdjJ5cnZqN3duaDR2dGkiLCJleHAiOjM2MDAwMDAwMDAsIm5iZiI6MCwibm5jIjoiMTEwMDI2M2E0MDEyIiwiZmN0Ijp7fSwiY2FwIjp7Inplcm9mczovL3B1YmxpYy9waG90b3MvZG9ncy8iOnsiZW50aXR5L3JlYWQiOlt7fV0sImVudGl0eS93cml0ZSI6W3t9XX19fQ.0AdFn0L_oHqxWz-0ybqy43N0Rumhp0MObGqOE-tSkqLiyunCASwuHyVrMBWes2TsdvDe4YNbaWWlVXaOEDtBBA"
        );

        let decoded = SignedUcan::try_from_str(&encoded, PlaceholderStore)?;
        assert_eq!(decoded, signed_ucan);

        // Remove optional fields
        let signed_ucan = Ucan::builder()
            .store(PlaceholderStore)
            .issuer("did:wk:m5wECtxi2kxRme2uhswu46BwzRtqvhEznWKucFrrph0I7+uo")
            .audience("did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti")
            .expiration(None)
            .capabilities(caps!()?)
            .sign(&keypair)?;

        let encoded = signed_ucan.to_string();
        tracing::debug!(?encoded);
        assert_eq!(encoded, "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ1Y3YiOiIwLjEwLjAtYWxwaGEuMSIsImlzcyI6ImRpZDp3azptNXdFQ3R4aTJreFJtZTJ1aHN3dTQ2Qnd6UnRxdmhFem5XS3VjRnJycGgwSTcrdW8iLCJhdWQiOiJkaWQ6d2s6YjV1YTVsNHdnY3A0NnpydG4zaWhqam11NWdieWh1c215dDViaWFubDVvdjJ5cnZqN3duaDR2dGkiLCJleHAiOm51bGwsImNhcCI6e319.3vSKJiWMUBf_rXFOqiSG-PoGHZG63fPOqIeCoLKX0IW4cUVPxCw94k6rg6e5lKmWu27XKUt1RYQJXoA91su6BA");

        let decoded = SignedUcan::try_from_str(&encoded, PlaceholderStore)?;
        assert_eq!(decoded, signed_ucan);

        Ok(())
    }

    #[tokio::test]
    async fn test_ucan_stores_and_loads() -> anyhow::Result<()> {
        let now = SystemTime::now();
        let store = MemoryStore::default();
        let base = Base::Base58Btc;
        let principal_0_key = Ed25519KeyPair::generate(&mut rand::thread_rng())?;
        let principal_1_key = Ed25519KeyPair::generate(&mut rand::thread_rng())?;
        let principal_0_did = WrappedDidWebKey::from_key(&principal_0_key, base)?;
        let principal_1_did = WrappedDidWebKey::from_key(&principal_1_key, base)?;

        let ucan = Ucan::builder()
            .store(store.clone())
            .issuer(principal_0_did)
            .audience(principal_1_did.clone())
            .expiration(now + Duration::from_secs(720_000))
            .capabilities(caps! {
                "zerodb://": {
                    "db/read": [{}],
                }
            }?)
            .sign(&principal_0_key)?;

        let cid = ucan.store().await?;
        let stored_ucan = SignedUcan::load(&cid, store).await?;

        assert_eq!(ucan, stored_ucan);

        Ok(())
    }
}
