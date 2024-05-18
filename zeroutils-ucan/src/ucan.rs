use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use zeroutils_key::{JwsAlgName, JwsAlgorithm, Sign, Verify};
use zeroutils_store::{IpldStore, PlaceholderStore};

use crate::{
    Ability, DefaultUcanBuilder, ResourceUri, UcanBuilder, UcanHeader, UcanPayload, UcanResult,
    UcanSignature,
};

use super::UcanError;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ucan<'a, S, H = (), V = ()>
where
    S: IpldStore,
{
    /// The header of the UCAN, containing metadata and cryptographic information.
    pub(crate) header: H,

    /// The payload of the UCAN, containing the actual authorization data and claims.
    pub(crate) payload: UcanPayload<'a, S>,

    /// The signature of the UCAN, proving its authenticity.
    pub(crate) signature: V,
    // /// Cached capabilities for the UCAN.
    // resolved_capabilities: OnceCell<Capabilities<'a>>,
}

/// Represents a signed [UCAN (User-Controlled Authorization Network)][ucan] token with a header and signature.
///
/// UCANs are a decentralized authorization scheme that offers fine-grained, user-centric
/// control over permissions. Unlike traditional access tokens, UCANs can be chained for
/// delegation, enabling complex authorization scenarios without a central authority.
///
/// # Important
///
/// This implementation currently only supports the `did:wk` DID method.
///
/// [ucan]: https://github.com/ucan-wg/spec
pub type SignedUcan<'a, S = PlaceholderStore> = Ucan<'a, S, UcanHeader, UcanSignature>;

/// Represents an unsigned [UCAN (User-Controlled Authorization Network)][ucan] token without a signature.
///
/// UCANs are a decentralized authorization scheme that offers fine-grained, user-centric
/// control over permissions. Unlike traditional access tokens, UCANs can be chained for
/// delegation, enabling complex authorization scenarios without a central authority.
///
/// # Important
///
/// This implementation currently only supports the `did:wk` DID method.
///
/// [ucan]: https://github.com/ucan-wg/spec
pub type UnsignedUcan<'a, S, H = ()> = Ucan<'a, S, H, ()>;

//--------------------------------------------------------------------------------------------------
// Types: Serde
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SignedUcanSerde<'a> {
    header: UcanHeader,
    payload: UcanPayload<'a, PlaceholderStore>,
    signature: UcanSignature,
}

#[derive(Serialize, Deserialize)]
struct UnsignedUcanSerde<'a, H> {
    header: H,
    payload: UcanPayload<'a, PlaceholderStore>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Ucan<'_, PlaceholderStore> {
    /// Creates a convenience builder for constructing a new UCAN.
    pub fn builder<'a>() -> DefaultUcanBuilder<'a> {
        UcanBuilder::default()
    }
}

impl<'a, S, H, V> Ucan<'a, S, H, V>
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
        }
    }

    /// Transforms the Ucan to use a different IPLD store.
    pub fn use_store<T>(self, store: &'a T) -> Ucan<'a, T, H, V>
    where
        T: IpldStore,
    {
        Ucan {
            header: self.header,
            payload: self.payload.use_store(store),
            signature: self.signature,
        }
    }

    /// Updates the UCAN to use a specified JWS algorithm.
    pub fn use_alg(self, alg: JwsAlgorithm) -> Ucan<'a, S, UcanHeader, V> {
        Ucan {
            header: alg.into(),
            payload: self.payload,
            signature: self.signature,
        }
    }

    /// Validates the UCAN, ensuring that it is well-formed.
    pub fn validate(&self) -> UcanResult<()> {
        self.payload.validate()
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
        })
    }
}

impl<'a, S> SignedUcan<'a, S>
where
    S: IpldStore,
{
    /// Parses a signed UCAN from a string representation with a specified IPLD store.
    pub fn with_store(string: impl AsRef<str>, store: &'a S) -> UcanResult<SignedUcan<'a, S>> {
        let ucan: SignedUcan<'a, PlaceholderStore> = string.as_ref().parse()?;
        Ok(ucan.use_store(store))
    }

    /// Resolves the capabilities of a UCAN to their final form.
    pub fn resolve_capabilities(&mut self) -> UcanResult<()> {
        self.validate()?;

        todo!("resolve capabilities")
    }

    /// Verifies the signature of the current UCAN against the public key of the issuer.
    pub fn verify_principal_alignment(&self, issuer_ucan: SignedUcan<'a, S>) -> UcanResult<()> {
        let our_issuer = self.payload.issuer();
        let their_audience = issuer_ucan.payload.audience();

        // Check if their `aud` field matches our `iss` field
        if our_issuer != their_audience {
            return Err(UcanError::PrincipalAlignmentFailed(
                our_issuer.to_string(),
                their_audience.to_string(),
            ));
        }

        // Check if issuer's key signed our UCAN
        let unsigned_ucan = UnsignedUcan::from_parts(self.header.clone(), self.payload.clone(), ());
        our_issuer
            .public_key()
            .verify(unsigned_ucan.to_string().as_bytes(), self.signature())?;

        Ok(())
    }

    /// TODO: Implement this method.
    pub fn allows<'b>(
        &self,
        _resource: impl TryInto<ResourceUri<'b>>,
        _ability: impl TryInto<Ability>,
    ) -> UcanResult<bool> {
        todo!()
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

impl<'a> FromStr for UnsignedUcan<'a, PlaceholderStore, UcanHeader> {
    type Err = UcanError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();

        if parts.len() != 2 {
            return Err(UcanError::UnableToParse);
        }

        let header = parts[0].parse()?;
        let payload: UcanPayload<PlaceholderStore> = parts[1].parse()?;

        Ok(Self {
            header,
            payload,
            signature: (),
        })
    }
}

impl<'a> FromStr for SignedUcan<'a, PlaceholderStore> {
    type Err = UcanError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();

        if parts.len() != 3 {
            return Err(UcanError::UnableToParse);
        }

        let header = parts[0].parse()?;
        let payload: UcanPayload<PlaceholderStore> = parts[1].parse()?;
        let signature = parts[2].parse()?;

        Ok(Self {
            header,
            payload,
            signature,
        })
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
        let parts = UnsignedUcanSerde {
            header: self.header.clone(),
            payload: self.payload.clone(),
        };

        parts.serialize(serializer)
    }
}

impl<'a> Serialize for SignedUcan<'a, PlaceholderStore> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'a, 'de, H> Deserialize<'de> for UnsignedUcan<'a, PlaceholderStore, H>
where
    H: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Ucan<'a, PlaceholderStore, H>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let parts = UnsignedUcanSerde::deserialize(deserializer)?;

        Ok(Ucan {
            header: parts.header,
            payload: parts.payload,
            signature: (),
        })
    }
}

impl<'a, 'de> Deserialize<'de> for SignedUcan<'a, PlaceholderStore> {
    fn deserialize<D>(deserializer: D) -> Result<SignedUcan<'a, PlaceholderStore>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use zeroutils_key::{Ed25519KeyPair, KeyPairGenerate};

    use crate::caps;

    use super::*;

    #[test_log::test]
    fn test_ucan_serde() -> anyhow::Result<()> {
        // Unsigned UCAN
        let ucan = Ucan::builder()
            .issuer("did:wk:m5wECtxi2kxRme2uhswu46BwzRtqvhEznWKucFrrph0I7+uo")
            .audience("did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti")
            .expiration(UNIX_EPOCH + std::time::Duration::from_secs(3600))
            .not_before(UNIX_EPOCH)
            .nonce("1100263a4012")
            .facts(vec![])
            .capabilities(caps!())
            .proofs(vec![])
            .build();

        let serialized = serde_json::to_string(&ucan)?;
        tracing::debug!(?serialized);
        assert_eq!(
            serialized,
            r#"{"header":null,"payload":{"ucv":"0.10.0-alpha.1","iss":"did:wk:m5wECtxi2kxRme2uhswu46BwzRtqvhEznWKucFrrph0I7+uo","aud":"did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti","exp":3600,"nbf":0,"nnc":"1100263a4012","fct":{},"cap":{}}}"#
        );

        let deserialized: UnsignedUcan<PlaceholderStore> = serde_json::from_str(&serialized)?;
        assert_eq!(deserialized, ucan);

        // Signed UCAN
        let keypair = Ed25519KeyPair::from_private_key(&vec![
            190, 244, 147, 155, 83, 151, 225, 133, 7, 166, 15, 183, 157, 168, 142, 25, 128, 4, 106,
            34, 199, 60, 60, 9, 190, 179, 2, 196, 179, 179, 64, 134,
        ])?;

        let signed_ucan = Ucan::builder()
            .issuer("did:wk:m5wECtxi2kxRme2uhswu46BwzRtqvhEznWKucFrrph0I7+uo")
            .audience("did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti")
            .expiration(UNIX_EPOCH + std::time::Duration::from_secs(3600))
            .not_before(UNIX_EPOCH)
            .nonce("1100263a4012")
            .facts(vec![])
            .capabilities(caps!())
            .proofs(vec![])
            .sign(&keypair)?;

        let serialized = serde_json::to_string(&signed_ucan)?;
        tracing::debug!(?serialized);
        assert_eq!(
            serialized,
            r#""eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ1Y3YiOiIwLjEwLjAtYWxwaGEuMSIsImlzcyI6ImRpZDp3azptNXdFQ3R4aTJreFJtZTJ1aHN3dTQ2Qnd6UnRxdmhFem5XS3VjRnJycGgwSTcrdW8iLCJhdWQiOiJkaWQ6d2s6YjV1YTVsNHdnY3A0NnpydG4zaWhqam11NWdieWh1c215dDViaWFubDVvdjJ5cnZqN3duaDR2dGkiLCJleHAiOjM2MDAsIm5iZiI6MCwibm5jIjoiMTEwMDI2M2E0MDEyIiwiZmN0Ijp7fSwiY2FwIjp7fX0.BS7o33ih64jHkYeWB02gT1PPlqMrbhx1hSzt-197X0sEFffnRT_riiSLLudqp_MhFOA1yO8BPDelrINMPURaCg""#
        );

        let deserialized: SignedUcan<PlaceholderStore> = serde_json::from_str(&serialized)?;
        assert_eq!(deserialized, signed_ucan);

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
            .issuer("did:wk:m5wECtxi2kxRme2uhswu46BwzRtqvhEznWKucFrrph0I7+uo")
            .audience("did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti")
            .expiration(UNIX_EPOCH + std::time::Duration::from_secs(3600))
            .not_before(UNIX_EPOCH)
            .nonce("1100263a4012")
            .facts(vec![])
            .capabilities(caps! {
                "zerofs://public/photos/dogs/": {
                    "entity/read": [{}],
                    "entity/write": [{}],
                },
            })
            .proofs(vec![])
            .sign(&keypair)?;

        let encoded = signed_ucan.to_string();
        tracing::debug!(?encoded);
        assert_eq!(
            encoded,
            "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ1Y3YiOiIwLjEwLjAtYWxwaGEuMSIsImlzcyI6ImRpZDp3azptNXdFQ3R4aTJreFJtZTJ1aHN3dTQ2Qnd6UnRxdmhFem5XS3VjRnJycGgwSTcrdW8iLCJhdWQiOiJkaWQ6d2s6YjV1YTVsNHdnY3A0NnpydG4zaWhqam11NWdieWh1c215dDViaWFubDVvdjJ5cnZqN3duaDR2dGkiLCJleHAiOjM2MDAsIm5iZiI6MCwibm5jIjoiMTEwMDI2M2E0MDEyIiwiZmN0Ijp7fSwiY2FwIjp7Inplcm9mczovL3B1YmxpYy9waG90b3MvZG9ncy8iOnsiZW50aXR5L3JlYWQiOlt7fV0sImVudGl0eS93cml0ZSI6W3t9XX19fQ.EPLDBEGlUi9pmFjahJEepLl1D7fKT8FbZ887SJshzauTWLZ8b9tkfke0_qYK0lOsexd62R3VC7RR9FIR_UYvCg"
        );

        let decoded: SignedUcan<PlaceholderStore> = encoded.parse()?;
        assert_eq!(decoded, signed_ucan);

        // Remove optional fields
        let signed_ucan = Ucan::builder()
            .issuer("did:wk:m5wECtxi2kxRme2uhswu46BwzRtqvhEznWKucFrrph0I7+uo")
            .audience("did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti")
            .expiration(None)
            .capabilities(caps!())
            .sign(&keypair)?;

        let encoded = signed_ucan.to_string();
        tracing::debug!(?encoded);
        assert_eq!(encoded, "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ1Y3YiOiIwLjEwLjAtYWxwaGEuMSIsImlzcyI6ImRpZDp3azptNXdFQ3R4aTJreFJtZTJ1aHN3dTQ2Qnd6UnRxdmhFem5XS3VjRnJycGgwSTcrdW8iLCJhdWQiOiJkaWQ6d2s6YjV1YTVsNHdnY3A0NnpydG4zaWhqam11NWdieWh1c215dDViaWFubDVvdjJ5cnZqN3duaDR2dGkiLCJleHAiOm51bGwsImNhcCI6e319.3vSKJiWMUBf_rXFOqiSG-PoGHZG63fPOqIeCoLKX0IW4cUVPxCw94k6rg6e5lKmWu27XKUt1RYQJXoA91su6BA");

        let decoded: SignedUcan<PlaceholderStore> = encoded.parse()?;
        assert_eq!(decoded, signed_ucan);

        Ok(())
    }
}
