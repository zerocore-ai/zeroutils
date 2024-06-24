#![allow(clippy::mutable_key_type)]

use std::{
    collections::BTreeSet,
    fmt::{Debug, Display},
    marker::PhantomData,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use libipld::{cid::Version, Cid};
use serde::{
    de::{self, DeserializeSeed},
    Deserialize, Deserializer, Serialize, Serializer,
};
use zeroutils_did_wk::WrappedDidWebKey;
use zeroutils_store::IpldStore;

use crate::{Capabilities, Facts, Proofs, UcanError, UcanResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Represents the payload part of a UCAN token, which contains all the claims and data necessary for the authorization process.
pub const VERSION: &str = "0.10.0-alpha.1";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents the payload part of a UCAN token, which contains all the claims and data necessary for the authorization process.
pub struct UcanPayload<'a, S>
where
    S: IpldStore,
{
    /// The DID (Decentralized Identifier) of the issuer who issued the UCAN.
    pub(crate) issuer: WrappedDidWebKey<'a>,

    /// The DID of the audience, which is typically the recipient or verifier of the UCAN.
    pub(crate) audience: WrappedDidWebKey<'a>,

    /// The expiration time of the UCAN, after which it should no longer be considered valid.
    pub(crate) expiration: Option<SystemTime>,

    /// The time before which the UCAN should not be considered valid.
    pub(crate) not_before: Option<SystemTime>,

    /// A nonce used to ensure the uniqueness and to prevent replay attacks.
    pub(crate) nonce: Option<String>,

    /// Additional facts or claims included in the UCAN.
    pub(crate) facts: Option<Facts>,

    /// The capabilities or permissions granted by the UCAN.
    pub(crate) capabilities: Capabilities<'a>,

    /// Proofs or delegations referenced by the UCAN.
    pub(crate) proofs: Proofs<S>,

    /// The data store used to resolve proof links in the UCAN.
    pub(crate) store: S,
}

//--------------------------------------------------------------------------------------------------
// Types: Serde
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UcanPayloadSerializable<'a> {
    pub(crate) ucv: String,

    pub(crate) iss: String,

    pub(crate) aud: String,

    pub(crate) exp: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) nbf: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) nnc: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) fct: Option<Facts>,

    pub(crate) cap: Capabilities<'a>,

    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(crate) prf: BTreeSet<Cid>,
}

pub(crate) struct UcanPayloadDeserializeSeed<'a, S> {
    pub(crate) store: S,
    phantom: PhantomData<&'a ()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a, S> UcanPayload<'a, S>
where
    S: IpldStore,
{
    /// Returns the issuer of the UCAN.
    pub fn issuer(&self) -> &WrappedDidWebKey<'a> {
        &self.issuer
    }

    /// Returns the audience of the UCAN.
    pub fn audience(&self) -> &WrappedDidWebKey<'a> {
        &self.audience
    }

    /// Returns the expiration time of the UCAN.
    pub fn expiration(&self) -> Option<SystemTime> {
        self.expiration
    }

    /// Returns the time before which the UCAN should not be considered valid.
    pub fn not_before(&self) -> Option<SystemTime> {
        self.not_before
    }

    /// Returns the nonce used to ensure the uniqueness and to prevent replay attacks.
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// Returns the additional facts or claims included in the UCAN.
    pub fn facts(&self) -> Option<&Facts> {
        self.facts.as_ref()
    }

    /// Returns the capabilities or permissions granted by the UCAN.
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// Returns the proofs or delegations referenced by the UCAN.
    pub fn proofs(&self) -> &Proofs<S> {
        &self.proofs
    }

    /// Returns the data store used to resolve proof links in the UCAN.
    pub fn store(&self) -> &S {
        &self.store
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a, S> UcanPayload<'a, S>
where
    S: IpldStore,
{
    /// Attempts to create a `UcanPayload` instance by parsing provided Base64 encoded string.
    pub fn try_from_str(string: impl AsRef<str>, store: S) -> UcanResult<Self> {
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(string.as_ref())?;
        Self::deserialize_with(&mut serde_json::Deserializer::from_slice(&decoded), store)
    }

    /// Checks if the UCAN's time bounds (`exp`, `nbf`) are valid relative to the current time (`now`).
    pub fn validate_time_bounds(&self) -> UcanResult<()> {
        if self.expiration < self.not_before {
            return Err(UcanError::InvalidTimeBounds(
                self.not_before,
                self.expiration,
            ));
        }

        let now = SystemTime::now();
        if self.expiration.map_or(false, |t| t < now) {
            return Err(UcanError::Expired(self.expiration));
        }

        if self.not_before.map_or(false, |t| t > now) {
            return Err(UcanError::NotYetValid(self.not_before));
        }

        Ok(())
    }

    /// Deserializes to a 'UcanPayload' using an arbitrary deserializer and store.
    pub fn deserialize_with<'de>(
        deserializer: impl Deserializer<'de, Error: Into<UcanError>>,
        store: S,
    ) -> UcanResult<Self> {
        UcanPayloadDeserializeSeed::new(store)
            .deserialize(deserializer)
            .map_err(Into::into)
    }

    pub(crate) fn try_from_serializable(
        serializable: UcanPayloadSerializable,
        store: S,
    ) -> UcanResult<UcanPayload<S>> {
        // Check if the UCAN's version is supported.
        if serializable.ucv != VERSION {
            return Err(UcanError::UnsupportedVersion(serializable.ucv.to_owned()));
        }

        // Check if the UCAN's proofs are all canonical CIDs. Essentially, this checks that the CIDs are
        // of version `1`, hash function `SHA-256`, and codec `Raw`.
        for cid in serializable.prf.iter() {
            let version = cid.version();
            if version != Version::V1 {
                return Err(UcanError::InvalidProofCidVersion(version));
            }

            // TODO: Add back support when IpldStore supports specifying hash method.
            // let hash_code = cid.hash().code();
            // if hash_code != u64::from(Code::Sha2_256) {
            //     return Err(serde::de::Error::custom(UcanError::InvalidProofCidHash(
            //         hash_code,
            //     )));
            // }

            let codec = cid.codec();
            if codec != 0x55 {
                return Err(UcanError::InvalidProofCidCodec(codec));
            }
        }

        let issuer = WrappedDidWebKey::from_str(&serializable.iss).map_err(UcanError::from)?;
        let audience = WrappedDidWebKey::from_str(&serializable.aud).map_err(UcanError::from)?;

        // `did:wk` with locator component not supported for issuer
        if issuer.locator_component().is_some() {
            return Err(UcanError::UnsupportedDidWkLocator(issuer.to_string()));
        }

        // `did:wk` with locator component not supported for audience
        if audience.locator_component().is_some() {
            return Err(UcanError::UnsupportedDidWkLocator(audience.to_string()));
        }

        Ok(UcanPayload {
            issuer,
            audience,
            expiration: serializable
                .exp
                .map(|d| UNIX_EPOCH + Duration::from_secs(d)),
            not_before: serializable
                .nbf
                .map(|d| UNIX_EPOCH + Duration::from_secs(d)),
            nonce: serializable.nnc,
            facts: serializable.fct,
            capabilities: serializable.cap,
            proofs: serializable.prf.into_iter().collect(),
            store,
        })
    }
}

impl<'a, S> UcanPayloadDeserializeSeed<'a, S> {
    pub(crate) fn new(store: S) -> Self {
        Self {
            store,
            phantom: PhantomData,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'a, S> From<&UcanPayload<'a, S>> for UcanPayloadSerializable<'a>
where
    S: IpldStore,
{
    fn from(value: &UcanPayload<'a, S>) -> Self {
        UcanPayloadSerializable {
            ucv: VERSION.to_string(),
            iss: value.issuer.to_string(),
            aud: value.audience.to_string(),
            exp: value
                .expiration
                .map(|t| t.duration_since(UNIX_EPOCH).unwrap().as_secs()),
            nbf: value
                .not_before
                .map(|t| t.duration_since(UNIX_EPOCH).unwrap().as_secs()),
            nnc: value.nonce.clone(),
            fct: value.facts.clone(),
            cap: value.capabilities.clone(),
            prf: value.proofs.iter().map(|prf| *prf.cid()).collect(),
        }
    }
}

impl<'a, S> Serialize for UcanPayload<'a, S>
where
    S: IpldStore,
{
    fn serialize<T>(&self, serializer: T) -> Result<T::Ok, T::Error>
    where
        T: Serializer,
    {
        UcanPayloadSerializable::from(self).serialize(serializer)
    }
}

impl<'a, 'de, S> DeserializeSeed<'de> for UcanPayloadDeserializeSeed<'a, S>
where
    S: IpldStore,
{
    type Value = UcanPayload<'a, S>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let payload = UcanPayloadSerializable::deserialize(deserializer)?;
        UcanPayload::try_from_serializable(payload, self.store).map_err(de::Error::custom)
    }
}

impl<'a, S> Display for UcanPayload<'a, S>
where
    S: IpldStore,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(json.as_bytes());
        write!(f, "{}", encoded)
    }
}

impl<'a, S> Clone for UcanPayload<'a, S>
where
    S: IpldStore,
{
    fn clone(&self) -> Self {
        Self {
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            expiration: self.expiration,
            not_before: self.not_before,
            nonce: self.nonce.clone(),
            facts: self.facts.clone(),
            capabilities: self.capabilities.clone(),
            proofs: self.proofs.clone(),
            store: self.store.clone(),
        }
    }
}

impl<'a, S> PartialEq for UcanPayload<'a, S>
where
    S: IpldStore,
{
    fn eq(&self, other: &Self) -> bool {
        self.issuer == other.issuer
            && self.audience == other.audience
            && self
                .expiration
                .map(|t| t.duration_since(UNIX_EPOCH).unwrap().as_secs())
                == other
                    .expiration
                    .map(|t| t.duration_since(UNIX_EPOCH).unwrap().as_secs())
            && self.not_before == other.not_before
            && self.nonce == other.nonce
            && self.facts == other.facts
            && self.capabilities == other.capabilities
            && self.proofs == other.proofs
    }
}

impl<'a, S> Debug for UcanPayload<'a, S>
where
    S: IpldStore,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UcanPayload")
            .field("issuer", &self.issuer.to_string())
            .field("audience", &self.audience.to_string())
            .field("expiration", &self.expiration)
            .field("not_before", &self.not_before)
            .field("nonce", &self.nonce)
            .field("facts", &self.facts)
            .field("capabilities", &self.capabilities)
            .field("proofs", &self.proofs)
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use zeroutils_store::PlaceholderStore;

    use super::*;
    use std::{str::FromStr, time::Duration};

    #[test_log::test]
    fn test_payload_serde() -> anyhow::Result<()> {
        let issuer =
            WrappedDidWebKey::from_str("did:wk:z6MkktN9TYbYWDPFBhEEZXeD9MyZyUZ2yRNSj5BzDyLBKLkd")?;
        let audience =
            WrappedDidWebKey::from_str("did:wk:m7QEI0Bnl9ShoGr1rc0+TQY64QH5hWC011zNh+CS96kg5Vw")?;

        let expiration = Some(UNIX_EPOCH + Duration::from_secs(3600));
        let not_before = Some(UNIX_EPOCH);
        let nonce = Some("2b812184".to_string());
        let facts = Some(Facts::default());
        let capabilities = Capabilities::default();
        let proofs = Proofs::default();

        let payload = UcanPayload {
            issuer,
            audience,
            expiration,
            not_before,
            nonce,
            facts,
            capabilities,
            proofs,
            store: PlaceholderStore,
        };

        let serialized = serde_json::to_string(&payload)?;
        tracing::debug!(?serialized);
        assert_eq!(
            serialized,
            r#"{"ucv":"0.10.0-alpha.1","iss":"did:wk:z6MkktN9TYbYWDPFBhEEZXeD9MyZyUZ2yRNSj5BzDyLBKLkd","aud":"did:wk:m7QEI0Bnl9ShoGr1rc0+TQY64QH5hWC011zNh+CS96kg5Vw","exp":3600,"nbf":0,"nnc":"2b812184","fct":{},"cap":{}}"#,
        );

        let deserialized = UcanPayload::deserialize_with(
            &mut serde_json::Deserializer::from_str(&serialized),
            PlaceholderStore,
        )?;

        assert_eq!(payload, deserialized);

        // Remove optional fields
        let issuer =
            WrappedDidWebKey::from_str("did:wk:z6MkktN9TYbYWDPFBhEEZXeD9MyZyUZ2yRNSj5BzDyLBKLkd")?;
        let audience =
            WrappedDidWebKey::from_str("did:wk:m7QEI0Bnl9ShoGr1rc0+TQY64QH5hWC011zNh+CS96kg5Vw")?;
        let capabilities = Capabilities::default();

        let payload = UcanPayload {
            issuer,
            audience,
            expiration: None,
            not_before: None,
            nonce: None,
            facts: None,
            capabilities,
            proofs: Proofs::default(),
            store: PlaceholderStore,
        };

        let serialized = serde_json::to_string(&payload)?;
        tracing::debug!(?serialized);
        assert_eq!(
            serialized,
            r#"{"ucv":"0.10.0-alpha.1","iss":"did:wk:z6MkktN9TYbYWDPFBhEEZXeD9MyZyUZ2yRNSj5BzDyLBKLkd","aud":"did:wk:m7QEI0Bnl9ShoGr1rc0+TQY64QH5hWC011zNh+CS96kg5Vw","exp":null,"cap":{}}"#
        );

        let deserialized = UcanPayload::deserialize_with(
            &mut serde_json::Deserializer::from_str(&serialized),
            PlaceholderStore,
        )?;

        assert_eq!(payload, deserialized);

        Ok(())
    }

    #[test_log::test]
    fn test_payload_display() -> anyhow::Result<()> {
        let issuer =
            WrappedDidWebKey::from_str("did:wk:z6MkktN9TYbYWDPFBhEEZXeD9MyZyUZ2yRNSj5BzDyLBKLkd")?;
        let audience =
            WrappedDidWebKey::from_str("did:wk:m7QEI0Bnl9ShoGr1rc0+TQY64QH5hWC011zNh+CS96kg5Vw")?;
        let expiration = Some(UNIX_EPOCH + Duration::from_secs(3600));
        let not_before = Some(UNIX_EPOCH);
        let nonce = Some("2b812184".to_string());
        let facts = Some(Facts::default());
        let capabilities = Capabilities::default();
        let proofs = Proofs::default();

        let payload = UcanPayload {
            issuer,
            audience,
            expiration,
            not_before,
            nonce,
            facts,
            capabilities,
            proofs,
            store: PlaceholderStore,
        };

        let displayed = payload.to_string();
        tracing::debug!(?displayed);
        assert_eq!(
            displayed,
            "eyJ1Y3YiOiIwLjEwLjAtYWxwaGEuMSIsImlzcyI6ImRpZDp3azp6Nk1ra3ROOVRZYllXRFBGQmhFRVpYZUQ5TXlaeVVaMnlSTlNqNUJ6RHlMQktMa2QiLCJhdWQiOiJkaWQ6d2s6bTdRRUkwQm5sOVNob0dyMXJjMCtUUVk2NFFINWhXQzAxMXpOaCtDUzk2a2c1VnciLCJleHAiOjM2MDAsIm5iZiI6MCwibm5jIjoiMmI4MTIxODQiLCJmY3QiOnt9LCJjYXAiOnt9fQ"
        );

        let parsed = UcanPayload::try_from_str(&displayed, PlaceholderStore)?;
        assert_eq!(payload, parsed);

        // Remove optional fields
        let issuer =
            WrappedDidWebKey::from_str("did:wk:z6MkktN9TYbYWDPFBhEEZXeD9MyZyUZ2yRNSj5BzDyLBKLkd")?;
        let audience =
            WrappedDidWebKey::from_str("did:wk:m7QEI0Bnl9ShoGr1rc0+TQY64QH5hWC011zNh+CS96kg5Vw")?;
        let capabilities = Capabilities::default();

        let payload = UcanPayload {
            issuer,
            audience,
            expiration: None,
            not_before: None,
            nonce: None,
            facts: None,
            capabilities,
            proofs: Proofs::default(),
            store: PlaceholderStore,
        };

        let displayed = payload.to_string();
        tracing::debug!(?displayed);
        assert_eq!(
            displayed,
            "eyJ1Y3YiOiIwLjEwLjAtYWxwaGEuMSIsImlzcyI6ImRpZDp3azp6Nk1ra3ROOVRZYllXRFBGQmhFRVpYZUQ5TXlaeVVaMnlSTlNqNUJ6RHlMQktMa2QiLCJhdWQiOiJkaWQ6d2s6bTdRRUkwQm5sOVNob0dyMXJjMCtUUVk2NFFINWhXQzAxMXpOaCtDUzk2a2c1VnciLCJleHAiOm51bGwsImNhcCI6e319"
        );

        let parsed = UcanPayload::try_from_str(&displayed, PlaceholderStore)?;
        assert_eq!(payload, parsed);

        Ok(())
    }
}
