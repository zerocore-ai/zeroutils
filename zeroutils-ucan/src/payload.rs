#![allow(clippy::mutable_key_type)]

use std::{
    collections::BTreeSet,
    fmt::Display,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use libipld::{cid::Version, multihash::Code, Cid};
use serde::{Deserialize, Serialize, Serializer};
use zeroutils_did_wk::WrappedDidWebKey;
use zeroutils_store::{IpldStore, PlaceholderStore};

use crate::{Capabilities, Facts, Proofs, SignedUcan, UcanError, UcanResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Represents the payload part of a UCAN token, which contains all the claims and data necessary for the authorization process.
pub const VERSION: &str = "0.10.0-alpha.1";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents the payload part of a UCAN token, which contains all the claims and data necessary for the authorization process.
#[derive(Debug)]
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
    pub(crate) proofs: Proofs<'a, S>,

    /// The data store used to resolve proof links in the UCAN.
    pub(crate) store: &'a S,
}

//--------------------------------------------------------------------------------------------------
// Types: Serde
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct UcanPayloadSerde<'a> {
    ucv: String,

    iss: String,

    aud: String,

    exp: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    nbf: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    nnc: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    fct: Option<Facts>,

    cap: Capabilities<'a>,

    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    prf: BTreeSet<Cid>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a, S> UcanPayload<'a, S>
where
    S: IpldStore,
{
    /// Changes the store for the UCAN payload.
    pub fn use_store<T>(self, store: &'a T) -> UcanPayload<'a, T>
    where
        T: IpldStore,
    {
        UcanPayload {
            issuer: self.issuer,
            audience: self.audience,
            expiration: self.expiration,
            not_before: self.not_before,
            nonce: self.nonce,
            facts: self.facts,
            capabilities: self.capabilities,
            proofs: self.proofs.use_store(store),
            store,
        }
    }

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
    pub fn proofs(&self) -> &Proofs<'a, S> {
        &self.proofs
    }

    /// Returns the data store used to resolve proof links in the UCAN.
    pub fn store(&self) -> &S {
        self.store
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a, S> UcanPayload<'a, S>
where
    S: IpldStore,
{
    /// Create a new UCAN payload with the given store.
    pub fn with_store(string: impl AsRef<str>, store: &'a S) -> UcanResult<UcanPayload<'a, S>> {
        let ucan = UcanPayload::from_str(string.as_ref())?;
        Ok(ucan.use_store(store))
    }

    /// Checks if the UCAN's time bounds (`exp`, `nbf`) are valid relative to the current time (`now`).
    pub fn validate_time_bounds(&self) -> UcanResult<()> {
        if let (Some(exp), Some(nbf)) = (self.expiration, self.not_before) {
            if exp < nbf {
                return Err(UcanError::InvalidTimeBounds(nbf, exp));
            }
        }

        let now = SystemTime::now();
        if let Some(exp) = self.expiration {
            if now > exp {
                return Err(UcanError::Expired(exp));
            }
        }

        if let Some(nbf) = self.not_before {
            if now < nbf {
                return Err(UcanError::NotYetValid(nbf));
            }
        }

        Ok(())
    }

    /// Fetches the signed UCAN associated with the given CID.
    pub async fn fetch_proof_ucan(&'a mut self, cid: &Cid) -> UcanResult<&'a SignedUcan<'a, S>> {
        self.proofs.fetch_ucan(cid, self.store).await
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'a, S> Serialize for UcanPayload<'a, S>
where
    S: IpldStore,
{
    fn serialize<T>(&self, serializer: T) -> Result<T::Ok, T::Error>
    where
        T: Serializer,
    {
        let serde = UcanPayloadSerde {
            ucv: VERSION.to_string(),
            iss: self.issuer.to_string(),
            aud: self.audience.to_string(),
            exp: self
                .expiration
                .map(|t| t.duration_since(UNIX_EPOCH).unwrap().as_secs()),
            nbf: self
                .not_before
                .map(|t| t.duration_since(UNIX_EPOCH).unwrap().as_secs()),
            nnc: self.nonce.clone(),
            fct: self.facts.clone(),
            cap: self.capabilities.clone(),
            prf: self.proofs.clone().into(),
        };

        serde.serialize(serializer)
    }
}

impl<'a, 'de> Deserialize<'de> for UcanPayload<'a, PlaceholderStore> {
    fn deserialize<D>(deserializer: D) -> Result<UcanPayload<'a, PlaceholderStore>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let payload = UcanPayloadSerde::deserialize(deserializer)?;

        // Check if the UCAN's version is supported.
        if payload.ucv != VERSION {
            return Err(serde::de::Error::custom(UcanError::UnsupportedVersion(
                payload.ucv.to_owned(),
            )));
        }

        // Check if the UCAN's proofs are all valid CIDs. Essentially, this checks that the CIDs are
        // of version `1`, hash function `SHA-256`, and codec `Raw`.
        for cid in &payload.prf {
            let version = cid.version();
            if version != Version::V1 {
                return Err(serde::de::Error::custom(UcanError::InvalidProofCidVersion(
                    version,
                )));
            }

            let hash_code = cid.hash().code();
            if hash_code != u64::from(Code::Sha2_256) {
                return Err(serde::de::Error::custom(UcanError::InvalidProofCidHash(
                    hash_code,
                )));
            }

            let codec = cid.codec();
            if codec != 0x55 {
                return Err(serde::de::Error::custom(UcanError::InvalidProofCidCodec(
                    codec,
                )));
            }
        }

        let issuer = WrappedDidWebKey::from_str(&payload.iss).map_err(serde::de::Error::custom)?;
        let audience =
            WrappedDidWebKey::from_str(&payload.aud).map_err(serde::de::Error::custom)?;

        // `did:wk` with locator component not supported for issuer
        if issuer.locator_component().is_some() {
            return Err(serde::de::Error::custom(
                UcanError::UnsupportedDidWkLocator(issuer.to_string()),
            ));
        }

        // `did:wk` with locator component not supported for audience
        if audience.locator_component().is_some() {
            return Err(serde::de::Error::custom(
                UcanError::UnsupportedDidWkLocator(audience.to_string()),
            ));
        }

        Ok(UcanPayload {
            issuer,
            audience,
            expiration: payload.exp.map(|d| UNIX_EPOCH + Duration::from_secs(d)),
            not_before: payload.nbf.map(|d| UNIX_EPOCH + Duration::from_secs(d)),
            nonce: payload.nnc,
            facts: payload.fct,
            capabilities: payload.cap,
            proofs: payload.prf.into_iter().collect(),
            store: &PlaceholderStore,
        })
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

impl<'a> FromStr for UcanPayload<'a, PlaceholderStore> {
    type Err = UcanError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(s.as_bytes())?;
        serde_json::from_slice(&decoded).map_err(UcanError::from)
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
            store: self.store,
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
            store: &PlaceholderStore,
        };

        let serialized = serde_json::to_string(&payload)?;
        tracing::debug!(?serialized);
        assert_eq!(
            serialized,
            r#"{"ucv":"0.10.0-alpha.1","iss":"did:wk:z6MkktN9TYbYWDPFBhEEZXeD9MyZyUZ2yRNSj5BzDyLBKLkd","aud":"did:wk:m7QEI0Bnl9ShoGr1rc0+TQY64QH5hWC011zNh+CS96kg5Vw","exp":3600,"nbf":0,"nnc":"2b812184","fct":{},"cap":{}}"#,
        );

        let deserialized: UcanPayload<PlaceholderStore> = serde_json::from_str(&serialized)?;
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
            store: &PlaceholderStore,
        };

        let serialized = serde_json::to_string(&payload)?;
        tracing::debug!(?serialized);
        assert_eq!(
            serialized,
            r#"{"ucv":"0.10.0-alpha.1","iss":"did:wk:z6MkktN9TYbYWDPFBhEEZXeD9MyZyUZ2yRNSj5BzDyLBKLkd","aud":"did:wk:m7QEI0Bnl9ShoGr1rc0+TQY64QH5hWC011zNh+CS96kg5Vw","exp":null,"cap":{}}"#
        );

        let deserialized: UcanPayload<PlaceholderStore> = serde_json::from_str(&serialized)?;
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
            store: &PlaceholderStore,
        };

        let displayed = payload.to_string();
        tracing::debug!(?displayed);
        assert_eq!(
            displayed,
            "eyJ1Y3YiOiIwLjEwLjAtYWxwaGEuMSIsImlzcyI6ImRpZDp3azp6Nk1ra3ROOVRZYllXRFBGQmhFRVpYZUQ5TXlaeVVaMnlSTlNqNUJ6RHlMQktMa2QiLCJhdWQiOiJkaWQ6d2s6bTdRRUkwQm5sOVNob0dyMXJjMCtUUVk2NFFINWhXQzAxMXpOaCtDUzk2a2c1VnciLCJleHAiOjM2MDAsIm5iZiI6MCwibm5jIjoiMmI4MTIxODQiLCJmY3QiOnt9LCJjYXAiOnt9fQ"
        );

        let parsed = UcanPayload::from_str(&displayed)?;
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
            store: &PlaceholderStore,
        };

        let displayed = payload.to_string();
        tracing::debug!(?displayed);
        assert_eq!(
            displayed,
            "eyJ1Y3YiOiIwLjEwLjAtYWxwaGEuMSIsImlzcyI6ImRpZDp3azp6Nk1ra3ROOVRZYllXRFBGQmhFRVpYZUQ5TXlaeVVaMnlSTlNqNUJ6RHlMQktMa2QiLCJhdWQiOiJkaWQ6d2s6bTdRRUkwQm5sOVNob0dyMXJjMCtUUVk2NFFINWhXQzAxMXpOaCtDUzk2a2c1VnciLCJleHAiOm51bGwsImNhcCI6e319"
        );

        let parsed = UcanPayload::from_str(&displayed)?;
        assert_eq!(payload, parsed);

        Ok(())
    }
}
