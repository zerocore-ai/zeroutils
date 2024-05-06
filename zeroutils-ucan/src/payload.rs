#![allow(clippy::mutable_key_type)]

use std::{
    fmt::Display,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, Serializer};
use zeroutils_did_wk::DidWebKeyType;
use zeroutils_store::{IpldStore, PlaceholderStore};

use crate::{UcanCapabilities, UcanError, UcanFacts, UcanProofs};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Represents the payload part of a UCAN token, which contains all the claims and data necessary for the authorization process.
pub const VERSION: &str = "0.10.0-alpha.1";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents the payload part of a UCAN token, which contains all the claims and data necessary for the authorization process.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UcanPayload<'a, I>
where
    I: IpldStore,
{
    /// The DID (Decentralized Identifier) of the issuer who issued the UCAN.
    pub(crate) issuer: DidWebKeyType<'a>,

    /// The DID of the audience, which is typically the recipient or verifier of the UCAN.
    pub(crate) audience: DidWebKeyType<'a>,

    /// The expiration time of the UCAN, after which it should no longer be considered valid.
    pub(crate) expiration: Option<SystemTime>,

    /// The time before which the UCAN should not be considered valid.
    pub(crate) not_before: Option<SystemTime>,

    /// A nonce used to ensure the uniqueness and to prevent replay attacks.
    pub(crate) nonce: Option<String>,

    /// Additional facts or claims included in the UCAN.
    pub(crate) facts: Option<UcanFacts>,

    /// The capabilities or permissions granted by the UCAN.
    pub(crate) capabilities: UcanCapabilities,

    /// Proofs or delegations referenced by the UCAN.
    pub(crate) proofs: UcanProofs,

    /// The data store used to resolve proof links in the UCAN.
    pub(crate) store: I,
}

//--------------------------------------------------------------------------------------------------
// Types: Serde
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct UcanPayloadSerde {
    #[serde(skip_deserializing)]
    ucv: &'static str,

    iss: String,

    aud: String,

    exp: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    nbf: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    nnc: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    fct: Option<UcanFacts>,

    #[serde(rename = "cap")]
    cap: UcanCapabilities,

    #[serde(default, skip_serializing_if = "UcanProofs::is_empty")]
    prf: UcanProofs,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a, I> UcanPayload<'a, I>
where
    I: IpldStore,
{
    /// Allows changing the data store for the UCAN payload.
    pub fn use_store<S>(self, store: S) -> UcanPayload<'a, S>
    where
        S: IpldStore,
    {
        UcanPayload {
            issuer: self.issuer,
            audience: self.audience,
            expiration: self.expiration,
            not_before: self.not_before,
            nonce: self.nonce,
            facts: self.facts,
            capabilities: self.capabilities,
            proofs: self.proofs,
            store,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'a, I> Serialize for UcanPayload<'a, I>
where
    I: IpldStore,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serde = UcanPayloadSerde {
            ucv: VERSION,
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
            prf: self.proofs.clone(),
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

        Ok(UcanPayload {
            issuer: payload.iss.parse().map_err(serde::de::Error::custom)?,
            audience: payload.aud.parse().map_err(serde::de::Error::custom)?,
            expiration: payload.exp.map(|d| UNIX_EPOCH + Duration::from_secs(d)),
            not_before: payload.nbf.map(|d| UNIX_EPOCH + Duration::from_secs(d)),
            nonce: payload.nnc,
            facts: payload.fct,
            capabilities: payload.cap,
            proofs: payload.prf,
            store: PlaceholderStore,
        })
    }
}

impl<'a, I> Display for UcanPayload<'a, I>
where
    I: IpldStore,
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
            DidWebKeyType::from_str("did:wk:z6MkktN9TYbYWDPFBhEEZXeD9MyZyUZ2yRNSj5BzDyLBKLkd")?;
        let audience =
            DidWebKeyType::from_str("did:wk:m7QEI0Bnl9ShoGr1rc0+TQY64QH5hWC011zNh+CS96kg5Vw")?;

        let expiration = Some(UNIX_EPOCH + Duration::from_secs(3600));
        let not_before = Some(UNIX_EPOCH);
        let nonce = Some("2b812184".to_string());
        let facts = Some(UcanFacts::default());
        let capabilities = UcanCapabilities::default();
        let proofs = UcanProofs::default();

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

        let deserialized: UcanPayload<PlaceholderStore> = serde_json::from_str(&serialized)?;
        assert_eq!(payload, deserialized);

        // Remove optional fields
        let issuer =
            DidWebKeyType::from_str("did:wk:z6MkktN9TYbYWDPFBhEEZXeD9MyZyUZ2yRNSj5BzDyLBKLkd")?;
        let audience =
            DidWebKeyType::from_str("did:wk:m7QEI0Bnl9ShoGr1rc0+TQY64QH5hWC011zNh+CS96kg5Vw")?;
        let capabilities = UcanCapabilities::default();

        let payload = UcanPayload {
            issuer,
            audience,
            expiration: None,
            not_before: None,
            nonce: None,
            facts: None,
            capabilities,
            proofs: UcanProofs::default(),
            store: PlaceholderStore,
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
            DidWebKeyType::from_str("did:wk:z6MkktN9TYbYWDPFBhEEZXeD9MyZyUZ2yRNSj5BzDyLBKLkd")?;
        let audience =
            DidWebKeyType::from_str("did:wk:m7QEI0Bnl9ShoGr1rc0+TQY64QH5hWC011zNh+CS96kg5Vw")?;
        let expiration = Some(UNIX_EPOCH + Duration::from_secs(3600));
        let not_before = Some(UNIX_EPOCH);
        let nonce = Some("2b812184".to_string());
        let facts = Some(UcanFacts::default());
        let capabilities = UcanCapabilities::default();
        let proofs = UcanProofs::default();

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

        let parsed = UcanPayload::from_str(&displayed)?;
        assert_eq!(payload, parsed);

        // Remove optional fields
        let issuer =
            DidWebKeyType::from_str("did:wk:z6MkktN9TYbYWDPFBhEEZXeD9MyZyUZ2yRNSj5BzDyLBKLkd")?;
        let audience =
            DidWebKeyType::from_str("did:wk:m7QEI0Bnl9ShoGr1rc0+TQY64QH5hWC011zNh+CS96kg5Vw")?;
        let capabilities = UcanCapabilities::default();

        let payload = UcanPayload {
            issuer,
            audience,
            expiration: None,
            not_before: None,
            nonce: None,
            facts: None,
            capabilities,
            proofs: UcanProofs::default(),
            store: PlaceholderStore,
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
