use std::time::SystemTime;

use libipld::Cid;
use serde_json::Value;
use zeroutils_did_wk::DidWebKeyType;
use zeroutils_key::{JwsAlgName, Sign};
use zeroutils_store::{IpldStore, PlaceholderStore};

use crate::{
    SignedUcan, Ucan, UcanAbilities, UcanCapabilities, UcanFacts, UcanPayload, UcanProofs,
    UcanResult, Uri,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A builder for creating UCAN (User-Controlled Authorization Network) tokens.
pub struct UcanBuilder<I = (), A = (), E = (), C = (), S = PlaceholderStore> {
    issuer: I,
    audience: A,
    expiration: E,
    not_before: Option<SystemTime>,
    nonce: Option<String>,
    facts: Option<UcanFacts>,
    capabilities: C,
    proofs: UcanProofs,
    store: S,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<I, A, E, C, S> UcanBuilder<I, A, E, C, S> {
    /// Sets the issuer of the UCAN.
    pub fn issuer<'a>(
        self,
        issuer: impl Into<DidWebKeyType<'a>>,
    ) -> UcanBuilder<DidWebKeyType<'a>, A, E, C, S> {
        UcanBuilder {
            issuer: issuer.into(),
            audience: self.audience,
            expiration: self.expiration,
            not_before: self.not_before,
            nonce: self.nonce,
            facts: self.facts,
            capabilities: self.capabilities,
            proofs: self.proofs,
            store: self.store,
        }
    }

    /// Sets the audience (recipient) of the UCAN.
    pub fn audience<'a>(
        self,
        audience: impl Into<DidWebKeyType<'a>>,
    ) -> UcanBuilder<I, DidWebKeyType<'a>, E, C, S> {
        UcanBuilder {
            issuer: self.issuer,
            audience: audience.into(),
            expiration: self.expiration,
            not_before: self.not_before,
            nonce: self.nonce,
            facts: self.facts,
            capabilities: self.capabilities,
            proofs: self.proofs,
            store: self.store,
        }
    }

    /// Sets the expiration time of the UCAN.
    pub fn expiration(
        self,
        expiration: Option<SystemTime>,
    ) -> UcanBuilder<I, A, Option<SystemTime>, C, S> {
        UcanBuilder {
            issuer: self.issuer,
            audience: self.audience,
            expiration,
            not_before: self.not_before,
            nonce: self.nonce,
            facts: self.facts,
            capabilities: self.capabilities,
            proofs: self.proofs,
            store: self.store,
        }
    }

    /// Sets the time before which the UCAN is not valid.
    pub fn not_before(mut self, not_before: impl Into<SystemTime>) -> Self {
        self.not_before = Some(not_before.into());
        self
    }

    /// Sets a nonce to prevent replay attacks.
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Adds facts (claims) to the UCAN.
    pub fn facts(mut self, facts: impl IntoIterator<Item = (String, Value)>) -> Self {
        self.facts = Some(facts.into_iter().collect());
        self
    }

    /// Adds proofs or delegations to the UCAN.
    pub fn proofs(mut self, proofs: impl IntoIterator<Item = Cid>) -> Self {
        self.proofs = proofs.into_iter().collect();
        self
    }

    /// Sets the capabilities or permissions granted by the UCAN.
    pub fn capabilities(
        self,
        capabilities: impl IntoIterator<Item = (Uri, UcanAbilities)>,
    ) -> UcanBuilder<I, A, E, UcanCapabilities, S> {
        UcanBuilder {
            issuer: self.issuer,
            audience: self.audience,
            expiration: self.expiration,
            not_before: self.not_before,
            nonce: self.nonce,
            facts: self.facts,
            capabilities: capabilities.into_iter().collect(),
            proofs: self.proofs,
            store: self.store,
        }
    }

    /// Changes the store used for handling IPLD data.
    pub fn store<T>(self, store: T) -> UcanBuilder<I, A, E, C, T>
    where
        T: IpldStore,
    {
        UcanBuilder {
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

impl<'a, I>
    UcanBuilder<DidWebKeyType<'a>, DidWebKeyType<'a>, Option<SystemTime>, UcanCapabilities, I>
where
    I: IpldStore,
{
    /// Builds a UCAN from the specified components.
    pub fn build(self) -> Ucan<'a, I, ()> {
        // TODO: Verify times are not stale and other necessary fields
        let payload = UcanPayload {
            issuer: self.issuer,
            audience: self.audience,
            expiration: self.expiration,
            not_before: self.not_before,
            nonce: self.nonce,
            facts: self.facts,
            capabilities: self.capabilities,
            proofs: self.proofs,
            store: self.store,
        };

        Ucan::from_parts((), payload, ())
    }

    /// Signs the built UCAN with a given keypair.
    pub fn sign<K>(self, keypair: &K) -> UcanResult<SignedUcan<'a, I>>
    where
        K: Sign + JwsAlgName,
    {
        let ucan = self.build().use_alg(keypair.alg());
        let encoded = ucan.to_string();
        let signature = keypair.sign(encoded.as_bytes())?;

        Ok(Ucan {
            payload: ucan.payload,
            header: ucan.header,
            signature: signature.into(),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for UcanBuilder<(), (), (), (), PlaceholderStore> {
    fn default() -> Self {
        UcanBuilder {
            issuer: (),
            audience: (),
            expiration: (),
            not_before: None,
            nonce: None,
            facts: None,
            capabilities: (),
            proofs: UcanProofs::default(),
            store: PlaceholderStore,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use anyhow::Ok;
    use zeroutils_store::PlaceholderStore;

    use super::*;

    #[test]
    fn test_ucan_builder() -> anyhow::Result<()> {
        let now = SystemTime::now();

        let ucan = UcanBuilder::default()
            .issuer("did:wk:b44aqepqvrvaix2aosv2oluhoa3kf7yan6xevmn2asn3scuev2iydukkv")
            .audience("did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti")
            .expiration(Some(now + Duration::from_secs(360_000)))
            .not_before(now)
            .nonce("1100263a4012")
            .facts(vec![])
            .capabilities(vec![])
            .proofs(vec![])
            .store(PlaceholderStore)
            .build();

        assert_eq!(
            ucan.payload.issuer,
            DidWebKeyType::from_str(
                "did:wk:b44aqepqvrvaix2aosv2oluhoa3kf7yan6xevmn2asn3scuev2iydukkv"
            )?
        );
        assert_eq!(
            ucan.payload.audience,
            DidWebKeyType::from_str(
                "did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti"
            )?
        );
        assert_eq!(
            ucan.payload.expiration,
            Some(now + Duration::from_secs(360_000))
        );
        assert_eq!(ucan.payload.not_before, Some(now));
        assert_eq!(ucan.payload.nonce, Some("1100263a4012".to_string()));
        assert_eq!(ucan.payload.facts, Some(UcanFacts::default()));
        assert_eq!(ucan.payload.capabilities, UcanCapabilities::default());
        assert_eq!(ucan.payload.proofs, UcanProofs::default());
        assert_eq!(ucan.payload.store, PlaceholderStore);

        Ok(())
    }
}
