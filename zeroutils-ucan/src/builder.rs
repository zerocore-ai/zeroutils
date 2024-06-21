use std::time::SystemTime;

use libipld::Cid;
use serde_json::Value;
use zeroutils_did_wk::{Base, WrappedDidWebKey};
use zeroutils_key::{GetPublicKey, IntoOwned, JwsAlgName, Sign};
use zeroutils_store::IpldStore;

use crate::{Capabilities, Facts, Proofs, SignedUcan, Ucan, UcanPayload, UcanResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A builder for creating UCAN (User-Controlled Authorization Network) tokens.
pub struct UcanBuilder<I = (), A = (), E = (), C = (), P = (), S = ()> {
    issuer: I,
    audience: A,
    expiration: E,
    not_before: Option<SystemTime>,
    nonce: Option<String>,
    facts: Option<Facts>,
    capabilities: C,
    proofs: P,
    store: S,
}

/// A builder for creating UCAN (User-Controlled Authorization Network) tokens.
pub type DefaultUcanBuilder = UcanBuilder<(), (), (), (), (), ()>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<I, A, E, C, P, S> UcanBuilder<I, A, E, C, P, S> {
    /// Sets the issuer of the UCAN.
    ///
    /// This can be omitted from the builder call chain if `.sign` is called as the issuer will be
    /// derived from the keypair.
    pub fn issuer<'b>(
        self,
        issuer: impl Into<WrappedDidWebKey<'b>>,
    ) -> UcanBuilder<WrappedDidWebKey<'b>, A, E, C, P, S> {
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
    pub fn audience<'b>(
        self,
        audience: impl Into<WrappedDidWebKey<'b>>,
    ) -> UcanBuilder<I, WrappedDidWebKey<'b>, E, C, P, S> {
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
        expiration: impl Into<Option<SystemTime>>,
    ) -> UcanBuilder<I, A, Option<SystemTime>, C, P, S> {
        UcanBuilder {
            issuer: self.issuer,
            audience: self.audience,
            expiration: expiration.into(),
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

    /// Changes the store used for handling IPLD data.
    pub fn store<T>(self, store: T) -> UcanBuilder<I, A, E, C, Proofs<T>, T>
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
            proofs: Proofs::<T>::new(),
            store,
        }
    }

    /// Sets the capabilities or permissions granted by the UCAN.
    pub fn capabilities(
        self,
        capabilities: Capabilities,
    ) -> UcanBuilder<I, A, E, Capabilities, P, S> {
        UcanBuilder {
            issuer: self.issuer,
            audience: self.audience,
            expiration: self.expiration,
            not_before: self.not_before,
            nonce: self.nonce,
            facts: self.facts,
            capabilities,
            proofs: self.proofs,
            store: self.store,
        }
    }
}

impl<I, A, E, C, P, S> UcanBuilder<I, A, E, C, P, S>
where
    S: IpldStore,
{
    /// Adds proofs or delegations to the UCAN.
    pub fn proofs(
        self,
        proofs: impl IntoIterator<Item = Cid>,
    ) -> UcanBuilder<I, A, E, C, Proofs<S>, S> {
        UcanBuilder {
            issuer: self.issuer,
            audience: self.audience,
            expiration: self.expiration,
            not_before: self.not_before,
            nonce: self.nonce,
            facts: self.facts,
            capabilities: self.capabilities,
            proofs: proofs.into_iter().collect(),
            store: self.store,
        }
    }
}

impl<'a, S>
    UcanBuilder<
        WrappedDidWebKey<'a>,
        WrappedDidWebKey<'a>,
        Option<SystemTime>,
        Capabilities<'a>,
        Proofs<S>,
        S,
    >
where
    S: IpldStore,
{
    /// Builds a UCAN from the specified components.
    pub fn build(self) -> Ucan<'a, S, ()> {
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
}

impl<'a, S>
    UcanBuilder<(), WrappedDidWebKey<'a>, Option<SystemTime>, Capabilities<'a>, Proofs<S>, S>
where
    S: IpldStore,
{
    /// Signs the built UCAN with a given keypair.
    pub fn sign<K>(self, keypair: &K) -> UcanResult<SignedUcan<'a, S>>
    where
        K: Sign + JwsAlgName + GetPublicKey + IntoOwned,
    {
        let issuer_did = WrappedDidWebKey::from_key(keypair, Base::Base58Btc)?;
        self.issuer(issuer_did)
            .build()
            .use_alg(keypair.alg())
            .sign(keypair)
    }
}

impl<'a, S>
    UcanBuilder<
        WrappedDidWebKey<'a>,
        WrappedDidWebKey<'a>,
        Option<SystemTime>,
        Capabilities<'a>,
        Proofs<S>,
        S,
    >
where
    S: IpldStore,
{
    /// Signs the built UCAN with a given keypair.
    pub fn sign<K>(self, keypair: &K) -> UcanResult<SignedUcan<'a, S>>
    where
        K: Sign + JwsAlgName + GetPublicKey,
    {
        self.build().sign(keypair)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for UcanBuilder<(), (), (), (), (), ()> {
    fn default() -> Self {
        UcanBuilder {
            issuer: (),
            audience: (),
            expiration: (),
            not_before: None,
            nonce: None,
            facts: None,
            capabilities: (),
            proofs: (),
            store: (),
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
    use zeroutils_key::{Ed25519KeyPair, KeyPairGenerate};
    use zeroutils_store::PlaceholderStore;

    use crate::caps;

    use super::*;

    #[test]
    fn test_ucan_builder() -> anyhow::Result<()> {
        let now = SystemTime::now();

        let ucan = UcanBuilder::default()
            .store(PlaceholderStore)
            .issuer("did:wk:b44aqepqvrvaix2aosv2oluhoa3kf7yan6xevmn2asn3scuev2iydukkv")
            .audience("did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti")
            .expiration(now + Duration::from_secs(360_000))
            .not_before(now)
            .nonce("1100263a4012")
            .facts(vec![])
            .capabilities(caps!()?)
            .proofs(vec![])
            .build();

        assert_eq!(
            ucan.payload.issuer,
            WrappedDidWebKey::from_str(
                "did:wk:b44aqepqvrvaix2aosv2oluhoa3kf7yan6xevmn2asn3scuev2iydukkv"
            )?
        );
        assert_eq!(
            ucan.payload.audience,
            WrappedDidWebKey::from_str(
                "did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti"
            )?
        );
        assert_eq!(
            ucan.payload.expiration,
            Some(now + Duration::from_secs(360_000))
        );
        assert_eq!(ucan.payload.not_before, Some(now));
        assert_eq!(ucan.payload.nonce, Some("1100263a4012".to_string()));
        assert_eq!(ucan.payload.facts, Some(Facts::default()));
        assert_eq!(ucan.payload.capabilities, Capabilities::default());
        assert_eq!(ucan.payload.proofs, Proofs::default());
        assert_eq!(ucan.payload.store, PlaceholderStore);

        // Sign the UCAN
        let keypair = Ed25519KeyPair::generate(&mut rand::thread_rng())?;
        let did = WrappedDidWebKey::from_key(&keypair, Base::Base58Btc)?;

        let ucan = UcanBuilder::default()
            .store(PlaceholderStore)
            .issuer(did)
            .audience("did:wk:b5ua5l4wgcp46zrtn3ihjjmu5gbyhusmyt5bianl5ov2yrvj7wnh4vti")
            .expiration(Some(now + Duration::from_secs(360_000)))
            .not_before(now)
            .nonce("1100263a4012")
            .facts(vec![])
            .capabilities(caps!()?)
            .proofs(vec![])
            .sign(&keypair)?;

        assert!(ucan.validate().is_ok());

        Ok(())
    }
}
