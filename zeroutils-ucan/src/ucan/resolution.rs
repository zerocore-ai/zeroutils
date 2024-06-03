#![allow(unused)] // TODO
use either::Either;
use libipld::Cid;
use zeroutils_did_wk::WrappedDidWebKey;
use zeroutils_store::IpldStore;

use crate::{
    Abilities, Ability, Caveats, OtherUri, ProofReference, ResourceUri, Scheme, SignedUcan,
    UcanResult,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type CapabilityTuple<'a> = (OtherUri, Ability, Caveats);

type MappedCapability<'a> = Either<UnresolvedCapability<'a>, ResolvedCapability<'a>>;

type Trace = Vec<Cid>;

/// Represents a singular or collection of capabilities that have not been resolved to its final form.
enum UnresolvedCapability<'a> {
    /// Represents the capabilities of current UCAN with a specific CID in the `prf` section.
    ///
    /// This is what `ucan:<cid>` and `ucan:./*` get converted to.
    UcanWithCid(Option<Cid>, Option<Abilities>),

    /// Represents the capabilities of any UCAN with a specific audience DID.
    /// This type eventually gets converted to `CapWithRootIss`.
    ///
    /// This is what `ucan://<did>/*` and `ucan://<did>/<scheme>` get converted to.
    UcanWithAud(WrappedDidWebKey<'a>, Option<Scheme>, Option<Abilities>),

    /// Represents a specific capability from any UCAN with root issuer DID.
    ///
    /// This what non-ucan-scheme capabilities get converted to.
    CapWithRootIss(CapabilityTuple<'a>),
}

/// Represents a capability that has been validated, resolved and is in its final form.
enum ResolvedCapability<'a> {
    /// Represents a capability that has been validated, resolved and is in its final form.
    Final(CapabilityTuple<'a>),

    /// Because `ucan:*` allows transient delegation, this represents all capabilities of a principal that are transient.
    UcanAllTransient(Box<WrappedDidWebKey<'a>>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a, S> SignedUcan<'a, S>
where
    S: IpldStore,
{
    /// Resolves the capabilities of a UCAN to their final form.
    pub(crate) async fn resolve_capabilities(
        &'a self,
        // unresolved: Vec<UnresolvedCapability<'a>>,
        // resolved: Arc<RwLock<Vec<ResolvedCapability<'a>>>>,
        // authority: RootAuthority<'a, K>,
        // trace: Trace,
        store: &'a S,
    ) -> UcanResult<()> {
        self.validate()?;

        // Resolving received mapped capabilities that can be resolved ahead of time.
        // - resolve ucan_with_cid

        // Mapping the capabilities in current ucan to their resolution-oriented forms.
        let mut mapped_caps = Vec::new();
        for (resource, abilities) in self.payload.capabilities.iter() {
            mapped_caps.extend(self.map_capability(resource, abilities));
        }

        // Fetching and verifying all the UCANs from the proof section
        let mut ucans = Vec::new();
        for proof in self.payload.proofs.iter() {
            let ucan = proof.fetch_ucan(store).await?;
            self.verify_principal_alignment(ucan)?;
            ucans.push(ucan);
        }

        // Post
        // - resolve `CapWithRootIss` than can be resolved to final form
        // - separate resolved capabilities into their own bucket
        // - recurse on each ucan
        //    - UcanWithCid that have Some are sent to their repective ucans
        //    - All othe unresolved are sent to each ucan

        todo!()
    }

    fn map_capability(
        &self,
        resource: &ResourceUri<'a>,
        abilities: &Abilities,
    ) -> Vec<MappedCapability<'a>> {
        match resource {
            ResourceUri::Reference(reference) => match reference {
                ProofReference::AllUcansByDid(did) => {
                    let unresolved = UnresolvedCapability::UcanWithAud(
                        did.clone(),
                        None,
                        Some(abilities.clone()),
                    );
                    vec![Either::Left(unresolved)]
                }
                ProofReference::AllUcansTransient => {
                    let unresolved = UnresolvedCapability::UcanWithAud(
                        self.payload.issuer.clone(),
                        None,
                        Some(abilities.clone()),
                    );
                    let resolved =
                        ResolvedCapability::UcanAllTransient(Box::new(self.payload.issuer.clone()));

                    vec![Either::Left(unresolved), Either::Right(resolved)]
                }
                ProofReference::AllUcansByDidAndScheme(did, scheme) => {
                    let unresolved = UnresolvedCapability::UcanWithAud(
                        did.clone(),
                        Some(scheme.clone()),
                        Some(abilities.clone()),
                    );
                    vec![Either::Left(unresolved)]
                }
                ProofReference::AllProofsInCurrentUcan => {
                    let unresolved =
                        UnresolvedCapability::UcanWithCid(None, Some(abilities.clone()));
                    vec![Either::Left(unresolved)]
                }
                ProofReference::SpecificProofByCid(cid) => {
                    let unresolved =
                        UnresolvedCapability::UcanWithCid(Some(*cid), Some(abilities.clone()));
                    vec![Either::Left(unresolved)]
                }
            },
            ResourceUri::Other(reference) => abilities
                .iter()
                .map(|(ability, caveats)| {
                    let tuple = (reference.clone(), ability.clone(), caveats.clone());
                    let unresolved = UnresolvedCapability::CapWithRootIss(tuple);
                    Either::Left(unresolved)
                })
                .collect(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn test_ucan_resolve_capabilities() -> anyhow::Result<()> {
        Ok(())
    }

    // #[tokio::test]
    // async fn test_ucan_resolve() -> anyhow::Result<()> {
    //     let now = SystemTime::now();
    //     let store = MemoryStore::default();
    //     let base = Base::Base58Btc;
    //     let principal_0_key = Ed25519KeyPair::generate(&mut rand::thread_rng())?;
    //     let principal_1_key = Ed25519KeyPair::generate(&mut rand::thread_rng())?;
    //     let principal_2_key = Ed25519KeyPair::generate(&mut rand::thread_rng())?;
    //     let principal_0_did = WrappedDidWebKey::from_key(&principal_0_key, base)?;
    //     let principal_1_did = WrappedDidWebKey::from_key(&principal_1_key, base)?;
    //     let principal_2_did = WrappedDidWebKey::from_key(&principal_2_key, base)?;

    //     let ucan_0 = Ucan::builder()
    //         .issuer(principal_0_did)
    //         .audience(principal_1_did.clone())
    //         .expiration(now + Duration::from_secs(720_000))
    //         .capabilities(caps! {
    //             "zerodb://": {
    //                 "db/read": [{}],
    //             }
    //         })
    //         .store(&store)
    //         .sign(&principal_0_key)?;

    //     let ucan_1 = Ucan::builder()
    //         .issuer(principal_1_did)
    //         .audience(principal_2_did)
    //         .expiration(now + Duration::from_secs(720_000))
    //         .capabilities(caps! {
    //             "ucan:./*": {
    //                 "ucan/*": [{}],
    //             }
    //         })
    //         .store(&store)
    //         .proofs([ucan_0.persist().await?])
    //         .build();

    //     Ok(())
    // }
}
