#![allow(unused)]
use std::{collections::HashSet, iter, vec};

use async_recursion::async_recursion;
use either::Either;
use libipld::Cid;
use zeroutils_did_wk::WrappedDidWebKey;
use zeroutils_key::{GetPublicKey, IntoOwned};
use zeroutils_store::IpldStore;

use crate::{
    abilities, Abilities, Ability, AttenuationError, Caveats, OtherUri, PermissionError, Proof,
    ProofReference, ResourceUri, RootAuthority, Scheme, SignedUcan, UcanError, UcanResult,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A capability tuple is a tuple of a resource ✕ ability ✕ caveats.
pub type CapabilityTuple = (OtherUri, Ability, Caveats);

/// The trace of CIDs along the proof chain.
pub type Trace = Vec<Cid>;

/// Represents the capabilities of current UCAN with a specific CID in the `prf` section.
///
/// This is what `ucan:<cid>` and `ucan:./*` get converted to.
#[derive(Clone, Debug)]
pub struct UnresolvedCapWithRootIss {
    /// The capability tuple.
    pub tuple: CapabilityTuple,
}

/// Represents the capabilities of current UCAN with a specific CID in the `prf` section.
///
/// This is what `ucan:<cid>` and `ucan:./*` get converted to.
#[derive(Clone, Debug)]
pub struct UnresolvedUcanWithCid {
    /// The CID of the UCAN.
    pub cid: Option<Cid>,
}

/// Represents the capabilities of any UCAN with a specific audience DID.
/// This type eventually gets converted to `CapWithRootIss`.
///
/// This is what `ucan://<did>/*` and `ucan://<did>/<scheme>` get converted to.
#[derive(Clone, Debug)]
pub struct UnresolvedUcanWithAud {
    /// The DID of the UCAN.
    pub did: WrappedDidWebKey<'static>,

    /// The scheme of the UCAN.
    pub scheme: Option<Scheme>,
}

/// Represents a capability that has been validated, resolved and is in its final form.
#[derive(Clone, Debug)]
pub enum ResolvedCapability {
    /// Represents a capability that has been validated, resolved and is in its final form.
    Final(CapabilityTuple),

    /// Because `ucan:*` allows transient delegation, this represents all capabilities of the delegating principal that are transient.
    UcanAllTransient(Box<WrappedDidWebKey<'static>>),
}

//--------------------------------------------------------------------------------------------------
// Methods: SignedUcan
//--------------------------------------------------------------------------------------------------

impl<'a, S> SignedUcan<'a, S>
where
    S: IpldStore + Sync,
{
    /// Resolves the capabilities of a UCAN to their final form.
    pub async fn resolve_capabilities<'b, K>(
        &self,
        authority: &RootAuthority<'b, K>,
        store: &S,
    ) -> UcanResult<Vec<ResolvedCapability>>
    where
        K: GetPublicKey + Sync,
    {
        self.resolve_capabilities_with(
            (
                vec![
                    // This is needed to ensure that the entry UCAN is mapped.
                    UnresolvedUcanWithCid { cid: None },
                ],
                vec![],
                vec![],
            ),
            authority,
            vec![],
            store,
        )
        .await
    }

    #[async_recursion(?Send)]
    async fn resolve_capabilities_with<'b, K>(
        &self,
        (ucan_with_cids, ucan_with_auds, cap_with_root_iss): (
            Vec<UnresolvedUcanWithCid>,
            Vec<UnresolvedUcanWithAud>,
            Vec<UnresolvedCapWithRootIss>,
        ),
        authority: &RootAuthority<'b, K>,
        trace: Trace,
        store: &S,
    ) -> UcanResult<Vec<ResolvedCapability>>
    where
        K: GetPublicKey + Sync,
    {
        println!("\nEntry"); // TODO: Remove
        println!("ucan_with_cids: {:?}", ucan_with_cids);
        println!("ucan_with_auds: {:?}", ucan_with_auds);
        println!("cap_with_root_iss: {:?}", cap_with_root_iss);

        // Validate the UCAN.
        self.validate()?;

        // Makes sure the `UcanWithCid` capabilities are attenuated.
        // TODO: Also make sure ucan schemes only accept ucan/* with any caveats only.

        // Partition the `UcanWithAud` capabilities into validated and unvalidated.
        let (ucan_with_auds_validated, ucan_with_auds_unvalidated) = ucan_with_auds
            .into_iter()
            .partition::<Vec<_>, _>(|ucan_with_aud| {
                self.validate_attenuation_with_aud(ucan_with_aud, &authority.key, &trace)
                    .is_ok()
            });

        let should_map = !ucan_with_auds_validated.is_empty() || !ucan_with_cids.is_empty();
        let (
            mut new_ucan_with_cids,
            mut new_ucan_with_auds,
            mut new_cap_with_root_iss,
            mut resolved,
            no_new_mapped_ucans,
        ) = if should_map {
            let (
                current_ucan_with_cids,
                mut current_ucan_with_auds,
                mut current_cap_with_root_iss,
                mut resolved,
            ) = self.map_all_capabilities();

            // Add new `CapWithRootIss` capabilities to the current ones.
            current_cap_with_root_iss.extend(cap_with_root_iss);

            // If there are no new `UcanWithCid` or `UcanWithAud` from the current UCAN.
            let no_new_mapped_ucans =
                current_ucan_with_cids.is_empty() && current_ucan_with_auds.is_empty();

            // Add new `UcanWithAud` capabilities to the current ones.
            current_ucan_with_auds.extend(ucan_with_auds_unvalidated);

            (
                current_ucan_with_cids,
                current_ucan_with_auds,
                current_cap_with_root_iss,
                resolved,
                no_new_mapped_ucans,
            )
        } else {
            (
                vec![],
                ucan_with_auds_unvalidated,
                cap_with_root_iss,
                vec![],
                true,
            )
        };

        // Filter out new `CapWithRootIss` that can be resolved to their final forms
        let new_cap_with_root_iss = new_cap_with_root_iss
            .into_iter()
            .filter_map(|unresolved| {
                if self
                    .validate_attenuation_with_root_iss(&unresolved, &authority.key, &trace)
                    .is_ok()
                {
                    resolved.push(ResolvedCapability::Final(unresolved.tuple.clone()));
                    return None;
                }

                Some(unresolved)
            })
            .collect::<Vec<_>>();

        // If there are no new mapped ucan capabilities while `CapWithRootIss` still remains to be resolved, return error.
        if no_new_mapped_ucans && !new_cap_with_root_iss.is_empty() {
            return Err(UcanError::UnresolvedCapabilities {
                ucan_with_cids: new_ucan_with_cids,
                ucan_with_auds: new_ucan_with_auds,
                cap_with_root_iss: new_cap_with_root_iss,
            });
        }

        // If there are no new capabilities, return the resolved capabilities.
        if new_ucan_with_cids.is_empty()
            && new_ucan_with_auds.is_empty()
            && new_cap_with_root_iss.is_empty()
        {
            return Ok(resolved);
        }

        // If there are no proofs, return an error.
        if self.payload.proofs.is_empty() {
            return Err(UcanError::UnresolvedCapabilities {
                ucan_with_cids: new_ucan_with_cids,
                ucan_with_auds: new_ucan_with_auds,
                cap_with_root_iss: new_cap_with_root_iss,
            });
        }

        // Ensure that Cids in `UcanWithCid`s can actually be found in the proofs.
        let mut ucan_with_actual_cids = HashSet::new();
        for ucan_with_cid in new_ucan_with_cids.iter() {
            if let Some(cid) = ucan_with_cid.cid {
                self.payload
                    .proofs
                    .get(&cid)
                    .ok_or(UcanError::ProofCidNotFound(cid))?;

                ucan_with_actual_cids.insert(cid);
            }
        }

        // Determine if we should filter or go through all the proofs. This depends on existence of ucan schemes like, ucan:./* or ucan:<cid>.
        let should_filter_proofs = new_ucan_with_auds.is_empty()
            && new_ucan_with_cids.len() == ucan_with_actual_cids.len();

        for proof in self.payload.proofs.iter() {
            println!("Got here"); // TODO: Remove

            // TODO: IMPORTANT: We should check that our expiry does not exceed delegator's and that our nbf is not before delegator's.
            // If we need to filter and the proof's CID is not in ucan_with_actual_cids, skip this proof.
            if should_filter_proofs && !ucan_with_actual_cids.contains(proof.cid()) {
                println!("Skipping proof"); // TODO: Remove
                continue;
            }

            let ucan = proof.fetch_ucan(store).await?;
            println!("Fetched UCAN: {:?}", ucan); // TODO: Remove

            let trace = iter::once(*proof.cid())
                .chain(trace.iter().cloned())
                .collect();

            let result = ucan
                .resolve_capabilities_with(
                    (
                        new_ucan_with_cids.clone(),
                        new_ucan_with_auds.clone(),
                        new_cap_with_root_iss.clone(),
                    ),
                    authority,
                    trace,
                    store,
                )
                .await?;

            resolved.extend(result);
        }

        Ok(resolved)
    }

    fn validate_attenuation_with_aud<K>(
        &self,
        unresolved: &UnresolvedUcanWithAud,
        root_key: &K,
        trace: &Trace,
    ) -> UcanResult<()>
    where
        K: GetPublicKey,
    {
        // Checks if the audience matches the UCAN.
        if self.payload.audience != unresolved.did {
            return Err(AttenuationError::AudienceDidNotMatch(
                unresolved.did.to_string(),
                trace.clone(),
            )
            .into());
        }

        // Checks if the scheme matches any of the UCAN's capabilities.
        if let Some(scheme) = &unresolved.scheme {
            if !self
                .payload
                .capabilities
                .iter()
                .any(|(resource_uri, abilities)| {
                    if let ResourceUri::Other(uri) = resource_uri {
                        return uri
                            .scheme()
                            .map_or(false, |s| s.to_lowercase() == scheme.to_lowercase());
                    }
                    false
                })
            {
                return Err(AttenuationError::SchemeNotPermittedInScope(
                    scheme.clone(),
                    trace.clone(),
                )
                .into());
            }
        }

        Ok(())
    }

    fn validate_attenuation_with_root_iss<K>(
        &self,
        unresolved: &UnresolvedCapWithRootIss,
        root_key: &K,
        trace: &Trace,
    ) -> UcanResult<()>
    where
        K: GetPublicKey,
    {
        let (uri, ability, caveats) = &unresolved.tuple;

        // Checks if the capability is present and permitted in the UCAN.
        if self
            .payload
            .capabilities
            .permits(&ResourceUri::Other(uri.clone()), ability, caveats)
            .is_none()
        {
            return Err(AttenuationError::CapabilityNotPermittedInScope(
                (uri.clone(), ability.clone(), caveats.clone()),
                trace.clone(),
            )
            .into());
        }

        // Checks if the capability is delegated by the root issuer.
        if self.payload.issuer != WrappedDidWebKey::from_key(root_key, self.payload.issuer.base())?
        {
            return Err(AttenuationError::CapabilityNotDelegatedByRootIssuer(
                (uri.clone(), ability.clone(), caveats.clone()),
                trace.clone(),
            )
            .into());
        }

        Ok(())
    }

    /// Maps capabilities defined in the UCAN to a representation that is easy to work with and can be resolved.
    ///
    /// # Returns
    ///
    /// The method returns a tuple of vectors containing the following:
    /// - 0. `UnresolvedCapability::CapWithRootIss`
    /// - 1. `UnresolvedCapability::UcanWithCid`
    /// - 2. `UnresolvedCapability::UcanWithAud`
    /// - 3. `ResolvedCapability::*`
    fn map_all_capabilities(
        &self,
    ) -> (
        Vec<UnresolvedUcanWithCid>,
        Vec<UnresolvedUcanWithAud>,
        Vec<UnresolvedCapWithRootIss>,
        Vec<ResolvedCapability>,
    ) {
        let mut unresolved_cap_with_root_iss = vec![];
        let mut unresolved_ucan_with_cids = vec![];
        let mut unresolved_ucan_with_auds = vec![];
        let mut resolved_capabilities = vec![];

        for (resource, abilities) in self.payload.capabilities.iter() {
            match resource {
                ResourceUri::Reference(reference) => match reference {
                    ProofReference::AllUcansByDid(did) => {
                        let unresolved = UnresolvedUcanWithAud {
                            did: did.clone().into_owned(),
                            scheme: None,
                        };

                        unresolved_ucan_with_auds.push(unresolved);
                    }
                    ProofReference::AllUcansTransient => {
                        let unresolved = UnresolvedUcanWithAud {
                            did: self.payload.issuer.clone().into_owned(),
                            scheme: None,
                        };

                        let resolved = ResolvedCapability::UcanAllTransient(Box::new(
                            self.payload.issuer.clone().into_owned(),
                        ));

                        unresolved_ucan_with_auds.push(unresolved);
                        resolved_capabilities.push(resolved);
                    }
                    ProofReference::AllUcansByDidAndScheme(did, scheme) => {
                        let unresolved = UnresolvedUcanWithAud {
                            did: did.clone().into_owned(),
                            scheme: Some(scheme.clone()),
                        };

                        unresolved_ucan_with_auds.push(unresolved);
                    }
                    ProofReference::AllProofsInCurrentUcan => {
                        let unresolved = UnresolvedUcanWithCid { cid: None };

                        unresolved_ucan_with_cids.push(unresolved);
                    }
                    ProofReference::SpecificProofByCid(cid) => {
                        let unresolved = UnresolvedUcanWithCid { cid: Some(*cid) };

                        unresolved_ucan_with_cids.push(unresolved);
                    }
                },
                ResourceUri::Other(reference) => {
                    for (ability, caveats) in abilities.iter() {
                        let tuple = (reference.clone(), ability.clone(), caveats.clone());
                        let unresolved = UnresolvedCapWithRootIss { tuple };
                        unresolved_cap_with_root_iss.push(unresolved);
                    }
                }
            }
        }

        (
            unresolved_ucan_with_cids,
            unresolved_ucan_with_auds,
            unresolved_cap_with_root_iss,
            resolved_capabilities,
        )
    }
}
