#![allow(clippy::mutable_key_type)]

use std::{collections::HashSet, iter};

use async_recursion::async_recursion;
use libipld::Cid;
use zeroutils_did_wk::WrappedDidWebKey;
use zeroutils_key::{GetPublicKey, IntoOwned};
use zeroutils_store::IpldStore;

use crate::{
    AttenuationError, CapabilityTuple, ProofReference, ResolvedCapabilities,
    ResolvedCapabilityTuple, ResourceUri, SignedUcan, UcanError, UcanResult, Unresolved,
    UnresolvedCapWithRootIss, UnresolvedUcanWithAud, UnresolvedUcanWithCid,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The trace of CIDs along the proof chain.
pub type Trace = Vec<Cid>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a, S> SignedUcan<'a, S>
where
    S: IpldStore + Sync,
{
    /// Resolves the capabilities of a UCAN to their final form.
    pub async fn resolve_capabilities<K>(
        &self,
        root_key: &K,
        store: &S,
    ) -> UcanResult<ResolvedCapabilities>
    where
        K: GetPublicKey + Sync,
    {
        self.resolve_capabilities_with(
            (
                [
                    // This is needed to ensure that the entry UCAN is mapped.
                    UnresolvedUcanWithCid { cid: None },
                ]
                .into_iter()
                .collect(),
                HashSet::new(),
                HashSet::new(),
            ),
            root_key,
            vec![],
            store,
        )
        .await
    }

    #[async_recursion(?Send)]
    async fn resolve_capabilities_with<K>(
        &self,
        (ucan_with_cids, ucan_with_auds, cap_with_root_iss): (
            HashSet<UnresolvedUcanWithCid>,
            HashSet<UnresolvedUcanWithAud>,
            HashSet<UnresolvedCapWithRootIss>,
        ),
        root_key: &K,
        trace: Trace,
        store: &S,
    ) -> UcanResult<ResolvedCapabilities>
    where
        K: GetPublicKey + Sync,
    {
        // Validate the UCAN.
        self.validate()?;

        // Partition the `UcanWithAud` capabilities into validated and unvalidated.
        let (ucan_with_auds_validated, ucan_with_auds_unvalidated) =
            ucan_with_auds
                .into_iter()
                .partition::<HashSet<_>, _>(|ucan_with_aud| {
                    self.validate_ucan_with_aud_constraint(ucan_with_aud, &trace)
                        .is_ok()
                });

        let should_map = !ucan_with_auds_validated.is_empty() || !ucan_with_cids.is_empty();
        let (
            new_ucan_with_cids,
            new_ucan_with_auds,
            new_cap_with_root_iss,
            mut resolved,
            no_new_mapped_ucans,
        ) = if should_map {
            let (
                current_ucan_with_cids,
                mut current_ucan_with_auds,
                mut current_cap_with_root_iss,
                resolved,
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
                HashSet::new(),
                ucan_with_auds_unvalidated,
                cap_with_root_iss,
                ResolvedCapabilities::new(),
                true,
            )
        };

        // Filter out new `CapWithRootIss` that can be resolved to their final forms
        let new_cap_with_root_iss = new_cap_with_root_iss
            .into_iter()
            .filter_map(|unresolved| {
                if self
                    .validate_cap_with_root_iss_constraint(&unresolved, root_key, &trace)
                    .is_ok()
                {
                    resolved.insert(ResolvedCapabilityTuple::from(unresolved.tuple.clone()));
                    return None;
                }

                Some(unresolved)
            })
            .collect::<HashSet<_>>();

        // If there are no new mapped ucan capabilities while `CapWithRootIss` still remains to be resolved, return error.
        if no_new_mapped_ucans && !new_cap_with_root_iss.is_empty() {
            return Err(UcanError::UnresolvedCapabilities(
                Box::new(Unresolved::from((
                    new_ucan_with_cids,
                    new_ucan_with_auds,
                    new_cap_with_root_iss,
                ))),
                trace,
            ));
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
            return Err(UcanError::UnresolvedCapabilities(
                Box::new(Unresolved::from((
                    new_ucan_with_cids,
                    new_ucan_with_auds,
                    new_cap_with_root_iss,
                ))),
                trace,
            ));
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
            // If we need to filter and the proof's CID is not in ucan_with_actual_cids, skip this proof.
            if should_filter_proofs && !ucan_with_actual_cids.contains(proof.cid()) {
                continue;
            }

            let ucan = proof.fetch_ucan(store).await?;

            self.validate_proof_constraints(ucan)?;

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
                    root_key,
                    trace,
                    store,
                )
                .await?;

            resolved.extend(result);
        }

        Ok(resolved)
    }

    fn validate_ucan_with_aud_constraint(
        &self,
        unresolved: &UnresolvedUcanWithAud,
        trace: &Trace,
    ) -> UcanResult<()> {
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
            if !self.payload.capabilities.iter().any(|(resource_uri, _)| {
                if let ResourceUri::Other(uri) = resource_uri {
                    return uri
                        .scheme()
                        .map_or(false, |s| s.to_lowercase() == scheme.to_lowercase());
                }
                false
            }) {
                return Err(AttenuationError::SchemeNotPermittedInScope(
                    scheme.clone(),
                    trace.clone(),
                )
                .into());
            }
        }

        Ok(())
    }

    fn validate_cap_with_root_iss_constraint<K>(
        &self,
        unresolved: &UnresolvedCapWithRootIss,
        root_key: &K,
        trace: &Trace,
    ) -> UcanResult<()>
    where
        K: GetPublicKey,
    {
        let CapabilityTuple(uri, ability, caveats) = &unresolved.tuple;

        // TODO: We should check that capability tuple exists in the root capabilities definition
        // authority.capabilities.contains(&unresolved.tuple)

        // Checks if the capability is present and permitted in the UCAN.
        if self
            .payload
            .capabilities
            .permits(&ResourceUri::Other(uri.clone()), ability, caveats)
            .is_none()
        {
            return Err(AttenuationError::CapabilityNotPermittedInScope(
                unresolved.tuple.clone(),
                trace.clone(),
            )
            .into());
        }

        // Checks if the capability is delegated by the root issuer.
        if self.payload.issuer != WrappedDidWebKey::from_key(root_key, self.payload.issuer.base())?
        {
            return Err(AttenuationError::CapabilityNotDelegatedByRootIssuer(
                unresolved.tuple.clone(),
                trace.clone(),
            )
            .into());
        }

        Ok(())
    }

    /// Maps capabilities defined in the UCAN to a representation that is easy to work with and can be resolved.
    fn map_all_capabilities(
        &self,
    ) -> (
        HashSet<UnresolvedUcanWithCid>,
        HashSet<UnresolvedUcanWithAud>,
        HashSet<UnresolvedCapWithRootIss>,
        ResolvedCapabilities,
    ) {
        let mut unresolved_cap_with_root_iss = HashSet::new();
        let mut unresolved_ucan_with_cids = HashSet::new();
        let mut unresolved_ucan_with_auds = HashSet::new();
        let mut resolved_capabilities = ResolvedCapabilities::new();

        for (resource, abilities) in self.payload.capabilities.iter() {
            match resource {
                ResourceUri::Reference(reference) => match reference {
                    ProofReference::AllUcansByDid(did) => {
                        let unresolved = UnresolvedUcanWithAud {
                            did: did.clone().into_owned(),
                            scheme: None,
                        };

                        unresolved_ucan_with_auds.insert(unresolved);
                    }
                    ProofReference::AllUcansTransient => {
                        let unresolved = UnresolvedUcanWithAud {
                            did: self.payload.issuer.clone().into_owned(),
                            scheme: None,
                        };

                        let resolved = ResolvedCapabilityTuple::ucan_all(
                            self.payload.issuer.clone().into_owned(),
                        );

                        unresolved_ucan_with_auds.insert(unresolved);
                        resolved_capabilities.insert(resolved);
                    }
                    ProofReference::AllUcansByDidAndScheme(did, scheme) => {
                        let unresolved = UnresolvedUcanWithAud {
                            did: did.clone().into_owned(),
                            scheme: Some(scheme.clone()),
                        };

                        unresolved_ucan_with_auds.insert(unresolved);
                    }
                    ProofReference::AllProofsInCurrentUcan => {
                        let unresolved = UnresolvedUcanWithCid { cid: None };

                        unresolved_ucan_with_cids.insert(unresolved);
                    }
                    ProofReference::SpecificProofByCid(cid) => {
                        let unresolved = UnresolvedUcanWithCid { cid: Some(*cid) };

                        unresolved_ucan_with_cids.insert(unresolved);
                    }
                },
                ResourceUri::Other(reference) => {
                    for (ability, caveats) in abilities.iter() {
                        let tuple =
                            CapabilityTuple(reference.clone(), ability.clone(), caveats.clone());
                        let unresolved = UnresolvedCapWithRootIss { tuple };
                        unresolved_cap_with_root_iss.insert(unresolved);
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
