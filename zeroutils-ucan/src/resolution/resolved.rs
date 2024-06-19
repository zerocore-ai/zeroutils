use std::{
    collections::HashMap,
    fmt::{self, Display},
};

use zeroutils_did_wk::WrappedDidWebKey;

use crate::{Ability, CapabilityTuple, Caveats, NonUcanUri};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A resolved resource.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResolvedResource {
    /// A non-ucan resource.
    NonUcan(NonUcanUri),

    /// Because `ucan:*` allows transient delegation, this represents all capabilities of the delegating principal that are transient.
    UcanAllTransient(Box<WrappedDidWebKey<'static>>),
}

/// Represents a capability that has been validated, resolved and is in its final form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedCapabilityTuple(pub ResolvedResource, pub Ability, pub Caveats);

/// A collection of resolved capabilities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedCapabilities(HashMap<ResolvedResource, HashMap<Ability, Caveats>>);

/// The level of permit for a capability.
enum PermitLevel {
    /// The existing capability item is the same as the new capability item.
    Same,

    // The new capability item is permitted by the existing capability item.
    Permitted,

    // The existing capability item is permitted by the new capability item.
    ReversePermitted,

    // The new capability item is not permitted by the existing capability item and vice versa.
    Unpermitted,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ResolvedCapabilities {
    // pub fn permits(&self, capability: &ResolvedCapabilityTuple) -> bool {
    //     todo!()
    // }

    /// Insert a resolved capability into the collection.
    ///
    /// TODO: Add documentation on how specificity is not supported
    pub fn insert(&mut self, capability: ResolvedCapabilityTuple) {
        use PermitLevel::*;
        match self.get_permit_levels(&capability) {
            // ...
            (Same | Permitted, Same | Permitted, Same | Permitted) => {}

            // ...
            (Same | Permitted, Unpermitted, _) => {
                // TODO: Implement
            }
            (Same | Permitted, Same | Permitted, Unpermitted) => {
                // TODO: Implement
            }

            // ...
            (ReversePermitted, ReversePermitted, ReversePermitted) => {
                // TODO: Implement
            }
            (ReversePermitted, ReversePermitted, Same) => {
                // TODO: Implement
            }
            (ReversePermitted, Same, ReversePermitted) => {
                // TODO: Implement
            }
            (ReversePermitted, Same, Same) => {
                // TODO: Implement
            }
            (Same, ReversePermitted, ReversePermitted) => {
                // TODO: Implement
            }
            (Same, ReversePermitted, Same) => {
                // TODO: Implement
            }
            (Same, Same, ReversePermitted) => {
                // TODO: Implement
            }

            // ...
            (ReversePermitted, Unpermitted, _) => {
                // TODO: Implement
            }
            (ReversePermitted, ReversePermitted, Unpermitted) => {
                // TODO: Implement
            }
            (ReversePermitted, Same, Unpermitted) => {
                // TODO: Implement
            }
            (Same, ReversePermitted, Unpermitted) => {
                // TODO: Implement
            }

            // ...
            _ => {}
        }
    }

    fn get_permit_levels(
        &self,
        ResolvedCapabilityTuple(resource, ability, caveats): &ResolvedCapabilityTuple,
    ) -> (PermitLevel, PermitLevel, PermitLevel) {
        Self::get_permit_levels_with_resources(&self.0, resource, ability, caveats)
    }

    #[inline]
    fn get_permit_levels_with_resources(
        resources: &HashMap<ResolvedResource, HashMap<Ability, Caveats>>,
        resource: &ResolvedResource,
        ability: &Ability,
        caveats: &Caveats,
    ) -> (PermitLevel, PermitLevel, PermitLevel) {
        if let Some(abilities) = resources.get(resource) {
            let (ability_permit, caveats_permit) =
                Self::get_permit_levels_with_abilities(abilities, ability, caveats);
            return (PermitLevel::Same, ability_permit, caveats_permit);
        }

        for (existing_resource, abilities) in resources.iter() {
            if existing_resource.permits(resource) {
                let (ability_permit, caveats_permit) =
                    Self::get_permit_levels_with_abilities(abilities, ability, caveats);
                return (PermitLevel::Permitted, ability_permit, caveats_permit);
            } else if resource.permits(existing_resource) {
                let (ability_permit, caveats_permit) =
                    Self::get_permit_levels_with_abilities(abilities, ability, caveats);
                return (
                    PermitLevel::ReversePermitted,
                    ability_permit,
                    caveats_permit,
                );
            }
        }

        return (
            PermitLevel::Unpermitted,
            PermitLevel::Unpermitted,
            PermitLevel::Unpermitted,
        );
    }

    #[inline]
    fn get_permit_levels_with_abilities(
        abilities: &HashMap<Ability, Caveats>,
        ability: &Ability,
        caveats: &Caveats,
    ) -> (PermitLevel, PermitLevel) {
        if let Some(existing_caveats) = abilities.get(ability) {
            let caveat_permit = Self::get_permit_levels_with_caveats(existing_caveats, caveats);
            return (PermitLevel::Same, caveat_permit);
        }

        for (existing_ability, existing_caveats) in abilities.iter() {
            if existing_ability.permits(ability) {
                let caveat_permit = Self::get_permit_levels_with_caveats(existing_caveats, caveats);
                return (PermitLevel::Permitted, caveat_permit);
            } else if ability.permits(existing_ability) {
                let caveat_permit = Self::get_permit_levels_with_caveats(existing_caveats, caveats);
                return (PermitLevel::ReversePermitted, caveat_permit);
            }
        }

        return (PermitLevel::Unpermitted, PermitLevel::Unpermitted);
    }

    #[inline]
    fn get_permit_levels_with_caveats(
        existing_caveats: &Caveats,
        caveats: &Caveats,
    ) -> PermitLevel {
        if existing_caveats == caveats {
            return PermitLevel::Same;
        } else if existing_caveats.permits(caveats) {
            return PermitLevel::Permitted;
        } else if caveats.permits(existing_caveats) {
            return PermitLevel::ReversePermitted;
        }

        return PermitLevel::Unpermitted;
    }
}

impl ResolvedCapabilityTuple {
    /// Create a new resolved capability for the `ucan:*` resource.
    pub fn ucan_all(did: WrappedDidWebKey<'static>) -> Self {
        Self(
            ResolvedResource::UcanAllTransient(Box::new(did)),
            Ability::Ucan,
            Caveats::any(),
        )
    }

    /// Check if this capability permits the requested capability.
    pub fn permits(&self, requested: &ResolvedCapabilityTuple) -> bool {
        self.0.permits(&requested.0) && self.1.permits(&requested.1) && self.2.permits(&requested.2)
    }
}

impl ResolvedResource {
    /// Check if this resource permits the requested resource.
    pub fn permits(&self, requested: &ResolvedResource) -> bool {
        match (self, requested) {
            (ResolvedResource::NonUcan(uri), ResolvedResource::NonUcan(requested_uri)) => {
                uri.permits(requested_uri)
            }
            (
                ResolvedResource::UcanAllTransient(did),
                ResolvedResource::UcanAllTransient(requested_did),
            ) => did == requested_did,
            _ => false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<CapabilityTuple> for ResolvedCapabilityTuple {
    fn from(CapabilityTuple(resource, ability, caveats): CapabilityTuple) -> Self {
        Self(ResolvedResource::NonUcan(resource), ability, caveats)
    }
}

impl Display for ResolvedCapabilityTuple {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ✕ {} ✕ {}", self.0, self.1, self.2)
    }
}

impl Display for ResolvedResource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ResolvedResource::NonUcan(uri) => write!(f, "{}", uri),
            ResolvedResource::UcanAllTransient(did) => write!(f, "ucan:* ({})", did),
        }
    }
}
