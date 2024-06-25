use std::{
    collections::HashSet,
    fmt::{self, Display},
    ops::{Deref, DerefMut},
    str::FromStr,
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
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ResolvedCapabilities(HashSet<ResolvedCapabilityTuple>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ResolvedCapabilities {
    /// Create a new empty set of resolved capabilities.
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    /// Check if this set of capabilities permits the requested capability. // TODO: Might need to optimize this.
    pub fn permits(&self, requested: impl Into<ResolvedCapabilityTuple>) -> bool {
        let requested = requested.into();
        self.0.iter().any(|c| c.permits(&requested))
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

impl From<(ResolvedResource, Ability, Caveats)> for ResolvedCapabilityTuple {
    fn from((resource, ability, caveats): (ResolvedResource, Ability, Caveats)) -> Self {
        Self(resource, ability, caveats)
    }
}

impl From<(NonUcanUri, Ability, Caveats)> for ResolvedCapabilityTuple {
    fn from((resource, ability, caveats): (NonUcanUri, Ability, Caveats)) -> Self {
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

impl FromStr for ResolvedResource {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ResolvedResource::NonUcan(NonUcanUri::from_str(s)?))
    }
}

impl Deref for ResolvedCapabilities {
    type Target = HashSet<ResolvedCapabilityTuple>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ResolvedCapabilities {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl IntoIterator for ResolvedCapabilities {
    type IntoIter = <HashSet<ResolvedCapabilityTuple> as IntoIterator>::IntoIter;
    type Item = ResolvedCapabilityTuple;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::caveats;

    use super::*;

    #[test]
    fn test_resolved_capability_permits() -> anyhow::Result<()> {
        // Permitted
        let resolved_capability = ResolvedCapabilityTuple(
            ResolvedResource::NonUcan(NonUcanUri::from_str("zerodb://public")?),
            "crud/*".parse()?,
            Caveats::any(),
        );

        assert!(resolved_capability.permits(&ResolvedCapabilityTuple(
            ResolvedResource::NonUcan(NonUcanUri::from_str("zerodb://public")?),
            "crud/*".parse()?,
            Caveats::any(),
        )));

        assert!(resolved_capability.permits(&ResolvedCapabilityTuple(
            ResolvedResource::NonUcan(NonUcanUri::from_str("zerodb://public/test")?),
            "crud/READ".parse()?,
            caveats![{ "test": 1 }]?,
        )));

        // Unpermitted
        assert!(!resolved_capability.permits(&ResolvedCapabilityTuple(
            ResolvedResource::NonUcan(NonUcanUri::from_str("zerodb://private")?),
            "crud/*".parse()?,
            Caveats::any(),
        )));

        Ok(())
    }
}
