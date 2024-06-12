#![allow(clippy::mutable_key_type)]

use std::{
    collections::BTreeMap,
    ops::{Deref, Index},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use crate::{Ability, Caveats, ResourceUri, UcanError, UcanResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Capabilities are a mapping of _resources_ to abilities. Each resource can have a set of _abilities_
/// and each ability can have a set of _caveats_ that adds restrictions or conditions to the ability.
///
/// Capabilities are how UCANs define what actions can be performed on a resource and under what
/// conditions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities<'a>(BTreeMap<ResourceUri<'a>, Abilities>);

/// Represents a set of actions (abilities) that can be performed on a resource, mapped to potential caveats.
///
/// Abilities should be consistent with the resource's context (e.g., HTTP methods for web resources) and are case-insensitive.
///
/// Abilities can be organized hierarchically, allowing for broad capabilities to encompass more specific ones.
///
/// Abilities must contain [at least one entry][abilities]. An empty abilities array is invalid.
///
/// [abilities]: https://github.com/ucan-wg/spec?tab=readme-ov-file#3262-abilities
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Abilities(BTreeMap<Ability, Caveats>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> Capabilities<'a> {
    /// Creates a new `Capabilities` instance.
    pub fn new() -> Self {
        Capabilities(BTreeMap::new())
    }

    /// Checks if the provided `resource ✕ ability ✕ caveats` access tuple is permitted by the main capabilities.
    pub fn permits<'b>(
        &self,
        resource: &ResourceUri<'b>,
        ability: &Ability,
        caveats: &Caveats,
    ) -> Option<(&ResourceUri<'a>, &Ability, &Caveats)> {
        for (r, abilities) in &self.0 {
            if !r.permits(resource) {
                continue;
            }

            for (a, c) in &abilities.0 {
                if a.permits(ability) && c.permits(caveats) {
                    return Some((r, a, c));
                }
            }
        }

        None
    }

    /// Gets the abilities for a given resource.
    pub fn get(&'a self, resource: &'a ResourceUri) -> Option<&Abilities> {
        self.0.get(resource)
    }

    /// Checks if the capabilities are empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of resources in the capabilities.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Inserts a resource and its abilities into the capabilities.
    pub fn insert(
        &mut self,
        resource: ResourceUri<'a>,
        abilities: Abilities,
    ) -> UcanResult<Option<Abilities>> {
        if let ResourceUri::Reference(_) = resource {
            if !abilities.is_ucan() {
                return Err(UcanError::InvalidUcanResourceAbility(abilities));
            }

            let caveats = abilities.get(&Ability::Ucan).unwrap();
            if !caveats.is_any() {
                return Err(UcanError::InvalidUcanResourceCaveats(caveats.clone()));
            }
        }

        Ok(self.0.insert(resource, abilities))
    }

    /// Returns an iterator over the capabilities.
    pub fn iter(&self) -> impl Iterator<Item = (&ResourceUri, &Abilities)> {
        self.0.iter()
    }
}

impl Abilities {
    /// Creates a new `Abilities` instance from an iterator.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter(iter: impl IntoIterator<Item = (Ability, Caveats)>) -> UcanResult<Self> {
        let abilities: BTreeMap<_, _> = iter.into_iter().collect();
        if abilities.is_empty() {
            return Err(UcanError::NoAbility);
        }

        Ok(Abilities(abilities))
    }

    /// Checks if abilities is a single `ucan/*` ability.
    pub fn is_ucan(&self) -> bool {
        self.0.len() == 1 && self.0.keys().next().map_or(false, |a| a.is_ucan())
    }

    /// Gets the caveats for a given ability.
    pub fn get(&self, ability: &Ability) -> Option<&Caveats> {
        self.0.get(ability)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: Derefs
//--------------------------------------------------------------------------------------------------

impl Deref for Abilities {
    type Target = BTreeMap<Ability, Caveats>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: Froms
//--------------------------------------------------------------------------------------------------

impl<'a> TryFrom<BTreeMap<ResourceUri<'a>, Abilities>> for Capabilities<'a> {
    type Error = UcanError;

    fn try_from(map: BTreeMap<ResourceUri<'a>, Abilities>) -> Result<Self, Self::Error> {
        let mut capabilities = Capabilities::new();
        for (resource, abilities) in map {
            capabilities.insert(resource, abilities)?;
        }

        Ok(capabilities)
    }
}

impl TryFrom<BTreeMap<Ability, Caveats>> for Abilities {
    type Error = UcanError;

    fn try_from(map: BTreeMap<Ability, Caveats>) -> Result<Self, Self::Error> {
        Abilities::from_iter(map)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: Indexing
//--------------------------------------------------------------------------------------------------

impl<'a, I> Index<I> for Capabilities<'a>
where
    I: AsRef<str>,
{
    type Output = Abilities;

    fn index(&self, index: I) -> &Self::Output {
        self.0
            .get(&ResourceUri::from_str(index.as_ref()).unwrap())
            .unwrap()
    }
}

impl<I> Index<I> for Abilities
where
    I: AsRef<str>,
{
    type Output = Caveats;

    fn index(&self, index: I) -> &Self::Output {
        self.0
            .get(&Ability::from_str(index.as_ref()).unwrap())
            .unwrap()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::Map;

    use crate::{caps, caveats};

    use super::*;

    #[test]
    fn test_capabilities_constructors() -> anyhow::Result<()> {
        let mut capabilities = Capabilities::new();

        assert!(capabilities
            .insert(
                "example://example.com/public/photos/".parse()?,
                Abilities::from_iter([
                    (
                        "crud/read".parse()?,
                        Caveats::from_iter([Map::from_iter([("public".into(), true.into())])])?,
                    ),
                    ("crud/delete".parse()?, Caveats::any()),
                ])?,
            )
            .is_ok());

        // Fails for wrong ucan resource capability combination
        assert!(capabilities
            .insert(
                "ucan:*".parse()?,
                Abilities::from_iter([("crud/delete".parse()?, Caveats::any())])?,
            )
            .is_err());

        assert!(capabilities
            .insert(
                "ucan:./*".parse()?,
                Abilities::from_iter([(
                    "ucan/*".parse()?,
                    Caveats::from_iter([Map::from_iter([("public".into(), true.into())])])?
                )])?,
            )
            .is_err());

        assert!(capabilities
            .insert(
                "ucan://did:wk:z6MkqAywjQVwsr7m1HMamynCZZjH8AKPqYZNXwpHg842pPsG/fs".parse()?,
                Abilities::from_iter([(
                    "crud/*".parse()?,
                    Caveats::from_iter([Map::from_iter([("public".into(), true.into())])])?
                )])?,
            )
            .is_err());

        Ok(())
    }

    #[test]
    fn test_abilities_constructors() -> anyhow::Result<()> {
        let abilities = Abilities::from_iter(vec![
            ("crud/read".parse()?, Caveats::any()),
            ("crud/delete".parse()?, Caveats::any()),
        ])?;

        assert_eq!(abilities.len(), 2);

        // Empty abilities are invalid
        assert!(Abilities::from_iter(vec![]).is_err());

        Ok(())
    }

    #[test]
    fn test_capabilities_indexing() -> anyhow::Result<()> {
        let capabilities = caps! {
            "example://example.com/public/photos/": {
                "crud/read": [{}],
                "crud/delete": [{}],
            },
            "mailto:username@example.com": {
                "msg/send": [{}],
                "msg/receive": [
                    {
                        "max_count": 5,
                        "templates": [
                            "newsletter",
                            "marketing"
                        ]
                    }
                ]
            },
        };

        assert_eq!(capabilities.len(), 2);

        let abilities = &capabilities["example://example.com/public/photos/"];

        assert_eq!(abilities.len(), 2);

        let caveats = &capabilities["example://example.com/public/photos/"]["crud/read"];

        assert_eq!(caveats.len(), 1);

        let caveat = &capabilities["example://example.com/public/photos/"]["crud/read"][0];

        assert_eq!(caveat.len(), 0);

        let value = &capabilities["mailto:username@example.com"]["msg/receive"][0]["max_count"];

        assert_eq!(value, 5);

        Ok(())
    }

    #[test]
    fn test_capabilities_permits() -> anyhow::Result<()> {
        let main = caps! {
            "example://example.com/public/": {
                "crud/read": [{}],
                "crud/delete": [{ "max_count": 5 }, { "public": true }],
            },
            "zerodb://app/users/": {
                "db/table/*": [{ "rate_limit": 100 }],
            }
        };

        assert!(main
            .permits(
                &"example://example.com/public/photos/".parse()?,
                &"crud/read".parse()?,
                &caveats![{ "public": true }]
            )
            .is_some());

        assert!(main
            .permits(
                &"example://example.com/public/photos/".parse()?,
                &"crud/delete".parse()?,
                &caveats![{ "max_count": 5 }]
            )
            .is_some());

        assert!(main
            .permits(
                &"zerodb://app/users/".parse()?,
                &"db/table/read".parse()?,
                &caveats![{ "rate_limit": 100 }]
            )
            .is_some());

        // Fails

        assert!(main
            .permits(
                &"example://example.com/".parse()?,
                &"crud/read".parse()?,
                &caveats![{}]
            )
            .is_none());

        assert!(main
            .permits(
                &"zerodb://app/users/".parse()?,
                &"db/table/read".parse()?,
                &caveats![{ "rate_limit": 100 }, { "public": true }]
            )
            .is_none());

        Ok(())
    }
}
