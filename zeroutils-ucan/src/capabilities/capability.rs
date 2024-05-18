#![allow(clippy::mutable_key_type)]

use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Ability, Caveats, ResourceUri, UcanError, UcanResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A hierarchical mapping from a URI (as a namespace and resource identifier) to the associated abilities.
///
/// Each ability can have a set of caveats, which are conditions or restrictions on the ability's use.
/// This structure allows for a granular definition of permissions across different resources and actions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities<'a>(BTreeMap<ResourceUri<'a>, Abilities>);

/// Represents a set of actions (abilities) that can be performed on a resource, mapped to potential caveats.
///
/// Abilities must be consistent with the resource's context (e.g., HTTP methods for web resources) and are case-insensitive.
///
/// Abilities can be organized hierarchically, allowing for broad capabilities to encompass more specific ones.
///
/// Abilities must contain [at least one entry][abilities]. An empty abilities array is invalid.
///
/// [abilities]: https://github.com/ucan-wg/spec?tab=readme-ov-file#3262-abilities
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Abilities(BTreeMap<Ability, Caveats>);

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// A trait for selecting a value from a hierarchical structure based on a set of arguments.
pub trait Select<A, R> {
    /// The error type for the selection operation.
    type Error;

    /// Selects a value from the hierarchical structure based on the provided arguments.
    fn select(&self, args: A) -> Result<Option<&R>, Self::Error>;
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Capabilities<'_> {
    /// Creates a new `Capabilities` instance.
    pub fn new() -> Self {
        Capabilities(BTreeMap::new())
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
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: Derefs
//--------------------------------------------------------------------------------------------------

impl<'a> Deref for Capabilities<'a> {
    type Target = BTreeMap<ResourceUri<'a>, Abilities>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for Capabilities<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for Abilities {
    type Target = BTreeMap<Ability, Caveats>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: Froms
//--------------------------------------------------------------------------------------------------

impl<'a> From<BTreeMap<ResourceUri<'a>, Abilities>> for Capabilities<'a> {
    fn from(map: BTreeMap<ResourceUri<'a>, Abilities>) -> Self {
        Capabilities(map)
    }
}

impl TryFrom<BTreeMap<Ability, Caveats>> for Abilities {
    type Error = UcanError;

    fn try_from(map: BTreeMap<Ability, Caveats>) -> Result<Self, Self::Error> {
        Abilities::from_iter(map)
    }
}

impl<'a> FromIterator<(ResourceUri<'a>, Abilities)> for Capabilities<'a> {
    fn from_iter<T: IntoIterator<Item = (ResourceUri<'a>, Abilities)>>(iter: T) -> Self {
        Capabilities(iter.into_iter().collect())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: Select
//--------------------------------------------------------------------------------------------------

impl<U> Select<U, Abilities> for Capabilities<'_>
where
    U: AsRef<str>,
{
    type Error = UcanError;

    fn select(&self, uri: U) -> Result<Option<&Abilities>, Self::Error> {
        let uri = ResourceUri::from_str(uri.as_ref())?;
        Ok(self.get(&uri))
    }
}

impl<U, A> Select<(U, A), Caveats> for Capabilities<'_>
where
    U: AsRef<str>,
    A: AsRef<str>,
{
    type Error = UcanError;

    fn select(&self, (uri, ability): (U, A)) -> Result<Option<&Caveats>, Self::Error> {
        let abilities = self.select(uri)?;
        let ability = Ability::from_str(ability.as_ref())?;
        let caveats = abilities.and_then(|abilities| abilities.get(&ability));
        Ok(caveats)
    }
}

impl<U, A> Select<(U, A, usize), BTreeMap<String, Value>> for Capabilities<'_>
where
    U: AsRef<str>,
    A: AsRef<str>,
{
    type Error = UcanError;

    fn select(
        &self,
        (uri, ability, caveat): (U, A, usize),
    ) -> Result<Option<&BTreeMap<String, Value>>, Self::Error> {
        let caveats = self.select((uri, ability))?;
        let caveat = caveats.and_then(|caveats| caveats.get(caveat));
        Ok(caveat)
    }
}

impl<U, A, K> Select<(U, A, usize, K), Value> for Capabilities<'_>
where
    U: AsRef<str>,
    A: AsRef<str>,
    K: AsRef<str>,
{
    type Error = UcanError;

    fn select(
        &self,
        (uri, ability, caveat, key): (U, A, usize, K),
    ) -> Result<Option<&Value>, Self::Error> {
        let caveat = self.select((uri, ability, caveat))?;
        let key = caveat.and_then(|caveat| caveat.get(key.as_ref()));
        Ok(key)
    }
}

impl<A> Select<A, Caveats> for Abilities
where
    A: AsRef<str>,
{
    type Error = UcanError;

    fn select(&self, ability: A) -> Result<Option<&Caveats>, Self::Error> {
        let ability = Ability::from_str(ability.as_ref())?;
        let caveats = self.get(&ability);
        Ok(caveats)
    }
}

impl<A> Select<(A, usize), BTreeMap<String, Value>> for Abilities
where
    A: AsRef<str>,
{
    type Error = UcanError;

    fn select(
        &self,
        (ability, caveat): (A, usize),
    ) -> Result<Option<&BTreeMap<String, Value>>, Self::Error> {
        let caveats = self.select(ability)?;
        let caveat = caveats.and_then(|caveats| caveats.get(caveat));
        Ok(caveat)
    }
}

impl<A, K> Select<(A, usize, K), Value> for Abilities
where
    A: AsRef<str>,
    K: AsRef<str>,
{
    type Error = UcanError;

    fn select(&self, (ability, caveat, key): (A, usize, K)) -> Result<Option<&Value>, Self::Error> {
        let caveat = self.select((ability, caveat))?;
        let key = caveat.and_then(|caveat| caveat.get(key.as_ref()));
        Ok(key)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::caps;

    use super::*;

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
    fn test_capabilities_select() -> anyhow::Result<()> {
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

        let abilities = capabilities
            .select("example://example.com/public/photos/")?
            .unwrap();

        assert_eq!(abilities.len(), 2);

        let caveats = capabilities
            .select(("example://example.com/public/photos/", "crud/read"))?
            .unwrap();

        assert_eq!(caveats.len(), 1);

        let caveat = capabilities
            .select(("example://example.com/public/photos/", "crud/read", 0))?
            .unwrap();

        assert_eq!(caveat.len(), 0);

        let value = capabilities
            .select(("mailto:username@example.com", "msg/receive", 0, "max_count"))?
            .unwrap();

        assert_eq!(value, &5);

        Ok(())
    }
}
