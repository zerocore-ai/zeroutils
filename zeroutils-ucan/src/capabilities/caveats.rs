use std::{collections::BTreeMap, ops::Deref};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Select, UcanError, UcanResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Conditions or stipulations that modify or restrict how an associated ability can be used.
///
/// Caveats function as additional details or requirements that must be met for the ability to be validly exercised,
/// serving as an "escape hatch" to cover use cases not fully captured by resource an ability fields alone.
///
/// Caveats must contain [at least one empty object][caveats] which means the ability applies in all cases.
///
/// NOTE: An empty caveat array means "in no case" does the ability apply, effectively denying access to
/// the associated resource. This behavior is not supported.
///
/// [caveats]: https://github.com/ucan-wg/spec?tab=readme-ov-file#3263-caveat-array
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caveats(Vec<Caveat>);

/// A single caveat that modifies or restricts how an associated ability can be used.
pub type Caveat = BTreeMap<String, Value>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Caveats {
    /// Creates a `Caveats` instance that represents applying to all cases.
    pub fn any() -> Self {
        Caveats(vec![BTreeMap::new()])
    }

    /// Creates a new `Caveats` instance from an iterator.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter(iter: impl IntoIterator<Item = BTreeMap<String, Value>>) -> UcanResult<Self> {
        let caveats: Vec<_> = iter.into_iter().collect();
        if caveats.is_empty() {
            return Err(UcanError::EmptyCaveats);
        }

        if caveats.len() > 1 {
            caveats.iter().try_for_each(|caveat| {
                if caveat.is_empty() {
                    return Err(UcanError::InvalidCaveatsMix);
                }

                Ok(())
            })?;
        }

        Ok(Caveats(caveats))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Deref for Caveats {
    type Target = Vec<BTreeMap<String, Value>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<BTreeMap<String, Value>>> for Caveats {
    type Error = UcanError;

    fn try_from(vec: Vec<BTreeMap<String, Value>>) -> Result<Self, Self::Error> {
        Caveats::from_iter(vec)
    }
}

impl Select<usize, BTreeMap<String, Value>> for Caveats {
    type Error = UcanError;

    fn select(&self, caveat: usize) -> Result<Option<&BTreeMap<String, Value>>, Self::Error> {
        Ok(self.get(caveat))
    }
}

impl<K> Select<(usize, K), Value> for Caveats
where
    K: AsRef<str>,
{
    type Error = UcanError;

    fn select(&self, (caveat, key): (usize, K)) -> Result<Option<&Value>, Self::Error> {
        let caveat = self.select(caveat)?;
        let key = caveat.and_then(|caveat| caveat.get(key.as_ref()));
        Ok(key)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn test_caveats_constructors() -> anyhow::Result<()> {
        let caveats = Caveats::from_iter(vec![BTreeMap::new()])?;

        assert_eq!(caveats.len(), 1);

        // Empty caveats are invalid
        assert!(Caveats::from_iter(vec![]).is_err());

        // Multiple caveats must have at least one non-empty caveat
        assert!(Caveats::from_iter(vec![BTreeMap::new(), BTreeMap::new()]).is_err());

        Ok(())
    }
}
