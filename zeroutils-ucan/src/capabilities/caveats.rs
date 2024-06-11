use std::{
    collections::BTreeMap,
    ops::{Deref, Index},
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{UcanError, UcanResult};

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
/// ## Important
/// An empty caveat array means "in no case" does the ability apply, effectively denying access to
/// the associated resource. This behavior is not supported.
///
/// When used in the construction of [`CapabilitiesDefinition`][crate::CapabilitiesDefinition], caveats
/// are expected to be represented as JSON Type Definitions ([JTD][jtd]). More on that in
/// [`CapabilitiesDefinition`][crate::CapabilitiesDefinition]
///
/// [caveats]: https://github.com/ucan-wg/spec?tab=readme-ov-file#3263-caveat-array
/// [jtd]: https://datatracker.ietf.org/doc/html/rfc8927
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caveats(pub(super) Vec<Caveat>);

/// A single caveat that modifies or restricts how an associated ability can be used.
pub type Caveat = Map<String, Value>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Caveats {
    /// Creates the empty `Caveats` instance (`[{}]`) that represents applying to all cases. i.e., no restrictions.
    pub fn any() -> Self {
        Caveats(vec![Map::new()])
    }

    /// Creates a new `Caveats` instance from an iterator.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter(iter: impl IntoIterator<Item = BTreeMap<String, Value>>) -> UcanResult<Self> {
        let caveats: Vec<_> = iter.into_iter().map(Map::from_iter).collect();
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

    /// Gets the caveat at the given index.
    pub fn get(&self, index: usize) -> Option<&Caveat> {
        self.0.get(index)
    }

    /// Checks if the given `requested` caveats are permitted by main caveats.
    ///
    /// An object in the caveat array, represents a caveat. When checking the `requested` caveats array against
    /// the main one, the objects in the caveats array are ORed together while the fields in each object
    /// are ANDed together.
    ///
    /// ### ANDed Fields
    ///
    /// ANDed fields means the value of each object in the `requested` caveats array must have a superset relationship with
    /// corresponding objects in the main caveats array.
    ///
    /// For example, if the main caveat array is `[{ "max_count": 5 }]` and `requested` is
    /// `[{ "max_count": 5, "status": "active" }]`, the `requested` caveats are permitted. This is due to the `AND` semantics
    /// of caveat fields, the `status` field here adds an additional constraint to `requested` caveats.
    ///
    /// ### ORed Array
    ///
    /// Meanwhile, the `requested` caveats array itself has a subset relationship with the main caveats array.
    ///
    /// For example, if the main caveats array contains `[{ "max_count": 5 }, { "status": "active" }]` and `requested` has
    /// `[{ "max_count": 5 }]`, the `requested` caveats are permitted. This is due to the `OR` semantics of the caveats array,
    /// the removal of a caveat object here adds additional restriction, reducing the number of valid cases.
    pub fn permits(&self, requested: &Caveats) -> bool {
        if requested.len() > self.len() {
            return false;
        }

        for requested_caveat in requested.iter() {
            if !self
                .iter()
                .any(|caveat| Caveats::is_subset_object(caveat, requested_caveat))
            {
                return false;
            }
        }

        true
    }

    /// Checks if the given `this` object is a subset of the `that` object. It also takes nested fields into account.
    pub(crate) fn is_subset_object(this: &Map<String, Value>, that: &Map<String, Value>) -> bool {
        for (key, this_value) in this.iter() {
            if let Some(that_value) = that.get(key) {
                match (this_value, that_value) {
                    (Value::Object(this_map), Value::Object(that_map)) => {
                        if !Caveats::is_subset_object(this_map, that_map) {
                            return false;
                        }
                    }
                    (Value::Array(this_array), Value::Array(that_array)) => {
                        if !Caveats::is_subset_array(this_array, that_array) {
                            return false;
                        }
                    }
                    (this_value, that_value) => {
                        if this_value != that_value {
                            return false;
                        }
                    }
                }
            } else {
                return false;
            }
        }

        true
    }

    /// Checks if the given `this` array is a subset of the `that` array.
    pub(crate) fn is_subset_array(this: &[Value], that: &[Value]) -> bool {
        if this.len() > that.len() {
            return false;
        }

        for (this_value, that_value) in this.iter().zip(that.iter()) {
            match (this_value, that_value) {
                (Value::Object(this_map), Value::Object(that_map)) => {
                    if !Caveats::is_subset_object(this_map, that_map) {
                        return false;
                    }
                }
                (Value::Array(this_array), Value::Array(that_array)) => {
                    if !Caveats::is_subset_array(this_array, that_array) {
                        return false;
                    }
                }
                (this_value, that_value) => {
                    if this_value != that_value {
                        return false;
                    }
                }
            }
        }

        true
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Deref for Caveats {
    type Target = Vec<Map<String, Value>>;

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

impl Index<usize> for Caveats {
    type Output = Map<String, Value>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::caveats;

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

    #[test]
    fn test_caveats_indexing() -> anyhow::Result<()> {
        let caveats = caveats! [{
            "max_count": 5,
            "templates": ["newsletter", "marketing"]
        }];

        assert_eq!(caveats[0]["max_count"], 5);
        assert_eq!(caveats[0]["templates"][0], "newsletter");

        Ok(())
    }

    #[test]
    fn test_caveat_is_subset() -> anyhow::Result<()> {
        // Equal

        let this = caveats![{}];

        assert!(Caveats::is_subset_object(&this[0], &this[0]));

        let this = caveats! [{
            "max_count": 5,
            "templates": ["newsletter"]
        }];

        assert!(Caveats::is_subset_object(&this[0], &this[0]));

        // Subset

        let this = caveats![{}];
        let that = caveats! [{"max_count": 5}];

        assert!(Caveats::is_subset_object(&this[0], &that[0]));

        let this = caveats! [{
            "templates": []
        }];

        let that = caveats! [{
            "templates": ["newsletter"]
        }];

        assert!(Caveats::is_subset_object(&this[0], &that[0]));

        let this = caveats! [{
            "max_count": 5,
            "templates": ["newsletter"]
        }];

        let that = caveats! [{
            "max_count": 5,
            "status": "active",
            "templates": ["newsletter", "marketing"]
        }];

        assert!(Caveats::is_subset_object(&this[0], &that[0]));

        let this = caveats! [{
            "status": {},
            "templates": [{
                "newsletter": true
            }]
        }];

        let that = caveats! [{
            "max_count": 5,
            "status": {
                "active": true
            },
            "templates": [{
                "newsletter": true,
                "types": ["marketing"]
            }]
        }];

        assert!(Caveats::is_subset_object(&this[0], &that[0]));

        // Fails

        let this = caveats! [{
            "max_count": 5,
        }];

        let that = caveats![{}];

        assert!(!Caveats::is_subset_object(&this[0], &that[0]));

        let this = caveats! [{
            "max_count": 5,
        }];

        let that = caveats! [{
            "max_count": "5"
        }];

        assert!(!Caveats::is_subset_object(&this[0], &that[0]));

        let this = caveats! [{
            "max_count": 5,
            "templates": ["newsletter"]
        }];

        let that = caveats! [{
            "max_count": 5,
            "status": "active",
        }];

        assert!(!Caveats::is_subset_object(&this[0], &that[0]));

        let this = caveats! [{
            "max_count": 5,
            "status": "active",
            "templates": ["newsletter", "marketing"]
        }];

        let that = caveats! [{
            "max_count": 5,
            "templates": ["newsletter"]
        }];

        assert!(!Caveats::is_subset_object(&this[0], &that[0]));

        Ok(())
    }

    #[test]
    fn test_caveats_permits() -> anyhow::Result<()> {
        let main = caveats![{}];
        let requested = caveats![{"status": "active"}];

        assert!(main.permits(&requested));

        let main = caveats![{"status": "active"}, {"max_count": 5}];
        let requested = caveats![{"status": "active"}];

        assert!(main.permits(&requested));

        let main = caveats![{"status": "active"}, {"max_count": 5}];
        let requested = caveats![{"status": "active"}];

        assert!(main.permits(&requested));

        let main = caveats! [
            {
                "max_count": 5,
                "templates": ["newsletter"]
            },
            {
                "public": true
            }
        ];

        let requested = caveats! [
            {
                "max_count": 5,
                "status": "active",
                "templates": ["newsletter", "marketing"]
            }
        ];

        assert!(main.permits(&requested));

        // Fails

        let main = caveats![{"status": "active"}];
        let requested = caveats![{}];

        assert!(!main.permits(&requested));

        let main = caveats![{"status": "active"}];
        let requested = caveats![{"status": "active"}, {"max_count": 5}];

        assert!(!main.permits(&requested));

        Ok(())
    }
}
