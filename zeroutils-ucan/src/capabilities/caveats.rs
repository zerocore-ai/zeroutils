use std::{
    fmt::Display,
    hash::{Hash, Hasher},
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
///
/// An empty caveat array means "in no case" does the ability apply, effectively denying access to
/// the associated resource. This behavior is not supported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caveats(pub(super) Vec<Caveat>);

/// A single caveat that modifies or restricts how an associated ability can be used.
///
/// A caveat must be a valid JSON object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caveat(pub(super) Value);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Caveats {
    /// Creates the empty `Caveats` instance (`[{}]`) that represents applying to all cases. i.e., no restrictions.
    pub fn any() -> Self {
        Caveats(vec![Caveat::default()])
    }

    /// Returns true if caveats is an any caveats.
    pub fn is_any(&self) -> bool {
        self.0.len() == 1 && self.0[0].is_empty()
    }

    /// Creates a new `Caveats` instance from an iterator.
    pub fn try_from_iter<T>(iter: impl IntoIterator<Item = T>) -> UcanResult<Self>
    where
        T: TryInto<Caveat>,
        T::Error: Into<UcanError>,
    {
        let caveats = iter
            .into_iter()
            .map(T::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)?;

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
                .any(|caveat| Caveat::is_subset(&caveat.0, &requested_caveat.0))
            {
                return false;
            }
        }

        true
    }
}

impl Caveat {
    /// Creates a new empty caveat.
    pub fn new() -> Self {
        Caveat::default()
    }

    /// Returns true if the caveat is empty.
    pub fn is_empty(&self) -> bool {
        self.as_object().is_empty()
    }

    /// Returns the number of fields in the caveat.
    pub fn len(&self) -> usize {
        self.as_object().len()
    }

    /// Returns the caveat as a map.
    pub fn as_object(&self) -> &Map<String, Value> {
        match &self.0 {
            Value::Object(map) => map,
            _ => panic!("Caveat is not an object"),
        }
    }

    /// Checks if the given `this` json value is a subset of the `that` json value. Nested fields are also taken into account.
    pub(crate) fn is_subset(this: &Value, that: &Value) -> bool {
        match (this, that) {
            (Value::Object(this_map), Value::Object(that_map)) => {
                for (key, value) in this_map.iter() {
                    if let Some(that_value) = that_map.get(key) {
                        if !Caveat::is_subset(value, that_value) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }
            (Value::Array(this_array), Value::Array(that_array)) => {
                if this_array.len() > that_array.len() {
                    return false;
                }

                for (this_value, that_value) in this_array.iter().zip(that_array.iter()) {
                    if !Caveat::is_subset(this_value, that_value) {
                        return false;
                    }
                }
            }
            (this_value, that_value) => {
                if this_value != that_value {
                    return false;
                }
            }
        };

        true
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Deref for Caveats {
    type Target = Vec<Caveat>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Index<usize> for Caveats {
    type Output = Caveat;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl Display for Caveats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json_array = Value::Array(
            self.0
                .clone()
                .into_iter()
                .map(|caveat| caveat.0)
                .collect::<Vec<_>>(),
        );

        write!(f, "{}", json_array)
    }
}

impl Hash for Caveats {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        for caveat in self.0.iter() {
            for (key, value) in caveat.as_object().iter() {
                key.hash(state);
                value.to_string().hash(state); // TODO: Not optimal, but works for now. This works because `serde_json::Value` uses BTreeMap
            }
        }
    }
}

impl TryFrom<Value> for Caveat {
    type Error = UcanError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if !matches!(value, Value::Object(_)) {
            return Err(UcanError::InvalidCaveat(value));
        }

        Ok(Caveat(value))
    }
}

impl Index<&str> for Caveat {
    type Output = Value;

    fn index(&self, index: &str) -> &Self::Output {
        self.as_object().get(index).unwrap()
    }
}

impl Default for Caveat {
    fn default() -> Self {
        Caveat(Value::Object(Map::new()))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use crate::caveats;

    use super::*;

    #[test]
    fn test_caveats_constructors() -> anyhow::Result<()> {
        let caveats = Caveats::try_from_iter([Caveat::default()])?;

        assert_eq!(caveats.len(), 1);

        // Empty caveats are invalid
        assert!(Caveats::try_from_iter(Vec::<Caveat>::new()).is_err());

        // Multiple caveats must have at least one non-empty caveat
        assert!(Caveats::try_from_iter([Caveat::default(), Caveat::default()]).is_err());

        Ok(())
    }

    #[test]
    fn test_caveats_indexing() -> anyhow::Result<()> {
        let caveats = caveats! [{
            "max_count": 5,
            "templates": ["newsletter", "marketing"]
        }]?;

        assert_eq!(caveats[0]["max_count"], 5);
        assert_eq!(caveats[0]["templates"][0], "newsletter");

        Ok(())
    }

    #[test]
    fn test_caveat_is_subset() -> anyhow::Result<()> {
        // Equal

        let this = caveats![{}]?;

        assert!(Caveat::is_subset(&this[0].0, &this[0].0));

        let this = caveats! [{
            "max_count": 5,
            "templates": ["newsletter"]
        }]?;

        assert!(Caveat::is_subset(&this[0].0, &this[0].0));

        // Subset

        let this = caveats![{}]?;
        let that = caveats! [{"max_count": 5}]?;

        assert!(Caveat::is_subset(&this[0].0, &that[0].0));

        let this = caveats! [{
            "max_count": 5,
        }]?;

        let that = caveats! [{
            "max_count": 5,
            "status": "active",
        }]?;

        assert!(Caveat::is_subset(&this[0].0, &that[0].0));

        let this = caveats! [{
            "templates": []
        }]?;

        let that = caveats! [{
            "templates": ["newsletter"]
        }]?;

        assert!(Caveat::is_subset(&this[0].0, &that[0].0));

        let this = caveats! [{
            "max_count": 5,
            "templates": ["newsletter"]
        }]?;

        let that = caveats! [{
            "max_count": 5,
            "status": "active",
            "templates": ["newsletter", "marketing"]
        }]?;

        assert!(Caveat::is_subset(&this[0].0, &that[0].0));

        let this = caveats! [{
            "status": {},
            "templates": [{
                "newsletter": true
            }]
        }]?;

        let that = caveats! [{
            "max_count": 5,
            "status": {
                "active": true
            },
            "templates": [{
                "newsletter": true,
                "types": ["marketing"]
            }]
        }]?;

        assert!(Caveat::is_subset(&this[0].0, &that[0].0));

        // Fails

        let this = caveats! [{
            "max_count": 5,
        }]?;

        let that = caveats![{}]?;

        assert!(!Caveat::is_subset(&this[0].0, &that[0].0));

        let this = caveats! [{
            "max_count": 5,
        }]?;

        let that = caveats! [{
            "max_count": "5"
        }]?;

        assert!(!Caveat::is_subset(&this[0].0, &that[0].0));

        let this = caveats! [{
            "max_count": 5,
            "templates": ["newsletter"]
        }]?;

        let that = caveats! [{
            "max_count": 5,
            "status": "active",
        }]?;

        assert!(!Caveat::is_subset(&this[0].0, &that[0].0));

        let this = caveats! [{
            "max_count": 5,
            "status": "active",
            "templates": ["newsletter", "marketing"]
        }]?;

        let that = caveats! [{
            "max_count": 5,
            "templates": ["newsletter"]
        }]?;

        assert!(!Caveat::is_subset(&this[0].0, &that[0].0));

        Ok(())
    }

    #[test]
    fn test_caveats_permits() -> anyhow::Result<()> {
        let main = caveats![{}]?;
        let requested = caveats![{}]?;

        assert!(main.permits(&requested));

        let main = caveats![{"status": "active"}]?;
        let requested = caveats![{"status": "active"}]?;

        assert!(main.permits(&requested));

        let main = caveats![{}]?;
        let requested = caveats![{"status": "active"}]?;

        assert!(main.permits(&requested));

        let main = caveats![{"status": "active"}, {"max_count": 5}]?;
        let requested = caveats![{"status": "active"}]?;

        assert!(main.permits(&requested));

        let main = caveats![{"status": "active"}, {"max_count": 5}]?;
        let requested =
            caveats![{"status": "active"}, {"max_count": 5, "templates": ["newsletter"]}]?;

        assert!(main.permits(&requested));

        let main = caveats! [
            {
                "max_count": 5,
                "templates": ["newsletter"]
            },
            {
                "public": true
            }
        ]?;

        let requested = caveats! [
            {
                "max_count": 5,
                "status": "active",
                "templates": ["newsletter", "marketing"]
            }
        ]?;

        assert!(main.permits(&requested));

        // Fails

        let main = caveats![{"status": "active"}]?;
        let requested = caveats![{}]?;

        assert!(!main.permits(&requested));

        let main = caveats![{"status": "active"}]?;
        let requested = caveats![{"status": "active"}, {"max_count": 5}]?;

        assert!(!main.permits(&requested));

        Ok(())
    }
}
