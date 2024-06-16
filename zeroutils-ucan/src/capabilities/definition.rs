use std::collections::HashSet;

use jtd::{Schema, ValidateOptions};
use serde_json::Value;

use crate::{Ability, CapabilityTuple, Caveats, NonUcanUri, UcanError, UcanResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// `CapabilitiesDefinition` is a canonical representation of supported _resources_, _abilities_, and _caveats_
/// that lets a verifier quickly determine if a given `resource ✕ ability ✕ caveats` tuple is permitted
/// based on the definition.
///
/// ## Definitions
///
/// Here is how the definitions are structured:
///
/// [**Resources**][crate::ResourceUri] are expected to be non-ucan schemes and are to be represented as their [root] URIs
/// from which other URIs can be derived. For example, the canonical form for a file system resource could be `zerofs://home`
/// which would allow sub-resources such as `zerofs://home/alice` and `zerofs://home/alice/file`.
///
/// [**Abilities**][crate::Abilities] are to be expressed as a set of all actions that can be performed on a resource. This cannot
/// include actions with wildcards as they are not canonical forms. For example, `file/read` and `file/write`
/// could be listed as abilities for a file system resource but not `file/*`.
///
/// [**Caveats**][CaveatsDefinition] are to be defined as JSON Type Definitions ([JTD][jtd]). For example, a caveat could be:
/// ```json
/// [
///     {
///         "properties": {
///             "status": { "type": "string" }
///         },
///         "optionalProperties": {
///             "public": { "type": "boolean" }
///         }
///     }
/// ]
/// ```
///
/// [jtd]: https://datatracker.ietf.org/doc/html/rfc8927
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilitiesDefinition(Vec<(NonUcanUri, Vec<(Ability, CaveatsDefinition)>)>);
// pub struct CapabilitiesDefinition(HashMap<Scheme, (NonUcanUri, HashMap<Ability, CaveatsDefinition>)>);

/// A set of supported caveats represented in JSON Type Definitions ([JTD][jtd]).
///
/// For example, a caveat could be:
/// ```json
/// [
///     {
///         "properties": {
///             "maximum_allowed": { "type": "int32" }
///         }
///     },
///     {
///         "properties": {
///             "status": { "type": "string" }
///         },
///         "optionalProperties": {
///             "public": { "type": "boolean" }
///         }
///     }
/// ]
/// ```
///
/// [jtd]: https://datatracker.ietf.org/doc/html/rfc8927
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaveatsDefinition(HashSet<Schema>);

/// A definition of a capability represented as a tuple of non-ucan resource, ability, and caveats [JTD][jtd].
///
/// [jtd]: https://datatracker.ietf.org/doc/html/rfc8927
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityDefinitionTuple(pub NonUcanUri, pub Ability, pub CaveatsDefinition);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CapabilitiesDefinition {
    /// Creates a new empty capabilities definition.
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if the provided `resource ✕ ability ✕ caveats` capability tuple is an accepted capability within the definition.
    pub fn accepts(&self, _capability: &CapabilityTuple) -> bool {
        // TODO: Implement this method
        todo!()
    }

    /// TODO: Remove
    /// Inserts a new capability into the definition if unique.
    pub fn insert(&mut self, capability: impl Into<CapabilityDefinitionTuple>) {
        let CapabilityDefinitionTuple(resource, ability, caveats_def) = capability.into();

        for (existing_resource, abilities) in self.0.iter_mut() {
            if existing_resource.permits(&resource) {
                // TODO: Dedup
                for (existing_ability, existing_caveats_def) in abilities.iter_mut() {
                    if existing_ability == &ability {
                        if existing_caveats_def == &caveats_def {
                            return;
                        }

                        // existing_caveats_def.union(&caveats_def);
                    }
                }

                abilities.push((ability.clone(), caveats_def.clone()));
            } else if resource.permits(&existing_resource) {
                *existing_resource = resource.clone();
                // TODO: Dedup
                for (existing_ability, existing_caveats_def) in abilities.iter_mut() {
                    if existing_ability == &ability {
                        if existing_caveats_def == &caveats_def {
                            return;
                        }

                        // existing_caveats_def.union(&caveats_def);
                    }
                }

                abilities.push((ability.clone(), caveats_def.clone()));
            }
        }

        self.0.push((resource, vec![(ability, caveats_def)]));
    }

    // pub fn try_from_iter<T>(iter: impl IntoIterator<Item = T>) -> UcanResult<Self>
    // where
    //     T: TryInto<CapabilityDefinitionTuple>,
    //     T::Error: Into<UcanError>,
    // {
    //     todo!()
    // }

    /// Returns the count of capabilities in the definition.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Checks if the definition is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the capability definitions.
    pub fn iter(&self) -> impl Iterator<Item = (&NonUcanUri, &Ability, &CaveatsDefinition)> {
        self.0.iter().flat_map(|(resource, abilities)| {
            abilities
                .iter()
                .map(move |(ability, caveats)| (resource, ability, caveats))
        })
    }
}

impl CaveatsDefinition {
    /// Creates a new `CaveatsDefinition` from an iterator of [`serde_json::Value`]s.
    pub fn try_from_iter(caveats: impl IntoIterator<Item = Value>) -> UcanResult<Self> {
        let mut set = HashSet::new();
        for caveat in caveats {
            let schema = Schema::from_serde_schema(
                serde_json::from_value(caveat.clone()).map_err(|e| UcanError::from(e))?,
            )
            .map_err(|e| UcanError::from(e))?;

            if !matches!(schema, Schema::Properties { .. }) {
                return Err(UcanError::UnsupportedCaveatTypeDefinitionSchemaType(caveat));
            }

            schema.validate().map_err(|e| UcanError::from(e))?;

            set.insert(schema);
        }

        Ok(Self(set))
    }

    /// Checks if the provided `caveat` is accepted by the caveats type definition.
    pub fn accepts(&self, requested: &Caveats) -> UcanResult<()> {
        if self.0.is_empty() && requested.is_any() {
            return Ok(());
        }

        for caveat in requested.iter() {
            for schema in &self.0 {
                let options = ValidateOptions::new().with_max_depth(5).with_max_errors(5);
                let result = jtd::validate(schema, &caveat.0, options)
                    .map_err(UcanError::JtdValidateError)?;

                if result.is_empty() {
                    return Ok(());
                }
            }
        }

        Err(UcanError::CaveatsDefinitionValidationError)
    }

    /// Checks if the definition is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the count of caveats in the definition.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over the caveats.
    pub fn iter(&self) -> impl Iterator<Item = &Schema> {
        self.0.iter()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FromIterator<CapabilityDefinitionTuple> for CapabilitiesDefinition {
    fn from_iter<T: IntoIterator<Item = CapabilityDefinitionTuple>>(iter: T) -> Self {
        let mut set = CapabilitiesDefinition::new();
        for item in iter {
            set.insert(item);
        }

        set
    }
}

impl Default for CapabilitiesDefinition {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl From<(NonUcanUri, Ability, CaveatsDefinition)> for CapabilityDefinitionTuple {
    fn from(tuple: (NonUcanUri, Ability, CaveatsDefinition)) -> Self {
        Self(tuple.0, tuple.1, tuple.2)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::{caps_def, caveats, caveats_def};

    #[test]
    fn test_capabilities_definition() -> anyhow::Result<()> {
        let _caps_def = caps_def! {
            "zerofs://": {
                "dir/read": [{}],
                "dir/write": [{}],
                "dir/file/read": [{}],
                "dir/file/write": [{}],
                "dir/symlink/follow": [{}],
            }
        };

        Ok(())
    }

    #[test]
    fn test_caveats_definition() -> anyhow::Result<()> {
        let caveats = caveats_def![];

        assert!(caveats.is_ok());

        let caveats_def = caveats_def![
            {
                "properties": {
                    "status": { "type": "string" }
                },
                "optionalProperties": {
                    "audience": {
                        "properties": {
                            "type": { "type": "string" }
                        }
                    }
                }
            }
        ];

        assert!(caveats_def.is_ok());

        // Fails
        let caveats_def = caveats_def![
            {
                "status": "published",
                "public": true,
            }
        ];

        assert!(caveats_def.is_err());

        let caveats_def = caveats_def![
            {
                "elements": {
                    "type": "uint8"
                },
            }
        ];

        assert!(caveats_def.is_err());

        Ok(())
    }

    #[test]
    fn test_caveats_def_accepts_caveats() -> anyhow::Result<()> {
        let caveats_def = caveats_def![]?;

        assert!(caveats_def.accepts(&caveats![{}]?).is_ok());

        let caveats_def = caveats_def![
            {
                "properties": {
                    "status": { "type": "string" }
                }
            },
            {
                "properties": {
                    "user": {
                        "properties": {
                            "name": { "type": "string" },
                        },
                        "optionalProperties": {
                            "email": { "type": "string" }
                        }
                    }
                }
            }
        ]?;

        caveats_def.accepts(&caveats! [{ "status": "published" }]?)?;

        assert!(caveats_def
            .accepts(&caveats! [{ "status": "published" }]?)
            .is_ok());

        assert!(caveats_def
            .accepts(&caveats! [{ "user": { "name": "Alice", "email": "alice@example.com" } }]?)
            .is_ok());

        assert!(caveats_def
            .accepts(&caveats! [{ "user": { "name": "Alice" } }]?)
            .is_ok());

        // Fails

        let caveats_def = caveats_def![]?;

        assert!(caveats_def
            .accepts(&caveats! [{ "status": "published" }]?)
            .is_err());

        let caveats_def = caveats_def![
            {
                "properties": {
                    "user": {
                        "properties": {
                            "name": { "type": "string" },
                        },
                    }
                }
            },
        ]?;

        assert!(caveats_def.accepts(&caveats![{}]?).is_err());

        assert!(caveats_def
            .accepts(&caveats! [{ "user": { "name": "Alice", "email": "alice@example.com" } }]?)
            .is_err());

        Ok(())
    }
}
