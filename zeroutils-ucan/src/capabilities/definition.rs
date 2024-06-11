use crate::{Ability, Capabilities, Caveats, ResourceUri, UcanError, UcanResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// `CapabilitiesDefinition` is a canonical representation of supported _resources_, _abilities_, and _caveats_
/// that lets a verifier quickly determine if a given `resource ✕ ability ✕ caveats` access tuple is allowed.
///
/// This is a newtype wrapper around [`Capabilities`][crate::Capabilities] that does validations and
/// canonicalization to ensure that the capabilities defined are well-formed.
///
/// ## Definitions
///
/// [**Resources**][crate::ResourceUri] are to be represented as their [root] URIs from which other URIs can be derived.
/// For example, the canonical form for a file system resource could be `zerofs://` which would allow
/// sub-resources such as `zerofs://home/` and `zerofs://home/alice/`.
///
/// [**Abilities**][crate::Abilities] are to be expressed as a set of all actions that can be performed on a resource. This cannot
/// include actions with wildcards as they are not canonical forms. For example, `file/read` and `file/write`
/// could be listed as abilities for a file system resource but not `file/*`.
///
/// [**Caveats**][crate::Caveats] are to be expressed using JSON Type Definitions ([JTD][jtd]). For example, a caveat could be:
/// ```json
/// {
///     "properties": {
///         "maximum_allowed": { "type": "int32" }
///     }
/// }
/// ```
///
/// [jtd]: https://datatracker.ietf.org/doc/html/rfc8927
pub struct CapabilitiesDefinition<'a>(Capabilities<'a>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> CapabilitiesDefinition<'a> {
    /// Validates and canonicalizes the capabilities definition.
    pub fn canonicalize(_capabilities: Capabilities<'a>) -> UcanResult<Self> {
        // TODO: Implement this method
        Ok(Self(_capabilities))
    }

    /// Checks if the given `resource ✕ ability ✕ caveats` access tuple is included in the definition.
    pub fn includes(&self, _resource: &ResourceUri, _ability: &Ability, _caveats: &Caveats) {
        todo!()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'a> TryFrom<Capabilities<'a>> for CapabilitiesDefinition<'a> {
    type Error = UcanError;

    fn try_from(capabilities: Capabilities<'a>) -> Result<Self, Self::Error> {
        CapabilitiesDefinition::canonicalize(capabilities)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // use crate::caps;

    // use super::*;

    // #[test]
    // fn test_capabilities_definition() -> anyhow::Result<()> {
    //     let _caps_def = CapabilitiesDefinition::try_from(caps! {
    //         "zerofs://": {
    //             "dir/read": [{}],
    //             "dir/write": [{}],
    //             "dir/file/read": [{}],
    //             "dir/file/write": [{}],
    //             "dir/symlink/follow": [{}],
    //         }
    //     })?;

    //     Ok(())
    // }
}
