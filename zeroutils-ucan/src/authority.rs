use crate::CapabilitiesDefinition;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents a root authority that can issue UCANs.
pub struct RootAuthority<K> {
    /// The key of the root authority.
    pub key: K,

    /// The capabilities available to the root authority.
    pub capabilities_definition: CapabilitiesDefinition,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<K> RootAuthority<K> {
    /// Creates a new root authority.
    pub fn new(key: K, capabilities_definition: CapabilitiesDefinition) -> Self {
        Self {
            key,
            capabilities_definition,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------
