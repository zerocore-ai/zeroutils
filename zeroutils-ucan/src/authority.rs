use crate::CapabilitiesDefinition;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents a root authority that can issue UCANs.
pub struct RootAuthority<'a, K> {
    /// The key of the root authority.
    pub key: K,

    /// The capabilities available to the root authority.
    pub capabilities: CapabilitiesDefinition<'a>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a, K> RootAuthority<'a, K> {
    /// Creates a new root authority.
    pub fn new(key: K, capabilities: CapabilitiesDefinition<'a>) -> Self {
        Self { key, capabilities }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------
