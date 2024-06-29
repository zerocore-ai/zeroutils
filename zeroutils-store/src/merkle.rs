use libipld::Cid;
use serde::{Deserialize, Serialize};

use crate::IpldReferences;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A `MerkleNode` is a simple data structure for constructing a Directed Acyclic Graph (DAG) out of
/// multiple leaf data. It is a non-leaf data structure containing references (CIDs) its direct
/// dependencies which can be either leaf or non-leaf data structures.
///
/// This data structure is usually used internally by `IpldStore`s to store chunked data in a way that
/// preserves the original order of the data. See [`MemoryStore`] for an example of how this is
/// used.
///
/// # Important
///
/// The serialized form of this data structure is typically expected to fit in a single node block.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MerkleNode {
    /// The size in bytes of the data this node represents.
    pub size: usize,

    /// The CIDs of the direct dependencies of this node.
    pub dependencies: Vec<Cid>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MerkleNode {
    /// Create a new `MerkleNode` with the given size and dependencies.
    pub fn new(size: usize, dependencies: impl IntoIterator<Item = Cid>) -> Self {
        Self {
            size,
            dependencies: dependencies.into_iter().collect(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl IpldReferences for MerkleNode {
    fn references<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Cid> + Send + 'a> {
        Box::new(self.dependencies.iter())
    }
}
