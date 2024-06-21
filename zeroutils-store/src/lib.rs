//! TODO: Add a description

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod dualstore;
mod error;
mod ipldstore;
mod lrustore;
mod memstore;
mod plcstore;
mod storable;
pub(crate) mod utils;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use dualstore::*;
pub use error::*;
pub use ipldstore::*;
pub use lrustore::*;
pub use memstore::*;
pub use plcstore::*;
pub use storable::*;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

/// Re-exports of the `libipld` crate.
pub mod ipld {
    pub use libipld::{cid, codec, multihash};
}
