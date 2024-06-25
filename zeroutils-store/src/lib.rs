//! TODO: Add a description

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod dualstore;
mod error;
mod lrustore;
mod memstore;
mod plcstore;
mod references;
mod storable;
mod store;
pub(crate) mod utils;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use dualstore::*;
pub use error::*;
pub use lrustore::*;
pub use memstore::*;
pub use plcstore::*;
pub use references::*;
pub use storable::*;
pub use store::*;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

/// Re-exports of the `libipld` crate.
pub mod ipld {
    pub use libipld::{cid, codec, multihash};
}
