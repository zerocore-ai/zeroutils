//! TODO: Add a description

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod diskstore;
mod dualstore;
mod error;
mod memstore;
mod plcstore;
mod store;
pub(crate) mod utils;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use diskstore::*;
pub use dualstore::*;
pub use error::*;
pub use memstore::*;
pub use plcstore::*;
pub use store::*;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

/// Re-exports of the `libipld` crate.
pub mod ipld {
    pub use libipld::{cid, codec, multihash};
}
