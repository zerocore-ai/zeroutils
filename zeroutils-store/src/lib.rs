//! TODO: Add a description

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod disk_ipld_store;
mod error;
mod ipld_store;
mod mem_ipld_store;
pub(crate) mod utils;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use disk_ipld_store::*;
pub use error::*;
pub use ipld_store::*;
pub use mem_ipld_store::*;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

/// Re-exports of the `libipld` crate.
pub mod ipld {
    pub use libipld::{cid, codec, multihash};
}
