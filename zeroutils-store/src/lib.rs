//! TODO: Add a description

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod disk_store;
mod error;
mod mem_store;
mod store;
pub(crate) mod utils;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use disk_store::*;
pub use error::*;
pub use mem_store::*;
pub use store::*;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

/// Re-exports of the `libipld` crate.
pub mod ipld {
    pub use libipld::{cid, codec, multihash};
}
