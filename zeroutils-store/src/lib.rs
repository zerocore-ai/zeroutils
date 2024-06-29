//! TODO: Add a description

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod chunker;
mod error;
mod impls;
mod layout;
mod merkle;
mod references;
mod storable;
mod store;
pub(crate) mod utils;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use chunker::*;
pub use error::*;
pub use impls::*;
pub use layout::*;
pub use merkle::*;
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
