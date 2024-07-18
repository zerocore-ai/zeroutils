//! `zeroutils-did` is a library for working with Decentralized Identifiers (DIDs) and DID
//! Documents supported by the `zerocore` ecosystem.

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod base;
mod doc;
mod error;
mod traits;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod did_key;
pub mod did_wk;

pub use base::*;
pub use doc::*;
pub use error::*;
pub use traits::*;
