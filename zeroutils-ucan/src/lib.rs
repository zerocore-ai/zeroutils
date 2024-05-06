//! TODO: Add a description
//!
//! This module currently only support the following DID methods:
//! - `did:wk`

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod builder;
mod capabilities;
mod error;
mod facts;
mod header;
mod payload;
mod proofs;
mod signature;
mod ucan;
mod uri;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use builder::*;
pub use capabilities::*;
pub use error::*;
pub use facts::*;
pub use header::*;
pub use payload::*;
pub use proofs::*;
pub use signature::*;
pub use ucan::*;
pub use uri::*;
