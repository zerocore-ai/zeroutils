#![warn(missing_docs)]
#![allow(clippy::module_inception)]

//! TODO
//!
//! This module currently only support the following DID methods:
//! - `did:wk`

mod builder;
mod error;
mod ucan;
mod uri;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use builder::*;
pub use error::*;
pub use ucan::*;
pub use uri::*;
