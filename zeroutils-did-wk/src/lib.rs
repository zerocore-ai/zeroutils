//! A module for generating and managing `did:wk`s.

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod base;
mod builder;
mod did;
mod doc;
mod error;
mod locator;
mod regex;
mod traits;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use base::*;
pub use builder::*;
pub use did::*;
pub use doc::*;
pub use error::*;
pub use locator::*;
pub use regex::*;
pub use traits::*;
