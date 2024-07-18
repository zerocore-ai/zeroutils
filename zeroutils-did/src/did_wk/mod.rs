//! Module for working with `did:wk:` DIDs.

mod builder;
mod did;
mod locator;
mod regex;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use builder::*;
pub use did::*;
pub use locator::*;
pub use regex::*;
