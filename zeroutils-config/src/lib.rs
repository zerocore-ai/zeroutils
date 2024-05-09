//! # Zeroutils Config
//!
//! This crate provides common configuration values for the zerocore services.

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod error;
mod traits;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod default;
pub mod network;

pub use error::*;
pub use traits::*;
