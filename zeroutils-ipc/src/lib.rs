//! # Zeroutils IPC
//!
//! This crate provides common IPC utilities for the zerocore services.

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod client;
mod error;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use client::*;
pub use error::*;
