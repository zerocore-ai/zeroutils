//! # `zeroutils-key`
//!
//! A library for working with cryptographic key pairs.

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod ed25519;
mod error;
mod jws;
mod key;
mod p256;
mod secp256k1;
mod traits;
mod x25519;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use ed25519::*;
pub use error::*;
pub use jws::*;
pub use key::*;
pub use p256::*;
pub use secp256k1::*;
pub use traits::*;
pub use x25519::*;
