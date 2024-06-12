//! # `zeroutils-ucan`
//!
//! This crate provides a Rust implementation of the [UCAN (User Controlled Authorization Network)][ucan] specification version 0.10.0.
//!
//! UCANs are a decentralized authorization scheme that offers fine-grained, user-centric
//! control over permissions. Unlike traditional access tokens, UCANs can be chained for
//! delegation, enabling complex authorization scenarios without a central authority.
//!
//! **Key Concepts from the UCAN Spec:**
//!
//! * **Trustless:** No central authority is needed for verification; trust is established through cryptographic signatures and Decentralized Identifiers (DIDs).
//! * **Local-first:** Authorization logic resides with the user, promoting privacy.
//! * **Delegable:** Permissions can be fluidly passed along a chain of trust.
//! * **Expressive:**  UCAN payload (`UcanPayload`) allows for a rich set of claims.
//! * **Openly Extensible:** UCANs can be adapted for various use cases.
//!
//! Although this library currently only works for [DID Web Key (`did:wk`)][did-wk] method, there are plans to support `did:key` in the future
//! to make it fully spec-compliant with UCAN v0.10.0. Also note that `did:wk` with locator components are not supported. The did methods supported are expected
//! to be self-certifying.
//!
//! [ucan]: https://github.com/ucan-wg/spec
//! [did-wk]: https://github.com/zerocore-ai/did-wk

#![warn(missing_docs)]
#![allow(clippy::module_inception)]

mod authority;
mod builder;
mod capabilities;
mod error;
mod facts;
mod header;
mod payload;
mod proofs;
mod resolution;
mod signature;
mod ucan;
mod uri;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod testgen;

pub use authority::*;
pub use builder::*;
pub use capabilities::*;
pub use error::*;
pub use facts::*;
pub use header::*;
pub use payload::*;
pub use proofs::*;
pub use resolution::*;
pub use signature::*;
pub use ucan::*;
pub use uri::*;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

/// Re-export of the `serde_json` crate.
pub mod serde_json {
    pub use serde_json::*;
}
