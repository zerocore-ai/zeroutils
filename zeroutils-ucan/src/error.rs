//! Error types of the zeroraft crate.

use std::time::SystemTime;

use libipld::{cid::Version, Cid};
use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The result type for UCAN operations.
pub type UcanResult<T> = Result<T, UcanError>;

/// Defines the types of errors that can occur in UCAN operations.
#[derive(Debug, Error)]
pub enum UcanError {
    /// Unable to parse the input.
    #[error("Unable to parse")]
    UnableToParse,

    /// Json (de)serialization errors
    #[error("Json serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Key errors
    #[error("Key error: {0}")]
    KeyError(#[from] zeroutils_key::KeyError),

    /// Base64 decoding errors
    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// Invalid ability
    #[error("Invalid ability: {0}")]
    InvalidAbility(String),

    /// The abilities map of a resource must contain at least one ability
    #[error("The abilities map of a resource must contain at least one ability")]
    NoAbility,

    /// Caveats must contain at least an empty object
    #[error("Caveats must contain at least an empty object")]
    EmptyCaveats,

    /// Invalid mixtures of caveats
    #[error("Invalid mixtures of caveats")]
    InvalidCaveatsMix,

    /// Uri parse error
    #[error("Uri parse error: {0}")]
    UriParseError(#[from] fluent_uri::ParseError),

    /// Did Web Key error
    #[error("Did Web Key error: {0}")]
    DidWebKeyError(#[from] zeroutils_did_wk::DidError),

    /// Invalid proof reference
    #[error("Invalid proof reference: {0}")]
    InvalidProofReference(String),

    /// Cid parse error
    #[error("Cid parse error: {0}")]
    CidParseError(#[from] libipld::cid::Error),

    /// UCAN expired
    #[error("UCAN expired: {0:?}")]
    Expired(SystemTime),

    /// UCAN not yet valid
    #[error("UCAN not yet valid: {0:?}")]
    NotYetValid(SystemTime),

    /// Invalid time bounds
    #[error("Invalid time bounds: nbf: {0:?}, exp: {1:?}")]
    InvalidTimeBounds(SystemTime, SystemTime),

    /// Invalid proof Cid version
    #[error("Invalid proof Cid version: {0:?}")]
    InvalidProofCidVersion(Version),

    /// Invalid proof Cid codec
    #[error("Invalid proof Cid codec: {0}")]
    InvalidProofCidCodec(u64),

    /// Invalid proof Cid hash
    #[error("Invalid proof Cid hash: {0}")]
    InvalidProofCidHash(u64),

    /// Unsupported did:wk with locator component
    #[error("Unsupported did:wk with locator component: {0}")]
    UnsupportedDidWkLocator(String),

    /// Ipld store error
    #[error("Ipld store error: {0}")]
    IpldStoreError(#[from] zeroutils_store::StoreError),

    /// Utf8 error
    #[error("Utf8 error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    /// Proof Cid not found
    #[error("Proof Cid not found: {0}")]
    ProofCidNotFound(Cid),

    /// Principal alignment error
    #[error("Principal alignment failed: our issuer: {0}, their aud: {1}")]
    PrincipalAlignmentFailed(String, String),

    /// Unsupported version
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),

    /// Unsupported token type
    #[error("Unsupported token type: {0}")]
    UnsupportedTokenType(String),
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Creates an `Ok` `UcanResult`.
#[allow(non_snake_case)]
pub fn Ok<T>(value: T) -> UcanResult<T> {
    Result::Ok(value)
}
