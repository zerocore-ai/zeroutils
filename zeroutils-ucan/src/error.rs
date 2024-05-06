//! Error types of the zeroraft crate.

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
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Creates an `Ok` `UcanResult`.
#[allow(non_snake_case)]
pub fn Ok<T>(value: T) -> UcanResult<T> {
    Result::Ok(value)
}
