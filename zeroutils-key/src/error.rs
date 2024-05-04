//! Error types of the zeroraft crate.

use std::{error::Error, fmt::Display};

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A type alias for a `Result` that uses `KeyError` as the error type.
pub type KeyResult<T> = Result<T, KeyError>;

/// The main error type of the zeroengine crate.
#[derive(Debug, Error)]
pub enum KeyError {
    /// `ed25519` error.
    #[error("ed25519 error: {0}")]
    ED25519Error(#[from] ed25519_dalek::SignatureError),

    /// `secp256k1` error.
    #[error("secp256k1 error: {0}")]
    Secp256k1Error(#[from] libsecp256k1::Error),

    /// Custom error.
    #[error("Custom error: {0}")]
    Custom(#[from] AnyError),
}

/// An error that can represent any error.
#[derive(Debug)]
pub struct AnyError {
    error: anyhow::Error,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl KeyError {
    /// Creates a new `Err` result.
    pub fn custom(error: impl Into<anyhow::Error>) -> KeyError {
        KeyError::Custom(AnyError {
            error: error.into(),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Creates an `Ok` `KeyResult`.
#[allow(non_snake_case)]
pub fn Ok<T>(value: T) -> KeyResult<T> {
    Result::Ok(value)
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl PartialEq for AnyError {
    fn eq(&self, other: &Self) -> bool {
        self.error.to_string() == other.error.to_string()
    }
}

impl Display for AnyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl Error for AnyError {}
