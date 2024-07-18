use std::{error::Error, fmt::Display};

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A type alias for a `Result` that uses `IpcError` as the error type.
pub type IpcResult<T> = Result<T, IpcError>;

/// The main error type.
#[derive(Debug, Error)]
pub enum IpcError {
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

impl IpcError {
    /// Creates a new `Err` result.
    pub fn custom(error: impl Into<anyhow::Error>) -> IpcError {
        IpcError::Custom(AnyError {
            error: error.into(),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Creates an `Ok` `IpcResult`.
#[allow(non_snake_case)]
pub fn Ok<T>(value: T) -> IpcResult<T> {
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
