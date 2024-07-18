use std::{error::Error, fmt::Display};

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A type alias for a `Result` that uses `ConfigError` as the error type.
pub type ConfigResult<T> = Result<T, ConfigError>;

/// The main error type.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// `peer port` and `user port` cannot be the same.
    #[error("Peer and user ports cannot be the same: {0}")]
    EqualPeerUserPorts(u16),

    /// Io error.
    #[error("Io error: {0}")]
    IoError(#[from] std::io::Error),

    /// Toml deserialization error.
    #[error("Toml deserialization error: {0}")]
    TomlError(#[from] toml::de::Error),

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

impl ConfigError {
    /// Creates a new `Err` result.
    pub fn custom(error: impl Into<anyhow::Error>) -> ConfigError {
        ConfigError::Custom(AnyError {
            error: error.into(),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Creates an `Ok` `ConfigResult`.
#[allow(non_snake_case)]
pub fn Ok<T>(value: T) -> ConfigResult<T> {
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
