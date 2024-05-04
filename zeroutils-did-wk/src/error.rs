//! Error types of the zeroraft crate.

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A type alias for a `Result` that uses `DidError` as the error type.
pub type DidResult<T> = Result<T, DidError>;

/// The main error type of the zeroengine crate.
#[derive(Debug, Error)]
pub enum DidError {
    /// Invalid method.
    #[error("Expected the `did:wk` method.")]
    InvalidMethod,

    /// Invalid key.
    #[error("Expected an encoded key: {0}")]
    InvalidKey(String),

    /// Invalid host.
    #[error("Expected a valid host domain, ipv4 or ipv6 address: {0}")]
    InvalidHost(String),

    /// Invalid port.
    #[error("Expected a valid port number: {0}")]
    InvalidPort(String),

    /// Invalid path.
    #[error("Expected a valid path: {0}")]
    InvalidPath(String),

    /// Invalid locator component.
    #[error("Invalid locator component: {0}")]
    InvalidLocatorComponent(String),

    /// Expected an certain key type.
    #[error("Expected a {0} key type.")]
    ExpectedKeyType(String),

    /// Key error.
    #[error("Key error: {0}")]
    KeyError(#[from] zeroutils_key::KeyError),

    /// Base encoding or decoding error.
    #[error("Base encoding or decoding error: {0}")]
    BaseError(#[from] multibase::Error),
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Creates an `Ok` `DidResult`.
#[allow(non_snake_case)]
pub fn Ok<T>(value: T) -> DidResult<T> {
    Result::Ok(value)
}
