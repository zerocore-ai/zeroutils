//! Error types of the zeroraft crate.

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub type UcanResult<T> = Result<T, UcanError>;

/// The main error type of the zeroengine crate.
#[derive(Debug, Error)]
pub enum UcanError {}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Creates an `Ok` `UcanResult`.
#[allow(non_snake_case)]
pub fn Ok<T>(value: T) -> UcanResult<T> {
    Result::Ok(value)
}
