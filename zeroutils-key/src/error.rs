//! Error types of the zeroraft crate.

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub type KeyResult<T> = Result<T, KeyError>;

/// The main error type of the zeroengine crate.
#[derive(Debug, Error)]
pub enum KeyError {}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Creates an `Ok` `KeyResult`.
#[allow(non_snake_case)]
pub fn Ok<T>(value: T) -> KeyResult<T> {
    Result::Ok(value)
}
