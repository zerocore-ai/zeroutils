use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The result of a path operation.
pub type PathResult<T> = Result<T, PathError>;

/// An error that occurred during a path operation.
#[derive(Debug, Error)]
pub enum PathError {
    /// When a path segment is invalid.
    #[error("Invalid path segment: {0:?}")]
    InvalidPathSegment(String),

    /// Leading `.` in path.
    #[error("Leading `.` in path")]
    LeadingCurrentDir,

    /// Out of bounds `..` in path.
    #[error("Out of bounds `..` in path")]
    OutOfBoundsParentDir,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Creates an `Ok` `PathResult`.
#[allow(non_snake_case)]
pub fn Ok<T>(value: T) -> PathResult<T> {
    Result::Ok(value)
}
