use thiserror::Error;

use crate::wasi::io::IoError;

use super::constant;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Error type for stream operations.
#[derive(Debug, Error)]
pub enum StreamError {
    /// Stream is already closed.
    #[error("Stream is already closed")]
    Closed,

    /// Last operation failed.
    #[error("Last operation failed: {0}")]
    LastOperationFailed(IoError),

    /// An error that occurred while using wasmtime resource table.
    #[error("Resource table error: {0}")]
    ResourceTableError(#[from] wasmtime::component::ResourceTableError),

    /// Bytes to be written to stream is larger than the maximum write size.
    #[error(
        "Bytes to be written is larger than `MAX_WRITE_SIZE`({}): {0}",
        constant::MAX_WRITE_SIZE
    )]
    WriteTooLarge(u64),

    /// Downstream error.
    #[error("Downstream error: {0}")]
    DownstreamError(#[from] anyhow::Error),
}
