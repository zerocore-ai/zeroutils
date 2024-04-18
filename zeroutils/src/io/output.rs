use tokio::io::AsyncWrite;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents an output stream.
pub struct OutputStream<'a> {
    /// The writer.
    _writer: &'a mut dyn AsyncWrite,
}
