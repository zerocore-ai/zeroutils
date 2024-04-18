use tokio::io::AsyncRead;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents an input stream.
pub struct InputStream<'a> {
    /// The reader.
    _reader: &'a mut dyn AsyncRead,
}
