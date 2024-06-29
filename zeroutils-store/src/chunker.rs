use bytes::Bytes;
use futures::stream::BoxStream;
use tokio::io::AsyncRead;

use crate::StoreResult;

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// A chunker that splits data into chunks and returns a stream of bytes.
///
/// This can be used by stores chunkers.
pub trait Chunker {
    /// Chunks the given reader and returns a stream of bytes.
    fn chunk<'a>(
        &self,
        reader: impl AsyncRead + Send + 'a,
    ) -> StoreResult<BoxStream<'a, StoreResult<Bytes>>>;

    /// Returns the allowed maximum chunk size. If there is no limit, `None` is returned.
    fn chunk_max_size(&self) -> Option<u64>;
}
