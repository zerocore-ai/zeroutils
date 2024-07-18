use std::pin::pin;

use async_stream::try_stream;
use bytes::Bytes;
use futures::stream::BoxStream;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::cas::{Chunker, StoreError, StoreResult};

use super::DEFAULT_CHUNK_MAX_SIZE;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// `FixedSizeChunker` splits data into fixed-size chunks, regardless of the content, in a simple
/// and deterministic.
#[derive(Clone, Debug)]
pub struct FixedSizeChunker {
    /// The size of each chunk.
    chunk_size: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FixedSizeChunker {
    /// Creates a new `FixedSizeChunker` with the given `chunk_size`.
    pub fn new(chunk_size: u64) -> Self {
        Self { chunk_size }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Chunker for FixedSizeChunker {
    async fn chunk<'a>(
        &self,
        reader: impl AsyncRead + Send + 'a,
    ) -> StoreResult<BoxStream<'a, StoreResult<Bytes>>> {
        let chunk_size = self.chunk_size;

        let s = try_stream! {
            let reader = pin!(reader);
            let mut chunk_reader = reader.take(chunk_size); // Derives a reader for reading the first chunk.

            loop {
                let mut chunk = vec![];
                let n = chunk_reader.read_to_end(&mut chunk).await.map_err(StoreError::custom)?;

                if n == 0 {
                    break;
                }

                yield Bytes::from(chunk);

                chunk_reader = chunk_reader.into_inner().take(chunk_size); // Derives a reader for reading the next chunk.
            }
        };

        Ok(Box::pin(s))
    }

    fn chunk_max_size(&self) -> Option<u64> {
        Some(self.chunk_size)
    }
}

impl Default for FixedSizeChunker {
    fn default() -> Self {
        Self::new(DEFAULT_CHUNK_MAX_SIZE)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;

    #[tokio::test]
    async fn test_fixed_size_chunker() -> anyhow::Result<()> {
        let data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        let chunker = FixedSizeChunker::new(10);

        let mut chunk_stream = chunker.chunk(&data[..]).await?;
        let mut chunks = vec![];

        while let Some(chunk) = chunk_stream.next().await {
            chunks.push(chunk?);
        }

        assert_eq!(chunks.len(), 6);
        assert_eq!(chunks[0].to_vec(), b"Lorem ipsu");
        assert_eq!(chunks[1].to_vec(), b"m dolor si");
        assert_eq!(chunks[2].to_vec(), b"t amet, co");
        assert_eq!(chunks[3].to_vec(), b"nsectetur ");
        assert_eq!(chunks[4].to_vec(), b"adipiscing");
        assert_eq!(chunks[5].to_vec(), b" elit.");

        Ok(())
    }
}
