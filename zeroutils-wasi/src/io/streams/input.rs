use async_trait::async_trait;
use bytes::Bytes;
use wasmtime::component::Resource;

use crate::{
    bindgen::streams,
    io::{Await, PollableHandle, Subscribe},
    state::WasiTableState,
};

use super::StreamError;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A handle to an input stream.
pub type InputStreamHandle = Box<dyn InputStream>;

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// An input stream implementation that conforms with `wasi:io/streams.input-stream`.
#[async_trait]
pub trait InputStream: Await {
    /// Reads up to `len` bytes from the stream.
    /// This is a non-blocking operation and should return as early as possible.
    ///
    /// If the stream has less than `len` bytes, it should return the available bytes.
    /// If the stream has no bytes, it should return an empty buffer.
    ///
    /// # Errors
    ///
    /// Returns a [`StreamError`] if the stream is closed.
    fn read(&mut self, len: u64) -> Result<Bytes, StreamError>;

    /// Same as `read` except the bytes get skipped and the number of bytes skipped is returned.
    fn skip(&mut self, len: u64) -> Result<u64, StreamError>;
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[async_trait]
impl Await for InputStreamHandle {
    async fn wait(&mut self) {
        (**self).wait().await
    }
}

#[async_trait]
impl<T> streams::HostInputStream for T
where
    T: WasiTableState,
{
    fn read(
        &mut self,
        stream: Resource<InputStreamHandle>,
        len: u64,
    ) -> Result<Vec<u8>, StreamError> {
        let stream: &mut Box<dyn InputStream> = self.table_mut().get_mut(&stream)?;
        stream.read(len).map(|bytes| bytes.to_vec())
    }

    async fn blocking_read(
        &mut self,
        stream: Resource<InputStreamHandle>,
        len: u64,
    ) -> Result<Vec<u8>, StreamError> {
        let stream: &mut Box<dyn InputStream> = self.table_mut().get_mut(&stream)?;
        stream.wait().await;
        stream.read(len).map(|bytes| bytes.to_vec())
    }

    fn skip(&mut self, stream: Resource<InputStreamHandle>, len: u64) -> Result<u64, StreamError> {
        let stream: &mut Box<dyn InputStream> = self.table_mut().get_mut(&stream)?;
        stream.skip(len)
    }

    async fn blocking_skip(
        &mut self,
        stream: Resource<InputStreamHandle>,
        len: u64,
    ) -> Result<u64, StreamError> {
        let stream: &mut Box<dyn InputStream> = self.table_mut().get_mut(&stream)?;
        stream.wait().await;
        stream.skip(len)
    }

    fn subscribe(
        &mut self,
        stream: Resource<InputStreamHandle>,
    ) -> wasmtime::Result<Resource<PollableHandle>> {
        Subscribe::subscribe(stream, self.table_mut())
    }

    fn drop(&mut self, stream: Resource<InputStreamHandle>) -> wasmtime::Result<()> {
        self.table_mut().delete(stream)?;
        Ok(())
    }
}
