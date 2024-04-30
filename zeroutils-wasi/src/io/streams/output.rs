use async_trait::async_trait;
use bytes::Bytes;
use wasmtime::component::Resource;

use crate::{
    bindgen::streams,
    io::{PollableHandle, Subscribe},
    state::WasiTableState,
};

use super::{constant, InputStreamHandle, StreamError};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A handle to an output stream.
pub type OutputStreamHandle = Box<dyn OutputStream>;

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// An output stream implementation that conforms with `wasi:io/streams.output-stream`.
#[async_trait]
pub trait OutputStream: Subscribe {
    /// Writes bytes to the stream. This is a non-blocking operation.
    ///
    /// This operation requires that `check_write_permit` is called first to ensure that
    /// the stream can accept that amount of bytes to be written. If the stream cannot accept
    /// the bytes, the operation should fail.
    ///
    /// # Errors
    ///
    /// Returns a [`StreamError`] if:
    /// - stream is closed
    /// - prior operation ([`write`](Self::write) or [`flush`](Self::flush)) failed
    /// - caller performed an illegal operation (e.g. wrote more bytes than were permitted)
    fn write(&mut self, bytes: Bytes) -> Result<(), StreamError>;

    /// Flushes the stream to ensure any buffered bytes is written.
    ///
    /// This is a non-blocking operation and can be called at any time.
    ///
    /// # Errors
    ///
    /// Returns a [`StreamError`] if:
    /// - stream is closed
    /// - prior operation ([`write`](Self::write) or [`flush`](Self::flush)) failed
    /// - caller performed an illegal operation (e.g. wrote more bytes than were permitted)
    fn flush(&mut self) -> Result<(), StreamError>;

    /// A non-blocking check for the number of bytes the stream can currently accept to
    /// be written to it.
    ///
    /// # Errors
    ///
    /// Returns a [`StreamError`] if:
    /// - stream is closed
    /// - prior operation ([`write`](Self::write) or [`flush`](Self::flush)) failed
    fn write_permit(&mut self) -> Result<u64, StreamError>;

    /// Waits for the stream to be ready for writing and returns the number bytes that
    /// can be written to it.
    async fn blocking_write_permit(&mut self) -> Result<u64, StreamError> {
        self.block().await;
        self.write_permit()
    }

    /// Same as `write` but writes `len` amount of zeroes to the stream.
    fn write_zeroes(&mut self, len: u64) -> Result<(), StreamError> {
        self.write(Bytes::from(vec![0; len as usize]))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[async_trait]
impl<T> streams::HostOutputStream for T
where
    T: WasiTableState,
{
    fn check_write(&mut self, stream: Resource<OutputStreamHandle>) -> Result<u64, StreamError> {
        self.table_mut().get_mut(&stream)?.write_permit()
    }

    fn write(
        &mut self,
        stream: Resource<OutputStreamHandle>,
        bytes: Vec<u8>,
    ) -> Result<(), StreamError> {
        self.table_mut().get_mut(&stream)?.write(bytes.into())
    }

    async fn blocking_write_and_flush(
        &mut self,
        stream: Resource<OutputStreamHandle>,
        bytes: Vec<u8>,
    ) -> Result<(), StreamError> {
        let stream = self.table_mut().get_mut(&stream)?;

        // Check if the write size is too large.
        let byte_len = bytes.len() as u64;
        if byte_len > constant::MAX_WRITE_SIZE {
            return Err(StreamError::WriteTooLarge(byte_len));
        }

        // Write bytes in chunks of permitted size. The loop makes it a blocking operation.
        let mut bytes = Bytes::from(bytes);
        while !bytes.is_empty() {
            let write_len = stream.write_permit()? as usize;
            let min_write_len = bytes.len().min(write_len);
            let chunk = bytes.split_to(min_write_len);
            stream.write(chunk)?;
        }

        stream.flush()?; // Flush the stream.
        stream.block().await; // Wait for the stream to be ready again to be sure all data is written.

        Ok(())
    }

    fn write_zeroes(
        &mut self,
        stream: Resource<OutputStreamHandle>,
        len: u64,
    ) -> Result<(), StreamError> {
        self.table_mut().get_mut(&stream)?.write_zeroes(len)
    }

    async fn blocking_write_zeroes_and_flush(
        &mut self,
        stream: Resource<OutputStreamHandle>,
        len: u64,
    ) -> Result<(), StreamError> {
        let stream = self.table_mut().get_mut(&stream)?;

        // Check if the write size is too large.
        if len > constant::MAX_WRITE_SIZE {
            return Err(StreamError::WriteTooLarge(len));
        }

        // Write zeroes in chunks of permitted size. The loop makes it a blocking operation.
        let mut len = len;
        while len > 0 {
            let write_len = stream.write_permit()?;
            let min_write_len = len.min(write_len);
            stream.write_zeroes(min_write_len)?;
            len -= min_write_len;
        }

        stream.flush()?; // Flush the stream.
        stream.block().await; // Wait for the stream to be ready again to be sure all data is written.

        Ok(())
    }

    fn flush(&mut self, stream: Resource<OutputStreamHandle>) -> Result<(), StreamError> {
        self.table_mut().get_mut(&stream)?.flush()
    }

    async fn blocking_flush(
        &mut self,
        stream: Resource<OutputStreamHandle>,
    ) -> Result<(), StreamError> {
        let stream = self.table_mut().get_mut(&stream)?;
        stream.flush()?;
        stream.block().await; // Wait for the stream to be ready again to be sure all data is written.
        Ok(())
    }

    async fn splice(
        &mut self,
        dest: Resource<OutputStreamHandle>,
        src: Resource<InputStreamHandle>,
        len: u64,
    ) -> Result<u64, StreamError> {
        let write_len = self.table_mut().get_mut(&dest)?.write_permit()?;
        let min_write_len = len.min(write_len);
        if min_write_len == 0 {
            return Ok(0);
        }

        let src_stream = self.table_mut().get_mut(&src)?;
        let bytes = src_stream.read(min_write_len)?;
        let bytes_len = bytes.len() as u64;
        if bytes_len == 0 {
            return Ok(0);
        }

        let dest_stream = self.table_mut().get_mut(&dest)?;
        dest_stream.write(bytes)?;
        Ok(bytes_len)
    }

    async fn blocking_splice(
        &mut self,
        dest: Resource<OutputStreamHandle>,
        src: Resource<InputStreamHandle>,
        len: u64,
    ) -> Result<u64, StreamError> {
        // TODO(appcypher): This is based on https://github.com/bytecodealliance/wasmtime/blob/7de48789b788b4554919b28559f80c5dc395e038/crates/wasi/src/host/io.rs#L158-L172
        // TODO(appcypher): But shouldn't `blocking_splice` be similar to `blocking_write_and_flush` by writing exactly `len` bytes from `src` to `dest` instead of writing as much as possible?
        self.table_mut().get_mut(&src)?.block().await;
        self.table_mut().get_mut(&dest)?.block().await;
        self.splice(dest, src, len).await
    }

    fn subscribe(
        &mut self,
        stream: Resource<OutputStreamHandle>,
    ) -> wasmtime::Result<Resource<PollableHandle>> {
        Subscribe::subscribe(stream, self.table_mut())
    }

    fn drop(&mut self, stream: Resource<OutputStreamHandle>) -> wasmtime::Result<()> {
        self.table_mut().delete(stream)?;
        Ok(())
    }
}

#[async_trait]
impl Subscribe for OutputStreamHandle {
    async fn block(&self) {
        (**self).block().await;
    }
}
