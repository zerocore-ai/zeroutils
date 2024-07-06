use std::pin::Pin;

use bytes::Bytes;
use futures::{stream::BoxStream, Future};
use libipld::Cid;
use tokio::io::AsyncRead;

use crate::{IpldStore, SeekableReader, StoreResult};

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// A layout strategy for organizing a stream of chunks into a graph of blocks.
pub trait Layout {
    /// Organizes a stream of chunks into a graph of blocks storing them as either raw blocks or
    /// IPLD node blocks.
    ///
    /// Method returns a stream of `Cid`s of the blocks that were created and the last `Cid` is
    /// always the root of the graph.
    fn organize<'a>(
        &self,
        stream: BoxStream<'a, StoreResult<Bytes>>,
        store: impl IpldStore + Send + Sync + 'a,
    ) -> impl Future<Output = StoreResult<BoxStream<'a, StoreResult<Cid>>>> + Send;

    /// Retrieves the underlying byte chunks associated with a given `Cid`.
    ///
    /// This traverses the graph of blocks to reconstruct the original byte stream.
    fn retrieve<'a>(
        &self,
        cid: &Cid,
        store: impl IpldStore + Send + Sync + 'a,
    ) -> impl Future<Output = StoreResult<Pin<Box<dyn AsyncRead + Send + 'a>>>> + Send;
}

/// A trait that extends the `Layout` trait to allow for seeking.
pub trait LayoutSeekable: Layout {
    /// Retrieves the underlying byte chunks associated with a given `Cid` as a seekable reader.
    fn retrieve_seekable<'a>(
        &self,
        cid: &'a Cid,
        store: impl IpldStore + Send + Sync + 'a,
    ) -> impl Future<Output = StoreResult<Pin<Box<dyn SeekableReader + Send + 'a>>>> + Send;
}
