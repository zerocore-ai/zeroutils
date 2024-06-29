use bytes::Bytes;
use futures::stream::BoxStream;
use libipld::Cid;

use crate::{IpldStore, StoreResult};

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// A layout strategy for organizing a stream of bytes into a graph of blocks.
pub trait Layout {
    /// Organizes a stream of bytes into a graph of blocks storing them as either raw blocks or
    /// IPLD node blocks.
    ///
    /// Method returns a stream of `Cid`s of the blocks that were created and the last `Cid` is
    /// always the root of the graph.
    fn store<'a>(
        &self,
        stream: BoxStream<'a, StoreResult<Bytes>>,
        store: impl IpldStore + Send + 'a,
    ) -> StoreResult<BoxStream<'a, StoreResult<Cid>>>;

    /// Loads the byte chunks associated with a given `Cid`.
    ///
    /// This traverses the graph of blocks to reconstruct the original byte stream.
    fn load<'a>(
        &self,
        cid: &'a Cid,
        store: impl IpldStore + Send + 'a,
    ) -> StoreResult<BoxStream<'a, StoreResult<Bytes>>>;
}
