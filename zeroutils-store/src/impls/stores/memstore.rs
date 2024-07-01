use std::{
    collections::{HashMap, HashSet},
    pin::Pin,
    sync::Arc,
};

use bytes::Bytes;
use futures::StreamExt;
use libipld::Cid;
use serde::{de::DeserializeOwned, Serialize};
use tokio::{io::AsyncRead, sync::RwLock};
use tokio_util::io::StreamReader;

use crate::{
    utils, Chunker, Codec, FixedSizeChunker, FlatDagLayout, IpldReferences, IpldStore, Layout,
    StoreError, StoreResult,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An in-memory storage for IPLD node and raw blocks with reference counting.
///
/// This store maintains a reference count for each stored block. Reference counting is used to
/// determine when a block can be safely removed from the store.
#[derive(Debug, Clone)]
// TODO: Use RabinChunker and BalancedDagLayout as default
pub struct MemoryStore<C = FixedSizeChunker, L = FlatDagLayout>
where
    C: Chunker,
    L: Layout,
{
    /// Represents the blocks stored in the store.
    ///
    /// When data is added to the store, it may not necessarily fit into the acceptable block size
    /// limit, so it is chunked into smaller blocks.
    ///
    /// The `usize` is used for counting the references to blocks within the store.
    blocks: Arc<RwLock<HashMap<Cid, (usize, Bytes)>>>,

    /// The chunking algorithm used to split data into chunks.
    chunker: C,

    /// The layout strategy used to store chunked data.
    layout: L,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<C, L> MemoryStore<C, L>
where
    C: Chunker,
    L: Layout,
{
    /// Creates a new `MemoryStore` with the given `chunker` and `layout`.
    pub fn new(chunker: C, layout: L) -> Self {
        MemoryStore {
            blocks: Arc::new(RwLock::new(HashMap::new())),
            chunker,
            layout,
        }
    }

    /// Prints all the blocks in the store.
    pub async fn print(&self) {
        let blocks = self.blocks.read().await;
        for (cid, (size, bytes)) in blocks.iter() {
            println!("\ncid: {} ({:?})\nkey: {}", cid, size, hex::encode(bytes));
        }
    }

    /// Increments the reference count of the blocks with the given `Cid`s.
    async fn inc_refs(&self, cids: impl Iterator<Item = &Cid>) {
        for cid in cids {
            if let Some((size, _)) = self.blocks.write().await.get_mut(cid) {
                *size += 1;
            }
        }
    }

    /// Stores raw bytes in the store without any size checks.
    async fn store_raw(&self, bytes: Bytes, codec: Codec) -> Cid {
        let cid = utils::make_cid(codec, &bytes);
        self.blocks.write().await.insert(cid, (1, bytes));
        cid
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<C, L> IpldStore for MemoryStore<C, L>
where
    C: Chunker + Clone + Send + Sync,
    L: Layout + Clone + Send + Sync,
{
    async fn put_node<T>(&self, data: &T) -> StoreResult<Cid>
    where
        T: Serialize + IpldReferences + Sync,
    {
        // Serialize the data to bytes.
        let bytes = Bytes::from(serde_ipld_dagcbor::to_vec(&data).map_err(StoreError::custom)?);

        // Check if the data exceeds the node maximum block size.
        if let Some(max_size) = self.node_block_max_size() {
            if bytes.len() as u64 > max_size {
                return Err(StoreError::NodeBlockTooLarge(bytes.len() as u64, max_size));
            }
        }

        // Increment the reference count of the block.
        self.inc_refs(data.references()).await;

        Ok(self.store_raw(bytes, Codec::DagCbor).await)
    }

    async fn put_bytes(&self, reader: impl AsyncRead + Send) -> StoreResult<Cid> {
        let chunk_stream = self.chunker.chunk(reader)?;
        let mut cid_stream = self.layout.store(chunk_stream, self.clone())?;

        // Take the last `Cid` from the stream.
        let mut cid = cid_stream.next().await.unwrap()?;
        while let Some(result) = cid_stream.next().await {
            cid = result?;
        }

        Ok(cid)
    }

    async fn put_raw_block(&self, bytes: impl Into<Bytes> + Send) -> StoreResult<Cid> {
        let bytes = bytes.into();
        if let Some(max_size) = self.raw_block_max_size() {
            if bytes.len() as u64 > max_size {
                return Err(StoreError::RawBlockTooLarge(bytes.len() as u64, max_size));
            }
        }

        Ok(self.store_raw(bytes, Codec::Raw).await)
    }

    async fn get_node<T>(&self, cid: &Cid) -> StoreResult<T>
    where
        T: DeserializeOwned,
    {
        let blocks = self.blocks.read().await;
        match blocks.get(cid) {
            Some((_, bytes)) => match cid.codec().try_into()? {
                Codec::DagCbor => {
                    let data = serde_ipld_dagcbor::from_slice(bytes).map_err(StoreError::custom)?;
                    Ok(data)
                }
                codec => Err(StoreError::UnexpectedBlockCodec(Codec::DagCbor, codec)),
            },
            None => Err(StoreError::BlockNotFound(*cid)),
        }
    }

    async fn get_bytes<'a>(
        &'a self,
        cid: &'a Cid,
    ) -> StoreResult<Pin<Box<dyn AsyncRead + Send + 'a>>> {
        let chunk_stream = self.layout.load(cid, self.clone())?;
        let chunk_stream = chunk_stream.map(|result| {
            result.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
        });

        let reader = StreamReader::new(chunk_stream);
        Ok(Box::pin(reader))
    }

    async fn get_raw_block(&self, cid: &Cid) -> StoreResult<Bytes> {
        let blocks = self.blocks.read().await;
        match blocks.get(cid) {
            Some((_, bytes)) => match cid.codec().try_into()? {
                Codec::Raw => Ok(bytes.clone()),
                codec => Err(StoreError::UnexpectedBlockCodec(Codec::Raw, codec)),
            },
            None => Err(StoreError::BlockNotFound(*cid)),
        }
    }

    #[inline]
    async fn has(&self, cid: &Cid) -> bool {
        let blocks = self.blocks.read().await;
        blocks.contains_key(cid)
    }

    fn supported_codecs(&self) -> HashSet<Codec> {
        let mut codecs = HashSet::new();
        codecs.insert(Codec::DagCbor);
        codecs.insert(Codec::Raw);
        codecs
    }

    #[inline]
    fn node_block_max_size(&self) -> Option<u64> {
        self.chunker.chunk_max_size()
    }

    #[inline]
    fn raw_block_max_size(&self) -> Option<u64> {
        self.chunker.chunk_max_size()
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        MemoryStore {
            blocks: Arc::new(RwLock::new(HashMap::new())),
            chunker: FixedSizeChunker::default(),
            layout: FlatDagLayout::default(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    mod fixture {
        use libipld::Cid;
        use serde::{Deserialize, Serialize};

        use crate::IpldReferences;

        //--------------------------------------------------------------------------------------------------
        // Types
        //--------------------------------------------------------------------------------------------------

        #[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
        pub(super) struct Directory {
            pub(super) name: String,
            pub(super) entries: Vec<Cid>,
        }

        //--------------------------------------------------------------------------------------------------
        // Trait Implementations
        //--------------------------------------------------------------------------------------------------

        impl IpldReferences for Directory {
            fn references<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Cid> + Send + 'a> {
                Box::new(self.entries.iter())
            }
        }
    }

    #[tokio::test]
    async fn test_memory_store_put_and_get() -> anyhow::Result<()> {
        let store = MemoryStore::default();

        //================== Raw ==================

        let data = vec![1, 2, 3, 4, 5];
        let cid = store.put_bytes(&data[..]).await?;
        let mut res = store.get_bytes(&cid).await?;

        let mut buf = Vec::new();
        res.read_to_end(&mut buf).await?;

        assert_eq!(data, buf);

        //================= IPLD =================

        let data = fixture::Directory {
            name: "root".to_string(),
            entries: vec![
                utils::make_cid(Codec::Raw, &[1, 2, 3]),
                utils::make_cid(Codec::Raw, &[4, 5, 6]),
            ],
        };

        let cid = store.put_node(&data).await?;
        let res = store.get_node::<fixture::Directory>(&cid).await?;

        assert_eq!(res, data);

        Ok(())
    }
}
