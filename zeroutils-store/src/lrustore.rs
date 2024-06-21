use std::{collections::HashSet, num::NonZeroUsize, sync::Arc};

use bytes::Bytes;
use libipld::{
    cbor::DagCborCodec, codec::Codec as C, json::DagJsonCodec, pb::DagPbCodec, Cid, Ipld,
};
use lru::LruCache;
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::RwLock;

use crate::{utils, Codec, IpldReferences, IpldStore, StoreError, StoreResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The maximum size of a block in the LRU store.
// TODO: Not supported yet. In the future, we will use this to break big IPLD blocks into smaller blocks.
pub const LRU_STORE_BLOCK_SIZE: usize = 256 * 1024; // 256 KiB

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A Least Recently Used (LRU) cache store for storing IPLD blocks.
///
/// The `LruStore` struct provides an in-memory storage mechanism for IPLD blocks with a specified capacity.
/// It leverages an LRU cache to manage the stored blocks, evicting the least recently used blocks when the
/// capacity is reached.
#[derive(Clone)]
pub struct LruStore {
    blocks: Arc<RwLock<LruCache<Cid, Bytes>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LruStore {
    /// Creates a new `LruStore` with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            blocks: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("capacity must be non-zero"),
            ))),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl IpldStore for LruStore {
    async fn put<T>(&self, data: &T) -> StoreResult<Cid>
    where
        T: Serialize + IpldReferences,
    {
        // Serialize the data to bytes.
        let bytes: Bytes =
            Bytes::from(serde_ipld_dagcbor::to_vec(&data).map_err(StoreError::custom)?);

        // Construct the CID from the hash of the serialized data.
        let cid = utils::make_cid(Codec::DagCbor, &bytes);

        // Insert the block if it doesn't already exist.
        if self.blocks.write().await.get(&cid).is_none() {
            self.blocks.write().await.put(cid, bytes);
        }

        Ok(cid)
    }

    async fn put_bytes(&self, bytes: impl Into<Bytes>) -> StoreResult<Cid> {
        let bytes = bytes.into();

        // Construct the CID from the hash of the bytes.
        let cid = utils::make_cid(Codec::Raw, &bytes);

        // Insert the block if it doesn't already exist.
        if self.blocks.write().await.get(&cid).is_none() {
            self.blocks.write().await.put(cid, bytes);
        }

        Ok(cid)
    }

    async fn get<T>(&self, cid: impl Into<Cid>) -> StoreResult<T>
    where
        T: DeserializeOwned,
    {
        let cid = cid.into();
        let mut blocks = self.blocks.write().await;
        match blocks.get(&cid) {
            Some(bytes) => match cid.codec().try_into()? {
                Codec::DagCbor => {
                    let data = serde_ipld_dagcbor::from_slice(bytes).map_err(StoreError::custom)?;
                    Ok(data)
                }
                _ => Err(StoreError::UnsupportedCodec(cid.codec())),
            },
            None => Err(StoreError::BlockNotFound(cid)),
        }
    }

    async fn get_bytes(&self, cid: impl Into<Cid>) -> StoreResult<Bytes> {
        let cid = cid.into();
        let mut blocks = self.blocks.write().await;
        match blocks.get(&cid) {
            Some(bytes) => Ok(bytes.clone()),
            None => Err(StoreError::BlockNotFound(cid)),
        }
    }

    async fn references(&self, cid: impl Into<Cid>) -> StoreResult<HashSet<Cid>> {
        // TODO: Should figure out how to get references without deserializing the block. Think UCAN proof links.
        let cid = cid.into();
        let mut blocks = self.blocks.write().await;
        match blocks.get(&cid) {
            Some(bytes) => match cid.codec().try_into()? {
                Codec::Raw => Ok(HashSet::new()),
                Codec::DagCbor => {
                    let mut cids = HashSet::new();
                    DagCborCodec
                        .references::<Ipld, _>(bytes, &mut cids)
                        .map_err(StoreError::custom)?;

                    Ok(cids)
                }
                Codec::DagJson => {
                    let mut cids = HashSet::new();
                    DagJsonCodec
                        .references::<Ipld, _>(bytes, &mut cids)
                        .map_err(StoreError::custom)?;

                    Ok(cids)
                }
                Codec::DagPb => {
                    let mut cids = HashSet::new();
                    DagPbCodec
                        .references::<Ipld, _>(bytes, &mut cids)
                        .map_err(StoreError::custom)?;

                    Ok(cids)
                }
            },
            None => Err(StoreError::BlockNotFound(cid)),
        }
    }

    fn supported_codecs(&self) -> HashSet<Codec> {
        let mut codecs = HashSet::new();
        codecs.insert(Codec::DagCbor);
        codecs
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
            fn references<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Cid> + 'a> {
                Box::new(self.entries.iter())
            }
        }
    }

    #[tokio::test]
    async fn test_memory_store_put_and_get() -> anyhow::Result<()> {
        let store = LruStore::new(2);

        //================== Raw ==================

        let data_0 = vec![1, 2, 3, 4, 5];
        let cid_0 = store.put_bytes(Bytes::from(data_0.clone())).await?;
        let res = store.get_bytes(cid_0).await?;
        assert_eq!(res, Bytes::from(data_0));

        //================= IPLD =================

        let data_1 = fixture::Directory {
            name: "root".to_string(),
            entries: vec![
                utils::make_cid(Codec::Raw, &[1, 2, 3]),
                utils::make_cid(Codec::Raw, &[4, 5, 6]),
            ],
        };

        let cid_1 = store.put(&data_1).await?;
        let res = store.get::<fixture::Directory>(cid_1).await?;
        assert_eq!(res, data_1);

        //================= Least Recently Used Eviction =================

        let data_2 = vec![7, 8, 9, 10, 11];
        let cid_2 = store.put_bytes(Bytes::from(data_2.clone())).await?; // This should evict the first block.

        assert_eq!(
            store.get_bytes(cid_0).await,
            Err(StoreError::BlockNotFound(cid_0))
        );
        assert_eq!(store.get::<fixture::Directory>(cid_1).await?, data_1);
        assert_eq!(store.get_bytes(cid_2).await?, Bytes::from(data_2));

        Ok(())
    }

    #[tokio::test]
    async fn test_memory_store_get_references() -> anyhow::Result<()> {
        let store = LruStore::new(2);

        let data = fixture::Directory {
            name: "root".to_string(),
            entries: vec![
                utils::make_cid(Codec::Raw, &[1, 2, 3]),
                utils::make_cid(Codec::Raw, &[4, 5, 6]),
            ],
        };

        let cid = store.put(&data).await?;
        let res = store.references(cid).await?;
        let expected = data.entries.iter().cloned().collect::<HashSet<_>>();

        assert_eq!(res, expected);

        Ok(())
    }
}
