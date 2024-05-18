use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use bytes::Bytes;
use libipld::{
    cbor::DagCborCodec, codec::Codec as C, json::DagJsonCodec, pb::DagPbCodec, Cid, Ipld,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::RwLock;

use crate::{utils, Codec, IpldReferences, IpldStore, StoreError, StoreResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The maximum size of a block in the in-memory IPLD store.
// TODO: Not supported yet. In the future, we will use this to break big IPLD blocks into smaller blocks.
pub const MEM_IPLD_STORE_BLOCK_SIZE: usize = 256 * 1024; // 256 KiB

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An in-memory storage for IPLD blocks with reference counting.
///
/// This store maintains a reference count for each stored block. Blocks are eligible for removal
/// once their reference count drops to zero. It's designed for efficient in-memory storage and
/// retrieval of blocks.
///
/// NOTE: Currently, this implementation only supports DAG-CBOR codecs.
#[derive(Debug, Clone)]
pub struct MemoryIpldStore {
    blocks: Arc<RwLock<HashMap<Cid, (usize, Bytes)>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MemoryIpldStore {
    async fn inc_refs(&self, cids: impl Iterator<Item = &Cid>) {
        for cid in cids {
            if let Some((size, _)) = self.blocks.write().await.get_mut(cid) {
                *size += 1;
            }
        }
    }

    async fn _dec_refs(&self, cids: impl Iterator<Item = &Cid>) -> Vec<Cid> {
        let mut to_remove = Vec::new();
        for cid in cids {
            if let Some((size, _)) = self.blocks.write().await.get_mut(cid) {
                *size -= 1;
                if *size == 0 {
                    to_remove.push(*cid);
                }
            }
        }

        to_remove
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl IpldStore for MemoryIpldStore {
    async fn put<T>(&self, data: T) -> StoreResult<Cid>
    where
        T: Serialize + IpldReferences,
    {
        // Serialize the data to bytes.
        let bytes: Bytes =
            Bytes::from(serde_ipld_dagcbor::to_vec(&data).map_err(StoreError::custom)?);

        // Construct the CID from the hash of the serialized data.
        let cid = utils::make_cid(Codec::DagCbor, &bytes);

        // Insert the block if it doesn't already exist.
        if self.blocks.read().await.get(&cid).is_none() {
            self.blocks.write().await.insert(cid, (1, bytes));
            self.inc_refs(data.references()).await; // Increment reference counts of referenced blocks.
        }

        Ok(cid)
    }

    async fn put_bytes(&self, bytes: impl Into<Bytes>) -> StoreResult<Cid> {
        let bytes = bytes.into();

        // Construct the CID from the hash of the bytes.
        let cid = utils::make_cid(Codec::Raw, &bytes);

        // Insert the block if it doesn't already exist.
        if self.blocks.read().await.get(&cid).is_none() {
            self.blocks.write().await.insert(cid, (1, bytes));
        }

        Ok(cid)
    }

    async fn get<T>(&self, cid: impl Into<Cid>) -> StoreResult<T>
    where
        T: DeserializeOwned,
    {
        let cid = cid.into();
        let blocks = self.blocks.read().await;
        match blocks.get(&cid) {
            Some((_, bytes)) => match cid.codec().try_into()? {
                Codec::DagCbor => {
                    let data = serde_ipld_dagcbor::from_slice(bytes).map_err(StoreError::custom)?;
                    Ok(data)
                }
                Codec::DagJson => {
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
        let blocks = self.blocks.read().await;
        match blocks.get(&cid) {
            Some((_, bytes)) => Ok(bytes.clone()),
            None => Err(StoreError::BlockNotFound(cid)),
        }
    }

    async fn references(&self, cid: impl Into<Cid>) -> StoreResult<HashSet<Cid>> {
        // TODO: Should figure out how to get references without deserializing the block. Think UCAN proof links.
        let cid = cid.into();
        let blocks = self.blocks.read().await;
        match blocks.get(&cid) {
            Some((_, bytes)) => match cid.codec().try_into()? {
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

    fn supported_codec(&self) -> Codec {
        Codec::DagCbor
    }
}

impl Default for MemoryIpldStore {
    fn default() -> Self {
        MemoryIpldStore {
            blocks: Arc::new(RwLock::new(HashMap::new())),
        }
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
            fn references(&self) -> impl Iterator<Item = &Cid> {
                self.entries.iter()
            }
        }
    }

    #[tokio::test]
    async fn test_memory_ipld_store_put_and_get() -> anyhow::Result<()> {
        let store = MemoryIpldStore::default();

        //================== Raw ==================

        let data = vec![1, 2, 3, 4, 5];
        let cid = store.put_bytes(Bytes::from(data.clone())).await?;
        let res = store.get_bytes(cid).await?;
        assert_eq!(res, Bytes::from(data));

        //================= IPLD =================

        let data = fixture::Directory {
            name: "root".to_string(),
            entries: vec![
                utils::make_cid(Codec::Raw, &[1, 2, 3]),
                utils::make_cid(Codec::Raw, &[4, 5, 6]),
            ],
        };

        let cid = store.put(data.clone()).await?;
        let res = store.get::<fixture::Directory>(cid).await?;
        assert_eq!(res, data);

        Ok(())
    }

    #[tokio::test]
    async fn test_memory_ipld_store_get_references() -> anyhow::Result<()> {
        let store = MemoryIpldStore::default();

        let data = fixture::Directory {
            name: "root".to_string(),
            entries: vec![
                utils::make_cid(Codec::Raw, &[1, 2, 3]),
                utils::make_cid(Codec::Raw, &[4, 5, 6]),
            ],
        };

        let cid = store.put(data.clone()).await?;
        let res = store.references(cid).await?;
        let expected = data.entries.iter().cloned().collect::<HashSet<_>>();

        assert_eq!(res, expected);

        Ok(())
    }
}
