use std::{collections::HashSet, path::PathBuf, sync::Arc};

use bytes::Bytes;
use libipld::Cid;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::{Codec, IpldReferences, IpldStore, StoreResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The default base directory where the blocks are stored.
pub const DEFAULT_BASE_DIR: &str = ".zerofs";

/// The maximum size of a block in the disk IPLD store.
// TODO: Not supported yet. In the future, we will use this to break big IPLD blocks into smaller blocks.
pub const DISK_IPLD_STORE_BLOCK_SIZE: usize = 256 * 1024; // 256 KiB

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A block store that stores blocks on disk.
#[derive(Clone)]
pub struct DiskStore {
    _inner: Arc<RwLock<DiskStoreInner>>,
}

struct DiskStoreInner {
    /// The base directory where the blocks are stored.
    ///
    /// Default is set to `~/.zerofs`.
    _base_dir: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DiskStore {
    /// Creates a new `DiskStore` with the given base directory.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            _inner: Arc::new(RwLock::new(DiskStoreInner {
                _base_dir: base_dir.into(),
            })),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl IpldStore for DiskStore {
    async fn put<T>(&self, _data: T) -> StoreResult<Cid>
    where
        T: Serialize + IpldReferences,
    {
        todo!()
    }

    async fn put_bytes(&self, _bytes: impl Into<Bytes>) -> StoreResult<Cid> {
        todo!()
    }

    async fn get<D>(&self, _cid: impl Into<Cid>) -> StoreResult<D>
    where
        D: serde::de::DeserializeOwned,
    {
        todo!()
    }

    async fn get_bytes(&self, _cid: impl Into<Cid>) -> StoreResult<Bytes> {
        todo!()
    }

    async fn references(&self, _cid: impl Into<Cid>) -> StoreResult<HashSet<Cid>> {
        todo!()
    }

    fn supported_codecs(&self) -> HashSet<Codec> {
        todo!()
    }
}
