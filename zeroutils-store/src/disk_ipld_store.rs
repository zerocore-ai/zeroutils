use std::{collections::HashSet, path::PathBuf};

use bytes::Bytes;
use libipld::Cid;
use serde::Serialize;

use crate::{IpldReferences, IpldStore, StoreData, StoreResult};

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
pub struct DiskIpldStore {
    /// The base directory where the blocks are stored.
    ///
    /// Default is set to `~/.zerofs`.
    _base_dir: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DiskIpldStore {
    /// Creates a new `DiskIpldStore` with the given base directory.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            _base_dir: base_dir.into(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl IpldStore for DiskIpldStore {
    async fn put<T>(&self, _data: T) -> StoreResult<Cid>
    where
        T: Serialize + IpldReferences,
    {
        todo!()
    }

    async fn put_bytes(&self, _bytes: Bytes) -> StoreResult<Cid> {
        todo!()
    }

    async fn get<D>(&self, _cid: impl Into<Cid>) -> StoreResult<StoreData<D>>
    where
        D: serde::de::DeserializeOwned,
    {
        todo!()
    }

    async fn get_references(&self, _cid: impl Into<Cid>) -> StoreResult<HashSet<Cid>> {
        todo!()
    }

    fn supported_codec(&self) -> crate::Codec {
        todo!()
    }
}
