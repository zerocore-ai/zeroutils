use std::collections::HashSet;

use bytes::Bytes;
use libipld::Cid;
use serde::{de::DeserializeOwned, Serialize};

use crate::{Codec, IpldReferences, IpldStore, StoreError, StoreResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A dual store that stores blocks on two different stores.
#[derive(Debug, Clone)]
pub struct DualStore<A, B>
where
    A: IpldStore,
    B: IpldStore,
{
    store_a: A,
    store_b: B,
    config: DualStoreConfig,
}

/// Choices for selecting which store to use for a given operation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Choice {
    /// Use the first store.
    A,
    /// Use the second store.
    B,
}

/// Configuration for a dual store.
#[derive(Debug, Clone)]
pub struct DualStoreConfig {
    /// The default store to use.
    pub default: Choice,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<A, B> DualStore<A, B>
where
    A: IpldStore,
    B: IpldStore,
{
    /// Creates a new dual store from two stores.
    pub fn new(store_a: A, store_b: B, config: DualStoreConfig) -> Self {
        Self {
            store_a,
            store_b,
            config,
        }
    }

    /// Gets a type stored as an IPLD data from a chosen store by its `Cid`.
    pub async fn get_from<D>(&self, cid: impl Into<Cid>, choice: Choice) -> StoreResult<D>
    where
        D: serde::de::DeserializeOwned,
    {
        match choice {
            Choice::A => self.store_a.get(cid).await,
            Choice::B => self.store_b.get(cid).await,
        }
    }

    /// Gets the block stored in a chosen store as raw bytes by its `Cid`.
    pub async fn get_bytes_from(&self, cid: impl Into<Cid>, choice: Choice) -> StoreResult<Bytes> {
        match choice {
            Choice::A => self.store_a.get_bytes(cid).await,
            Choice::B => self.store_b.get_bytes(cid).await,
        }
    }

    /// Saves an IPLD serializable object to a chosen store and returns the `Cid` to it.
    pub async fn put_into<T>(&self, data: &T, choice: Choice) -> StoreResult<Cid>
    where
        T: Serialize + IpldReferences,
    {
        match choice {
            Choice::A => self.store_a.put(data).await,
            Choice::B => self.store_b.put(data).await,
        }
    }

    /// Saves raw bytes to a chosen store and returns the `Cid` to it.
    pub async fn put_bytes_into(
        &self,
        bytes: impl Into<Bytes>,
        choice: Choice,
    ) -> StoreResult<Cid> {
        match choice {
            Choice::A => self.store_a.put_bytes(bytes).await,
            Choice::B => self.store_b.put_bytes(bytes).await,
        }
    }

    /// Gets the direct CID references contained in a given IPLD data from a chosen store.
    pub async fn references_from(
        &self,
        cid: impl Into<Cid>,
        choice: Choice,
    ) -> StoreResult<HashSet<Cid>> {
        match choice {
            Choice::A => self.store_a.references(cid).await,
            Choice::B => self.store_b.references(cid).await,
        }
    }
}

impl Choice {
    /// Returns the other choice.
    pub fn other(&self) -> Self {
        match self {
            Choice::A => Choice::B,
            Choice::B => Choice::A,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<A, B> IpldStore for DualStore<A, B>
where
    A: IpldStore,
    B: IpldStore,
{
    async fn put<T>(&self, data: &T) -> StoreResult<Cid>
    where
        T: Serialize + IpldReferences,
    {
        self.put_into(data, self.config.default).await
    }

    async fn put_bytes(&self, bytes: impl Into<Bytes>) -> StoreResult<Cid> {
        self.put_bytes_into(bytes, self.config.default).await
    }

    async fn get<D>(&self, cid: impl Into<Cid>) -> StoreResult<D>
    where
        D: DeserializeOwned,
    {
        match self.get_from(cid, self.config.default).await {
            Ok(data) => Ok(data),
            Err(StoreError::BlockNotFound(cid)) => {
                let choice = self.config.default.other();
                self.get_from(cid, choice).await
            }
            Err(err) => Err(err),
        }
    }

    async fn get_bytes(&self, cid: impl Into<Cid>) -> StoreResult<Bytes> {
        match self.get_bytes_from(cid, self.config.default).await {
            Ok(bytes) => Ok(bytes),
            Err(StoreError::BlockNotFound(cid)) => {
                let choice = self.config.default.other();
                self.get_bytes_from(cid, choice).await
            }
            Err(err) => Err(err),
        }
    }

    async fn references(&self, cid: impl Into<Cid>) -> StoreResult<HashSet<Cid>> {
        self.references_from(cid, self.config.default).await
    }

    fn supported_codecs(&self) -> HashSet<Codec> {
        self.store_a
            .supported_codecs()
            .into_iter()
            .chain(self.store_b.supported_codecs())
            .collect()
    }
}

impl Default for DualStoreConfig {
    fn default() -> Self {
        Self { default: Choice::A }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::{LruStore, MemoryStore};

    use super::*;

    #[tokio::test]
    async fn test_dual_store_put_and_get() -> anyhow::Result<()> {
        let store_a = MemoryStore::default();
        let store_b = LruStore::new(2);
        let dual_store = DualStore::new(store_a, store_b, Default::default());

        let cid_0 = dual_store.put_into(&"hello", Choice::A).await?;
        let cid_1 = dual_store.put_into(&250, Choice::B).await?;
        let cid_2 = dual_store.put_into(&"world", Choice::A).await?;
        let cid_3 = dual_store.put_into(&500, Choice::B).await?;

        // This should evict the first block from the LRU store.
        let cid_4 = dual_store.put_into(&1000, Choice::B).await?;

        assert_eq!(dual_store.get::<String>(cid_0).await?, "hello");
        assert_eq!(dual_store.get::<String>(cid_2).await?, "world");
        assert_eq!(dual_store.get::<usize>(cid_4).await?, 1000);
        assert_eq!(dual_store.get::<usize>(cid_3).await?, 500);
        assert!(dual_store.get::<usize>(cid_1).await.is_err());

        Ok(())
    }
}
