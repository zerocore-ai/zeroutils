use std::collections::HashSet;

use libipld::Cid;
use serde::Serialize;

use crate::{Codec, IpldReferences, IpldStore, StoreResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A placeholder store that does nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaceholderStore;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl IpldStore for PlaceholderStore {
    async fn put<T>(&self, _: &T) -> StoreResult<Cid>
    where
        T: Serialize + IpldReferences,
    {
        unimplemented!("placeholder")
    }

    async fn put_bytes(&self, _: impl Into<bytes::Bytes>) -> StoreResult<Cid> {
        unimplemented!("placeholder")
    }

    async fn get<D>(&self, _: impl Into<Cid>) -> StoreResult<D>
    where
        D: serde::de::DeserializeOwned,
    {
        unimplemented!("placeholder")
    }

    async fn get_bytes(&self, _: impl Into<Cid>) -> StoreResult<bytes::Bytes> {
        unimplemented!("placeholder")
    }

    async fn references(&self, _: impl Into<Cid>) -> StoreResult<HashSet<Cid>> {
        unimplemented!("placeholder")
    }

    fn supported_codecs(&self) -> HashSet<Codec> {
        unimplemented!("placeholder")
    }
}
