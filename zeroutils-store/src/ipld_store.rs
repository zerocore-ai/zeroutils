use std::{collections::HashSet, future::Future};

use bytes::Bytes;
use libipld::Cid;
use serde::{de::DeserializeOwned, Serialize};

use crate::StoreError;

use super::StoreResult;

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// `IpldStore` is a content-addressable store for [`IPLD` (InterPlanetary Linked Data)][ipld].
///
/// It can store raw bytes of data, but more importantly, it stores structured IPLDs; making it responsible for
/// encoding and decoding them. This gives the store a chance to construct a dependency graph at insertion time.
///
/// The key used to identify an stored data is known as a [`Cid` (Content Identifier)][cid] which is basically a hash of the
/// encoded IPLD or raw bytes. This means stored data with the same bytes will always have the same key. This makes the
/// store ideal for deduplication of data and ensuring data integrity.
///
/// `IpldStore` supports `DAG-CBOR`, `DAG-JSON`, and `DAG-PB` codecs, which all have canonical representations that make
/// them suitable for content addressing. However, implementations may choose not to support all codecs.
///
/// NOTE: An implementation is responsible for how it breaks down the encoded IPLD data into blocks when it exceeds
/// a certain pre-determined size.
///
/// [cid]: https://docs.ipfs.tech/concepts/content-addressing/
/// [ipld]: https://ipld.io/
///
// TODO: Add support for deleting blocks with `derefence` method.
pub trait IpldStore {
    /// Saves an IPLD serializable object to the store and returns the `Cid` to it.
    ///
    /// This operation provides an opportunity for the store to build an internal graph of dependency.
    fn put<T>(&self, data: IpldData<T>) -> impl Future<Output = StoreResult<Cid>>
    where
        T: Serialize + IpldReferences;

    /// Saves raw bytes  to the store and returns the `Cid` to it.
    ///
    /// This operation provides an opportunity for the store to build an internal graph of dependency.
    fn put_bytes(&self, bytes: Bytes) -> impl Future<Output = StoreResult<Cid>>;

    /// Gets a type stored as an IPLD data or raw bytes from the store.
    fn get<D>(&self, cid: impl Into<Cid>) -> impl Future<Output = StoreResult<StoreData<D>>>
    where
        D: DeserializeOwned;

    /// Gets the direct CID references contained in a given IPLD data.
    fn get_references(
        &self,
        cid: impl Into<Cid>,
    ) -> impl Future<Output = StoreResult<HashSet<Cid>>>;

    // /// Tries to delete all blocks reachable from the given `cid` as long as the blocks are not reachable to other blocks
    // /// outside the given `cid` and its references.
    // ///
    // /// Returns `true` if at least the `cid` block was deleted.
    // fn derefence(&self, cid: impl Into<Cid>) -> impl Future<Output = StoreResult<bool>>;

    // /// Returns the maximum block size the store can handle.
    // fn max_block_size(&self) -> usize;
}

/// The different types of IPLD data that can be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpldData<T> {
    /// DAG-CBOR encoded data.
    DagCbor(T),

    /// DAG-JSON encoded data.
    DagJson(T),

    /// DAG-PB encoded data.
    DagPb(T),
}

/// The different types of data that can be stored in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreData<T = ()> {
    /// Raw bytes.
    Raw(Bytes),

    /// IPLD data.
    Ipld(T),
}

/// The different codecs supported by the IPLD store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Codec {
    /// Raw bytes.
    Raw,

    /// DAG-CBOR codec.
    DagCbor,

    /// DAG-JSON codec.
    DagJson,

    /// DAG-PB codec.
    DagPb,
}

/// A trait for types that can hold [CID][cid] references to some data.
///
/// [cid]: https://docs.ipfs.tech/concepts/content-addressing/
pub trait IpldReferences {
    /// Returns all the direct CID references the type has to other data.
    fn references(&self) -> impl Iterator<Item = &Cid>;
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl IpldReferences for () {
    fn references(&self) -> impl Iterator<Item = &Cid> {
        [].iter()
    }
}

impl IpldReferences for Vec<u8> {
    fn references(&self) -> impl Iterator<Item = &Cid> {
        [].iter()
    }
}

impl IpldReferences for &[u8] {
    fn references(&self) -> impl Iterator<Item = &Cid> {
        [].iter()
    }
}

impl IpldReferences for Bytes {
    fn references(&self) -> impl Iterator<Item = &Cid> {
        [].iter()
    }
}

impl TryFrom<u64> for Codec {
    type Error = StoreError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0x55 => Ok(Codec::Raw),
            0x71 => Ok(Codec::DagCbor),
            0x0129 => Ok(Codec::DagJson),
            0x70 => Ok(Codec::DagPb),
            _ => Err(StoreError::UnsupportedCodec(value)),
        }
    }
}

impl From<Codec> for u64 {
    fn from(codec: Codec) -> Self {
        match codec {
            Codec::Raw => 0x55,
            Codec::DagCbor => 0x71,
            Codec::DagJson => 0x0129,
            Codec::DagPb => 0x70,
        }
    }
}

impl<T> From<IpldData<T>> for Codec {
    fn from(data: IpldData<T>) -> Self {
        match data {
            IpldData::DagCbor(_) => Codec::DagCbor,
            IpldData::DagJson(_) => Codec::DagJson,
            IpldData::DagPb(_) => Codec::DagPb,
        }
    }
}
