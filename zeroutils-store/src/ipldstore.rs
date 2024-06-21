use std::{collections::HashSet, future::Future, iter};

use bytes::Bytes;
use libipld::Cid;
use serde::{de::DeserializeOwned, Serialize};

use crate::StoreError;

use super::StoreResult;

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// `IpldStore` is a content-addressable store for [`IPLD` (InterPlanetary Linked Data)][ipld] that
/// emphasizes the structured nature of the data it stores.
///
/// It can store raw bytes of data, but more importantly, it stores structured IPLDs; making it responsible for
/// encoding and decoding them. This gives the store a chance to construct a dependency graph at insertion time.
///
/// The key used to identify a stored data is known as a [`Cid` (Content Identifier)][cid] which is basically a hash of the
/// encoded IPLD or raw bytes. This means stored data with the same bytes will always have the same key. This makes the
/// store ideal for deduplication of data and ensuring data integrity.
///
/// ## Important
///
/// The trait is designed for cheap clones, therefore it is recommended to implement `Clone` for your store with
/// inexpensive cloning semantics.
///
/// An implementation is responsible for how it encodes types and how encoded IPLD data is broken down into smaller blocks
/// when it exceeds a certain pre-determined size.
///
/// [cid]: https://docs.ipfs.tech/concepts/content-addressing/
/// [ipld]: https://ipld.io/
///
// TODO: Add support for deleting blocks with `derefence` method.
// TODO: Add support for specifying hash type.
pub trait IpldStore: Clone {
    /// Saves an IPLD serializable object to the store and returns the `Cid` to it.
    ///
    /// This operation provides an opportunity for the store to build an internal graph of dependency.
    fn put<T>(&self, data: &T) -> impl Future<Output = StoreResult<Cid>>
    where
        T: Serialize + IpldReferences;

    /// Saves raw bytes  to the store and returns the `Cid` to it.
    ///
    /// This operation provides an opportunity for the store to build an internal graph of dependency.
    fn put_bytes(&self, bytes: impl Into<Bytes>) -> impl Future<Output = StoreResult<Cid>>;

    /// Gets a type stored as an IPLD data from the store by its `Cid`.
    fn get<D>(&self, cid: impl Into<Cid>) -> impl Future<Output = StoreResult<D>>
    where
        D: DeserializeOwned;

    /// Gets the block stored in the store as raw bytes by its `Cid`.
    fn get_bytes(&self, cid: impl Into<Cid>) -> impl Future<Output = StoreResult<Bytes>>;

    /// Gets the direct CID references contained in a given IPLD data.
    fn references(&self, cid: impl Into<Cid>) -> impl Future<Output = StoreResult<HashSet<Cid>>>;

    /// Returns the codecs supported by the store.
    fn supported_codecs(&self) -> HashSet<Codec>;

    // /// Tries to delete all blocks reachable from the given `cid` as long as the blocks are not reachable to other blocks
    // /// outside the given `cid` and its references.
    // ///
    // /// Returns `true` if at least the `cid` block was deleted.
    // fn derefence(&self, cid: impl Into<Cid>) -> impl Future<Output = StoreResult<bool>>;

    // /// Returns the maximum block size the store can handle.
    // fn max_block_size(&self) -> usize;
}

/// The different codecs supported by the IPLD store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    fn references<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Cid> + 'a>;
}

//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------

macro_rules! impl_ipld_references {
    (($($name:ident),+)) => {
        impl<$($name),+> IpldReferences for ($($name,)+)
        where
            $($name: IpldReferences,)*
        {
            fn references<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Cid> + 'a> {
                #[allow(non_snake_case)]
                let ($($name,)+) = self;
                Box::new(
                    Vec::new().into_iter()
                    $(.chain($name.references()))+
                )
            }
        }
    };
    ($type:ty) => {
        impl IpldReferences for $type {
            fn references<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Cid> + 'a> {
                Box::new([].iter())
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

// Nothing
impl_ipld_references!(());

// Scalars
impl_ipld_references!(bool);
impl_ipld_references!(u8);
impl_ipld_references!(u16);
impl_ipld_references!(u32);
impl_ipld_references!(u64);
impl_ipld_references!(u128);
impl_ipld_references!(usize);
impl_ipld_references!(i8);
impl_ipld_references!(i16);
impl_ipld_references!(i32);
impl_ipld_references!(i64);
impl_ipld_references!(i128);
impl_ipld_references!(isize);
impl_ipld_references!(f32);
impl_ipld_references!(f64);

// Containers
impl_ipld_references!(Vec<u8>);
impl_ipld_references!(&[u8]);
impl_ipld_references!(Bytes);
impl_ipld_references!(String);
impl_ipld_references!(&str);

// Tuples
impl_ipld_references!((A, B));
impl_ipld_references!((A, B, C));
impl_ipld_references!((A, B, C, D));
impl_ipld_references!((A, B, C, D, E));
impl_ipld_references!((A, B, C, D, E, F));
impl_ipld_references!((A, B, C, D, E, F, G));
impl_ipld_references!((A, B, C, D, E, F, G, H));

impl<T> IpldReferences for Option<T>
where
    T: IpldReferences,
{
    fn references<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Cid> + 'a> {
        match self {
            Some(value) => Box::new(value.references()),
            None => Box::new(iter::empty()),
        }
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
