use futures::Future;
use libipld::Cid;

use crate::StoreResult;

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// A trait that all types that need to be stored in an IPLD store must implement.
pub trait Storable: Sized {
    /// Stores the type in the IPLD store and returns the Cid.
    fn store(&self) -> impl Future<Output = StoreResult<Cid>>;

    /// Loads the type from the IPLD store.
    fn load(cid: &Cid) -> impl Future<Output = StoreResult<Self>>;
}
