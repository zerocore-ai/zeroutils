use bytes::Bytes;
use futures::stream::BoxStream;
use libipld::Cid;

use crate::{IpldStore, Layout, StoreResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A layout that organizes data into a balanced DAG.
#[derive(Clone, Debug, PartialEq)]
pub struct BalancedDagLayout {}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Layout for BalancedDagLayout {
    fn store<'a>(
        &self,
        mut _stream: BoxStream<'a, StoreResult<Bytes>>,
        _store: impl IpldStore + Send + 'a,
    ) -> StoreResult<BoxStream<'a, StoreResult<Cid>>> {
        todo!() // TODO: To be implemented
    }

    fn load<'a>(
        &self,
        _cid: &'a Cid,
        _store: impl IpldStore + Send + 'a,
    ) -> StoreResult<BoxStream<'a, StoreResult<Bytes>>> {
        todo!() // TODO: To be implemented
    }
}
