use bytes::Bytes;
use futures::stream::BoxStream;
use libipld::Cid;

use crate::{IpldStore, Layout, StoreResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A layout that organizes data into a trickle DAG.
#[derive(Clone, Debug, PartialEq)]
pub struct TrickleDagLayout {}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Layout for TrickleDagLayout {
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
