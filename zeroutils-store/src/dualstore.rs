use crate::IpldStore;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A dual store that stores blocks on two different stores.
pub struct DualStore<T, U>
where
    T: IpldStore,
    U: IpldStore,
{
    _store_a: T,
    _store_b: U,
    // config: DualStoreConfig, // Configuration for say how to write, e.g., a, b, alternate, heuristics, etc.
}

// pub enum Choice {
//     A,
//     B,
// }

// pub struct DualStoreConfig {}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

// impl<T, U> DualStore<T, U>
// where
//     T: IpldStore,
//     U: IpldStore,
// {
//     pub fn new(store_a: T, store_b: U, config: DualStoreConfig) -> Self {
//         Self {
//             store_a,
//             store_b,
//             config,
//         }
//     }

//     pub fn get_from<D>(&self, _cid: impl Into<Cid>, choice: Choice) -> StoreResult<D>
//     where
//         D: serde::de::DeserializeOwned,
//     {
//         todo!()
//     }
// }

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------
