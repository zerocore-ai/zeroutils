use anyhow::Ok;
use thiserror::Error;
use wasmtime::component::Resource;

use crate::wasi::{bindgen::error, state::WasiTableState};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Error type for io operations.
#[derive(Debug, Error)]
pub enum IoError {}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<T> error::HostError for T
where
    T: WasiTableState,
{
    fn to_debug_string(&mut self, error: Resource<error::Error>) -> wasmtime::Result<String> {
        Ok(format!("{:?}", self.table().get(&error)?))
    }

    fn drop(&mut self, error: Resource<error::Error>) -> wasmtime::Result<()> {
        self.table_mut().delete(error)?;
        Ok(())
    }
}

impl<T> error::Host for T where T: WasiTableState {}
