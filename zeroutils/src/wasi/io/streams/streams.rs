use anyhow::Ok;

use crate::wasi::{bindgen::streams, state::WasiTableState};

use super::StreamError;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<T> streams::Host for T
where
    T: WasiTableState,
{
    fn convert_stream_error(
        &mut self,
        error: StreamError,
    ) -> wasmtime::Result<streams::StreamError> {
        match error {
            StreamError::Closed => Ok(streams::StreamError::Closed),
            StreamError::LastOperationFailed(e) => {
                let resource = self.table_mut().push(e)?;
                Ok(streams::StreamError::LastOperationFailed(resource))
            }
            e => Err(e.into()),
        }
    }
}
