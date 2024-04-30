//! WASI state traits.

use wasmtime::component::ResourceTable;

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// Trait for providing the resource table of a WASI context.
pub trait WasiTableState: Send {
    /// Returns the resource table.
    fn table(&self) -> &ResourceTable;

    /// Returns a mutable reference to the resource table.
    fn table_mut(&mut self) -> &mut ResourceTable;
}
