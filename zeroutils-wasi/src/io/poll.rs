//! Pollable trait for objects that can be polled for readiness.

use std::{any::Any, collections::HashMap, pin::Pin, task::Poll};

use anyhow::Ok;
use async_trait::async_trait;
use futures::{
    future::{self, poll_fn},
    Future,
};
use wasmtime::component::{Resource, ResourceTable};

use crate::{bindgen::poll, state::WasiTableState};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A future that blocks until a resource is ready.
pub type PollableFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// A handle to an input stream.
pub struct PollableHandle {
    /// The underlying resource index.
    resource_index: u32,

    /// A function that returns a future that blocks until the resource is ready.
    block_future: for<'a> fn(&'a mut dyn Any) -> PollableFuture<'a>,

    /// Lets the pollable drop the resource when no longer needed.
    drop_fn: Option<fn(&mut ResourceTable, u32) -> wasmtime::Result<()>>,
}

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// Allows a resource to be waited on.
#[async_trait]
pub trait Subscribe: Send + Sync + 'static {
    /// **Waits** for the resource to be ready.
    ///
    /// Although the name says "block", this only refers to the wasm execution context. We don't
    /// actually want the host runtime thread to block. This is why it is an async function so that
    /// it can be spawned on a separate blocking thread.
    async fn block(&self);

    /// Derives a pollable resource that can be waited on from `resource`.
    ///
    /// This creates a dependency between the resource and the pollable resource.
    fn subscribe(
        resource: Resource<Self>,
        table: &mut ResourceTable,
    ) -> anyhow::Result<Resource<PollableHandle>>
    where
        Self: Sized,
    {
        // Create a pollable resource that can be waited on.
        let pollable = PollableHandle {
            resource_index: resource.rep(),
            block_future: |resource| {
                let resource = resource.downcast_mut::<Self>().unwrap();
                resource.block()
            },
            drop_fn: resource.owned().then_some(|table, index| {
                let resource = Resource::<Self>::new_own(index);
                table.delete(resource)?;
                Ok(())
            }),
        };

        // Push the pollable resource to the table with main resource as parent.
        let pollable = table.push_child(pollable, &resource)?;
        Ok(pollable)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[async_trait]
impl<T> poll::HostPollable for T
where
    T: WasiTableState,
{
    async fn block(&mut self, pollable: Resource<PollableHandle>) -> wasmtime::Result<()> {
        let table = self.table_mut();
        let pollable = table.get(&pollable)?;
        let block = (pollable.block_future)(table.get_any_mut(pollable.resource_index)?);
        block.await;
        Ok(())
    }

    async fn ready(&mut self, pollable: Resource<PollableHandle>) -> wasmtime::Result<bool> {
        let table = self.table_mut();
        let pollable = table.get(&pollable)?;
        let block = (pollable.block_future)(table.get_any_mut(pollable.resource_index)?);
        Ok(matches!(future::poll_immediate(block).await, Some(())))
    }

    fn drop(&mut self, pollable: Resource<PollableHandle>) -> wasmtime::Result<()> {
        let pollable = self.table_mut().delete(pollable)?;
        if let Some(drop_fn) = pollable.drop_fn {
            drop_fn(self.table_mut(), pollable.resource_index)?;
        }
        Ok(())
    }
}

#[async_trait]
impl<T> poll::Host for T
where
    T: WasiTableState,
{
    async fn poll(
        &mut self,
        pollables: Vec<Resource<PollableHandle>>,
    ) -> wasmtime::Result<Vec<u32>> {
        // If there are no pollables, return an error. This behavior has not been decided so there is an issue for it
        // here: https://github.com/WebAssembly/wasi-io/issues/67
        if pollables.is_empty() {
            return Err(anyhow::anyhow!("pollables is empty"));
        }

        let table = self.table_mut();

        // Create a map of pollable resource indices to their `block` futures.
        let pollable_futures_map = pollables
            .iter()
            .map(|pollable| {
                let pollable = table.get(pollable)?;
                Ok((pollable.resource_index, pollable.block_future))
            })
            .collect::<anyhow::Result<HashMap<u32, _>>>()?;

        // Get the `block` futures for each pollable resource.
        let mut pollable_futures = table
            .iter_entries(pollable_futures_map)
            .enumerate()
            .map(|(index, (entry, block_future))| Ok((index, block_future(entry?))))
            .collect::<anyhow::Result<Vec<_>>>()?;

        // Poll the `block` futures until one or more are ready.
        let poller = poll_fn(|cx| {
            let mut indices = vec![];
            for (index, pollable_future) in pollable_futures.iter_mut() {
                if let Poll::Ready(()) = pollable_future.as_mut().poll(cx) {
                    indices.push(*index as u32);
                }
            }

            if indices.is_empty() {
                Poll::Pending
            } else {
                Poll::Ready(indices)
            }
        });

        Ok(poller.await)
    }
}
