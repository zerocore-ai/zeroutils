use async_stream::try_stream;
use bytes::Bytes;
use futures::{stream::BoxStream, StreamExt};
use libipld::Cid;

use crate::{IpldStore, Layout, MerkleNode, StoreResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A layout that organizes data into a flat DAG.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct FlatDagLayout {}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FlatDagLayout {
    /// Create a new flat DAG layout.
    pub fn new() -> Self {
        FlatDagLayout {}
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Layout for FlatDagLayout {
    fn store<'a>(
        &self,
        mut stream: BoxStream<'a, StoreResult<Bytes>>,
        store: impl IpldStore + Send + 'a,
    ) -> StoreResult<BoxStream<'a, StoreResult<Cid>>> {
        let s = try_stream! {
            let mut byte_size = 0;
            let mut cids = Vec::new();
            while let Some(Ok(chunk)) = stream.next().await {
                byte_size += chunk.len();
                let cid = store.put_raw_block(chunk).await?;
                cids.push(cid);
            }

            let node = MerkleNode::new(byte_size, cids);
            let cid = store.put_node(&node).await?;

            yield cid;
        };

        Ok(Box::pin(s))
    }

    fn load<'a>(
        &self,
        cid: &'a Cid,
        store: impl IpldStore + Send + 'a,
    ) -> StoreResult<BoxStream<'a, StoreResult<Bytes>>> {
        let s = try_stream! {
            let node: MerkleNode = store.get_node(cid).await?;
            for cid in node.dependencies {
                yield store.get_raw_block(&cid).await?;
            }
        };

        Ok(Box::pin(s))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;

    use crate::MemoryStore;

    use super::*;

    #[tokio::test]
    async fn test_flat_dag_layout_store_and_load() -> anyhow::Result<()> {
        let store = MemoryStore::default();
        let data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

        let chunk_stream = Box::pin(try_stream! {
            yield Bytes::from("Lorem");
            yield Bytes::from(" ipsu");
            yield Bytes::from("m dol");
            yield Bytes::from("or sit");
            yield Bytes::from(" amet,");
            yield Bytes::from(" conse");
            yield Bytes::from("ctetur");
            yield Bytes::from(" adipi");
            yield Bytes::from("scing ");
            yield Bytes::from("elit.");
        });

        let layout = FlatDagLayout::default();
        let cid_stream = layout.store(chunk_stream, store.clone())?;
        let cids = cid_stream.try_collect::<Vec<_>>().await?;

        assert_eq!(cids.len(), 1);

        let node: MerkleNode = store.get_node(&cids[0]).await?;

        assert_eq!(node.size, data.len());
        assert_eq!(node.dependencies.len(), 10);

        let chunk_stream = layout.load(&cids[0], store.clone())?;
        let loaded_bytes = chunk_stream
            .try_fold(Vec::new(), |mut acc, chunk| {
                let mut chunk = chunk.clone().to_vec();
                async move {
                    acc.append(&mut chunk);
                    Ok(acc)
                }
            })
            .await?;

        assert_eq!(loaded_bytes, data);

        Ok(())
    }
}
