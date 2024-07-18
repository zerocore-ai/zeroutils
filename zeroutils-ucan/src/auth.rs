use std::{ops::Deref, sync::Arc};

use zeroutils_key::GetPublicKey;
use zeroutils_store::cas::IpldStore;

use crate::{ResolvedCapabilityTuple, SignedUcan, UcanResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A signed UCAN with a root public key.
///
/// This is a self-contained data structure for verifying a UCAN and checking capabilities available
/// to the UCAN.
pub struct UcanAuth<'a, S, K>
where
    S: IpldStore,
    K: GetPublicKey,
{
    /// The inner signed UCAN.
    inner: Arc<UcanAuthInner<'a, S, K>>,
}

struct UcanAuthInner<'a, S, K>
where
    S: IpldStore,
    K: GetPublicKey,
{
    /// The signed UCAN.
    ucan: SignedUcan<'a, S>,

    /// The root public key.
    root_key: K,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a, S, K> UcanAuth<'a, S, K>
where
    S: IpldStore,
    K: GetPublicKey,
{
    /// Creates a new signed UCAN with a root public key.
    pub fn new(ucan: SignedUcan<'a, S>, root_key: K) -> Self {
        Self {
            inner: Arc::new(UcanAuthInner { ucan, root_key }),
        }
    }

    /// Checks if the UCAN permits the capability.
    pub async fn permits(
        &self,
        capability: impl Into<ResolvedCapabilityTuple>,
    ) -> UcanResult<bool> {
        self.inner
            .ucan
            .permits(capability, &self.inner.root_key)
            .await
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'a, S, K> Deref for UcanAuth<'a, S, K>
where
    S: IpldStore,
    K: GetPublicKey,
{
    type Target = SignedUcan<'a, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner.ucan
    }
}
