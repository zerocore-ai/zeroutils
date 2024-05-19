use std::{
    collections::{BTreeMap, BTreeSet},
    ops::{Deref, DerefMut},
};

use async_once_cell::OnceCell;
use libipld::Cid;
use serde::{Deserialize, Serialize};
use zeroutils_store::{IpldStore, PlaceholderStore};

use crate::{SignedUcan, UcanError, UcanResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A collection of proofs, typically represented by Content Identifiers (CIDs), used in a UCAN.
///
/// This type stores proofs in a sorted set, ensuring that each proof is unique and allowing
/// efficient querying and verification. These proofs are used to link UCANs hierarchically,
/// establishing chains of delegation.
#[derive(Debug)]
pub struct Proofs<'a, S = PlaceholderStore>(BTreeMap<Cid, CachedUcan<'a, S>>)
where
    S: IpldStore;

/// A cached UCAN for a specific proof CID.
pub type CachedUcan<'a, S> = OnceCell<SignedUcan<'a, S>>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a, S> Proofs<'a, S>
where
    S: IpldStore,
{
    /// Creates a new collection of proofs.
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Changes the store used to resolve the proofs.
    pub fn use_store<T>(self, store: &'a T) -> Proofs<'a, T>
    where
        T: IpldStore,
    {
        self.0
            .into_iter()
            .map(|(cid, mut cached)| {
                let cached = match cached.take().map(|ucan| ucan.use_store(store)) {
                    Some(ucan) => OnceCell::from(ucan),
                    None => OnceCell::new(),
                };
                (cid, cached)
            })
            .collect()
    }

    /// Gets the UCAN associated with the given proof CID.
    pub async fn fetch_cached_ucan(
        &'a self,
        cid: &Cid,
        store: &'a S,
    ) -> UcanResult<&'a SignedUcan<'a, S>> {
        let cache = self.0.get(cid).ok_or(UcanError::ProofCidNotFound(*cid))?;
        let ucan = cache
            .get_or_try_init(async {
                let bytes = store.get_bytes(cid).await?;
                let ucan_str = std::str::from_utf8(&bytes)?;
                SignedUcan::with_store(ucan_str, store)
            })
            .await?;

        Ok(ucan)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: Proofs
//--------------------------------------------------------------------------------------------------

impl<'a, S> Deref for Proofs<'a, S>
where
    S: IpldStore,
{
    type Target = BTreeMap<Cid, CachedUcan<'a, S>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, S> DerefMut for Proofs<'a, S>
where
    S: IpldStore,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a, S> FromIterator<(Cid, CachedUcan<'a, S>)> for Proofs<'a, S>
where
    S: IpldStore,
{
    fn from_iter<T: IntoIterator<Item = (Cid, CachedUcan<'a, S>)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<'a, S> FromIterator<Cid> for Proofs<'a, S>
where
    S: IpldStore,
{
    fn from_iter<T: IntoIterator<Item = Cid>>(iter: T) -> Self {
        Self(iter.into_iter().map(|cid| (cid, OnceCell::new())).collect())
    }
}

impl<'a, S> From<BTreeMap<Cid, CachedUcan<'a, S>>> for Proofs<'a, S>
where
    S: IpldStore,
{
    fn from(cids: BTreeMap<Cid, CachedUcan<'a, S>>) -> Self {
        Self(cids)
    }
}

impl<'a, S> From<Proofs<'a, S>> for BTreeMap<Cid, CachedUcan<'a, S>>
where
    S: IpldStore,
{
    fn from(proofs: Proofs<'a, S>) -> Self {
        proofs.0
    }
}

impl<'a, S> From<Proofs<'a, S>> for BTreeSet<Cid>
where
    S: IpldStore,
{
    fn from(proofs: Proofs<'a, S>) -> Self {
        proofs.0.keys().cloned().collect()
    }
}

impl<'a, S> Default for Proofs<'a, S>
where
    S: IpldStore,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, S> Clone for Proofs<'a, S>
where
    S: IpldStore,
{
    fn clone(&self) -> Self {
        Self(self.0.keys().map(|cid| (*cid, OnceCell::new())).collect())
    }
}

impl<'a, S> Serialize for Proofs<'a, S>
where
    S: IpldStore,
{
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::Serializer,
    {
        self.0.keys().collect::<BTreeSet<_>>().serialize(serializer)
    }
}

impl<'a, 'de, S> Deserialize<'de> for Proofs<'a, S>
where
    S: IpldStore,
{
    fn deserialize<D>(deserializer: D) -> Result<Proofs<'a, S>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cids = BTreeSet::<Cid>::deserialize(deserializer)?;
        Ok(cids.into_iter().map(|cid| (cid, OnceCell::new())).collect())
    }
}

impl<'a, S> PartialEq for Proofs<'a, S>
where
    S: IpldStore,
{
    fn eq(&self, other: &Self) -> bool {
        self.0.keys().eq(other.0.keys())
    }
}

impl<'a, S> Eq for Proofs<'a, S> where S: IpldStore {}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::UNIX_EPOCH};

    use zeroutils_did_wk::{Base, WrappedDidWebKey};
    use zeroutils_key::{Ed25519KeyPair, KeyPairGenerate};
    use zeroutils_store::MemoryStore;

    use crate::{caps, Ucan};

    use super::*;

    #[test]
    fn test_proof_constructors() -> anyhow::Result<()> {
        let cid_0 = Cid::from_str("bafkreih43byuv2f6ils5kpsj2qwzbwgdd2pqzs6anwm3nhfrhlagqjektm")?;
        let cid_1 = Cid::from_str("bafkreifiul3oxyugnf6fe7vtljmlku4vglu3hlr3mtkowcsg7nsxwqkwfq")?;
        let proofs = Proofs::<PlaceholderStore>::from_iter(vec![cid_0, cid_1]);

        assert_eq!(proofs.len(), 2);
        assert!(proofs.contains_key(&cid_0));
        assert!(proofs.contains_key(&cid_1));

        Ok(())
    }

    #[tokio::test]
    async fn test_proof_equality() -> anyhow::Result<()> {
        let store = MemoryStore::default();
        let issuer_key = Ed25519KeyPair::generate(&mut rand::thread_rng())?;
        let audience_key = Ed25519KeyPair::generate(&mut rand::thread_rng())?;

        let signed_ucan = Ucan::builder()
            .audience(WrappedDidWebKey::from_key(&audience_key, Base::Base64Url)?)
            .expiration(UNIX_EPOCH + std::time::Duration::from_secs(3_600_000))
            .capabilities(caps!())
            .sign(&issuer_key)?;

        let ucan_encoded = signed_ucan.to_string();
        let cid = store.put_bytes(ucan_encoded).await?;

        let proofs_0 = Proofs::from_iter(vec![cid]);
        let proofs_1 = Proofs::from_iter(vec![(cid, OnceCell::from(signed_ucan))]);

        assert_eq!(proofs_0, proofs_1);

        Ok(())
    }
}
