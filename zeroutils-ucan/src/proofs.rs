use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
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
pub struct Proofs<S = PlaceholderStore>(pub(crate) BTreeMap<Cid, CachedUcan<S>>)
where
    S: IpldStore;

/// A cached UCAN for a specific proof CID.
pub type CachedUcan<S> = OnceCell<SignedUcan<'static, S>>;

/// Represents a proof in a `Proofs` collection.
pub struct Proof<'a, S>
where
    S: IpldStore,
{
    cid: Cid,
    cache: &'a CachedUcan<S>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<S> Proofs<S>
where
    S: IpldStore,
{
    /// Creates a new collection of proofs.
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Changes the store used to resolve the proofs.
    pub fn use_store<T>(self, store: T) -> Proofs<T>
    where
        T: IpldStore,
    {
        self.0
            .into_iter()
            .map(|(cid, mut cached)| {
                let cached = match cached.take().map(|ucan| ucan.use_store(store.clone())) {
                    Some(ucan) => OnceCell::from(ucan),
                    None => OnceCell::new(),
                };
                (cid, cached)
            })
            .collect()
    }

    /// Fetches the UCAN associated with the given proof CID from the store.
    pub async fn fetch_ucan<'b>(
        &'b self,
        cid: &Cid,
        store: &'b S,
    ) -> UcanResult<&'b SignedUcan<S>> {
        self.0
            .get(cid)
            .ok_or(UcanError::ProofCidNotFound(*cid))?
            .get_or_try_init(async {
                let bytes = store.get_bytes(cid).await?;
                let ucan_str = std::str::from_utf8(&bytes)?;
                SignedUcan::with_store(ucan_str, store.clone())
            })
            .await
    }

    /// Gets the number of proofs in the collection.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Checks if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Checks if the collection contains the given proof CID.
    pub fn contains_cid(&self, cid: &Cid) -> bool {
        self.0.contains_key(cid)
    }

    /// Returns an iterator over the proofs in the collection.
    pub fn iter(&self) -> impl Iterator<Item = Proof<S>> {
        self.0.iter().map(|(cid, cache)| Proof { cid: *cid, cache })
    }

    /// Gets the proof associated with the given CID.
    pub fn get<'b>(&'b self, cid: &Cid) -> Option<Proof<'b, S>> {
        self.0.get(cid).map(|cache| Proof { cid: *cid, cache })
    }
}

impl<S> Proof<'_, S>
where
    S: IpldStore,
{
    /// Fetches the UCAN associated with the proof from the store.
    pub async fn fetch_ucan<'b>(&'b self, store: &'b S) -> UcanResult<&'b SignedUcan<S>> {
        self.cache
            .get_or_try_init(async {
                let bytes = store.get_bytes(self.cid).await?;
                let ucan_str = std::str::from_utf8(&bytes)?;
                SignedUcan::with_store(ucan_str, store.clone())
            })
            .await
    }

    /// Gets the CID of the proof.
    pub fn cid(&self) -> &Cid {
        &self.cid
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: Proofs
//--------------------------------------------------------------------------------------------------

impl<S> FromIterator<(Cid, CachedUcan<S>)> for Proofs<S>
where
    S: IpldStore,
{
    fn from_iter<T: IntoIterator<Item = (Cid, CachedUcan<S>)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<S> FromIterator<Cid> for Proofs<S>
where
    S: IpldStore,
{
    fn from_iter<T: IntoIterator<Item = Cid>>(iter: T) -> Self {
        Self(iter.into_iter().map(|cid| (cid, OnceCell::new())).collect())
    }
}

impl<'a, S> FromIterator<Proof<'a, S>> for Proofs<S>
where
    S: IpldStore,
{
    fn from_iter<T: IntoIterator<Item = Proof<'a, S>>>(iter: T) -> Self {
        iter.into_iter()
            .map(|proof| (*proof.cid(), OnceCell::new()))
            .collect()
    }
}

impl<S> From<BTreeMap<Cid, CachedUcan<S>>> for Proofs<S>
where
    S: IpldStore,
{
    fn from(cids: BTreeMap<Cid, CachedUcan<S>>) -> Self {
        Self(cids)
    }
}

impl<S> From<Proofs<S>> for BTreeMap<Cid, CachedUcan<S>>
where
    S: IpldStore,
{
    fn from(proofs: Proofs<S>) -> Self {
        proofs.0
    }
}

impl<S> From<Proofs<S>> for BTreeSet<Cid>
where
    S: IpldStore,
{
    fn from(proofs: Proofs<S>) -> Self {
        proofs.0.keys().cloned().collect()
    }
}

impl<S> Default for Proofs<S>
where
    S: IpldStore,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Clone for Proofs<S>
where
    S: IpldStore,
{
    fn clone(&self) -> Self {
        // TODO: We should be able to clone the cached UCANs too.
        Self(self.0.keys().map(|cid| (*cid, OnceCell::new())).collect())
    }
}

impl<S> Serialize for Proofs<S>
where
    S: IpldStore,
{
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::Serializer,
    {
        self.0
            .keys()
            .map(|cid| cid.to_string())
            .collect::<BTreeSet<_>>()
            .serialize(serializer)
    }
}

impl<'de, S> Deserialize<'de> for Proofs<S>
where
    S: IpldStore,
{
    fn deserialize<D>(deserializer: D) -> Result<Proofs<S>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cids = BTreeSet::<String>::deserialize(deserializer)?;

        let proofs = cids
            .into_iter()
            .map(|cid| Ok((cid.parse()?, OnceCell::new())))
            .collect::<Result<Proofs<_>, libipld::cid::Error>>()
            .map_err(serde::de::Error::custom)?;

        Ok(proofs)
    }
}

impl<S> PartialEq for Proofs<S>
where
    S: IpldStore,
{
    fn eq(&self, other: &Self) -> bool {
        self.0.keys().eq(other.0.keys())
    }
}

impl<S> Eq for Proofs<S> where S: IpldStore {}

impl<S> Debug for Proofs<S>
where
    S: IpldStore,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        str::FromStr,
        time::{Duration, SystemTime},
    };

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
        assert!(proofs.contains_cid(&cid_0));
        assert!(proofs.contains_cid(&cid_1));

        Ok(())
    }

    #[tokio::test]
    async fn test_proof_equality() -> anyhow::Result<()> {
        let store = MemoryStore::default();
        let issuer_key = Ed25519KeyPair::generate(&mut rand::thread_rng())?;
        let audience_key = Ed25519KeyPair::generate(&mut rand::thread_rng())?;

        let signed_ucan = Ucan::builder()
            .audience(WrappedDidWebKey::from_key(&audience_key, Base::Base64Url)?)
            .expiration(SystemTime::now() + Duration::from_secs(3_600_000))
            .capabilities(caps!()?)
            .sign(&issuer_key)?;

        let ucan_encoded = signed_ucan.to_string();
        let cid = store.put_bytes(ucan_encoded).await?;

        let proofs_0 = Proofs::from_iter(vec![cid]);
        let proofs_1 = Proofs::from_iter(vec![(cid, OnceCell::from(signed_ucan))]);

        assert_eq!(proofs_0, proofs_1);

        Ok(())
    }

    #[test]
    fn test_proofs_serde() -> anyhow::Result<()> {
        let proofs = Proofs::from_iter(vec![
            Cid::from_str("bafkreih43byuv2f6ils5kpsj2qwzbwgdd2pqzs6anwm3nhfrhlagqjektm")?,
            Cid::from_str("bafkreifiul3oxyugnf6fe7vtljmlku4vglu3hlr3mtkowcsg7nsxwqkwfq")?,
        ]);

        let ser = serde_json::to_string(&proofs)?;
        let de: Proofs<PlaceholderStore> = serde_json::from_str(&ser)?;

        assert_eq!(proofs, de);

        Ok(())
    }
}
