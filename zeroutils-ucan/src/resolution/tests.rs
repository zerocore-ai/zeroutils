use std::time::{Duration, SystemTime};

use rand::thread_rng;
use zeroutils_did_wk::{Base, WrappedDidWebKey};
use zeroutils_key::{Ed25519KeyPair, KeyPairGenerate};
use zeroutils_store::{IpldStore, MemoryStore};

use crate::{caps, RootAuthority, Ucan};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_ucan_resolve_capabilities() -> anyhow::Result<()> {
    let store = MemoryStore::default();

    let p0 = Ed25519KeyPair::generate(&mut thread_rng())?;
    let p1 = Ed25519KeyPair::generate(&mut thread_rng())?;
    let p2 = Ed25519KeyPair::generate(&mut thread_rng())?;

    let p0_did = WrappedDidWebKey::from_key(&p0, Base::Base58Btc)?;
    let p1_did = WrappedDidWebKey::from_key(&p1, Base::Base58Btc)?;
    let p2_did = WrappedDidWebKey::from_key(&p2, Base::Base58Btc)?;

    let now = SystemTime::now();

    let root_authority = RootAuthority {
        key: p0.clone(),
        capabilities: caps! {
            "zerodb://": { "db/table/read": [{}] }
        }?
        .try_into()?,
    };

    let ucan0 = Ucan::builder()
        .issuer(p0_did.clone())
        .audience(p1_did.clone())
        .expiration(now + Duration::from_secs(50))
        .capabilities(caps! {
            "zerodb://": { "db/table/read": [{}] }
        }?)
        .store(store.clone())
        .proofs([])
        .sign(&p0)?;

    let cid0 = store.put_bytes(ucan0.to_string()).await?;

    let ucan1 = Ucan::builder()
        .issuer(p1_did)
        .audience(p2_did)
        .expiration(now + Duration::from_secs(25))
        .capabilities(caps! {
            "ucan:./*": { "ucan/*": [{}] },
            "zerodb://": { "db/table/read": [{}] }
        }?)
        .store(store.clone())
        .proofs([cid0])
        .sign(&p1)?;

    let resolved = ucan1.resolve_capabilities(&root_authority, &store).await?;

    for r in resolved {
        println!("resolved: {}", r);
    }

    Ok(())
}
