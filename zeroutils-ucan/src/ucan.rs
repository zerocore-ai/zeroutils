use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    time::SystemTime,
};

use cid::Cid;
use serde_json::{Map, Value};

use crate::{
    ipldstore::BlockStore,
    key::{did_web_key::DidWebKey, JwsAlgName},
};

use super::{UcanError, Uri};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Ucan<S>
where
    S: BlockStore,
{
    header: UcanHeader,
    payload: UcanPayload<S>,
    signature: Vec<u8>,
}

pub struct UcanHeader {
    alg: JwsAlgName,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UcanPayload<S>
where
    S: BlockStore,
{
    #[cfg_attr(feature = "serde", serde(rename = "iss"))]
    issuer: DidWebKey,

    #[cfg_attr(feature = "serde", serde(rename = "aud"))]
    audience: DidWebKey,

    #[cfg_attr(feature = "serde", serde(rename = "exp"))]
    expiration: SystemTime,

    #[cfg_attr(
        feature = "serde",
        serde(rename = "nbf", skip_serializing_if = "Option::is_none")
    )]
    not_before: Option<SystemTime>,

    #[cfg_attr(
        feature = "serde",
        serde(rename = "nnc", skip_serializing_if = "Option::is_none")
    )]
    nonce: Option<String>,

    #[cfg_attr(
        feature = "serde",
        serde(rename = "fct", skip_serializing_if = "Option::is_none")
    )]
    facts: Option<UcanFacts>,

    #[cfg_attr(feature = "serde", serde(rename = "cap"))]
    capabilities: UcanCapabilities,

    #[cfg_attr(
        feature = "serde",
        serde(rename = "prf", skip_serializing_if = "BTreeSet::is_empty")
    )]
    proofs: UcanProofs,

    #[cfg_attr(feature = "serde", serde(skip))]
    block_store: S,
}

pub type UcanFacts = BTreeMap<String, Value>;

pub type UcanCapabilities = BTreeMap<String, UcanCapability>;

pub type UcanProofs = BTreeSet<Cid>;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UcanCapability {
    abilities: BTreeMap<Uri, Map<String, Value>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<S> Ucan<S>
where
    S: BlockStore,
{
    pub fn from_parts(header: UcanHeader, payload: UcanPayload<S>, signature: Vec<u8>) -> Self {
        Self {
            header,
            payload,
            signature,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<S> FromStr for Ucan<S>
where
    S: BlockStore,
{
    type Err = UcanError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        unimplemented!()
    }
}

impl<S> From<Value> for Ucan<S>
where
    S: BlockStore,
{
    fn from(value: Value) -> Self {
        unimplemented!()
    }
}
