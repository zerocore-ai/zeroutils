//! Error types of the zeroraft crate.

use std::{
    collections::HashSet, convert::Infallible, error::Error, fmt::Display, time::SystemTime,
};

use libipld::{cid::Version, Cid};
use serde_json::Value;
use thiserror::Error;

use crate::{
    Abilities, CapabilityTuple, Caveats, Trace, UnresolvedCapWithRootIss, UnresolvedUcanWithAud,
    UnresolvedUcanWithCid,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The result type for UCAN operations.
pub type UcanResult<T> = Result<T, UcanError>;

/// Defines the types of errors that can occur in UCAN operations.
#[derive(Debug, Error)]
pub enum UcanError {
    /// Infallible is an impossible error.
    #[error("Infallible")]
    Infallible(#[from] Infallible),

    /// Unable to parse the input.
    #[error("Unable to parse")]
    UnableToParse,

    /// Json (de)serialization errors
    #[error("Json serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Key errors
    #[error("Key error: {0}")]
    KeyError(#[from] zeroutils_key::KeyError),

    /// Base64 decoding errors
    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// Invalid ability
    #[error("Invalid ability: {0}")]
    InvalidAbility(String),

    /// The abilities map of a resource must contain at least one ability
    #[error("The abilities map of a resource must contain at least one ability")]
    NoAbility,

    /// Caveats must contain at least an empty object
    #[error("Caveats must contain at least an empty object")]
    EmptyCaveats,

    /// Invalid mixtures of caveats
    #[error("Invalid mixtures of caveats")]
    InvalidCaveatsMix,

    /// Invalid caveat
    #[error("Invalid caveat: {0}")]
    InvalidCaveat(Value),

    /// Uri parse error
    #[error("Uri parse error: {0}")]
    UriParseError(#[from] fluent_uri::ParseError),

    /// Invalid non-UCAN uri
    #[error("Invalid non-UCAN uri: {0}")]
    InvalidNonUcanUri(String),

    /// Did Web Key error
    #[error("Did Web Key error: {0}")]
    DidWebKeyError(#[from] zeroutils_did::DidError),

    /// Invalid proof reference
    #[error("Invalid proof reference: {0}")]
    InvalidProofReference(String),

    /// Cid parse error
    #[error("Cid parse error: {0}")]
    CidParseError(#[from] libipld::cid::Error),

    /// UCAN expired
    #[error("UCAN expired: {0:?}")]
    Expired(Option<SystemTime>),

    /// UCAN not yet valid
    #[error("UCAN not yet valid: {0:?}")]
    NotYetValid(Option<SystemTime>),

    /// Invalid time bounds
    #[error("Invalid time bounds: nbf: {0:?}, exp: {1:?}")]
    InvalidTimeBounds(Option<SystemTime>, Option<SystemTime>),

    /// Invalid proof Cid version
    #[error("Invalid proof Cid version: {0:?}")]
    InvalidProofCidVersion(Version),

    /// Invalid proof Cid codec
    #[error("Invalid proof Cid codec: {0}")]
    InvalidProofCidCodec(u64),

    /// Invalid proof Cid hash
    #[error("Invalid proof Cid hash: {0}")]
    InvalidProofCidHash(u64),

    /// Unsupported did:wk with locator component
    #[error("Unsupported did:wk with locator component: {0}")]
    UnsupportedDidWkLocator(String),

    /// Ipld store error
    #[error("Ipld store error: {0}")]
    IpldStoreError(#[from] zeroutils_store::cas::StoreError),

    /// Utf8 error
    #[error("Utf8 error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    /// Proof Cid not found
    #[error("Proof Cid not found: {0}")]
    ProofCidNotFound(Cid),

    /// Principal alignment error
    #[error("Principal alignment failed: our issuer: {0}, their aud: {1}")]
    PrincipalAlignmentFailed(String, String),

    /// Unsupported version
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),

    /// Unsupported token type
    #[error("Unsupported token type: {0}")]
    UnsupportedTokenType(String),

    /// Attenuation failed
    #[error(transparent)]
    AttenuationError(#[from] AttenuationError),

    /// Permission error
    #[error(transparent)]
    PermissionError(#[from] PermissionError),

    /// Unresolved capabilities
    #[error("Unresolved capabilities: {0:?}")]
    UnresolvedCapabilities(Box<Unresolved>, Trace),

    /// Invalid UCAN resource ability
    #[error("Invalid UCAN resource ability: {0:?}. Expected `ucan/*`")]
    InvalidUcanResourceAbility(Abilities),

    /// Invalid UCAN resource caveats
    #[error("Invalid UCAN resource caveats: {0}. Expected `[{{}}]`")]
    InvalidUcanResourceCaveats(Caveats),

    /// Expiration constraint violated
    #[error("Expiration constraint violated: {0:?}, {1:?}")]
    ExpirationConstraintViolated(Option<SystemTime>, Option<SystemTime>),

    /// Not before constraint violated
    #[error("Not before constraint violated: {0:?}, {1:?}")]
    NotBeforeConstraintViolated(Option<SystemTime>, Option<SystemTime>),

    /// Custom error.
    #[error("Custom error: {0}")]
    Custom(#[from] AnyError),
}

/// Defines the attenuation errors that can occur in UCAN operations.
#[derive(Debug, Error)]
pub enum AttenuationError {
    /// Capability not delegated by root issuer
    #[error("Capability not delegated by root issuer: {0}, trace: {1:?}")]
    CapabilityNotDelegatedByRootIssuer(CapabilityTuple, Trace),

    /// Capability not permitted
    #[error("Capability not permitted in scope: {0}, trace: {1:?}")]
    CapabilityNotPermittedInScope(CapabilityTuple, Trace),

    /// Abilities not permitted in scope
    #[error("Abilities not permitted in scope: requested abilities: {0:?}, trace: {1:?}")]
    AbilitiesNotPermittedInScope(Abilities, Trace),

    /// Audience did not match
    #[error("Audience did not match: {0}, trace: {1:?}")]
    AudienceDidNotMatch(String, Trace),

    /// Scheme not permitted in scope
    #[error("Scheme not permitted in scope: {0}, trace: {1:?}")]
    SchemeNotPermittedInScope(String, Trace),
}

/// Defines the permission errors that can occur in UCAN operations.
#[derive(Debug, Error)]
pub enum PermissionError {
    /// Resource URI not permitted
    #[error("Resource URI not permitted: allowed identifier: {0}, requested identifier: {1}")]
    UnpermittedResourceUri(String, String),

    /// Ability not permitted
    #[error("Ability not permitted: allowed ability: {0}, requested ability: {1}")]
    UnpermittedAbility(String, String),

    /// Caveats not permitted
    #[error("Caveats not permitted: allowed caveats: {0}, requested caveats: {1}")]
    UnpermittedCaveats(String, String),
}

/// Unresolved capabilities
#[derive(Debug, Clone)]
pub struct Unresolved(
    pub HashSet<UnresolvedUcanWithCid>,
    pub HashSet<UnresolvedUcanWithAud>,
    pub HashSet<UnresolvedCapWithRootIss>,
);

/// An error that can represent any error.
#[derive(Debug)]
pub struct AnyError {
    error: anyhow::Error,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl UcanError {
    /// Creates a new `Err` result.
    pub fn custom(error: impl Into<anyhow::Error>) -> UcanError {
        UcanError::Custom(AnyError {
            error: error.into(),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl
    From<(
        HashSet<UnresolvedUcanWithCid>,
        HashSet<UnresolvedUcanWithAud>,
        HashSet<UnresolvedCapWithRootIss>,
    )> for Unresolved
{
    fn from(
        value: (
            HashSet<UnresolvedUcanWithCid>,
            HashSet<UnresolvedUcanWithAud>,
            HashSet<UnresolvedCapWithRootIss>,
        ),
    ) -> Self {
        Self(value.0, value.1, value.2)
    }
}

impl PartialEq for AnyError {
    fn eq(&self, other: &Self) -> bool {
        self.error.to_string() == other.error.to_string()
    }
}

impl Display for AnyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl Error for AnyError {}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Creates an `Ok` `UcanResult`.
#[allow(non_snake_case)]
pub fn Ok<T>(value: T) -> UcanResult<T> {
    Result::Ok(value)
}
