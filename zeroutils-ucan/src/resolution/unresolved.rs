use libipld::Cid;
use zeroutils_did_wk::WrappedDidWebKey;

use crate::{CapabilityTuple, Scheme};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents a unresolved capability.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnresolvedCapWithRootIss {
    /// The capability tuple.
    pub tuple: CapabilityTuple,
}

/// Represents the capabilities of a specific UCAN by CID within the `prf` section.
/// And if no CID is provided, it refers to all the UCANs in the `prf` section.
///
/// This is what `ucan:<cid>` and `ucan:./*` get converted to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnresolvedUcanWithCid {
    /// The CID of the UCAN.
    pub cid: Option<Cid>,
}

/// Represents the capabilities of any UCAN with a specific audience DID.
/// This type eventually gets converted to `CapWithRootIss`.
///
/// This is what `ucan://<did>/*` and `ucan://<did>/<scheme>` get converted to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnresolvedUcanWithAud {
    /// The DID of the UCAN.
    pub did: WrappedDidWebKey<'static>,

    /// The scheme of the UCAN.
    pub scheme: Option<Scheme>,
}
