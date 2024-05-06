use std::collections::BTreeSet;

use libipld::Cid;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A collection of proofs, typically represented by Content Identifiers (CIDs), used in a UCAN.
///
/// This type stores proofs in a sorted set, ensuring that each proof is unique and allowing
/// efficient querying and verification. These proofs are used to link UCANs hierarchically,
/// establishing chains of delegation.
pub type UcanProofs = BTreeSet<Cid>;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------
