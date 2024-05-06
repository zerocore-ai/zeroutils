use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::Uri;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A hierarchical mapping from a URI (as a namespace and resource identifier) to the associated abilities.
///
/// Each ability can have a set of caveats, which are conditions or restrictions on the ability's use.
/// This structure allows for a granular definition of permissions across different resources and actions.
pub type UcanCapabilities = BTreeMap<Uri, UcanAbilities>;

/// Represents a set of actions (abilities) that can be performed on a resource, mapped to potential caveats.
///
/// Abilities must be consistent with the resource's context (e.g., HTTP methods for web resources) and are case-insensitive.
///
/// Abilities can be organized hierarchically, allowing for broad capabilities (like a superuser) to encompass more specific ones.
pub type UcanAbilities = BTreeMap<UcanAbility, UcanCaveats>;

/// Conditions or stipulations that modify or restrict how an associated ability can be used.
///
/// Caveats function as additional details or requirements that must be met for the ability to be validly exercised,
/// serving as an "escape hatch" to cover use cases not fully captured by resource and ability fields alone.
pub type UcanCaveats = Vec<Map<String, Value>>;

/// Defines a specific action or permission applicable to a resource within a UCAN.
///
/// An ability must include at least one namespace segment to distinguish it across different contexts,
/// such as `http/put` versus `db/put`. The ability `*` is reserved to denote universal permission across any resource.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct UcanAbility(String);

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------
