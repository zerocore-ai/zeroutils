use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{UcanError, UcanResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Represents the character used to separate path segments in an ability.
pub const PATH_SEPARATOR: char = '/';

/// Represents ucan ability.
pub const UCAN_ABILITY: &str = "ucan/*";

/// Represents all possible abilities in the hierarchical level it is used. e.g. `http/*` or `db/table/*`.
pub const WILDCARD: &str = "*";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Defines a specific action or permission applicable to a resource within a UCAN.
///
/// An ability must include at least one namespace segment to distinguish it across different contexts,
/// such as `http/put` versus `db/put`. The ability `*` is reserved to denote all possible abilities for a given resource.
///
/// Abilities are case-insensitive and should be consistent with the resource's context (e.g., HTTP methods for web resources).
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub enum Ability {
    /// Resources referenced using the `ucan:` delegation scheme have the [`ucan/*` ability][ucan-ability], which represents
    /// all possible abilities for that given resource.
    ///
    /// [ucan-ability]: https://github.com/ucan-wg/spec?tab=readme-ov-file#51-ucan-delegation
    Ucan,

    /// Represents a namespaced ability delimited by a forward slash, such as `http/post`.
    ///
    /// An ability can have multiple segments, such as `db/table/read` and it can also include wildcards
    /// like `db/table/*` to represent all actions on a table.
    ///
    /// The [`top`][top] ability is represented as just `*` denotes all possible abilities for a given
    /// resource.
    ///
    /// [top]: https://github.com/ucan-wg/spec?tab=readme-ov-file#52-top
    Path(Path),
}

/// Represents a path in an ability, such as `http/get` or `db/table/read`.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct Path {
    segments: Vec<PathSegment>,
}

/// Represents a segment in a path, such as `http` or `db`. The segment is case-insensitive.
#[derive(PartialOrd, Ord, Clone, Debug)]
pub enum PathSegment {
    /// Represents a specific segment in a path, such as `http` or `db`. The segment is case-insensitive.
    Segment(String),

    /// Represents a wildcard segment in a path, such as `*`.
    Wildcard,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Ability {
    /// Creates an ability from an iterator of path segments.
    pub fn from_path_iter<T>(iter: impl IntoIterator<Item = T>) -> UcanResult<Self>
    where
        T: TryInto<PathSegment>,
        T::Error: Into<UcanError>,
    {
        Path::from_iter(iter).map(Self::Path)
    }

    /// TODO: Implement this method.
    pub fn allows(&self, _other: &Ability) -> UcanResult<bool> {
        unimplemented!()
    }
}

impl Path {
    /// Creates a path from an iterator of path segments.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: impl IntoIterator<Item = T>) -> UcanResult<Self>
    where
        T: TryInto<PathSegment>,
        T::Error: Into<UcanError>,
    {
        let segments = iter
            .into_iter()
            .map(T::try_into)
            .collect::<Result<Vec<_>, <T as TryInto<PathSegment>>::Error>>()
            .map_err(Into::into)?;

        if segments.is_empty() {
            return Err(UcanError::InvalidAbility("<empty>".into()));
        }

        Ok(Self { segments })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: Serialize and Deserialize
//--------------------------------------------------------------------------------------------------

impl Serialize for Ability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Ucan => serializer.serialize_str(UCAN_ABILITY),
            Self::Path(path) => path.serialize(serializer),
        }
    }
}

impl Serialize for Path {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self)
    }
}

impl<'de> Deserialize<'de> for Ability {
    fn deserialize<D>(deserializer: D) -> Result<Ability, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.as_str().try_into().map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for Path {
    fn deserialize<D>(deserializer: D) -> Result<Path, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.as_str().try_into().map_err(serde::de::Error::custom)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: Froms
//--------------------------------------------------------------------------------------------------

impl FromStr for Ability {
    type Err = UcanError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl TryFrom<String> for Ability {
    type Error = UcanError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&str> for Ability {
    type Error = UcanError;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        if path == UCAN_ABILITY {
            Ok(Self::Ucan)
        } else {
            Path::from_str(path).map(Self::Path)
        }
    }
}

impl Display for Ability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ucan => write!(f, "{}", UCAN_ABILITY),
            Self::Path(path) => write!(f, "{}", path),
        }
    }
}

impl FromStr for Path {
    type Err = UcanError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        path.try_into()
    }
}

impl TryFrom<&str> for Path {
    type Error = UcanError;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        let segments = path
            .split(PATH_SEPARATOR)
            .map(PathSegment::try_from)
            .collect::<UcanResult<Vec<_>>>()?;

        Ok(Self { segments })
    }
}

impl TryFrom<String> for Path {
    type Error = UcanError;

    fn try_from(path: String) -> Result<Self, Self::Error> {
        path.as_str().try_into()
    }
}

impl Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.segments
                .iter()
                .map(String::from)
                .collect::<Vec<_>>()
                .join("/")
        )
    }
}

impl TryFrom<&str> for PathSegment {
    type Error = UcanError;

    fn try_from(segment: &str) -> Result<Self, Self::Error> {
        segment.to_string().try_into()
    }
}

impl TryFrom<String> for PathSegment {
    type Error = UcanError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(UcanError::InvalidAbility(value));
        }

        if value == WILDCARD {
            Ok(Self::Wildcard)
        } else {
            Ok(Self::Segment(value))
        }
    }
}

impl From<PathSegment> for String {
    fn from(segment: PathSegment) -> Self {
        match segment {
            PathSegment::Segment(s) => s,
            PathSegment::Wildcard => WILDCARD.to_string(),
        }
    }
}

impl From<&PathSegment> for String {
    fn from(segment: &PathSegment) -> Self {
        match segment {
            PathSegment::Segment(s) => s.clone(),
            PathSegment::Wildcard => WILDCARD.to_string(),
        }
    }
}

impl Display for PathSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Segment(segment) => write!(f, "{}", segment),
            Self::Wildcard => write!(f, "{}", WILDCARD),
        }
    }
}

impl PartialEq for PathSegment {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Segment(a), Self::Segment(b)) => a.to_lowercase() == b.to_lowercase(),
            (Self::Wildcard, Self::Wildcard) => true,
            _ => false,
        }
    }
}

impl Eq for PathSegment {}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ability_constructor() -> anyhow::Result<()> {
        // One path segement.
        let ability = Ability::from_str("http")?;
        assert_eq!(ability, Ability::from_path_iter(vec!["http"])?);

        // Two path segements.
        let ability = Ability::from_str("http/get")?;
        assert_eq!(ability, Ability::from_path_iter(vec!["http", "get"])?,);

        // Three path segements.
        let ability = Ability::from_str("db/table/read")?;
        assert_eq!(
            ability,
            Ability::from_path_iter(vec!["db", "table", "read"])?
        );

        // Path with wildcard.
        let ability = Ability::from_str("db/table/*")?;
        assert_eq!(ability, Ability::from_path_iter(vec!["db", "table", "*"])?);

        // Ucan ability
        let ability = Ability::from_str("ucan/*")?;
        assert_eq!(ability, Ability::Ucan);

        // Invalid empty ability
        assert!(Ability::from_str("").is_err());

        Ok(())
    }

    #[test]
    fn test_ability_case_insensitive() -> anyhow::Result<()> {
        let ability1 = Ability::from_str("http/get")?;
        let ability2 = Ability::from_str("HTTP/GET")?;
        assert_eq!(ability1, ability2);

        Ok(())
    }
}
