use std::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
    fmt::Display,
    hash::{Hash, Hasher},
    str::FromStr,
};

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{PathError, PathResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

lazy_static! {
    static ref RE_VALID_PATH_SEGMENT: Regex = Regex::new(r"^[a-zA-Z0-9]+$").unwrap();
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A `PathSegment` represents a single part of a path. For example, the path `/home/user/file.txt`
/// includes the segments: `home`, `user`, and `file.txt`.
///
/// ## Important
///
/// Path segments are case-insensitive, which affects their equality and hash implementations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PathSegment {
    /// Represents the current directory, denoted by a single dot `.`.
    CurrentDir,

    /// Represents the parent directory, denoted by a double dot `..`.
    ParentDir,

    /// Represents a named directory or file.
    Named(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PathSegment {
    /// Validates a path segment.
    pub fn validate(segment: &str) -> PathResult<()> {
        if segment == "." || segment == ".." {
            return Ok(());
        }

        if !RE_VALID_PATH_SEGMENT.is_match(segment) {
            return Err(PathError::InvalidPathSegment(segment.to_owned()));
        }

        Ok(())
    }

    /// Canonicalizes a path segment.
    pub fn canonicalize(&self) -> PathSegment {
        match self {
            PathSegment::Named(segment) => PathSegment::Named(segment.to_lowercase()),
            _ => self.clone(),
        }
    }

    /// Returns whether the path segment is a named segment.
    pub fn is_named(&self) -> bool {
        matches!(self, PathSegment::Named(_))
    }

    /// Returns the path segment as a string.
    pub fn as_str(&self) -> &str {
        match self {
            PathSegment::Named(segment) => segment.as_str(),
            PathSegment::CurrentDir => ".",
            PathSegment::ParentDir => "..",
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FromStr for PathSegment {
    type Err = PathError;

    fn from_str(segment: &str) -> Result<Self, Self::Err> {
        PathSegment::try_from(segment)
    }
}

impl TryFrom<String> for PathSegment {
    type Error = PathError;

    fn try_from(segment: String) -> Result<Self, Self::Error> {
        PathSegment::validate(&segment)?;
        match segment.as_str() {
            "." => Ok(PathSegment::CurrentDir),
            ".." => Ok(PathSegment::ParentDir),
            _ => Ok(PathSegment::Named(segment)),
        }
    }
}

impl TryFrom<&str> for PathSegment {
    type Error = PathError;

    fn try_from(segment: &str) -> Result<Self, Self::Error> {
        segment.to_string().try_into()
    }
}

impl Display for PathSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathSegment::CurrentDir => write!(f, "."),
            PathSegment::ParentDir => write!(f, ".."),
            PathSegment::Named(segment) => write!(f, "{}", segment),
        }
    }
}

impl PartialEq for PathSegment {
    fn eq(&self, other: &Self) -> bool {
        match (self.canonicalize(), other.canonicalize()) {
            (PathSegment::CurrentDir, PathSegment::CurrentDir) => true,
            (PathSegment::ParentDir, PathSegment::ParentDir) => true,
            (PathSegment::Named(a), PathSegment::Named(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for PathSegment {}

impl PartialOrd for PathSegment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PathSegment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonicalize()
            .as_str()
            .cmp(other.canonicalize().as_str())
    }
}

impl Hash for PathSegment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonicalize().as_str().hash(state)
    }
}
