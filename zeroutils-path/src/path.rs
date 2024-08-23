use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    hash::Hash,
    slice::SliceIndex,
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use crate::PathSegment;

use super::{PathError, PathResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The path separator.
pub const PATH_SEPARATOR: char = '/';

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A `Path` represents a sequence of path segments that can reference a directory or file in the
/// file system. For instance, the path `/home/user/file.txt` consists of the segments:
/// `home`, `user`, and `file.txt`.
///
/// ## Important
///
/// Paths are case-insensitive, which affects their equality and hash implementations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Path {
    /// The segments composing the path.
    segments: Vec<PathSegment>,
}

/// A slice of a path.
pub struct PathSlice<'a> {
    /// The segments composing the path.
    segments: &'a [PathSegment],
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Path {
    /// Creates a path from an iterator of path segments.
    pub fn try_from_iter<T>(
        iter: impl IntoIterator<Item = T>,
    ) -> Result<Self, <T as TryInto<PathSegment>>::Error>
    where
        T: TryInto<PathSegment>,
    {
        let segments = iter
            .into_iter()
            .map(T::try_into)
            .collect::<Result<Vec<_>, <T as TryInto<PathSegment>>::Error>>()?;

        Ok(Self { segments })
    }

    /// Returns the segments of the path.
    pub fn get_segments(&self) -> &[PathSegment] {
        &self.segments
    }

    /// Canonicalizes the path by trying to remove all `.` and `..` from the path.
    ///
    /// Leading `.` and `..` that go past the root segment are not supported.
    pub fn canonicalize(&self) -> PathResult<Self> {
        let mut resolved_segments = Vec::new();

        for (i, segment) in self.segments.iter().enumerate() {
            match segment {
                PathSegment::CurrentDir => {
                    if i == 0 {
                        return Err(PathError::LeadingCurrentDir);
                    }
                    // Skip the current directory segment otherwise
                }
                PathSegment::ParentDir => {
                    // Remove the preceding segment unless out of bounds
                    if resolved_segments.is_empty() {
                        return Err(PathError::OutOfBoundsParentDir);
                    }
                    resolved_segments.pop();
                }
                PathSegment::Named(name) => {
                    resolved_segments.push(PathSegment::Named(name.clone()));
                }
            }
        }

        Ok(Self {
            segments: resolved_segments,
        })
    }

    /// Pushes a segment to the path.
    pub fn push(&mut self, segment: PathSegment) {
        self.segments.push(segment);
    }

    /// Pops a segment from the path.
    pub fn pop(&mut self) -> Option<PathSegment> {
        self.segments.pop()
    }

    /// Returns the number of segments in the path.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Returns whether the path is empty.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns the first segment of the path.
    pub fn first(&self) -> Option<&PathSegment> {
        self.segments.first()
    }

    /// Returns the last segment of the path.
    pub fn last(&self) -> Option<&PathSegment> {
        self.segments.last()
    }

    /// Returns an iterator over the path segments.
    pub fn iter(&self) -> impl Iterator<Item = &PathSegment> {
        self.segments.iter()
    }

    /// Borrows the path as a `PathSlice`.
    ///
    /// This method creates a borrowed view of the `Path`, allowing you to work with the segments
    /// of the path without taking ownership. This can be useful when you need a read-only
    /// view of the path.
    pub fn as_slice(&self) -> PathSlice {
        PathSlice {
            segments: &self.segments,
        }
    }

    /// Slices the path.
    ///
    /// This method creates a borrowed view of a sub-range of the `Path` segments. The `slice` parameter
    /// can be any type that implements the `SliceIndex` trait for slices of `PathSegment`. This provides
    /// flexibility in specifying the range of segments to include in the slice.
    ///
    /// # Panics
    ///
    /// Panics if the range is out of bounds.
    pub fn slice(
        &self,
        slice: impl SliceIndex<[PathSegment], Output = [PathSegment]>,
    ) -> PathSlice {
        PathSlice {
            segments: &self.segments[slice],
        }
    }
}

impl<'a> PathSlice<'a> {
    /// Returns the number of segments in the path.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Returns whether the path is empty.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns the first segment of the path.
    pub fn first(&self) -> Option<&PathSegment> {
        self.segments.first()
    }

    /// Returns the last segment of the path.
    pub fn last(&self) -> Option<&PathSegment> {
        self.segments.last()
    }

    /// Returns an iterator over the path segments.
    pub fn iter(&self) -> impl Iterator<Item = &PathSegment> {
        self.segments.iter()
    }

    /// Converts a borrowed `PathSlice` into an owned `Path`.
    ///
    /// This method creates a new `Path` instance by cloning the segments of the `PathSlice`.
    pub fn to_owned(&self) -> Path {
        Path {
            segments: self.segments.to_owned(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: Path
//--------------------------------------------------------------------------------------------------

impl FromStr for Path {
    type Err = PathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl TryFrom<&str> for Path {
    type Error = PathError;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        let segments = path
            .split(PATH_SEPARATOR)
            .filter(|segment| !segment.is_empty())
            .map(PathSegment::try_from)
            .collect::<PathResult<Vec<_>>>()?;

        Ok(Self { segments })
    }
}

impl TryFrom<String> for Path {
    type Error = PathError;

    fn try_from(path: String) -> Result<Self, Self::Error> {
        path.as_str().try_into()
    }
}

impl Extend<PathSegment> for Path {
    fn extend<T: IntoIterator<Item = PathSegment>>(&mut self, iter: T) {
        self.segments.extend(iter);
    }
}

impl Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "/{}",
            self.segments
                .iter()
                .map(|segment| segment.to_string())
                .collect::<Vec<_>>()
                .join("/")
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::hash::DefaultHasher;

    use super::*;

    #[test]
    fn test_path_constructor() -> anyhow::Result<()> {
        let path = Path::try_from_iter(vec!["a", "b", "c"])?;
        assert_eq!(path.segments.len(), 3);
        assert_eq!(path.segments[0], PathSegment::Named("a".to_owned()));
        assert_eq!(path.segments[1], PathSegment::Named("b".to_owned()));
        assert_eq!(path.segments[2], PathSegment::Named("c".to_owned()));

        let path = Path::from_str("/a/b/c")?;
        assert_eq!(path.segments.len(), 3);
        assert_eq!(path.segments[0], PathSegment::Named("a".to_owned()));
        assert_eq!(path.segments[1], PathSegment::Named("b".to_owned()));
        assert_eq!(path.segments[2], PathSegment::Named("c".to_owned()));

        let path = Path::try_from_iter(vec![".", "..", "a"])?;
        assert_eq!(path.segments.len(), 3);
        assert_eq!(path.segments[0], PathSegment::CurrentDir);
        assert_eq!(path.segments[1], PathSegment::ParentDir);
        assert_eq!(path.segments[2], PathSegment::Named("a".to_owned()));

        Ok(())
    }

    #[test]
    fn test_path_canonicalize() -> anyhow::Result<()> {
        let path = Path::try_from_iter(vec!["the", "quick", "brown", "fox"])?;
        assert_eq!(path.canonicalize()?, path);

        let path = Path::try_from_iter(vec!["the", "quick", "..", "..", "brown"])?;
        assert_eq!(path.canonicalize()?, Path::try_from_iter(vec!["brown"])?);

        let path = Path::try_from_iter(vec!["the", ".", "quick", "..", "..", "brown"])?;
        assert_eq!(path.canonicalize()?, Path::try_from_iter(vec!["brown"])?);

        // Fails

        let path = Path::try_from_iter(vec![".", "the"])?;
        assert!(path.canonicalize().is_err());

        let path = Path::try_from_iter(vec!["..", "quick"])?;
        assert!(path.canonicalize().is_err());

        let path = Path::try_from_iter(vec!["the", "..", "..", "quick"])?;
        assert!(path.canonicalize().is_err());

        let path = Path::try_from_iter(vec!["the", "..", "quick", "..", "..", "brown"])?;
        assert!(path.canonicalize().is_err());

        Ok(())
    }

    #[test]
    fn test_path_display() -> anyhow::Result<()> {
        let path = Path::try_from_iter(vec!["0", "the", "quick", "brown", "fox"])?;
        let encoded = path.to_string();

        assert_eq!(encoded, "/0/the/quick/brown/fox");
        assert_eq!(path, Path::from_str(&encoded)?);

        Ok(())
    }

    #[test]
    fn test_path_equality() -> anyhow::Result<()> {
        let base_path = Path::from_str("/0/the/quick/brown/fox")?;

        assert_eq!(base_path, Path::from_str("/0/the/quick/brown/fox")?);
        assert_eq!(base_path, Path::from_str("/0/THE/QUICK/BROWN/FOX")?);
        assert_eq!(base_path, Path::from_str("/0/The/Quick/Brown/Fox")?);

        Ok(())
    }

    #[test]
    fn test_path_ordering() -> anyhow::Result<()> {
        let a = Path::from_str("/a/b/c")?;
        let b = Path::from_str("/a/b/d")?;
        assert_eq!(a < b, true);

        let a = Path::from_str("/a/b/c")?;
        let b = Path::from_str("/a/b/c/d")?;
        assert_eq!(a < b, true);

        let a = Path::from_str("/A/b/c")?;
        let b = Path::from_str("/a/b/c")?;
        assert_eq!(a == b, true);

        Ok(())
    }

    #[test]
    fn test_path_hash() -> anyhow::Result<()> {
        let a = Path::from_str("/a/b/c")?;
        let b = Path::from_str("/A/b/C")?;
        assert_eq!(
            a.hash(&mut DefaultHasher::new()),
            b.hash(&mut DefaultHasher::new())
        );

        Ok(())
    }
}
