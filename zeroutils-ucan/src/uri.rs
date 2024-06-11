use std::{cmp, fmt, str::FromStr};

use fluent_uri::Uri;
use lazy_static::lazy_static;
use libipld::Cid;
use regex::Regex;
use serde::Serialize;
use zeroutils_did_wk::WrappedDidWebKey;

use crate::UcanError;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A `ResourceUri` is how a resource is identified within a UCAN. They are fundamental in specifying
/// the target of an ability, helping to distinguish between different resources.
///
/// ## Important
///
/// `did:wk` with locator components are not supported in URIs.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum ResourceUri<'a> {
    /// A reference to a specific proof within the UCAN.
    Reference(ProofReference<'a>),

    /// Any other URI format.
    Other(OtherUri),
}

/// A URI that is not a UCAN-specific reference.
pub type OtherUri = Uri<String>;

/// A reference to a proof within a UCAN, defined by various UCAN-specific URI schemes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProofReference<'a> {
    /// Represents the URI scheme `ucan:*`, which selects all provable (incl. transient) capabilities for the issuer of the current UCAN.
    AllUcansTransient,

    /// Represents the URI scheme `ucan://<did>/*`, selecting all provable capabilities of any UCAN with specified DID as audience.
    AllUcansByDid(WrappedDidWebKey<'a>),

    /// Represents the URI scheme `ucan://<did>/<scheme>`, selecting all provable capabilities - for a given scheme - of any UCAN with specified DID as audience.
    AllUcansByDidAndScheme(WrappedDidWebKey<'a>, Scheme),

    /// Represents the URI scheme `ucan:./*`, selecting all capabilities of all proofs in the current UCAN.
    AllProofsInCurrentUcan,

    /// Represents the URI scheme `ucan:<cid>`, selecting all capabilities of a specific proof in the current UCAN.
    SpecificProofByCid(Cid),
}

/// A scheme is a string that represents a valid URI scheme.
pub type Scheme = String; // TODO

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

lazy_static! {
    /// A regex pattern that matches the `ucan:*` URI, which selects all possible provable UCANs.
    pub static ref UCAN_ALL_REGEX: Regex = Regex::new(r"^ucan:\*$").unwrap();

    /// A regex pattern that matches the `ucan:./*` URI, which selects all proofs in the current UCAN.
    pub static ref UCAN_CURRENT_REGEX: Regex = Regex::new(r"^ucan:\./\*$").unwrap();

    /// A regex pattern that matches the `ucan://<did>/*` URI, which selects all proofs by a DID.
    pub static ref UCAN_DID_REGEX: Regex = Regex::new(r"^ucan://([^/]+)/\*$").unwrap();

    /// A regex pattern that matches the `ucan://<did>/<scheme>` URI, which selects all proofs by a DID and scheme.
    pub static ref UCAN_DID_SCHEME_REGEX: Regex = Regex::new(r"^ucan://([^/]+)/([a-zA-Z][a-zA-Z0-9+\-\.]*)$").unwrap();

    /// A regex pattern that matches the `ucan:<cid>` URI, which selects a specific UCAN by its CID.
    pub static ref UCAN_CID_REGEX: Regex = Regex::new(r"^ucan:([^/]+)$").unwrap();
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ResourceUri<'_> {
    /// Checks if the `requested` resource uri is permitted by the main uri.
    ///
    /// This library follows a strict non-flexible approach here, allowing only the same resource
    /// uri or a subset of it from a path perspective.
    ///
    /// That is if you have resource `zerofs://public`, for example, it will allow `zerofs://public`
    /// and `zerofs://public/photos` but not `zerofs://private`.
    pub fn permits(&self, requested: &ResourceUri<'_>) -> bool {
        match (self, requested) {
            (ResourceUri::Reference(pr1), ResourceUri::Reference(pr2)) => {
                if pr1 == pr2 {
                    return true;
                }

                // Allow ucan:<cid> as a subset of ucan:./*
                if let (
                    ProofReference::AllProofsInCurrentUcan,
                    ProofReference::SpecificProofByCid(_),
                ) = (pr1, pr2)
                {
                    return true;
                }

                // Allow ucan://<did>/scheme as a subset of ucan://<did>/*
                if let (
                    ProofReference::AllUcansByDid(did1),
                    ProofReference::AllUcansByDidAndScheme(did2, _),
                ) = (pr1, pr2)
                {
                    if did1 == did2 {
                        return true;
                    }
                }
            }
            (ResourceUri::Other(uri1), ResourceUri::Other(uri2)) => {
                if uri1.as_str() == uri2.as_str() {
                    return true;
                }

                // Allow a subset of the path delimited by `/`
                let uri1 = format!("{}/", uri1.as_str().trim_end_matches('/'));
                if uri2.as_str().starts_with(&uri1) {
                    return true;
                }
            }
            _ => (),
        }

        false
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FromStr for ProofReference<'_> {
    type Err = UcanError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if UCAN_ALL_REGEX.is_match(s) {
            Ok(ProofReference::AllUcansTransient)
        } else if UCAN_CURRENT_REGEX.is_match(s) {
            Ok(ProofReference::AllProofsInCurrentUcan)
        } else if let Some(captures) = UCAN_DID_REGEX.captures(s) {
            let did = captures.get(1).unwrap().as_str();
            Ok(ProofReference::AllUcansByDid(WrappedDidWebKey::from_str(
                did,
            )?))
        } else if let Some(captures) = UCAN_DID_SCHEME_REGEX.captures(s) {
            let did = captures.get(1).unwrap().as_str();
            let scheme = captures.get(2).unwrap().as_str();
            Ok(ProofReference::AllUcansByDidAndScheme(
                WrappedDidWebKey::from_str(did)?,
                scheme.to_string(),
            ))
        } else if let Some(captures) = UCAN_CID_REGEX.captures(s) {
            let cid = captures.get(1).unwrap().as_str();
            Ok(ProofReference::SpecificProofByCid(Cid::from_str(cid)?))
        } else {
            Err(UcanError::InvalidProofReference(s.to_string()))
        }
    }
}

impl<'a> FromStr for ResourceUri<'a> {
    type Err = UcanError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("ucan:") {
            ProofReference::from_str(s).map(ResourceUri::Reference)
        } else {
            Uri::parse_from(s.to_owned())
                .map_err(|(_, e)| UcanError::UriParseError(e))
                .map(ResourceUri::Other)
        }
    }
}

impl<'a> fmt::Display for ProofReference<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofReference::AllUcansTransient => write!(f, "ucan:*"),
            ProofReference::AllUcansByDid(did) => write!(f, "ucan://{}/*", did),
            ProofReference::AllUcansByDidAndScheme(did, scheme) => {
                write!(f, "ucan://{}/{}", did, scheme)
            }
            ProofReference::AllProofsInCurrentUcan => write!(f, "ucan:./*"),
            ProofReference::SpecificProofByCid(cid) => write!(f, "ucan:{}", cid),
        }
    }
}

impl<'a> fmt::Display for ResourceUri<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceUri::Reference(pr) => write!(f, "{}", pr),
            ResourceUri::Other(uri) => write!(f, "{}", uri),
        }
    }
}

impl Serialize for ResourceUri<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'a, 'de> serde::Deserialize<'de> for ResourceUri<'a> {
    fn deserialize<D>(deserializer: D) -> Result<ResourceUri<'a>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ResourceUri::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl PartialOrd for ResourceUri<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.to_string().cmp(&other.to_string()))
    }
}

impl Ord for ResourceUri<'_> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialEq for ResourceUri<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ResourceUri::Reference(pr1), ResourceUri::Reference(pr2)) => pr1 == pr2,
            (ResourceUri::Other(uri1), ResourceUri::Other(uri2)) => uri1.as_str() == uri2.as_str(),
            _ => false,
        }
    }
}

impl Eq for ResourceUri<'_> {}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_from_str() -> anyhow::Result<()> {
        let uri = ResourceUri::from_str("ucan:*")?;
        assert_eq!(
            uri,
            ResourceUri::Reference(ProofReference::AllUcansTransient)
        );

        let uri = ResourceUri::from_str(
            "ucan://did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp/*",
        )?;
        assert_eq!(
            uri,
            ResourceUri::Reference(ProofReference::AllUcansByDid(WrappedDidWebKey::from_str(
                "did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp"
            )?))
        );

        let uri = ResourceUri::from_str(
            "ucan://did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp/zerofs",
        )?;
        assert_eq!(
            uri,
            ResourceUri::Reference(ProofReference::AllUcansByDidAndScheme(
                WrappedDidWebKey::from_str(
                    "did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp"
                )?,
                "zerofs".to_string()
            ))
        );

        let uri = ResourceUri::from_str("ucan:./*")?;
        assert_eq!(
            uri,
            ResourceUri::Reference(ProofReference::AllProofsInCurrentUcan)
        );

        let uri = ResourceUri::from_str(
            "ucan:bafkreihogico5an3e2xy3fykalfwxxry7itbhfcgq6f47sif6d7w6uk2ze",
        )?;
        assert_eq!(
            uri,
            ResourceUri::Reference(ProofReference::SpecificProofByCid(Cid::from_str(
                "bafkreihogico5an3e2xy3fykalfwxxry7itbhfcgq6f47sif6d7w6uk2ze"
            )?))
        );

        let uri = ResourceUri::from_str("https://example.com")?;
        assert_eq!(
            uri,
            ResourceUri::Other(
                Uri::parse_from("https://example.com".to_string())
                    .map_err(|(_, e)| UcanError::UriParseError(e))?
            )
        );

        Ok(())
    }

    #[test]
    fn test_uri_display() -> anyhow::Result<()> {
        let uri = ResourceUri::Reference(ProofReference::AllUcansTransient);
        assert_eq!(uri.to_string(), "ucan:*");

        let uri = ResourceUri::Reference(ProofReference::AllUcansByDid(
            WrappedDidWebKey::from_str("did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp")?,
        ));
        assert_eq!(
            uri.to_string(),
            "ucan://did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp/*"
        );

        let uri = ResourceUri::Reference(ProofReference::AllUcansByDidAndScheme(
            WrappedDidWebKey::from_str("did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp")?,
            "zerofs".to_string(),
        ));
        assert_eq!(
            uri.to_string(),
            "ucan://did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp/zerofs"
        );

        let uri = ResourceUri::Reference(ProofReference::AllProofsInCurrentUcan);
        assert_eq!(uri.to_string(), "ucan:./*");

        let uri = ResourceUri::Reference(ProofReference::SpecificProofByCid(Cid::from_str(
            "bafkreihogico5an3e2xy3fykalfwxxry7itbhfcgq6f47sif6d7w6uk2ze",
        )?));
        assert_eq!(
            uri.to_string(),
            "ucan:bafkreihogico5an3e2xy3fykalfwxxry7itbhfcgq6f47sif6d7w6uk2ze"
        );

        let uri = ResourceUri::Other(
            Uri::parse_from("https://example.com".to_string())
                .map_err(|(_, e)| UcanError::UriParseError(e))?,
        );
        assert_eq!(uri.to_string(), "https://example.com");

        Ok(())
    }

    #[test]
    fn test_uri_permits() -> anyhow::Result<()> {
        // Requested URI is the same as the URI
        assert!(ResourceUri::from_str("ucan:*")?.permits(&ResourceUri::from_str("ucan:*")?));

        assert!(ResourceUri::from_str("ucan:./*")?.permits(&ResourceUri::from_str("ucan:./*")?));

        assert!(ResourceUri::from_str(
            "ucan://did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp/*"
        )?
        .permits(&ResourceUri::from_str(
            "ucan://did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp/*"
        )?));

        assert!(ResourceUri::from_str(
            "ucan://did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp/zerofs"
        )?
        .permits(&ResourceUri::from_str(
            "ucan://did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp/zerofs"
        )?));

        assert!(ResourceUri::from_str(
            "ucan:bafkreihogico5an3e2xy3fykalfwxxry7itbhfcgq6f47sif6d7w6uk2ze"
        )?
        .permits(&ResourceUri::from_str(
            "ucan:bafkreihogico5an3e2xy3fykalfwxxry7itbhfcgq6f47sif6d7w6uk2ze"
        )?));

        assert!(ResourceUri::from_str("https://example.com")?
            .permits(&ResourceUri::from_str("https://example.com")?));

        // Requested URI is a subset of the URI
        assert!(
            ResourceUri::from_str("ucan:./*")?.permits(&ResourceUri::from_str(
                "ucan:bafkreihogico5an3e2xy3fykalfwxxry7itbhfcgq6f47sif6d7w6uk2ze"
            )?)
        );

        assert!(ResourceUri::from_str(
            "ucan://did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp/*"
        )?
        .permits(&ResourceUri::from_str(
            "ucan://did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp/zerofs"
        )?));

        assert!(ResourceUri::from_str("https://example.com")?
            .permits(&ResourceUri::from_str("https://example.com/photos")?));

        assert!(ResourceUri::from_str("https://example.com/")?
            .permits(&ResourceUri::from_str("https://example.com/photos")?));

        // Fails
        assert!(!ResourceUri::from_str("ucan:*")?.permits(&ResourceUri::from_str("ucan:./*")?));

        assert!(!ResourceUri::from_str("ucan:./*")?.permits(&ResourceUri::from_str("ucan:*")?));

        assert!(
            !ResourceUri::from_str("ucan:*")?.permits(&ResourceUri::from_str(
                "ucan://did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp/*"
            )?)
        );

        assert!(!ResourceUri::from_str(
            "ucan://did:wk:z6MkhZCL2zJsfqdqSLkGdocC3rkU436qYvK8bsnPdFCW1iXp/*"
        )?
        .permits(&ResourceUri::from_str("ucan:*")?));

        assert!(!ResourceUri::from_str("https://example.com")?
            .permits(&ResourceUri::from_str("https://example.org")?));

        assert!(!ResourceUri::from_str("https://example.com/photos")?
            .permits(&ResourceUri::from_str("https://example.com")?));

        assert!(
            !ResourceUri::from_str("https://example.com/photos")?.permits(&ResourceUri::from_str(
                "https://example.com/photos_gallery"
            )?)
        );

        Ok(())
    }
}
