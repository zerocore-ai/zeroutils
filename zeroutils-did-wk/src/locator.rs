use std::{fmt::Display, net::Ipv4Addr, str::FromStr};

use serde::{Deserialize, Serialize};

use super::{DidError, RE_IPLITERAL, RE_IPV4ADDR, RE_PATH_ABEMPTY, RE_REGNAME};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Describes the locator component of a `did:wk` identifier, providing the necessary details to locate
/// the DID document over the web.
///
/// For example, this is the `steve.zerocore.ai/public` part of:
///
/// `did:wk:zQ3shZ1zUTvyi2FcEyeyHdXPpthvH8YcU3WFzQhgSLm9nb6Fk@steve.zerocore.ai/public`.
///
/// To get the DID document, this would get resolved to:
///
/// `https://steve.zerocore.ai/public/.well-known/did.json`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct LocatorComponent {
    /// The host part of the component.
    host: Host,

    /// The port part of the component.
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,

    /// The path part of the component.
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<Path>,
}

/// Represents the host part of a locator component. Host can be a domain name, an IP address (either
/// IPv4 or IPv6), or other types of hosts.
///
/// This is the `host` rule from [RFC 3986][ref].
///
/// [ref]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.2
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Host {
    /// A domain name.
    Domain(String),

    /// IPv4 address.
    IpV4Addr(Ipv4Addr),

    /// Ipv6, or IPvFuture address.
    IpLiteral(String),
}

/// Represents the path part of a locator component.
///
/// This is the `path_abempty` rule from [RFC 3986][ref].
///
/// NOTE: Path can be an empty string.
///
/// [ref]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Path(String);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocatorComponent {
    /// Creates a new `LocatorComponent`.
    pub fn new(
        host: impl Into<Host>,
        port: impl Into<Option<u16>>,
        path: impl Into<Option<Path>>,
    ) -> Self {
        Self {
            host: host.into(),
            port: port.into(),
            path: path.into(),
        }
    }

    /// Returns the host part of the component.
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Returns the port part of the component.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns the path part of the component.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_ref()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FromStr for Host {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(m) = RE_IPV4ADDR.find(s) {
            return Ok(Host::IpV4Addr(m.as_str().parse().unwrap()));
        }

        if let Some(m) = RE_IPLITERAL.find(s) {
            return Ok(Host::IpLiteral(m.as_str().to_owned()));
        }

        if let Some(m) = RE_REGNAME.find(s) {
            return Ok(Host::Domain(m.as_str().to_owned()));
        };

        Err(DidError::InvalidHost(s.to_owned()))
    }
}

impl FromStr for Path {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some(m) = RE_PATH_ABEMPTY.find(s) else {
            return Err(DidError::InvalidPath(s.to_owned()));
        };

        let path = m.as_str().to_owned();

        Ok(Path(path))
    }
}

impl<T> From<T> for Host
where
    T: AsRef<str>,
{
    fn from(s: T) -> Self {
        s.as_ref().parse().unwrap()
    }
}

impl<T> From<T> for Path
where
    T: AsRef<str>,
{
    fn from(s: T) -> Self {
        s.as_ref().parse().unwrap()
    }
}

impl Display for LocatorComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut locator = String::new();

        match &self.host {
            Host::Domain(domain) => locator.push_str(domain),
            Host::IpV4Addr(ipv4) => locator.push_str(&ipv4.to_string()),
            Host::IpLiteral(ipv6) => locator.push_str(ipv6),
        }

        if let Some(port) = self.port {
            locator.push_str(&format!(":{}", port));
        }

        if let Some(path) = &self.path {
            locator.push_str(&path.0);
        }

        write!(f, "{}", locator)
    }
}

impl FromStr for LocatorComponent {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let port_split: Vec<&str> = s.splitn(2, ':').collect();
        let (host, port, path) = match port_split.len() {
            1 => {
                let host_path: Option<(&str, &str)> =
                    port_split[0].find('/').map(|i| port_split[0].split_at(i));
                let (host, path): (Host, Option<Path>) = match host_path {
                    Some((host, path)) => {
                        let host = host.parse()?;
                        let path = path.parse().ok();

                        (host, path)
                    }
                    None => (port_split[0].parse()?, None),
                };
                (host, None, path)
            }
            2 => {
                let host = port_split[0];
                let port_path = port_split[1].find('/').map(|i| port_split[1].split_at(i));
                let (port, path): (Option<u16>, Option<Path>) = match port_path {
                    Some((port, path)) => {
                        let port = port.parse().ok();
                        let path = path.parse().ok();

                        (port, path)
                    }
                    None => (port_split[1].parse().ok(), None),
                };

                (host.parse()?, port, path)
            }
            _ => return Err(DidError::InvalidLocatorComponent(s.to_owned())),
        };

        Ok(LocatorComponent::new(host, port, path))
    }
}

impl Serialize for Host {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Host::Domain(domain) => serializer.serialize_str(domain),
            Host::IpV4Addr(ipv4) => serializer.serialize_str(&ipv4.to_string()),
            Host::IpLiteral(ipv6) => serializer.serialize_str(ipv6),
        }
    }
}

impl<'de> Deserialize<'de> for Host {
    fn deserialize<D>(deserializer: D) -> Result<Host, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locator_constructor() {
        let locator = LocatorComponent::new("steve.zerocore.ai", 443, Path::from("/public"));

        assert_eq!(
            locator.host(),
            &Host::Domain("steve.zerocore.ai".to_owned())
        );
        assert_eq!(locator.port(), Some(443));
        assert_eq!(locator.path(), Some(&Path("/public".to_owned())));
    }

    #[test]
    fn test_host_from_str() -> anyhow::Result<()> {
        let domain = "steve.zerocore.ai";
        let ipv4ddr = "192.168.123.132";
        let ipv6addr = "[2001:db8::1]";
        let ipvfut = "[v1.2001:db8::1]";

        assert_eq!(Host::from_str(domain)?, Host::Domain(domain.to_owned()));
        assert_eq!(Host::from_str(ipv4ddr)?, Host::IpV4Addr(ipv4ddr.parse()?));
        assert_eq!(
            Host::from_str(ipv6addr)?,
            Host::IpLiteral(ipv6addr.to_owned())
        );
        assert_eq!(Host::from_str(ipvfut)?, Host::IpLiteral(ipvfut.to_owned()));

        Ok(())
    }

    #[test]
    fn test_path_from_str() -> anyhow::Result<()> {
        let path = "/public";
        let path_empty = "";

        assert_eq!(Path::from_str(path)?, Path(path.to_owned()));
        assert_eq!(Path::from_str(path_empty)?, Path(path_empty.to_owned()));

        Ok(())
    }

    #[test]
    fn test_locator_display() {
        let locator = LocatorComponent::new("steve.zerocore.ai", 443, Path::from("/public"));
        assert_eq!(locator.to_string(), "steve.zerocore.ai:443/public");
    }

    #[test]
    fn test_locator_from_str() -> anyhow::Result<()> {
        let locator = "steve.zerocore.ai:443/public";
        let locator_no_port = "steve.zerocore.ai/public";
        let locator_no_path = "192.168.123.132:443";
        let locator_no_port_or_path = "steve.zerocore.ai";

        assert_eq!(
            LocatorComponent::from_str(locator)?,
            LocatorComponent::new("steve.zerocore.ai", 443, Path::from("/public"))
        );
        assert_eq!(
            LocatorComponent::from_str(locator_no_port)?,
            LocatorComponent::new("steve.zerocore.ai", None, Path::from("/public"))
        );
        assert_eq!(
            LocatorComponent::from_str(locator_no_path)?,
            LocatorComponent::new("192.168.123.132", Some(443), None) // Gotta fix!
        );
        assert_eq!(
            LocatorComponent::from_str(locator_no_port_or_path)?,
            LocatorComponent::new("steve.zerocore.ai", None, None) // Gotta fix!
        );

        Ok(())
    }

    #[test_log::test]
    fn test_locator_serde() -> anyhow::Result<()> {
        let locator = LocatorComponent::new("steve.zerocore.ai", 443, Path::from("/public"));
        let locator_no_port =
            LocatorComponent::new("steve.zerocore.ai", None, Path::from("/public"));
        let locator_no_path = LocatorComponent::new("192.168.123.132", Some(443), None);
        let locator_no_port_or_path = LocatorComponent::new("steve.zerocore.ai", None, None);

        let encoded = serde_json::to_string(&locator)?;
        tracing::debug!(?encoded);
        let decoded: LocatorComponent = serde_json::from_str(&encoded)?;
        assert_eq!(locator, decoded);

        let encoded_no_port = serde_json::to_string(&locator_no_port)?;
        tracing::debug!(?encoded_no_port);
        let decoded_no_port: LocatorComponent = serde_json::from_str(&encoded_no_port)?;
        assert_eq!(locator_no_port, decoded_no_port);

        let encoded_no_path = serde_json::to_string(&locator_no_path)?;
        tracing::debug!(?encoded_no_path);
        let decoded_no_path: LocatorComponent = serde_json::from_str(&encoded_no_path)?;
        assert_eq!(locator_no_path, decoded_no_path);

        let encoded_no_port_or_path = serde_json::to_string(&locator_no_port_or_path)?;
        tracing::debug!(?encoded_no_port_or_path);
        let decoded_no_port_or_path: LocatorComponent =
            serde_json::from_str(&encoded_no_port_or_path)?;
        assert_eq!(locator_no_port_or_path, decoded_no_port_or_path);

        Ok(())
    }
}
