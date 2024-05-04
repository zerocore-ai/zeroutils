use zeroutils_key::PubKey;

use crate::{DidResult, DidWebKey, LocatorComponent};

use super::{Host, Path};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A builder for a `DID Web Key`.
pub struct DidWebKeyBuilder<P = ()> {
    /// The public key.
    key: P,

    /// The host part of the component.
    host: Option<Host>,

    /// The port part of the component.
    port: Option<u16>,

    /// The path part of the component.
    path: Option<Path>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a, K> DidWebKeyBuilder<K> {
    /// Sets the public key.
    pub fn public_key<P>(self, key: PubKey<'a, P>) -> DidWebKeyBuilder<PubKey<'a, P>>
    where
        P: Clone,
    {
        DidWebKeyBuilder {
            key,
            host: self.host,
            port: self.port,
            path: self.path,
        }
    }

    /// Sets the host part of the component.
    pub fn host(mut self, host: impl Into<Host>) -> DidWebKeyBuilder<K> {
        self.host = Some(host.into());
        self
    }

    /// Sets the port part of the component.
    pub fn port(mut self, port: u16) -> DidWebKeyBuilder<K> {
        self.port = Some(port);
        self
    }

    /// Sets the path part of the component.
    pub fn path(mut self, path: impl Into<Path>) -> DidWebKeyBuilder<K> {
        self.path = Some(path.into());
        self
    }
}

impl<'a, P> DidWebKeyBuilder<PubKey<'a, P>>
where
    P: Clone,
{
    /// Builds a `DID Web Key`.
    pub fn build(self) -> DidResult<DidWebKey<PubKey<'a, P>>> {
        Ok(DidWebKey {
            public_key: self.key,
            locator_component: self
                .host
                .map(|host| LocatorComponent::new(host, self.port, self.path)),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for DidWebKeyBuilder {
    fn default() -> Self {
        DidWebKeyBuilder {
            key: (),
            host: None,
            port: None,
            path: None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use zeroutils_key::{Ed25519KeyPair, Ed25519PubKey, KeyPairGenerate};

    use super::*;

    #[test]
    fn test_did_web_key_builder() -> anyhow::Result<()> {
        let mut rng = &mut rand::thread_rng();
        let public_key = Ed25519PubKey::from(Ed25519KeyPair::generate(&mut rng)?);

        let did_web_key = DidWebKeyBuilder::default()
            .public_key(public_key.clone())
            .host("example.com")
            .port(8080)
            .path("/path")
            .build()?;

        assert_eq!(did_web_key.public_key, public_key);
        assert_eq!(
            did_web_key.locator_component.unwrap().encode(),
            "example.com:8080/path"
        );

        Ok(())
    }
}
