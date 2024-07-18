//! The network configuration for cluster communication.

use std::{
    collections::HashMap,
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
};

use serde::{Deserialize, Serialize};
use structstruck::strike;
use typed_builder::TypedBuilder;
use zeroutils_did::did_wk::WrappedDidWebKey;

use crate::{ConfigError, ConfigResult};

use super::default::{DEFAULT_ELECTION_TIMEOUT_RANGE, DEFAULT_HEARTBEAT_INTERVAL};

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// The default values for ports in the network configuration.
pub trait PortDefaults {
    /// The default port to listen on for users.
    fn default_user_port() -> u16;

    /// The default port to listen on for peers.
    fn default_peer_port() -> u16;
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

strike! {
    #[strikethrough[derive(Debug, Deserialize, Serialize, TypedBuilder)]]
    /// The network configuration for cluster communication.
    pub struct NetworkConfig<'a, D: PortDefaults> {
        #[serde(skip)]
        #[builder(default, setter(skip))]
        d: PhantomData<D>,

        /// The id of the node.
        #[serde(default = "super::default::default_id")]
        #[builder(default = super::default::default_id())]
        pub id: WrappedDidWebKey<'a>,

        /// Name of the node.
        #[serde(default)]
        #[builder(default)]
        pub name: String,

        /// The host to listen on.
        #[serde(default = "super::default::default_host")]
        #[builder(default = super::default::default_host())]
        pub host: IpAddr,

        /// The port to listen on for users.
        #[serde(default = "D::default_user_port")]
        #[builder(default = D::default_user_port())]
        pub user_port: u16,

        /// The port to listen on for peers.
        #[serde(default = "D::default_peer_port")]
        #[builder(default = D::default_peer_port())]
        pub peer_port: u16,

        /// The peers to connect to.
        #[serde(default)]
        #[builder(default)]
        pub seeds: HashMap<WrappedDidWebKey<'a>, SocketAddr>,

        // /// A passive node does not partake in consensus.
        // #[serde(default)]
        // #[builder(default)]
        // pub passive: bool,

        /// The consensus configuration.
        #[serde(default)]
        #[builder(default)]
        pub consensus:
            /// The consensus configuration.
            pub struct ConsensusConfig {
                /// The interval at which heartbeats are sent.
                #[serde(default = "super::default::default_heartbeat_interval")]
                #[builder(default = super::default::default_heartbeat_interval())]
                pub heartbeat_interval: u64,

                /// The range of election timeouts.
                #[serde(default = "super::default::default_election_timeout_range")]
                #[builder(default = super::default::default_election_timeout_range())]
                pub election_timeout_range: (u64, u64),
            }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<D> NetworkConfig<'_, D>
where
    D: PortDefaults,
{
    /// TODO: Use serde_valid instead of expecting the user to call this method.
    /// Validates the configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.peer_port == self.user_port {
            return Err(ConfigError::EqualPeerUserPorts(self.peer_port));
        }

        Ok(())
    }

    /// Gets the peer address.
    pub fn get_peer_address(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.peer_port)
    }

    /// Gets the user address.
    pub fn get_user_address(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.user_port)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'a, D: PortDefaults> Default for NetworkConfig<'a, D> {
    fn default() -> Self {
        Self {
            d: PhantomData,
            id: super::default::default_id(),
            name: Default::default(),
            host: super::default::default_host(),
            peer_port: D::default_peer_port(),
            user_port: D::default_user_port(),
            seeds: Default::default(),
            consensus: Default::default(),
        }
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            election_timeout_range: DEFAULT_ELECTION_TIMEOUT_RANGE,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::network::tests::fixture::MockPortDefaults;

    use super::*;
    use std::{net::Ipv4Addr, str::FromStr};

    mod fixture {
        use super::*;

        //--------------------------------------------------------------------------------------------------
        // Types
        //--------------------------------------------------------------------------------------------------

        pub struct MockPortDefaults;

        //--------------------------------------------------------------------------------------------------
        // Methods
        //--------------------------------------------------------------------------------------------------

        impl PortDefaults for MockPortDefaults {
            fn default_user_port() -> u16 {
                7700
            }

            fn default_peer_port() -> u16 {
                7711
            }
        }
    }

    #[test]
    fn test_toml_full() -> anyhow::Result<()> {
        let toml = r#"
        id = "did:wk:z6MkoVs2h6TnfyY8fx2ZqpREWSLS8rBDQmGpyXgFpg63CSUb"
        name = "alice"
        host = "127.0.0.1"
        user_port = 7700
        peer_port = 7711

        [seeds]
        "did:wk:m7QFAoSJPFzmaqQiTkLrWQ6pbYrmI6L07Fkdg8SCRpjP1Ig" = "127.0.0.1:7800"
        "did:wk:z6MknLif7jhwt6jUfn14EuDnxWoSHkkajyDi28QMMH5eS1DL" = "127.0.0.1:7900"

        [consensus]
        heartbeat_interval = 1000
        election_timeout_range = [150, 300]
        "#;

        let config: NetworkConfig<MockPortDefaults> = toml::from_str(toml)?;

        assert_eq!(
            config.id,
            WrappedDidWebKey::from_str("did:wk:z6MkoVs2h6TnfyY8fx2ZqpREWSLS8rBDQmGpyXgFpg63CSUb")?
        );
        assert_eq!(config.host, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(config.user_port, 7700);
        assert_eq!(config.peer_port, 7711);
        assert_eq!(config.seeds, {
            let mut peers = HashMap::new();
            peers.insert(
                WrappedDidWebKey::from_str(
                    "did:wk:m7QFAoSJPFzmaqQiTkLrWQ6pbYrmI6L07Fkdg8SCRpjP1Ig",
                )?,
                SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 7800),
            );
            peers.insert(
                WrappedDidWebKey::from_str(
                    "did:wk:z6MknLif7jhwt6jUfn14EuDnxWoSHkkajyDi28QMMH5eS1DL",
                )?,
                SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 7900),
            );
            peers
        });
        assert_eq!(config.consensus.heartbeat_interval, 1000);
        assert_eq!(config.consensus.election_timeout_range, (150, 300));

        Ok(())
    }

    #[test]
    fn test_toml_defaults() -> anyhow::Result<()> {
        let config: NetworkConfig<MockPortDefaults> = toml::from_str("")?;

        assert_eq!(config.host, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(config.user_port, 7700);
        assert_eq!(config.peer_port, 7711);
        assert!(config.seeds.is_empty());
        assert_eq!(
            config.consensus.heartbeat_interval,
            DEFAULT_HEARTBEAT_INTERVAL
        );
        assert_eq!(
            config.consensus.election_timeout_range,
            DEFAULT_ELECTION_TIMEOUT_RANGE
        );

        Ok(())
    }
}
