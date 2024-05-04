//! The network configuration for cluster communication.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use serde::{Deserialize, Serialize};
use structstruck::strike;
use zeroutils_key::did_wk::DidWebKeyType;

use super::default::{DEFAULT_ELECTION_TIMEOUT_RANGE, DEFAULT_HEARTBEAT_INTERVAL};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

strike! {
    /// The configuration for the `Zerodb` instance.
    #[strikethrough[derive(Debug, Deserialize, Serialize)]]
    /// The network configuration for cluster communication.
    pub struct NetworkConfig<'a, const pp: u16, const up: u16> {
        /// The id of the node.
        pub id: DidWebKeyType<'a>,

        /// Name of the node.
        #[serde(default)]
        pub name: String,

        /// The host to listen on.
        #[serde(default = "super::default::serde::default_host")]
        pub host: IpAddr,

        /// The port to listen on for peers.
        #[serde(default = "Self::const_pp")]
        pub peer_port: u16,

        /// The port to listen on for users.
        // #[serde(default = "Self::const_up")]
        pub user_port: u16,

        /// The peers to connect to.
        #[serde(default)]
        pub seeds: HashMap<DidWebKeyType<'a>, SocketAddr>,

        // /// A passive node does not partake in consensus.
        // #[builder(default)]
        // #[serde(default)]
        // pub passive: bool,

        /// The consensus configuration.
        pub consensus:
            /// The consensus configuration.
            pub struct ConsensusConfig {
                /// The interval at which heartbeats are sent.
                #[serde(default = "super::default::serde::default_heartbeat_interval")]
                pub heartbeat_interval: u64,

                /// The range of election timeouts.
                #[serde(default = "super::default::serde::default_election_timeout_range")]
                pub election_timeout_range: (u64, u64),
            }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<const pp: u16, const up: u16> NetworkConfig<'_, pp, up> {
    fn const_pp() -> u16 {
        pp
    }

    fn const_up() -> u16 {
        up
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
    use std::{net::Ipv4Addr, str::FromStr};

    use super::*;

    #[test]
    fn test_full_toml() -> anyhow::Result<()> {
        let toml = r#"
        id = did:wk:4b72a445-d90d-4fd7-9711-b0e587ab6a21
        name = "alice"
        host = "127.0.0.1"
        peer_port = 7700
        client_port = 7711

        [seeds]
        did:wk:4b72a445-d90d-4fd7-9711-b0e587ab6a21 = "127.0.0.1:7800"
        did:wk:0713a29e-9197-448a-9d34-e4ab1aa07eea = "127.0.0.1:7900"

        [consensus]
        heartbeat_interval = 1000
        election_timeout_range = [150, 300]
        "#;

        // let config: NetworkConfig = toml::from_str(toml)?;

        // assert_eq!(
        //     config.id,
        //     DidWebKey::from_str("4b72a445-d90d-4fd7-9711-b0e587ab6a21")?
        // );
        // assert_eq!(config.host, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        // assert_eq!(config.peer_port, 7700);
        // assert_eq!(config.client_port, 7711);
        // assert_eq!(config.seeds, {
        //     let mut peers = HashMap::new();
        //     peers.insert(
        //         DidWebKey::from_str("4b72a445-d90d-4fd7-9711-b0e587ab6a21")?,
        //         SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 7800),
        //     );
        //     peers.insert(
        //         DidWebKey::from_str("0713a29e-9197-448a-9d34-e4ab1aa07eea")?,
        //         SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 7900),
        //     );
        //     peers
        // });
        // assert_eq!(config.consensus.heartbeat_interval, 1000);
        // assert_eq!(config.consensus.election_timeout_range, (150, 300));

        Ok(())
    }
}
