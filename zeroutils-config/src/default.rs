//! Default configuration values.

use std::net::{IpAddr, Ipv4Addr};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The default host to bind for the database server.
pub const DEFAULT_HOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The default interval at which heartbeats are sent.
pub const DEFAULT_HEARTBEAT_INTERVAL: u64 = 50;

/// The default range of election timeouts.
pub const DEFAULT_ELECTION_TIMEOUT_RANGE: (u64, u64) = (150, 300);

//--------------------------------------------------------------------------------------------------
// Modules
//--------------------------------------------------------------------------------------------------

pub(super) mod serde {
    use std::net::IpAddr;

    pub(crate) fn default_host() -> IpAddr {
        super::DEFAULT_HOST
    }

    pub(crate) const fn default_heartbeat_interval() -> u64 {
        super::DEFAULT_HEARTBEAT_INTERVAL
    }

    pub(crate) const fn default_election_timeout_range() -> (u64, u64) {
        super::DEFAULT_ELECTION_TIMEOUT_RANGE
    }
}
