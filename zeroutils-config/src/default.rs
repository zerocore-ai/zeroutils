//! Default configuration values.

use std::net::{IpAddr, Ipv4Addr};

use zeroutils_did_wk::{Base, DidWebKey, WrappedDidWebKey};
use zeroutils_key::{Ed25519KeyPair, IntoOwned, KeyPairGenerate};

//--------------------------------------------------------------------------------------------------
//(crate) Constants
//--------------------------------------------------------------------------------------------------

/// The default host to bind for the database server.
pub const DEFAULT_HOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The default interval at which heartbeats are sent.
pub const DEFAULT_HEARTBEAT_INTERVAL: u64 = 50;

/// The default range of election timeouts.
pub const DEFAULT_ELECTION_TIMEOUT_RANGE: (u64, u64) = (150, 300);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) const fn default_host() -> IpAddr {
    DEFAULT_HOST
}

pub(crate) const fn default_heartbeat_interval() -> u64 {
    DEFAULT_HEARTBEAT_INTERVAL
}

pub(crate) const fn default_election_timeout_range() -> (u64, u64) {
    DEFAULT_ELECTION_TIMEOUT_RANGE
}

pub(crate) fn default_id() -> WrappedDidWebKey<'static> {
    let rng = &mut rand::thread_rng();
    let key = Ed25519KeyPair::generate(rng).unwrap();
    DidWebKey::from_key(&key, Base::Base58Btc)
        .into_owned()
        .into()
}
