#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Shared native clients for governance, LLM and federated operations services.
pub use authority::journal;
pub use identity::{Identity, PeerId};
pub use node::{AddressProtocol, Multiaddr, Node, NodeConfig, ServiceId};
pub use protocol::{self, Error, Result};
pub use state::governance;
pub mod application;
pub mod ops;
pub mod points;

pub mod generic;
pub mod rooms;

pub mod discovery;

pub mod files;

pub mod trust;

pub mod management;

#[cfg(feature = "documents")]
pub mod documents;

/// Parses an endpoint, appending the peer segment when the address omits it.
pub fn endpoint(address: &str, peer: &str) -> Result<(Multiaddr, PeerId)> {
    let peer: PeerId = peer
        .parse()
        .map_err(|_| Error::Protocol("invalid peer".into()))?;
    let mut address: Multiaddr = address
        .parse()
        .map_err(|_| Error::Protocol("invalid address".into()))?;
    match address.iter().last() {
        Some(AddressProtocol::P2p(id)) if id == peer => {}
        Some(AddressProtocol::P2p(_)) => return Err(Error::Denied),
        _ => address.push(AddressProtocol::P2p(peer)),
    }
    Ok((address, peer))
}
