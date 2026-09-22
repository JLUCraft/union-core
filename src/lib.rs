//! Minecraft-independent authenticated service networking for the university union.
//! A node may consume services, host services, and relay concurrently.
mod access;
pub mod authority;
pub mod client;
#[cfg(feature = "consensus")]
pub mod consensus;
pub mod council;
pub mod devices;
mod error;
pub mod events;
pub mod federation;
pub mod governance;
mod identity;
pub mod journal;
mod node;
pub mod protocol;
pub mod season;
mod service;

pub use access::{AccessPolicy, Grant, SignedGrant};
pub use error::{Error, Result};
pub use identity::Identity;
pub use libp2p::multiaddr::Protocol as AddressProtocol;
pub use libp2p::{Multiaddr, PeerId, Stream};
pub use node::{IncomingSession, Node, NodeConfig, RelayConfig};
pub use service::{Service, ServiceId};
