//! Authenticated service transport and admission.
pub use identity::Identity;
pub use libp2p::multiaddr::Protocol as AddressProtocol;
pub use libp2p::{Multiaddr, PeerId, Stream};
pub use wire::{Error, Result, protocol};
mod access;
mod node;
mod service;
pub use access::AccessPolicy;
pub use node::{IncomingSession, Node, NodeConfig, RelayConfig, SessionStream};
pub use service::{Service, ServiceId};
