#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Shared native clients for governance, LLM and federated operations services.
pub use authority::journal;
pub use identity::{Identity, PeerId};
pub use node::{AddressProtocol, Multiaddr, Node, NodeConfig, ServiceId};
pub use protocol::{self, Error, Result};
pub use state::governance;
#[cfg(feature = "league")]
pub mod client;
pub mod llm;
pub mod ops;

pub mod generic;
pub mod rooms;

#[cfg(feature = "office")]
pub mod office;

pub mod trust;

pub mod management;

#[cfg(feature = "documents")]
pub mod documents;
