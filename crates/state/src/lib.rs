#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Deterministic governance transitions; no socket or runtime dependencies.
pub use identity::PeerId;
pub use multiaddr::{Multiaddr, Protocol as AddressProtocol};
pub use protocol::{self, Error, Result};
pub mod governance;

mod domain;
pub use domain::{Context, CoreView, Domain, EmptyDomain, State};
