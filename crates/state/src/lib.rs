//! Deterministic governance transitions; no socket or runtime dependencies.
pub use identity::PeerId;
pub use multiaddr::{Multiaddr, Protocol as AddressProtocol};
pub use wire::{Error, Result, protocol};
pub mod governance;

mod domain;
pub use domain::{Context, CoreView, Domain, EmptyDomain, State};
