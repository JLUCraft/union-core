#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Durable governance state and revocation views, without a network node.
pub use identity::{Identity, PeerId};
pub use protocol::{self, Error, Result};
pub use state::governance;
#[cfg(feature = "consensus")]
pub mod consensus;
pub mod events;
pub mod journal;

pub mod trust;
