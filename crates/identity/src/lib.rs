#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Device identity without network transport.
mod identity;
pub use identity::Identity;
pub use libp2p_identity::{Keypair, PeerId, PublicKey};
pub use wire::{Error, Result};

pub mod trust;
