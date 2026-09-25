//! Device identity without network transport.
mod identity;
pub use identity::Identity;
pub use libp2p_identity::{Keypair, PeerId, PublicKey};
pub use wire::{Error, Result};

pub mod trust;
