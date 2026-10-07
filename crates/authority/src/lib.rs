#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Local and replicated authority service assembly.
pub use identity::{Identity, PeerId};
pub use node::{Node, Stream};
pub use protocol::{self, Error, Result};
pub use state::governance;
// tokio appears in authority's public signatures (e.g. journal::serve); expose
// it so domain binding crates can name those types without a direct tokio dep.
pub use tokio;
pub mod authority;
#[cfg(feature = "consensus")]
pub mod consensus;
pub mod events;
pub mod journal;

pub mod trust;
