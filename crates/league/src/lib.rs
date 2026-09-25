#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! League domain; the platform state machine does not depend on this crate.
pub use identity::PeerId;
pub use wire::{Error, Result};
pub mod governance;
pub mod season;
pub use governance::{LeagueAction, LeagueDomain, LeagueState};
/// LeagueDomain-bound authority assembly.
#[cfg(feature = "runtime")]
pub mod authority;
#[cfg(feature = "consensus")]
/// LeagueDomain-bound crash-fault consensus assembly.
pub mod consensus;
/// LeagueDomain-bound journal client bindings.
#[cfg(feature = "runtime")]
pub mod journal;
