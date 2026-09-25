//! League domain; the platform state machine does not depend on this crate.
pub use identity::PeerId;
pub use wire::{Error, Result};
pub mod governance;
pub mod season;
pub use governance::{LeagueAction, LeagueDomain, LeagueState};
/// LeagueDomain-bound authority assembly.
pub mod authority;
/// LeagueDomain-bound journal client bindings.
pub mod journal;
