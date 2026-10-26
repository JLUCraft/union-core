#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! League domain; the platform state machine does not depend on this crate.
pub use identity::PeerId;
pub use protocol::{Error, Result};
pub mod governance;
pub mod season;
pub use governance::{LeagueAction, LeagueDomain, LeagueState};
