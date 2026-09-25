#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Canonical wire schema and transport-independent errors.
mod error;
pub use error::{Error, Result};
pub mod protocol;

pub mod ipld;
