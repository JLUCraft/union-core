//! Canonical wire schema and transport-independent errors.
mod error;
pub use error::{Error, Result};
pub mod protocol;

pub mod ipld;
