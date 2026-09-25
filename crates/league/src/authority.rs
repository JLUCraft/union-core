//! LeagueDomain-bound authority assembly.
use crate::LeagueDomain;

/// Local or replicated authority service over the league domain.
pub type Authority = authority::authority::Authority<LeagueDomain>;
