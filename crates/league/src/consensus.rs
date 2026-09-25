//! LeagueDomain-bound crash-fault consensus assembly.
use crate::LeagueDomain;

pub use authority::consensus::{Applied, Peer, Raft, Replicated, TypeConfig};
/// League-bound replicated state machine cluster.
pub type Cluster = authority::consensus::Cluster<LeagueDomain>;
/// League-bound replicated log store.
pub type Store = authority::consensus::Store<LeagueDomain>;
