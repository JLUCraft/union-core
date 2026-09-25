mod store;
use crate::journal::SignedCommand;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
pub use store::Store;
pub type Peer = crate::governance::ConsensusPeer;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Replicated {
    pub cluster: String,
    pub command: SignedCommand,
    pub time_ms: u64,
    pub identity: crate::journal::TrustHistory,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Applied {
    pub revision: u64,
    pub error: Option<String>,
}
openraft::declare_raft_types!(pub TypeConfig:D=Replicated,R=Applied,Node=Peer);
