use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub revision: u64,
    pub state_hash: String,
    pub resync: bool,
}
