//! Crash-fault consensus over authenticated Union streams. No HTTP control plane.
mod network;
mod store;
use crate::{Error, Node, Result, governance::State, journal::SignedCommand};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Cursor, path::Path, sync::Arc};
pub use store::Store;

pub type Peer = crate::governance::ConsensusPeer;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Replicated {
    pub cluster: String,
    pub command: SignedCommand,
    pub time_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Applied {
    pub revision: u64,
    pub error: Option<String>,
}
openraft::declare_raft_types!(pub TypeConfig:D=Replicated,R=Applied,Node=Peer);
pub type Raft = openraft::Raft<TypeConfig>;
pub struct Cluster {
    pub raft: Raft,
    pub store: Store,
    pub node: Arc<Node>,
    pub peers: BTreeMap<u64, Peer>,
    pub id: u64,
    pub cluster: String,
}
impl Cluster {
    pub async fn start(
        id: u64,
        node: Arc<Node>,
        path: &Path,
        genesis: State,
        peers: BTreeMap<u64, Peer>,
    ) -> Result<Arc<Self>> {
        crate::governance::validate_consensus_members(&peers)?;
        if id == 0
            || peers
                .get(&id)
                .is_some_and(|p| p.peer != node.peer_id().to_string())
        {
            return Err(Error::Denied);
        }
        let genesis = Self::genesis(genesis, &peers)?;
        let store = Store::open(path, genesis)?;
        let cluster = store.cluster_id().await;
        let config = openraft::Config {
            heartbeat_interval: 500,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
            snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(256),
            max_in_snapshot_log_to_keep: 64,
            max_payload_entries: 16,
            snapshot_max_chunk_size: 16384,
            ..Default::default()
        }
        .validate()
        .map_err(err)?;
        let network = network::Network {
            node: node.clone(),
            cluster: cluster.clone(),
        };
        let raft = Raft::new(id, Arc::new(config), network, store.clone(), store.clone())
            .await
            .map_err(err)?;
        Ok(Arc::new(Self {
            raft,
            store,
            node,
            peers,
            id,
            cluster,
        }))
    }
    pub fn genesis(mut state: State, peers: &BTreeMap<u64, Peer>) -> Result<State> {
        crate::governance::validate_consensus_members(peers)?;
        if state.revision != 0
            || (!state.consensus_members.is_empty() && state.consensus_members != *peers)
        {
            return Err(Error::Denied);
        }
        state.consensus_members = peers.clone();
        Ok(state)
    }
    /// Bootstrap is explicit, once, on the chosen initial node. Restarts never reinitialize.
    pub async fn initialize(&self) -> Result<()> {
        self.raft.initialize(self.peers.clone()).await.map_err(err)
    }
    pub async fn execute(&self, actor: crate::PeerId, command: SignedCommand) -> Result<Applied> {
        let (signer, verified) = command.verify()?;
        if signer != actor.to_string() {
            return Err(Error::Denied);
        }
        if let Some((id, peer)) = self.remote_leader() {
            return network::forward(self, id, peer, Some(command), actor).await;
        }
        self.raft.ensure_linearizable().await.map_err(err)?;
        let now = crate::journal::now_ms()?;
        if verified.expires_ms < now {
            return Err(Error::Denied);
        }
        let mut preflight = self.store.state().await;
        preflight.apply(&signer, verified.revision, now, verified.action)?;
        let request = Replicated {
            cluster: self.cluster.clone(),
            command,
            time_ms: now,
        };
        self.raft
            .client_write(request)
            .await
            .map(|r| r.data)
            .map_err(err)
    }
    fn remote_leader(&self) -> Option<(u64, Peer)> {
        let metrics = self.raft.metrics().borrow().clone();
        let id = metrics.current_leader.filter(|id| *id != self.id)?;
        metrics
            .membership_config
            .membership()
            .get_node(&id)
            .cloned()
            .map(|peer| (id, peer))
    }
    pub async fn snapshot(&self, actor: crate::PeerId) -> Result<State> {
        if let Some((id, peer)) = self.remote_leader() {
            return network::forward(self, id, peer, None, actor).await;
        }
        self.raft.ensure_linearizable().await.map_err(err)?;
        let state = self.store.state().await;
        if !state.can_read(&actor.to_string()) {
            return Err(Error::Denied);
        }
        Ok(state)
    }
    pub async fn serve(self: Arc<Self>) -> Result<()> {
        tokio::select! {
            result = network::serve(self.clone()) => result,
            result = self.maintain_membership() => result,
        }
    }

    pub(crate) async fn accepts(&self, id: u64, peer: crate::PeerId) -> bool {
        let actual = peer.to_string();
        // Keep current voters authorized until joint consensus has committed removal.
        if self
            .raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .get_node(&id)
            .is_some_and(|p| p.peer == actual)
        {
            return true;
        }
        self.store
            .state()
            .await
            .consensus_members
            .get(&id)
            .is_some_and(|p| p.peer == actual)
    }
    async fn maintain_membership(&self) -> Result<()> {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            tick.tick().await;
            if self.raft.metrics().borrow().current_leader != Some(self.id) {
                continue;
            }
            let desired = self.store.state().await.consensus_members;
            let current = self.raft.metrics().borrow().membership_config.clone();
            if current
                .membership()
                .voter_ids()
                .collect::<std::collections::BTreeSet<_>>()
                == desired.keys().copied().collect()
                && desired
                    .iter()
                    .all(|(id, peer)| current.membership().get_node(id) == Some(peer))
            {
                continue;
            }
            let change = async {
                for (id, peer) in &desired {
                    if current.membership().get_node(id) != Some(peer) {
                        self.raft
                            .add_learner(*id, peer.clone(), true)
                            .await
                            .map_err(err)?;
                    }
                }
                self.raft
                    .change_membership(
                        desired
                            .keys()
                            .copied()
                            .collect::<std::collections::BTreeSet<_>>(),
                        false,
                    )
                    .await
                    .map_err(err)?;
                Ok::<(), Error>(())
            };
            match tokio::time::timeout(std::time::Duration::from_secs(30), change).await {
                Ok(Ok(())) => {}
                result => tracing::warn!(?result, "consensus membership reconciliation will retry"),
            }
        }
    }
    pub async fn shutdown(&self) -> Result<()> {
        self.raft.shutdown().await.map_err(err)
    }
}
fn err(e: impl std::fmt::Display) -> Error {
    Error::Network(e.to_string())
}
