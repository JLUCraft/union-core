//! Crash-fault consensus over authenticated Union streams. No HTTP control plane.
use state::Domain;
mod network;
use crate::{Error, Node, Result, governance::State, journal::SignedCommand};
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub use journal::consensus::{Applied, Peer, Replicated, Store, TypeConfig};
pub type Raft = openraft::Raft<TypeConfig>;
pub struct Cluster<D: Domain> {
    pub raft: Raft,
    pub store: Store<D>,
    pub node: Arc<Node>,
    pub peers: BTreeMap<u64, Peer>,
    pub id: u64,
    pub cluster: String,
    pub identity: (
        Arc<tokio::sync::Mutex<crate::trust::TrustLog>>,
        crate::trust::TrustView,
    ),
}
impl<D: Domain> Cluster<D> {
    pub async fn start(
        id: u64,
        node: Arc<Node>,
        path: &Path,
        genesis: State<D>,
        peers: BTreeMap<u64, Peer>,
        identity: (
            Arc<tokio::sync::Mutex<crate::trust::TrustLog>>,
            crate::trust::TrustView,
        ),
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
            identity,
        }))
    }
    pub fn genesis(mut state: State<D>, peers: &BTreeMap<u64, Peer>) -> Result<State<D>> {
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
    pub async fn execute(
        &self,
        actor: crate::PeerId,
        command: SignedCommand,
        history: crate::journal::TrustHistory,
    ) -> Result<Applied> {
        let signer = command.verify::<D>()?.0;
        if signer != actor.to_string() {
            return Err(Error::Denied);
        }
        // Every entry point, including a follower, requires a current independently verified identity view.
        let view = &self.identity.1;
        let current = view.state()?;
        if command.verify::<D>()?.1.identity != *current.checkpoint() {
            return Err(Error::Denied);
        }
        if let Some((_, peer)) = self.remote_leader() {
            return network::forward_request(
                self,
                peer,
                network::Rpc::Execute { command, history },
            )
            .await;
        }
        self.raft.ensure_linearizable().await.map_err(err)?;
        let now = crate::journal::now_ms()?;
        network::validate_clock(self, now).await?;
        if view.state()?.checkpoint() != current.checkpoint() {
            return Err(Error::Denied);
        }
        let request = Replicated {
            cluster: self.cluster.clone(),
            command,
            time_ms: now,
            identity: history,
        };
        self.store.preflight(&request).await?;
        self.raft
            .client_write(request)
            .await
            .map(|r| r.data)
            .map_err(err)
    }
    pub async fn response(&self, actor: crate::PeerId) -> Result<crate::journal::Response<D>> {
        if let Some((_, peer)) = self.remote_leader() {
            self.authorize(actor, &self.store.state().await)?;
            return network::forward_request(
                self,
                peer,
                network::Rpc::Response {
                    actor: actor.to_string(),
                },
            )
            .await;
        }
        self.raft.ensure_linearizable().await.map_err(err)?;
        let response = self.store.response().await?;
        self.authorize(actor, response.state.as_ref().ok_or(Error::Denied)?)?;
        Ok(response)
    }
    fn authorize(&self, actor: crate::PeerId, state: &State<D>) -> Result<()> {
        let current = self.identity.1.state()?;
        let allowed = state.can_read(&actor.to_string(), &current);
        if allowed { Ok(()) } else { Err(Error::Denied) }
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
    pub async fn snapshot(&self, actor: crate::PeerId) -> Result<State<D>> {
        self.response(actor).await?.state.ok_or(Error::Denied)
    }
    pub async fn serve(self: Arc<Self>, protocol: &'static str) -> Result<()> {
        tokio::select! {
            result = network::serve(self.clone(), protocol) => result,
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
            let desired = self.store.state().await.core.consensus_members;
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
