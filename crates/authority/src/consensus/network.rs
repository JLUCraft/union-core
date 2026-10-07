// OpenRaft trait signatures require its concrete, unboxed error types.
#![allow(clippy::result_large_err)]
use super::{Cluster, Peer, TypeConfig};
use crate::protocol::RAFT_PROTOCOL as PROTOCOL;
use crate::{
    Error, Node, Result,
    journal::{Exchange, JsonFrame, Request, Response},
    protocol::{read_frame, write_frame},
};
use futures::StreamExt;
use openraft::{
    RaftNetwork, RaftNetworkFactory,
    error::{InstallSnapshotError, RPCError, RaftError, RemoteError, Unreachable},
    network::RPCOption,
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use state::Domain;
use std::{sync::Arc, time::Duration};
use tokio::{sync::Semaphore, task::JoinSet, time::timeout};
const MAX_RPC: usize = crate::journal::MAX_SNAPSHOT;
type RpcResult<T, E = openraft::error::Infallible> =
    std::result::Result<T, RPCError<u64, Peer, RaftError<u64, E>>>;
#[derive(Serialize, Deserialize)]
struct Envelope {
    cluster: String,
    sender: u64,
    payload: Rpc,
}
#[derive(Serialize, Deserialize)]
pub(super) enum Rpc {
    Response {
        actor: String,
    },
    Execute {
        command: crate::journal::SignedCommand,
        history: crate::journal::TrustHistory,
    },
    Read {
        actor: String,
    },
    Clock {
        time_ms: u64,
    },
    Append(AppendEntriesRequest<TypeConfig>),
    Vote(VoteRequest<u64>),
    Snapshot(InstallSnapshotRequest<TypeConfig>),
}
#[derive(Clone)]
pub struct Network {
    pub node: Arc<Node>,
    pub cluster: String,
}
pub struct Connection {
    network: Network,
    target: u64,
    peer: Peer,
}
impl RaftNetworkFactory<TypeConfig> for Network {
    type Network = Connection;
    async fn new_client(&mut self, target: u64, node: &Peer) -> Connection {
        Connection {
            network: self.clone(),
            target,
            peer: node.clone(),
        }
    }
}
async fn send<T: Serialize>(stream: &mut crate::Stream, value: &T, max: usize) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(super::err)?;
    if bytes.len() > max {
        return Err(Error::Capacity);
    }
    let count = bytes.len().div_ceil(60000);
    for (index, chunk) in bytes.chunks(60000).enumerate() {
        write_frame(
            stream,
            &JsonFrame {
                json: chunk.to_vec(),
                sequence: index as u32,
                last: index + 1 == count,
            },
        )
        .await?;
    }
    Ok(())
}
async fn receive<T: DeserializeOwned>(stream: &mut crate::Stream, max: usize) -> Result<T> {
    let mut bytes = Vec::new();
    let mut expected = 0;
    loop {
        let frame: JsonFrame = read_frame(stream).await?;
        if frame.sequence != expected
            || frame.json.is_empty()
            || bytes.len() + frame.json.len() > max
        {
            return Err(Error::Denied);
        }
        bytes.extend(frame.json);
        if frame.last {
            break;
        }
        expected += 1;
    }
    serde_json::from_slice(&bytes).map_err(super::err)
}
impl Connection {
    async fn rpc<T: DeserializeOwned, E: std::error::Error + DeserializeOwned>(
        &self,
        sender: u64,
        payload: Rpc,
    ) -> RpcResult<T, E> {
        let operation = async {
            let peer: crate::PeerId = self.peer.peer.parse().map_err(super::err)?;
            for address in &self.peer.addresses {
                if self
                    .network
                    .node
                    .dial(address.parse().map_err(super::err)?)
                    .await
                    .is_ok()
                {
                    break;
                }
            }
            let mut stream = self.network.node.open_protocol(peer, PROTOCOL).await?;
            send(
                &mut stream,
                &Envelope {
                    cluster: self.network.cluster.clone(),
                    sender,
                    payload,
                },
                MAX_RPC,
            )
            .await?;
            receive::<std::result::Result<T, RaftError<u64, E>>>(&mut stream, MAX_RPC).await
        };
        match timeout(Duration::from_secs(10), operation).await {
            Ok(Ok(value)) => {
                value.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
            }
            Ok(Err(error)) => Err(RPCError::Unreachable(Unreachable::new(&error))),
            Err(error) => Err(RPCError::Unreachable(Unreachable::new(&error))),
        }
    }
}
impl RaftNetwork<TypeConfig> for Connection {
    async fn append_entries(
        &mut self,
        req: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> RpcResult<AppendEntriesResponse<u64>> {
        self.rpc(req.vote.leader_id.node_id, Rpc::Append(req)).await
    }
    async fn vote(
        &mut self,
        req: VoteRequest<u64>,
        _option: RPCOption,
    ) -> RpcResult<VoteResponse<u64>> {
        self.rpc(req.vote.leader_id.node_id, Rpc::Vote(req)).await
    }
    async fn install_snapshot(
        &mut self,
        req: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> RpcResult<InstallSnapshotResponse<u64>, InstallSnapshotError> {
        self.rpc(req.vote.leader_id.node_id, Rpc::Snapshot(req))
            .await
    }
}
pub async fn serve<D: Domain>(cluster: Arc<Cluster<D>>) -> Result<()> {
    let mut rpc = cluster.node.accept_protocol(PROTOCOL)?;
    let mut governance = cluster.node.accept_protocol(crate::journal::PROTOCOL)?;
    let capacity = Arc::new(Semaphore::new(128));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
         Some((peer,mut stream))=rpc.next()=>{
          let Ok(permit)=capacity.clone().try_acquire_owned()else{continue;};let cluster=cluster.clone();
          tasks.spawn(async move{let _permit=permit;let result=timeout(Duration::from_secs(15),async{
           let envelope:Envelope=receive(&mut stream,MAX_RPC).await?;
           if envelope.cluster!=cluster.cluster||!cluster.accepts(envelope.sender,peer).await{return Err(Error::Denied);}
           match envelope.payload{
            Rpc::Response {actor} => {let response=cluster.response(actor.parse().map_err(super::err)?).await.map_err(|e|e.to_string());send(&mut stream,&response,crate::journal::MAX_SNAPSHOT).await},
            Rpc::Execute {command,history} => {let actor=command.verify::<D>()?.0;let response=cluster.execute(actor.parse().map_err(super::err)?,command,history).await.map_err(|e|e.to_string());send(&mut stream,&response,MAX_RPC).await},
            Rpc::Clock { time_ms } => { let accepted=clock_matches(time_ms,crate::journal::now_ms()?); send(&mut stream,&accepted,MAX_RPC).await },
            Rpc::Read { actor } => { let response=cluster.snapshot(actor.parse().map_err(super::err)?).await.map_err(|e|e.to_string()); send(&mut stream,&response,crate::journal::MAX_SNAPSHOT).await },
            Rpc::Append(req)=>{if req.vote.leader_id.node_id!=envelope.sender{return Err(Error::Denied);}send(&mut stream,&cluster.raft.append_entries(req).await,MAX_RPC).await},
            Rpc::Vote(req)=>{if req.vote.leader_id.node_id!=envelope.sender{return Err(Error::Denied);}send(&mut stream,&cluster.raft.vote(req).await,MAX_RPC).await},
            Rpc::Snapshot(req)=>{if req.vote.leader_id.node_id!=envelope.sender||req.offset>16*1024*1024||req.data.len()>65536||req.offset.saturating_add(req.data.len() as u64)>16*1024*1024{return Err(Error::Denied);}send(&mut stream,&cluster.raft.install_snapshot(req).await,MAX_RPC).await}
           }
          }).await;if !matches!(result,Ok(Ok(()))){tracing::debug!(%peer,"raft RPC rejected");}});
         }
         Some((peer,mut stream))=governance.next()=>{
          let Ok(permit)=capacity.clone().try_acquire_owned()else{continue;};let cluster=cluster.clone();
          tasks.spawn(async move{let _permit=permit;let result=timeout(Duration::from_secs(30),async{
           let exchange:Exchange=receive(&mut stream,crate::journal::MAX_SNAPSHOT).await?;
           let result=async {
            let applied=match exchange.request {
                Request::Genesis=>return Ok(Response::<D>::genesis(cluster.store.genesis().await)),
                Request::Snapshot=>{
                    if exchange.genesis_hash!=cluster.cluster {return Err(Error::Denied);}
                    return cluster.response(peer).await;
                },
                Request::Execute{command,history}=>{
                    if exchange.genesis_hash!=cluster.cluster {return Err(Error::Denied);}
                    cluster.execute(peer,command,history).await?
                },
            };
            if let Some(error)=applied.error {return Err(Error::Protocol(error));}
            cluster.response(peer).await
           }.await;
           let response=match result {Ok(response)=>response,Err(e)=>Response::<D>::rejected(e)};
           send(&mut stream,&response,crate::journal::MAX_SNAPSHOT).await
          }).await;if !matches!(result,Ok(Ok(()))){tracing::debug!(%peer,"consensus governance request ended");}});
         }
         Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if let Err(error)=result{tracing::error!(%error,"consensus handler failed");}}
         else=>return Ok(())
        }
    }
}

/// Dial the first reachable address of `peer`, then open the consensus protocol stream.
async fn open_stream<D: Domain>(cluster: &Cluster<D>, peer: &Peer) -> Result<crate::Stream> {
    let remote = peer.peer.parse().map_err(super::err)?;
    for address in &peer.addresses {
        if cluster
            .node
            .dial(address.parse().map_err(super::err)?)
            .await
            .is_ok()
        {
            break;
        }
    }
    cluster.node.open_protocol(remote, PROTOCOL).await
}

pub(super) async fn forward_request<T: DeserializeOwned, D: Domain>(
    cluster: &Cluster<D>,
    peer: Peer,
    payload: Rpc,
) -> Result<T> {
    let operation = async {
        let mut stream = open_stream(cluster, &peer).await?;
        send(
            &mut stream,
            &Envelope {
                cluster: cluster.cluster.clone(),
                sender: cluster.id,
                payload,
            },
            MAX_RPC,
        )
        .await?;
        receive::<std::result::Result<T, String>>(&mut stream, crate::journal::MAX_SNAPSHOT)
            .await?
            .map_err(super::err)
    };
    timeout(Duration::from_secs(15), operation)
        .await
        .map_err(|_| Error::Timeout)?
}

/// Maximum accepted wall-clock disagreement for a proposed governance command.
const MAX_CLOCK_SKEW_MS: u64 = 5_000;

fn clock_matches(proposed: u64, local: u64) -> bool {
    proposed.abs_diff(local) <= MAX_CLOCK_SKEW_MS
}

fn clock_quorum(
    configs: &[std::collections::BTreeSet<u64>],
    accepted: &std::collections::BTreeSet<u64>,
) -> bool {
    !configs.is_empty()
        && configs
            .iter()
            .all(|voters| voters.intersection(accepted).count() > voters.len() / 2)
}

/// Check the exact timestamp that will enter the log, using authenticated voters.
/// This is a CFT clock check, not Byzantine evidence or an external time source.
pub(super) async fn validate_clock<D: Domain>(cluster: &Cluster<D>, time_ms: u64) -> Result<()> {
    let membership = cluster.raft.metrics().borrow().membership_config.clone();
    let configs = membership.membership().get_joint_config();
    let mut accepted = std::collections::BTreeSet::new();
    if clock_matches(time_ms, crate::journal::now_ms()?) {
        accepted.insert(cluster.id);
    }
    let mut pending = futures::stream::FuturesUnordered::new();
    for id in membership
        .membership()
        .voter_ids()
        .filter(|id| *id != cluster.id)
    {
        let peer = membership
            .membership()
            .get_node(&id)
            .ok_or(Error::Denied)?
            .clone();
        pending.push(async move {
            let result = async {
                let mut stream = open_stream(cluster, &peer).await?;
                send(
                    &mut stream,
                    &Envelope {
                        cluster: cluster.cluster.clone(),
                        sender: cluster.id,
                        payload: Rpc::Clock { time_ms },
                    },
                    MAX_RPC,
                )
                .await?;
                receive::<bool>(&mut stream, MAX_RPC).await
            }
            .await;
            (id, result)
        });
    }
    timeout(Duration::from_millis(MAX_CLOCK_SKEW_MS), async {
        while !clock_quorum(configs, &accepted) {
            match pending.next().await {
                Some((id, Ok(true))) => {
                    accepted.insert(id);
                }
                Some(_) => {}
                None => return Err(Error::Denied),
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| Error::Timeout)??;
    if cluster.raft.metrics().borrow().membership_config != membership
        || !clock_matches(time_ms, crate::journal::now_ms()?)
    {
        return Err(Error::Denied);
    }
    Ok(())
}

#[cfg(test)]
mod clock_tests {
    use super::{MAX_CLOCK_SKEW_MS, clock_matches, clock_quorum};

    #[test]
    fn clock_bounds_reject_both_directions_without_overflow() {
        let now = MAX_CLOCK_SKEW_MS * 2;
        assert!(clock_matches(now + MAX_CLOCK_SKEW_MS, now));
        assert!(clock_matches(now - MAX_CLOCK_SKEW_MS, now));
        assert!(!clock_matches(now + MAX_CLOCK_SKEW_MS + 1, now));
        assert!(!clock_matches(now - MAX_CLOCK_SKEW_MS - 1, now));
        assert!(!clock_matches(u64::MAX, 0));
        assert!(!clock_matches(0, u64::MAX));
    }

    #[test]
    fn clock_quorum_requires_each_joint_majority_and_excludes_learners() {
        let configs = vec![[1, 2, 3].into(), [3, 4, 5].into()];
        assert!(!clock_quorum(&configs, &[1, 2, 6, 7].into()));
        assert!(!clock_quorum(&configs, &[1, 3].into()));
        assert!(clock_quorum(&configs, &[1, 3, 4].into()));
        assert!(!clock_quorum(&[], &[1].into()));
        assert!(!clock_quorum(&[Default::default()], &[1].into()));
    }
}

#[cfg(test)]
mod clock_network_tests {
    use super::{MAX_CLOCK_SKEW_MS, validate_clock};
    use crate::{
        Identity, Node,
        consensus::{Cluster, Peer},
        governance::State,
        journal::now_ms,
    };
    use node::NodeConfig;
    use std::{collections::BTreeMap, sync::Arc, time::Duration};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn authenticated_voters_check_clock_and_missing_majority_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::time::timeout(Duration::from_secs(30), async {
            let dir = tempfile::tempdir()?;
            let admin = Identity::generate();
            let roots = crate::protocol::TrustGenesis {
                federation: "clock-test".into(),
                quorum: 1,
                founders: vec![crate::protocol::TrustFounder {
                    member: "chair".into(),
                    club: "club".into(),
                    public_key: admin.public_key().encode_protobuf(),
                }],
            };
            let pin = identity::trust::TrustState::genesis_digest(&roots)?;
            let log = crate::trust::TrustLog::open(&dir.path().join("identity"), &roots, &pin)?;
            log.mark_current()?;
            let view = log.view(Duration::from_secs(60))?;
            let log = Arc::new(tokio::sync::Mutex::new(log));
            let genesis =
                State::<state::EmptyDomain>::new(crate::protocol::TrustBusinessBinding {
                    genesis: pin,
                    namespace: "clock".into(),
                    service: "clock".into(),
                    club: "club".into(),
                    audience: admin.peer_id().to_string(),
                })?;
            let mut nodes = Vec::new();
            for _ in 0..3 {
                nodes.push(Arc::new(
                    Node::start(Identity::generate(), NodeConfig::default()).await?,
                ));
            }
            let peers: BTreeMap<_, _> = nodes
                .iter()
                .enumerate()
                .map(|(i, node)| {
                    (
                        (i + 1) as u64,
                        Peer {
                            peer: node.peer_id().to_string(),
                            addresses: node.addresses().iter().map(ToString::to_string).collect(),
                        },
                    )
                })
                .collect();
            let mut clusters = Vec::new();
            let mut serving = tokio::task::JoinSet::new();
            for (i, node) in nodes.into_iter().enumerate() {
                let cluster = Cluster::start(
                    (i + 1) as u64,
                    node,
                    &dir.path().join(format!("clock-{i}")),
                    genesis.clone(),
                    peers.clone(),
                    (log.clone(), view.clone()),
                )
                .await?;
                serving.spawn(cluster.clone().serve());
                clusters.push(cluster);
            }
            tokio::task::yield_now().await;
            clusters[0].initialize().await?;
            let leader = loop {
                let mut ready = None;
                for cluster in &clusters {
                    if cluster.raft.ensure_linearizable().await.is_ok() {
                        ready = Some(cluster.clone());
                        break;
                    }
                }
                if let Some(cluster) = ready {
                    break cluster;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            validate_clock(&leader, now_ms()?).await?;
            assert!(
                validate_clock(&leader, now_ms()? + MAX_CLOCK_SKEW_MS * 4)
                    .await
                    .is_err()
            );
            assert!(
                validate_clock(&leader, now_ms()? - MAX_CLOCK_SKEW_MS * 4)
                    .await
                    .is_err()
            );
            serving.shutdown().await;
            assert!(validate_clock(&leader, now_ms()?).await.is_err());
            for cluster in &clusters {
                assert_eq!(cluster.store.state().await.revision, 0);
                cluster.shutdown().await?;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await?
    }
}
