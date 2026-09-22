// OpenRaft trait signatures require its concrete, unboxed error types.
#![allow(clippy::result_large_err)]
use super::{Cluster, Peer, TypeConfig};
use crate::{
    Error, Node, Result,
    journal::{JsonFrame, Request, Response},
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
use std::{sync::Arc, time::Duration};
use tokio::{sync::Semaphore, task::JoinSet, time::timeout};
const PROTOCOL: &str = "/jlucraft/union/raft/1";
const MAX_RPC: usize = 2 * 1024 * 1024;
type RpcResult<T, E = openraft::error::Infallible> =
    std::result::Result<T, RPCError<u64, Peer, RaftError<u64, E>>>;
#[derive(Serialize, Deserialize)]
struct Envelope {
    cluster: String,
    sender: u64,
    payload: Rpc,
}
#[derive(Serialize, Deserialize)]
enum Rpc {
    Read {
        actor: String,
    },
    Execute {
        command: crate::journal::SignedCommand,
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
pub async fn serve(cluster: Arc<Cluster>) -> Result<()> {
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
            Rpc::Read { actor } => { let response=cluster.snapshot(actor.parse().map_err(super::err)?).await.map_err(|e|e.to_string()); send(&mut stream,&response,crate::journal::MAX_SNAPSHOT).await },
            Rpc::Execute { command } => { let (actor,_)=command.verify()?;let response=cluster.execute(actor.parse().map_err(super::err)?,command).await.map_err(|e|e.to_string());send(&mut stream,&response,MAX_RPC).await },
            Rpc::Append(req)=>{if req.vote.leader_id.node_id!=envelope.sender{return Err(Error::Denied);}send(&mut stream,&cluster.raft.append_entries(req).await,MAX_RPC).await},
            Rpc::Vote(req)=>{if req.vote.leader_id.node_id!=envelope.sender{return Err(Error::Denied);}send(&mut stream,&cluster.raft.vote(req).await,MAX_RPC).await},
            Rpc::Snapshot(req)=>{if req.vote.leader_id.node_id!=envelope.sender||req.offset>16*1024*1024||req.data.len()>65536||req.offset.saturating_add(req.data.len() as u64)>16*1024*1024{return Err(Error::Denied);}send(&mut stream,&cluster.raft.install_snapshot(req).await,MAX_RPC).await}
           }
          }).await;if !matches!(result,Ok(Ok(()))){tracing::debug!(%peer,"raft RPC rejected");}});
         }
         Some((peer,mut stream))=governance.next()=>{
          let Ok(permit)=capacity.clone().try_acquire_owned()else{continue;};let cluster=cluster.clone();
          tasks.spawn(async move{let _permit=permit;let result=timeout(Duration::from_secs(30),async{
           let request:Request=receive(&mut stream,crate::protocol::MAX_FRAME).await?;
           let result=match request{Request::Snapshot=>cluster.snapshot(peer).await,Request::Execute{command}=>match cluster.execute(peer,command).await{Ok(applied)if applied.error.is_none()=>cluster.snapshot(peer).await,Ok(applied)=>Err(Error::Protocol(applied.error.unwrap_or_default())),Err(e)=>Err(e)}};
           let response=match result{Ok(state)=>Response{state:Some(state),error:None},Err(e)=>Response{state:None,error:Some(e.to_string())}};
           send(&mut stream,&response,crate::journal::MAX_SNAPSHOT).await
          }).await;if !matches!(result,Ok(Ok(()))){tracing::debug!(%peer,"consensus governance request ended");}});
         }
         Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if let Err(error)=result{tracing::error!(%error,"consensus handler failed");}}
         else=>return Ok(())
        }
    }
}

pub async fn forward<T: DeserializeOwned>(
    cluster: &Cluster,
    target: u64,
    peer: Peer,
    command: Option<crate::journal::SignedCommand>,
    actor: crate::PeerId,
) -> Result<T> {
    let operation = async {
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
        let mut stream = cluster.node.open_protocol(remote, PROTOCOL).await?;
        send(
            &mut stream,
            &Envelope {
                cluster: cluster.cluster.clone(),
                sender: cluster.id,
                payload: match command {
                    Some(command) => Rpc::Execute { command },
                    None => Rpc::Read {
                        actor: actor.to_string(),
                    },
                },
            },
            MAX_RPC,
        )
        .await?;
        receive::<std::result::Result<T, String>>(&mut stream, crate::journal::MAX_SNAPSHOT)
            .await?
            .map_err(super::err)
    };
    let _ = target;
    timeout(Duration::from_secs(15), operation)
        .await
        .map_err(|_| Error::Timeout)?
}
