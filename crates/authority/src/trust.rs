//! Identity replication verifies records, never trusts remote state snapshots.
use crate::{Error, Node, PeerId, Result};
pub use journal::trust::{TrustLog, TrustView};
use protocol::{
    self, JsonFrame, MAX_TRUST_PAGE, MAX_TRUST_RECORD, TRUST_PROTOCOL, TrustRequest, TrustResponse,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
const TIMEOUT: Duration = Duration::from_secs(15);
const CHUNK: usize = protocol::MAX_FRAME - 128;
const MAX_RESPONSE: usize = MAX_TRUST_PAGE * MAX_TRUST_RECORD + CHUNK;
fn protocol_error(e: impl std::fmt::Display) -> Error {
    Error::Protocol(e.to_string())
}
pub async fn request(node: &Node, peer: PeerId, request: TrustRequest) -> Result<TrustResponse> {
    tokio::time::timeout(TIMEOUT, async {
        let mut stream = node.open_protocol(peer, TRUST_PROTOCOL).await?;
        protocol::write_frame(
            &mut stream,
            &JsonFrame {
                json: serde_json::to_vec(&request).map_err(protocol_error)?,
                sequence: 0,
                last: true,
            },
        )
        .await?;
        let mut bytes = Vec::new();
        for sequence in 0..=MAX_RESPONSE / CHUNK {
            let frame: JsonFrame = protocol::read_frame(&mut stream).await?;
            if frame.sequence as usize != sequence
                || frame.json.is_empty()
                || bytes.len() + frame.json.len() > MAX_RESPONSE
            {
                return Err(Error::Denied);
            }
            bytes.extend(frame.json);
            if frame.last {
                return serde_json::from_slice(&bytes).map_err(protocol_error);
            }
        }
        Err(Error::Capacity)
    })
    .await
    .map_err(|_| Error::Timeout)?
}
/// An authenticated peer supplies availability/currentness, while genesis and every action are verified locally.
pub async fn synchronize(node: &Node, peer: PeerId, log: &Mutex<TrustLog>) -> Result<()> {
    let result = synchronize_inner(node, peer, log).await;
    if result.is_err() {
        log.lock().await.mark_stale();
    }
    result
}
async fn synchronize_inner(node: &Node, peer: PeerId, log: &Mutex<TrustLog>) -> Result<()> {
    loop {
        let checkpoint = log.lock().await.state().checkpoint().clone();
        let response = request(
            node,
            peer,
            TrustRequest::Read {
                checkpoint: checkpoint.clone(),
            },
        )
        .await?;
        if response.error.is_some()
            || response.checkpoint.genesis != checkpoint.genesis
            || response.checkpoint.sequence < checkpoint.sequence
            || response.records.len() > MAX_TRUST_PAGE
        {
            return Err(Error::Denied);
        }
        let mut log = log.lock().await;
        if log.state().checkpoint() != &checkpoint {
            return Err(Error::Protocol(
                "concurrent identity synchronization".into(),
            ));
        }
        if !response.records.is_empty() {
            log.mark_stale();
        }
        for record in response.records {
            log.append(record)?;
        }
        let verified = log.state().checkpoint();
        if verified.sequence == response.checkpoint.sequence {
            if verified != &response.checkpoint {
                return Err(Error::Denied);
            }
            return log.mark_current();
        }
        if verified.sequence <= checkpoint.sequence
            || verified.sequence > response.checkpoint.sequence
        {
            return Err(Error::Denied);
        }
    }
}
pub async fn serve(node: &Node, log: Arc<Mutex<TrustLog>>, writable: bool) -> Result<()> {
    let view = log.lock().await.view(Duration::from_secs(60))?;
    serve_with_view(node, log, writable, view).await
}
pub async fn serve_with_view(
    node: &Node,
    log: Arc<Mutex<TrustLog>>,
    writable: bool,
    view: TrustView,
) -> Result<()> {
    use futures::{AsyncWriteExt, StreamExt};
    let mut incoming = node.accept_protocol(TRUST_PROTOCOL)?;
    let mut tasks = tokio::task::JoinSet::new();
    let permits = Arc::new(tokio::sync::Semaphore::new(32));
    loop {
        tokio::select! {
            next = incoming.next() => {
                let Some((_,mut stream)) = next else { return Err(Error::Stopped); };
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let log=log.clone();let view=view.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    tokio::time::timeout(TIMEOUT,async {
                        let frame:JsonFrame=protocol::read_frame(&mut stream).await?;
                        if frame.sequence != 0 || !frame.last { return Err(Error::Denied); }
                        let request:TrustRequest=serde_json::from_slice(&frame.json).map_err(protocol_error)?;
                        let mut log=log.lock().await;
                        let response=match request {
                            // TOFU discovery must work even on a stale replica view.
                            TrustRequest::Genesis => TrustResponse {checkpoint:log.state().checkpoint().clone(), records:Vec::new(), error:None, genesis:Some(log.genesis().clone())},
                            request => {
                            let result=match request {
                            TrustRequest::Read {checkpoint} => {if writable {log.mark_current()?;} view.state().and_then(|_|log.page(&checkpoint))},
                            TrustRequest::Append {record} if writable => log.append(record).and_then(|()| {log.mark_current()?; Ok(Vec::new())}),
                            _ => Err(Error::Denied),
                        };
                        match result {
                            Ok(records)=>TrustResponse {checkpoint:log.state().checkpoint().clone(), records,error:None, genesis:None},
                            Err(error)=>TrustResponse {checkpoint:log.state().checkpoint().clone(),records:Vec::new(),error:Some(error.to_string()), genesis:None},
                        }
                            }
                        };
                        drop(log);
                        let bytes=serde_json::to_vec(&response).map_err(protocol_error)?;
                        if bytes.len()>MAX_RESPONSE { return Err(Error::Capacity); }
                        let count=bytes.len().div_ceil(CHUNK);
                        for (sequence,chunk) in bytes.chunks(CHUNK).enumerate() {
                            protocol::write_frame(&mut stream,&JsonFrame {json:chunk.to_vec(),sequence:sequence as u32,last:sequence+1==count}).await?;
                        }
                        stream.close().await.map_err(Error::Io)
                    }).await.map_err(|_| Error::Timeout)?
                });
            },
            Some(result)=tasks.join_next(), if !tasks.is_empty()=> { if !matches!(result,Ok(Ok(()))) { tracing::debug!("identity exchange ended"); } },
        }
    }
}
