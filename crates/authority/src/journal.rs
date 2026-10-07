//! Governance protocol assembly over the durable journal.
use crate::{Error, Result};
pub use journal::journal::*;
use state::Domain;
const CHUNK_SIZE: usize = crate::protocol::MAX_FRAME - 64;
async fn send_chunked(
    stream: &mut (impl futures::AsyncWrite + Unpin),
    value: &impl serde::Serialize,
) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(Error::protocol)?;
    if bytes.len() > MAX_SNAPSHOT {
        return Err(Error::Capacity);
    }
    let count = bytes.len().div_ceil(CHUNK_SIZE);
    for (sequence, chunk) in bytes.chunks(CHUNK_SIZE).enumerate() {
        crate::protocol::write_frame(
            stream,
            &JsonFrame {
                json: chunk.to_vec(),
                sequence: sequence as u32,
                last: sequence + 1 == count,
            },
        )
        .await?;
    }
    Ok(())
}
/// One bounded exchange; the caller owns the Node and its lifecycle.
pub async fn request<D: Domain>(
    node: &crate::Node,
    peer: crate::PeerId,
    genesis_hash: &str,
    request: Request,
) -> Result<Response<D>> {
    wire::protocol::validate_digest(genesis_hash)
        .map_err(|_| Error::protocol("a pinned lowercase genesis SHA-256 is required"))?;
    let mut response = exchange(
        node,
        peer,
        &Exchange {
            genesis_hash: genesis_hash.into(),
            request,
        },
    )
    .await?;
    response.verify(genesis_hash)?;
    // Never accept a server-supplied identity projection as verified facts.
    response.identity_view = None;
    Ok(response)
}

/// TOFU discovery: the caller has no pinned hash yet, so the serve side skips the
/// pin comparison and the caller must verify the returned genesis locally.
pub async fn discover<D: Domain>(node: &crate::Node, peer: crate::PeerId) -> Result<Response<D>> {
    exchange(
        node,
        peer,
        &Exchange {
            genesis_hash: String::new(),
            request: Request::Genesis,
        },
    )
    .await
}

async fn exchange<D: Domain>(
    node: &crate::Node,
    peer: crate::PeerId,
    exchange: &Exchange,
) -> Result<Response<D>> {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let mut stream = node.open_protocol(peer, PROTOCOL).await?;
        send_chunked(&mut stream, exchange).await?;
        let mut json = Vec::new();
        for sequence in 0..=MAX_SNAPSHOT / CHUNK_SIZE {
            let reply: JsonFrame = crate::protocol::read_frame(&mut stream).await?;
            if reply.sequence as usize != sequence
                || reply.json.is_empty()
                || json.len().saturating_add(reply.json.len()) > MAX_SNAPSHOT
            {
                return Err(Error::protocol("invalid snapshot chunks"));
            }
            json.extend_from_slice(&reply.json);
            if reply.last {
                return serde_json::from_slice(&json).map_err(Error::protocol);
            }
        }
        Err(Error::Capacity)
    })
    .await
    .map_err(|_| Error::Timeout)?
}

pub async fn serve<D: Domain>(
    node: &crate::Node,
    journal: std::sync::Arc<tokio::sync::Mutex<Journal<D>>>,
    identity: crate::trust::TrustView,
) -> Result<()> {
    use futures::StreamExt;
    let mut incoming = node.accept_protocol(PROTOCOL)?;
    let mut tasks = tokio::task::JoinSet::new();
    let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(32));
    loop {
        tokio::select! {
            Some((peer, mut stream)) = incoming.next() => {
                let Ok(permit) = limit.clone().try_acquire_owned() else { continue; };
                let journal = journal.clone();
                let identity=identity.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = tokio::time::timeout(std::time::Duration::from_secs(15), async {
                        let mut bytes=Vec::new();
                        loop {
                            let frame:JsonFrame=crate::protocol::read_frame(&mut stream).await?;
                            if frame.sequence as usize != bytes.len().div_ceil(CHUNK_SIZE) || frame.json.is_empty() || bytes.len()+frame.json.len()>MAX_SNAPSHOT || (!frame.last && frame.json.len()!=CHUNK_SIZE) {return Err(Error::Denied);}
                            bytes.extend(frame.json);if frame.last {break;}
                        }
                        let exchange: Exchange = serde_json::from_slice(&bytes).map_err(Error::protocol)?;
                        let mut journal = journal.lock().await;
                        let actor = peer.to_string();
                        let reply = match exchange.request {
                            // Discovery has no pin yet; binding checks happen on the client.
                            Request::Genesis => Response::genesis(journal.genesis().clone()),
                            request => if exchange.genesis_hash != journal.genesis_hash() { Response::rejected(Error::Protocol("genesis mismatch".into())) } else { match request {
                            Request::Snapshot => {
                                let allowed=identity.state().map(|state|journal.state().can_read(&actor,&state));
                                match allowed {Ok(true)=>journal.snapshot()?,Ok(false)=>Response::rejected(Error::Denied),Err(error)=>Response::rejected(error)}
                            },
                            Request::Execute {command,history} => {
                                let result=match command.verify::<D>() {
                                    Ok((signer,_)) if signer==actor => identity.state().and_then(|state|journal.execute(command,history,&state,now_ms()?)),
                                    _=>Err(Error::Denied),
                                };
                                match result {Ok(())=>journal.snapshot()?,Err(error)=>Response::rejected(error)}
                            },
                            Request::Genesis => Response::rejected(Error::Denied),
                            }}};
                        drop(journal);
                        send_chunked(&mut stream, &reply).await?;
                        Ok::<(),Error>(())
                    }).await;
                    if !matches!(result, Ok(Ok(()))) { tracing::debug!(%peer, "governance exchange failed"); }
                });
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => { if let Err(error) = result { tracing::error!(%error, "governance task failed"); } }
            else => return Ok(()),
        }
    }
}
