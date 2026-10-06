//! Shared workflow LLM client. Partial output survives transport failure.
use crate::{
    Error, Identity, Node, NodeConfig, Result, ServiceId,
    protocol::{JsonFrame, LlmFrame, LlmRequest, LlmUsage, read_frame, write_llm_request},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(180);
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub address: String,
    pub peer: String,
    pub service: String,
    pub request: LlmRequest,
}
#[derive(Default, Serialize, Deserialize)]
pub struct Completion {
    pub content: String,
    pub usage: Option<LlmUsage>,
    pub truncated: bool,
    pub error: Option<String>,
}

pub async fn ask(
    node: &Node,
    peer: crate::PeerId,
    service: ServiceId,
    request: LlmRequest,
    mut on_delta: impl FnMut(&str),
) -> Result<Completion> {
    let mut result = Completion::default();
    let exchange = async {
        let mut stream = node.open_service(peer, service).await?;
        write_llm_request(&mut stream, &request).await?;
        loop {
            let frame: JsonFrame = read_frame(&mut stream).await?;
            if frame.sequence != 0 || !frame.last {
                return Err(Error::Protocol("invalid LLM envelope".into()));
            }
            match serde_json::from_slice::<LlmFrame>(&frame.json).map_err(Error::protocol)? {
                LlmFrame::Delta { content } => {
                    if result.content.len().saturating_add(content.len()) > MAX_OUTPUT_BYTES {
                        return Err(Error::Capacity);
                    }
                    on_delta(&content);
                    result.content.push_str(&content);
                }
                LlmFrame::Done { usage, truncated } => {
                    result.usage = usage;
                    result.truncated = truncated;
                    return Ok(());
                }
                LlmFrame::Error { error, .. } => return Err(Error::Protocol(error)),
            }
        }
    };
    let status = tokio::time::timeout(REQUEST_TIMEOUT, exchange).await;
    if let Err(error) = status.unwrap_or(Err(Error::Timeout)) {
        result.truncated = true;
        result.error = Some(error.to_string());
    }
    Ok(result)
}

pub async fn execute(identity: Identity, input: Input) -> Result<Completion> {
    let peer = input.peer.parse().map_err(Error::protocol)?;
    let address: crate::Multiaddr = input.address.parse().map_err(Error::protocol)?;
    if !matches!(address.iter().last(), Some(crate::AddressProtocol::P2p(id)) if id == peer) {
        return Err(Error::Denied);
    }
    let service = input.service.parse().map_err(Error::protocol)?;
    let node = Node::start(identity, NodeConfig::default()).await?;
    let result = async {
        node.dial(address).await?;
        ask(&node, peer, service, input.request, |_| {}).await
    }
    .await;
    node.shutdown().await?;
    result
}
