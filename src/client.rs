//! Shared Android JNI / Tauri command facade. Identity stays in native storage.
use crate::{
    Error, Identity, Multiaddr, Node, NodeConfig, PeerId, Result, governance::Action, journal,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Input {
    pub address: String,
    pub peer: String,
    pub revision: Option<u64>,
    pub action: Option<Action>,
}

pub async fn execute(identity: Identity, input: Input) -> Result<journal::Response> {
    let peer: PeerId = input
        .peer
        .parse()
        .map_err(|_| Error::Protocol("invalid peer".into()))?;
    let address: Multiaddr = input
        .address
        .parse()
        .map_err(|_| Error::Protocol("invalid address".into()))?;
    if !matches!(address.iter().last(),Some(crate::AddressProtocol::P2p(id)) if id == peer) {
        return Err(Error::Denied);
    }
    let request = match input.action {
        Some(action) => journal::Request::Execute {
            command: journal::SignedCommand::sign(
                &identity,
                journal::Command {
                    revision: input
                        .revision
                        .ok_or_else(|| Error::Protocol("revision required".into()))?,
                    expires_ms: journal::now_ms()?.saturating_add(30_000),
                    action,
                },
            )?,
        },
        None => journal::Request::Snapshot,
    };
    let node = Node::start(identity, NodeConfig::default()).await?;
    node.dial(address).await?;
    let response = journal::request(&node, peer, request).await;
    node.shutdown().await?;
    response
}
