//! Bounded, hash-verified downloads from independently authorized document services.
use crate::{Error, Identity, Node, NodeConfig, Result};
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub address: String,
    pub peer: String,
    pub service: String,
    pub hash: String,
}
pub async fn fetch(identity: Identity, input: Input) -> Result<Vec<u8>> {
    let peer = input.peer.parse().map_err(|_| Error::Denied)?;
    let address: crate::Multiaddr = input.address.parse().map_err(|_| Error::Denied)?;
    let service = input.service.parse().map_err(|_| Error::Denied)?;
    if !matches!(address.iter().last(),Some(crate::AddressProtocol::P2p(id)) if id==peer) {
        return Err(Error::Denied);
    }
    let node = Node::start(identity, NodeConfig::default()).await?;
    let result = async {
        node.dial(address).await?;
        events::documents::fetch(&node, peer, service, &input.hash).await
    }
    .await;
    node.shutdown().await?;
    result
}
