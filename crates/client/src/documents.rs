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
    let (address, peer) = crate::endpoint(&input.address, &input.peer)?;
    let service = input.service.parse().map_err(|_| Error::Denied)?;
    let node = Node::start(identity, NodeConfig::default()).await?;
    let result = async {
        node.dial(address).await?;
        events::documents::fetch(&node, peer, service, &input.hash).await
    }
    .await;
    node.shutdown().await?;
    result
}
