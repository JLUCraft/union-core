//! Shared Android JNI / Tauri command facade. Identity stays in native storage.
use crate::{
    Error, Identity, Multiaddr, Node, NodeConfig, PeerId, Result, governance::Action, journal,
};
use serde::{Deserialize, Serialize};
use state::Domain;

#[derive(Serialize, Deserialize)]
#[serde(bound = "", deny_unknown_fields)]
pub struct Input<D: Domain> {
    pub identity: crate::trust::Config,
    pub address: String,
    pub peer: String,
    pub genesis_hash: String,
    pub revision: Option<u64>,
    pub action: Option<Action<D>>,
}

pub async fn execute<D: Domain>(
    identity: Identity,
    input: Input<D>,
) -> Result<journal::Response<D>> {
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
    {
        let config = input.identity;
        let node = Node::start(identity.clone(), NodeConfig::default()).await?;
        let result = async {
            let log = tokio::sync::Mutex::new(config.open()?);
            config.synchronize(&node, &log).await?;
            node.dial(address).await?;
            let mut response = match input.action {
                Some(action) => {
                    crate::trust::execute(
                        &node,
                        peer,
                        &input.genesis_hash,
                        &identity,
                        &*log.lock().await,
                        action,
                    )
                    .await?
                }
                None => {
                    journal::request(&node, peer, &input.genesis_hash, journal::Request::Snapshot)
                        .await?
                }
            };
            if let Some(state) = &response.state {
                response.identity_view =
                    Some(state.identity_presentation(log.lock().await.state())?);
            }
            if response
                .state
                .as_ref()
                .is_some_and(|s| input.revision.is_some_and(|r| s.revision < r))
            {
                return Err(Error::Denied);
            }
            Ok(response)
        }
        .await;
        node.shutdown().await?;
        result
    }
}
