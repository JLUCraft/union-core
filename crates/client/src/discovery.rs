//! Shared LAN discovery for every terminal: find federation servers over mDNS,
//! pin their identity genesis locally, and return only tested connection targets.
//!
//! Announcements are untrusted hints. Authorization always comes from comparing the
//! returned `genesis_hash` against the terminal's built-in pin, never from the
//! announcement itself.
use crate::{Error, Identity, Node, NodeConfig, PeerId, Result, trust::TrustGenesis};
use std::time::Duration;
use tokio::task::JoinSet;

const DEFAULT_WAIT: Duration = Duration::from_millis(2500);
const MAX_WAIT: Duration = Duration::from_secs(10);
const ADDRESS_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_SERVERS: usize = 16;

/// One announced server. `address` answered a real dial before being returned.
pub struct Discovered {
    pub federation: String,
    pub peer: PeerId,
    pub address: String,
    pub genesis: TrustGenesis,
    pub genesis_hash: String,
    /// Pinned application genesis hash, when the host serves one.
    pub application: Option<String>,
    pub services: Vec<String>,
}

/// mDNS announcements hand out every local interface, including unreachable virtual
/// ones. Probe each candidate with a throwaway node and keep the first that answers.
async fn probe_address(peer: PeerId, candidates: Vec<crate::Multiaddr>) -> Option<String> {
    let mut tasks = JoinSet::new();
    for (index, candidate) in candidates.into_iter().enumerate() {
        tasks.spawn(async move {
            let (address, _) = crate::endpoint(&candidate.to_string(), &peer.to_string()).ok()?;
            let probe = Node::start(Identity::generate(), NodeConfig::default())
                .await
                .ok()?;
            let result = tokio::time::timeout(ADDRESS_PROBE_TIMEOUT, probe.dial(address)).await;
            probe.shutdown().await.ok()?;
            match result {
                Ok(Ok(())) => Some((index, candidate.to_string())),
                _ => None,
            }
        });
    }
    let mut reachable = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(Some(hit)) = result {
            reachable.push(hit);
        }
    }
    reachable.sort_by_key(|(index, _)| *index);
    reachable.into_iter().next().map(|(_, address)| address)
}

/// Listen for mDNS announcements, then read each host's public identity genesis and
/// application genesis. Hosts that never answer or have no reachable address are skipped.
pub async fn discover(identity: Identity, wait: Option<Duration>) -> Result<Vec<Discovered>> {
    let wait = wait.unwrap_or(DEFAULT_WAIT).min(MAX_WAIT);
    let node = Node::start(
        identity,
        NodeConfig {
            lan_discovery: true,
            ..Default::default()
        },
    )
    .await?;
    let result = async {
        tokio::time::sleep(wait).await;
        let mut servers = Vec::new();
        for peer in node.peers().await?.into_iter().take(MAX_SERVERS) {
            if node.dial_peer(peer).await.is_err() {
                continue;
            }
            let Ok(response) =
                crate::trust::request(&node, peer, crate::protocol::TrustRequest::Genesis).await
            else {
                continue;
            };
            let Some(genesis) = response.genesis else {
                continue;
            };
            let pin = crate::trust::TrustState::genesis_digest(&genesis)?;
            crate::trust::TrustState::new(&genesis, &pin)?;
            let application = match crate::journal::discover::<crate::application::Application>(
                &node,
                peer,
                crate::journal::PROTOCOL,
            )
            .await
            {
                Ok(response) => match response.genesis {
                    Some(state) => Some(crate::protocol::digest(
                        &serde_json::to_vec(&state).map_err(Error::protocol)?,
                    )),
                    None => None,
                },
                Err(_) => None,
            };
            let candidates = node.peer_addresses(peer).await?;
            let Some(address) = probe_address(peer, candidates).await else {
                continue;
            };
            servers.push(Discovered {
                federation: genesis.federation.clone(),
                peer,
                address,
                genesis,
                genesis_hash: pin,
                application,
                services: node
                    .list_services(peer)
                    .await
                    .map(|records| records.into_iter().map(|record| record.id).collect())
                    .unwrap_or_default(),
            });
        }
        Ok(servers)
    }
    .await;
    node.shutdown().await?;
    result
}

/// The announced server whose identity genesis matches the terminal's built-in pin.
/// `Ok(None)` means no matching server is present on this network right now.
pub async fn connect_pinned(
    identity: Identity,
    genesis_hash: &str,
    wait: Option<Duration>,
) -> Result<Option<Discovered>> {
    crate::protocol::validate_digest(genesis_hash)
        .map_err(|_| Error::protocol("a pinned lowercase genesis SHA-256 is required"))?;
    Ok(discover(identity, wait)
        .await?
        .into_iter()
        .find(|server| server.genesis_hash == genesis_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn failed_candidate_does_not_cancel_a_reachable_probe() -> Result<()> {
        let server = Node::start(
            Identity::generate(),
            NodeConfig {
                listen: vec![
                    "/ip4/127.0.0.1/udp/0/quic-v1"
                        .parse()
                        .map_err(Error::protocol)?,
                ],
                ..Default::default()
            },
        )
        .await?;
        let address = server.addresses().remove(0);
        let mut unreachable = address.clone();
        unreachable.push(crate::AddressProtocol::P2p(Identity::generate().peer_id()));
        let found = probe_address(server.peer_id(), vec![unreachable, address.clone()]).await;
        server.shutdown().await?;
        assert_eq!(found.as_deref(), Some(address.to_string().as_str()));
        Ok(())
    }
}
