//! Room discovery confirms provider hints against authenticated host directories.
use crate::{
    Error, Node, PeerId, Result,
    protocol::{ROOM_PROTOCOL, RoomMetadata},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Room {
    pub peer: String,
    pub service: String,
    pub name: String,
    pub addresses: Vec<String>,
    pub metadata: RoomMetadata,
}

#[derive(Default, Serialize)]
pub struct Discovery {
    pub rooms: Vec<Room>,
    /// Partial discovery remains useful when a seed or stale provider is unavailable.
    pub unavailable: Vec<String>,
}

pub async fn discover(node: &Node, seeds: &[crate::Multiaddr]) -> Result<Discovery> {
    if seeds.len() > 16 {
        return Err(Error::Capacity);
    }
    let mut result = Discovery::default();
    let mut peers = BTreeSet::new();
    for address in seeds {
        let Some(crate::AddressProtocol::P2p(peer)) = address.iter().last() else {
            return Err(Error::Protocol("seed address must end with peer".into()));
        };
        match node.dial(address.clone()).await {
            Ok(()) => {
                peers.insert(peer);
            }
            Err(_) => result.unavailable.push(peer.to_string()),
        }
    }
    match node.discover_protocol(ROOM_PROTOCOL).await {
        Ok(providers) => peers.extend(providers),
        Err(_) => result.unavailable.push(ROOM_PROTOCOL.into()),
    }
    for peer in peers {
        match host_rooms(node, peer).await {
            Ok(rooms) => result.rooms.extend(rooms),
            Err(_) => result.unavailable.push(peer.to_string()),
        }
    }
    result
        .rooms
        .sort_by(|a, b| (&a.name, &a.peer, &a.service).cmp(&(&b.name, &b.peer, &b.service)));
    Ok(result)
}

pub async fn host_rooms(node: &Node, peer: PeerId) -> Result<Vec<Room>> {
    let directory = node.directory(peer).await?;
    let mut rooms = Vec::new();
    for service in directory.services {
        if service.protocol != ROOM_PROTOCOL || service.metadata.is_empty() {
            continue;
        }
        let metadata: RoomMetadata = serde_json::from_slice(&service.metadata)
            .map_err(|e| Error::Protocol(e.to_string()))?;
        metadata.validate()?;
        rooms.push(Room {
            peer: peer.to_string(),
            service: service.id,
            name: service.name,
            addresses: directory.addresses.clone(),
            metadata,
        });
    }
    Ok(rooms)
}
