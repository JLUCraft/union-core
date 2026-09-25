use crate::{Error, PeerId, Result, ServiceId};
use std::collections::HashSet;
#[derive(Clone, Debug, Default)]
pub enum AccessPolicy {
    #[default]
    Deny,
    Public,
    Peers(HashSet<PeerId>),
    Trust {
        view: journal::trust::TrustView,
        requirement: crate::protocol::TrustRequirement,
    },
}
impl AccessPolicy {
    pub fn authorize(&self, peer: PeerId, audience: PeerId, service: ServiceId) -> Result<()> {
        match self {
            Self::Public => Ok(()),
            Self::Peers(peers) if peers.contains(&peer) => Ok(()),
            Self::Trust { view, requirement } => view
                .authorize(
                    &peer.to_string(),
                    &audience.to_string(),
                    &service.to_string(),
                    requirement,
                )
                .map(|_| ()),
            _ => Err(Error::Denied),
        }
    }
}
