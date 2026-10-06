//! Authoritative domain-neutral governance state machine. Hosting resources do not confer authority.
//! All external effects (routing, game plugins, notifications) consume this state.
pub use crate::State;
pub use crate::protocol::digest;
use crate::{Context, Domain, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusPeer {
    pub peer: String,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub club: String,
    pub device: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub additional_devices: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub roles: BTreeSet<String>,
}
impl Member {
    pub fn owns(&self, device: &str) -> bool {
        self.device == device || self.additional_devices.contains(device)
    }
    pub fn devices(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.device).chain(self.additional_devices.iter())
    }
}

/// An immutable, governance-authorized commitment to off-chain canonical bytes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DigestAnchor {
    pub digest: String,
    pub actor: String,
    pub time_ms: u64,
}
const MAX_DIGEST_ANCHORS: usize = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "")]
pub struct CoreState {
    pub identity: crate::protocol::TrustBusinessBinding,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub digest_anchors: BTreeMap<String, DigestAnchor>,
    pub revision: u64,
    pub admins: BTreeSet<String>,
    pub members: BTreeMap<String, Member>,
    pub clock_ms: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "consensus_map")]
    pub consensus_members: BTreeMap<u64, ConsensusPeer>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub retired_consensus_ids: BTreeSet<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(bound = "")]
pub enum Action<D: Domain> {
    AnchorDigest {
        id: String,
        digest: String,
    },
    SetConsensusMembers {
        #[serde(deserialize_with = "consensus_map")]
        members: BTreeMap<u64, ConsensusPeer>,
    },
    SetMemberRoles {
        member: String,
        roles: BTreeSet<String>,
    },
    #[serde(untagged)]
    Domain(D::Action),
}
/// Shared structural validation for domain roles; authority checks remain in apply.
pub fn validate_member_roles(roles: &BTreeSet<String>) -> Result<()> {
    const MAX_MEMBER_ROLES: usize = 16;
    if roles.len() > MAX_MEMBER_ROLES {
        return Err(Error::Capacity);
    }
    for role in roles {
        identifier(role)?;
    }
    Ok(())
}

fn invalid(message: &str) -> Error {
    Error::Protocol(message.into())
}
pub use wire::protocol::validate_identifier as identifier;

/// Node IDs and authenticated transport identities are explicit, never inferred from addresses.
pub fn validate_consensus_members(peers: &BTreeMap<u64, ConsensusPeer>) -> Result<()> {
    if !matches!(peers.len(), 1 | 3 | 5 | 7) {
        return Err(Error::Denied);
    }
    let mut unique = BTreeSet::new();
    for (id, peer) in peers {
        let parsed: crate::PeerId = peer.peer.parse().map_err(|_| Error::Denied)?;
        if *id == 0
            || !unique.insert(parsed)
            || peer.addresses.is_empty()
            || peer.addresses.len() > 8
        {
            return Err(Error::Denied);
        }
        for address in &peer.addresses {
            if address.len() > 2048 {
                return Err(Error::Capacity);
            }
            let addr: crate::Multiaddr = address.parse().map_err(|_| Error::Denied)?;
            if !matches!(addr.iter().last(), Some(crate::AddressProtocol::P2p(p)) if p == parsed) {
                return Err(Error::Denied);
            }
        }
    }
    Ok(())
}

fn consensus_map<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<u64, ConsensusPeer>, D::Error> {
    let values = BTreeMap::<String, ConsensusPeer>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|(key, value)| {
            let id: u64 = key.parse().map_err(serde::de::Error::custom)?;
            if id.to_string() != key {
                return Err(serde::de::Error::custom("noncanonical node id"));
            }
            Ok((id, value))
        })
        .collect()
}

fn validate_binding(binding: &crate::protocol::TrustBusinessBinding) -> Result<()> {
    identifier(&binding.namespace)?;
    identifier(&binding.service)?;
    identifier(&binding.club)?;
    binding
        .audience
        .parse::<crate::PeerId>()
        .map_err(|_| Error::Denied)?;
    crate::protocol::validate_digest(&binding.genesis)
}
impl<D: Domain> State<D> {
    pub fn new(binding: crate::protocol::TrustBusinessBinding) -> Result<Self> {
        validate_binding(&binding)?;
        Ok(Self {
            core: CoreState {
                identity: binding,
                digest_anchors: BTreeMap::new(),
                revision: 0,
                admins: BTreeSet::new(),
                members: BTreeMap::new(),
                clock_ms: 0,
                consensus_members: BTreeMap::new(),
                retired_consensus_ids: BTreeSet::new(),
            },
            domain: D::State::default(),
        })
    }
    /// Derive devices and qualifications from the unified identity log; retain only business roles.
    pub fn identity_core(&self, trust: &identity::trust::TrustState) -> Result<CoreState> {
        let binding = &self.core.identity;
        if trust.checkpoint().genesis != binding.genesis {
            return Err(Error::Denied);
        }
        let mut core = self.core.clone();
        core.admins.clear();
        core.members.clear();
        for (id, devices) in trust.members() {
            let clubs = trust.clubs(id);
            let Some(club) = clubs.first() else {
                continue;
            };
            core.members.insert(
                id.clone(),
                Member {
                    club: club.clone(),
                    device: devices.first().cloned().unwrap_or_default(),
                    additional_devices: devices.iter().skip(1).cloned().collect(),
                    roles: self
                        .core
                        .members
                        .get(id)
                        .map(|m| m.roles.clone())
                        .unwrap_or_default(),
                },
            );
            for device in devices {
                if trust.permits(device, &binding.audience, &binding.service, "admin") {
                    core.admins.insert(device.clone());
                }
            }
        }
        Ok(core)
    }
    pub fn can_read(&self, actor: &str, trust: &identity::trust::TrustState) -> bool {
        let binding = &self.core.identity;
        let Some(member) = trust.member_for_device(actor) else {
            return false;
        };
        !trust.clubs(member).is_empty()
            && ["read", "write", "admin"].iter().any(|permission| {
                trust.permits(actor, &binding.audience, &binding.service, permission)
            })
    }
    pub fn can_write(&self, actor: &str, trust: &identity::trust::TrustState) -> bool {
        self.can_read(actor, trust) && {
            let binding = &self.core.identity;
            ["write", "admin"]
                .iter()
                .any(|p| trust.permits(actor, &binding.audience, &binding.service, p))
        }
    }
    pub fn apply(
        &mut self,
        actor: &str,
        revision: u64,
        now_ms: u64,
        action: Action<D>,
        trust: &identity::trust::TrustState,
    ) -> Result<()> {
        let binding = &self.core.identity;
        if !self.can_read(actor, trust)
            || !["write", "admin"]
                .iter()
                .any(|p| trust.permits(actor, &binding.audience, &binding.service, p))
            || revision != self.core.revision
            || now_ms < self.core.clock_ms
        {
            return Err(Error::Denied);
        }
        let core = self.identity_core(trust)?;
        let admin = core.admins.contains(actor);
        let mut next = self.clone();
        match action {
            Action::Domain(action) => D::transition(
                &mut next.domain,
                &Context {
                    actor,
                    now_ms,
                    revision,
                    core: core.view(),
                    approved: false,
                },
                action,
            )?,
            Action::SetConsensusMembers { members } if admin => {
                validate_consensus_members(&members)?;
                for (id, peer) in &members {
                    if self.core.retired_consensus_ids.contains(id)
                        || self
                            .core
                            .consensus_members
                            .get(id)
                            .is_some_and(|old| old.peer != peer.peer)
                    {
                        return Err(Error::Denied);
                    }
                }
                next.core.retired_consensus_ids.extend(
                    self.core
                        .consensus_members
                        .keys()
                        .filter(|id| !members.contains_key(id))
                        .copied(),
                );
                next.core.consensus_members = members;
            }
            Action::SetMemberRoles { member, roles } if admin => {
                validate_member_roles(&roles)?;
                let mut m = core.members.get(&member).ok_or(Error::NotFound)?.clone();
                m.roles = roles;
                next.core.members.insert(member, m);
            }
            Action::AnchorDigest { id, digest } if admin => {
                identifier(&id)?;
                crate::protocol::validate_digest(&digest)?;
                if next.core.digest_anchors.contains_key(&id)
                    || next.core.digest_anchors.len() >= MAX_DIGEST_ANCHORS
                {
                    return Err(Error::Denied);
                }
                next.core.digest_anchors.insert(
                    id,
                    DigestAnchor {
                        digest,
                        actor: actor.into(),
                        time_ms: now_ms,
                    },
                );
            }
            _ => {
                return Err(invalid(
                    "identity, device and governance changes belong in the unified identity log",
                ));
            }
        }
        next.core.revision = revision.checked_add(1).ok_or(Error::Capacity)?;
        next.core.clock_ms = now_ms;
        *self = next;
        Ok(())
    }
}

/// Presentation derived from locally verified identity facts, separate from the signed business snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPresentation {
    pub members: BTreeMap<String, Member>,
    pub admins: BTreeSet<String>,
}
impl<D: Domain> State<D> {
    pub fn identity_presentation(
        &self,
        trust: &identity::trust::TrustState,
    ) -> Result<IdentityPresentation> {
        let core = self.identity_core(trust)?;
        Ok(IdentityPresentation {
            members: core.members,
            admins: core.admins,
        })
    }
}
