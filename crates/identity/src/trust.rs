//! Replay-only identity facts. Signatures bind the federation, genesis and exact log parent.
use crate::{Error, Identity, PeerId, PublicKey, Result};
use std::collections::{BTreeMap, BTreeSet};
use wire::protocol::{MAX_TRUST_RECORD, TRUST_SIGNING_DOMAIN, digest};
pub use wire::protocol::{
    TrustAction, TrustCheckpoint, TrustFounder, TrustGenesis, TrustRecord, TrustSignature,
};
const MAX_CHAIRS: usize = 128;
const MAX_DEVICES: usize = 8;
const MAX_EVIDENCE_TYPES: usize = 128;
const MAX_FACTS: usize = 100_000;

use wire::protocol::validate_identifier as identifier;
fn json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| Error::Protocol(e.to_string()))
}
fn key(bytes: &[u8]) -> Result<PublicKey> {
    if bytes.len() > 128 {
        return Err(Error::Denied);
    }
    let key = PublicKey::try_decode_protobuf(bytes).map_err(|_| Error::Denied)?;
    if key.clone().try_into_ed25519().is_err() {
        return Err(Error::Denied);
    }
    Ok(key)
}
/// Validate chair-count and distinct-member majority rules for governance and terminal previews.
pub fn validate_chairs(chairs: &BTreeMap<String, String>, quorum: usize) -> Result<()> {
    let voters: BTreeSet<_> = chairs.values().collect();
    if chairs.is_empty()
        || chairs.len() > MAX_CHAIRS
        || quorum <= voters.len() / 2
        || quorum > voters.len()
    {
        return Err(Error::Denied);
    }
    Ok(())
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct Verifier {
    pub club: String,
    pub device: String,
    pub evidence: BTreeSet<String>,
    pub revoked: bool,
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct Service {
    pub audience: String,
    pub club: String,
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct Permission {
    pub member: String,
    pub service: String,
    pub permission: String,
    pub revoked: bool,
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct Succession {
    pub chairs: BTreeMap<String, String>,
    pub quorum: usize,
    pub epoch: u64,
    pub approvals: BTreeSet<String>,
    pub accepted: BTreeSet<String>,
    pub closed: bool,
}
/// Construct only from a pinned genesis followed by verified records, never a remote snapshot.
#[derive(Clone, Debug, serde::Serialize)]
pub struct TrustState {
    federation: String,
    checkpoint: TrustCheckpoint,
    members: BTreeMap<String, BTreeSet<String>>,
    devices: BTreeMap<String, String>,
    revoked_devices: BTreeSet<String>,
    memberships: BTreeSet<(String, String)>,
    revoked_memberships: BTreeSet<(String, String)>,
    profiles: BTreeMap<String, String>,
    chair_epoch: u64,
    successions: BTreeMap<String, Succession>,
    chairs: BTreeMap<String, String>,
    quorum: usize,
    verifiers: BTreeMap<String, Verifier>,
    services: BTreeMap<String, Service>,
    permissions: BTreeMap<String, Permission>,
}
impl TrustState {
    pub fn new(genesis: &TrustGenesis, pinned: &str) -> Result<Self> {
        identifier(&genesis.federation)?;
        if genesis.founders.is_empty() || genesis.founders.len() > MAX_CHAIRS {
            return Err(Error::Capacity);
        }
        let hash = digest(&json(genesis)?);
        if hash != pinned {
            return Err(Error::Denied);
        }
        let mut state = Self {
            federation: genesis.federation.clone(),
            checkpoint: TrustCheckpoint {
                genesis: hash.clone(),
                sequence: 0,
                head: hash,
            },
            members: BTreeMap::new(),
            devices: BTreeMap::new(),
            revoked_devices: BTreeSet::new(),
            memberships: BTreeSet::new(),
            revoked_memberships: BTreeSet::new(),
            chairs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            chair_epoch: 0,
            successions: BTreeMap::new(),
            quorum: genesis.quorum,
            verifiers: BTreeMap::new(),
            services: BTreeMap::new(),
            permissions: BTreeMap::new(),
        };
        for founder in &genesis.founders {
            identifier(&founder.member)?;
            identifier(&founder.club)?;
            let device = key(&founder.public_key)?.to_peer_id().to_string();
            if state
                .chairs
                .insert(founder.club.clone(), founder.member.clone())
                .is_some()
            {
                return Err(Error::Denied);
            }
            state.bind(&founder.member, &device)?;
            state
                .memberships
                .insert((founder.member.clone(), founder.club.clone()));
        }
        validate_chairs(&state.chairs, state.quorum)?;
        Ok(state)
    }
    pub fn genesis_digest(genesis: &TrustGenesis) -> Result<String> {
        Ok(digest(&json(genesis)?))
    }
    pub fn checkpoint(&self) -> &TrustCheckpoint {
        &self.checkpoint
    }
    pub fn member_for_device(&self, device: &str) -> Option<&str> {
        if self.revoked_devices.contains(device) {
            return None;
        }
        self.devices.get(device).map(String::as_str)
    }
    pub fn is_member(&self, member: &str, club: &str) -> bool {
        self.memberships.contains(&(member.into(), club.into()))
    }
    pub fn clubs(&self, member: &str) -> BTreeSet<String> {
        self.memberships
            .iter()
            .filter(|(m, _)| m == member)
            .map(|(_, c)| c.clone())
            .collect()
    }
    pub fn profile(&self, member: &str) -> Option<&str> {
        self.profiles.get(member).map(String::as_str)
    }
    pub fn members(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.members
    }
    pub fn chairs(&self) -> &BTreeMap<String, String> {
        &self.chairs
    }
    pub fn permits(&self, device: &str, audience: &str, service: &str, permission: &str) -> bool {
        let Some(member) = self.member_for_device(device) else {
            return false;
        };
        self.services
            .get(service)
            .is_some_and(|s| s.audience == audience)
            && self.permissions.values().any(|p| {
                !p.revoked
                    && p.member == member
                    && p.service == service
                    && p.permission == permission
            })
    }
    pub fn draft(&self, action: TrustAction) -> TrustRecord {
        TrustRecord {
            federation: self.federation.clone(),
            genesis: self.checkpoint.genesis.clone(),
            sequence: self.checkpoint.sequence + 1,
            previous: self.checkpoint.head.clone(),
            action,
            signatures: Vec::new(),
        }
    }
    pub fn apply(&mut self, record: &TrustRecord) -> Result<()> {
        if json(record)?.len() > MAX_TRUST_RECORD
            || record.federation != self.federation
            || record.genesis != self.checkpoint.genesis
            || record.previous != self.checkpoint.head
            || Some(record.sequence) != self.checkpoint.sequence.checked_add(1)
        {
            return Err(Error::Denied);
        }
        let signers = verify_signatures(record)?;
        let mut next = self.clone();
        next.transition(&record.action, &signers)?;
        next.checkpoint.sequence = record.sequence;
        next.checkpoint.head = digest(&json(record)?);
        *self = next;
        Ok(())
    }
    fn bind(&mut self, member: &str, device: &str) -> Result<()> {
        identifier(member)?;
        device.parse::<PeerId>().map_err(|_| Error::Denied)?;
        if self.revoked_devices.contains(device)
            || self.devices.get(device).is_some_and(|m| m != member)
        {
            return Err(Error::Denied);
        }
        if self.members.len() >= MAX_FACTS && !self.members.contains_key(member) {
            return Err(Error::Capacity);
        }
        let devices = self.members.entry(member.into()).or_default();
        if devices.len() >= MAX_DEVICES && !devices.contains(device) {
            return Err(Error::Capacity);
        }
        devices.insert(device.into());
        self.devices.insert(device.into(), member.into());
        Ok(())
    }
    fn signed_member(&self, member: &str, signers: &BTreeSet<String>) -> bool {
        signers
            .iter()
            .any(|d| self.member_for_device(d) == Some(member))
    }
    fn chair(&self, club: &str, signers: &BTreeSet<String>) -> bool {
        self.chairs
            .get(club)
            .is_some_and(|m| self.signed_member(m, signers))
    }
    fn majority(&self, signers: &BTreeSet<String>) -> bool {
        self.chairs
            .values()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|m| self.signed_member(m, signers))
            .count()
            >= self.quorum
    }
    fn recovery(&self, _member: &str, signers: &BTreeSet<String>) -> bool {
        // A club chair must not seize a global identity and inherit permissions granted by other clubs.
        self.majority(signers)
    }
    fn transition(&mut self, action: &TrustAction, signers: &BTreeSet<String>) -> Result<()> {
        // Revoked keys cannot participate even as an extra signature.
        if signers.iter().any(|d| self.revoked_devices.contains(d)) {
            return Err(Error::Denied);
        }
        match action {
            TrustAction::ConfirmMember {
                member,
                club,
                device,
                evidence,
                verifier,
            } => {
                identifier(member)?;
                identifier(club)?;
                identifier(evidence)?;
                let manual = self.chair(club, signers);
                let automated = verifier
                    .as_ref()
                    .and_then(|id| self.verifiers.get(id))
                    .is_some_and(|v| {
                        !v.revoked
                            && v.club == *club
                            && v.evidence.contains(evidence)
                            && signers.contains(&v.device)
                            && !self.revoked_devices.contains(&v.device)
                    });
                let membership = (member.clone(), club.clone());
                if !manual && (!automated || self.revoked_memberships.contains(&membership)) {
                    return Err(Error::Denied);
                }
                if let Some(device) = device {
                    if !signers.contains(device) {
                        return Err(Error::Denied);
                    }
                    // An attestor cannot append its own key to somebody else's existing identity.
                    if self.members.contains_key(member) && !self.signed_member(member, signers) {
                        return Err(Error::Denied);
                    }
                    self.bind(member, device)?;
                } else if !self.members.contains_key(member) {
                    return Err(Error::Denied);
                }
                if self.memberships.len() >= MAX_FACTS {
                    return Err(Error::Capacity);
                }
                self.memberships.insert(membership.clone());
                self.revoked_memberships.remove(&membership);
            }
            TrustAction::RevokeMembership { member, club } => {
                if !self.chair(club, signers)
                    || !self.memberships.remove(&(member.clone(), club.clone()))
                {
                    return Err(Error::Denied);
                }
                self.revoked_memberships
                    .insert((member.clone(), club.clone()));
            }
            TrustAction::BindGameProfile {
                member,
                club,
                profile,
            } => {
                if !(self.chair(club, signers)
                    || self.verifiers.values().any(|v| {
                        !v.revoked
                            && v.club == *club
                            && v.evidence.contains("game_profile")
                            && signers.contains(&v.device)
                            && !self.revoked_devices.contains(&v.device)
                    }))
                    || !self.signed_member(member, signers)
                    || !self.is_member(member, club)
                    || wire::protocol::validate_game_profile(profile).is_err()
                    || self
                        .profiles
                        .iter()
                        .any(|(m, p)| m != member && p == profile)
                {
                    return Err(Error::Denied);
                }
                self.profiles.insert(member.clone(), profile.clone());
            }
            TrustAction::BindDevice { member, device } => {
                if !self.members.contains_key(member)
                    || !signers.contains(device)
                    || !(self.signed_member(member, signers) || self.recovery(member, signers))
                {
                    return Err(Error::Denied);
                }
                self.bind(member, device)?;
            }
            TrustAction::RevokeDevice { member, device } => {
                if self.member_for_device(device) != Some(member)
                    || !(self.signed_member(member, signers) || self.recovery(member, signers))
                {
                    return Err(Error::Denied);
                }
                // A chair remains in office even with no usable device; quorum recovery is separate.
                self.members
                    .get_mut(member)
                    .ok_or(Error::Denied)?
                    .remove(device);
                self.revoked_devices.insert(device.clone());
            }
            TrustAction::ProposeSuccession { id, chairs, quorum } => {
                identifier(id)?;
                validate_chairs(chairs, *quorum)?;
                if !self.chairs.values().any(|m| self.signed_member(m, signers))
                    || self.successions.contains_key(id)
                    || self.successions.len() >= MAX_FACTS
                {
                    return Err(Error::Denied);
                }
                for (club, member) in chairs {
                    identifier(club)?;
                    if self.members.get(member).is_none_or(BTreeSet::is_empty) {
                        return Err(Error::Denied);
                    }
                }
                self.successions.insert(
                    id.clone(),
                    Succession {
                        chairs: chairs.clone(),
                        quorum: *quorum,
                        epoch: self.chair_epoch,
                        approvals: BTreeSet::new(),
                        accepted: BTreeSet::new(),
                        closed: false,
                    },
                );
            }
            TrustAction::ApproveSuccession { id } => {
                let proposal = self.successions.get(id).ok_or(Error::NotFound)?;
                if proposal.closed || proposal.epoch != self.chair_epoch {
                    return Err(Error::Denied);
                }
                let approvals: BTreeSet<_> = self
                    .chairs
                    .values()
                    .filter(|m| self.signed_member(m, signers))
                    .cloned()
                    .collect();
                let accepted: BTreeSet<_> = proposal
                    .chairs
                    .values()
                    .filter(|m| self.signed_member(m, signers))
                    .cloned()
                    .collect();
                if approvals.is_empty() && accepted.is_empty() {
                    return Err(Error::Denied);
                }
                let proposal = self.successions.get_mut(id).ok_or(Error::NotFound)?;
                proposal.approvals.extend(approvals);
                proposal.accepted.extend(accepted);
            }
            TrustAction::ExecuteSuccession { id } => {
                let proposal = self.successions.get(id).ok_or(Error::NotFound)?;
                if proposal.closed
                    || proposal.epoch != self.chair_epoch
                    || proposal.approvals.len() < self.quorum
                    || !self.chairs.values().any(|m| self.signed_member(m, signers))
                {
                    return Err(Error::Denied);
                }
                for (club, member) in &proposal.chairs {
                    if self.members.get(member).is_none_or(BTreeSet::is_empty)
                        || (self.chairs.get(club) != Some(member)
                            && !proposal.accepted.contains(member))
                    {
                        return Err(Error::Denied);
                    }
                }
                self.chairs = proposal.chairs.clone();
                self.quorum = proposal.quorum;
                self.chair_epoch = self.chair_epoch.checked_add(1).ok_or(Error::Capacity)?;
                self.successions.get_mut(id).ok_or(Error::NotFound)?.closed = true;
            }
            TrustAction::CancelSuccession { id } => {
                if !self.majority(signers) {
                    return Err(Error::Denied);
                }
                let proposal = self.successions.get_mut(id).ok_or(Error::NotFound)?;
                if proposal.epoch != self.chair_epoch || proposal.closed {
                    return Err(Error::Denied);
                }
                proposal.closed = true;
            }
            TrustAction::ReplaceChairs { chairs, quorum } => {
                if !self.majority(signers) {
                    return Err(Error::Denied);
                }
                validate_chairs(chairs, *quorum)?;
                for (club, member) in chairs {
                    identifier(club)?;
                    if self.members.get(member).is_none_or(BTreeSet::is_empty) {
                        return Err(Error::Denied);
                    }
                    if self.chairs.get(club) != Some(member) && !self.signed_member(member, signers)
                    {
                        return Err(Error::Denied);
                    }
                }
                self.chairs = chairs.clone();
                self.quorum = *quorum;
                self.chair_epoch = self.chair_epoch.checked_add(1).ok_or(Error::Capacity)?;
            }
            TrustAction::AuthorizeVerifier {
                id,
                club,
                device,
                evidence,
            } => {
                identifier(id)?;
                device.parse::<PeerId>().map_err(|_| Error::Denied)?;
                if !self.chair(club, signers)
                    || evidence.is_empty()
                    || evidence.len() > MAX_EVIDENCE_TYPES
                    || self.verifiers.contains_key(id)
                    || self.verifiers.len() >= MAX_FACTS
                    || self.revoked_devices.contains(device)
                {
                    return Err(Error::Denied);
                }
                for e in evidence {
                    identifier(e)?;
                }
                self.verifiers.insert(
                    id.clone(),
                    Verifier {
                        club: club.clone(),
                        device: device.clone(),
                        evidence: evidence.clone(),
                        revoked: false,
                    },
                );
            }
            TrustAction::RevokeVerifier { id } => {
                let v = self.verifiers.get(id).ok_or(Error::NotFound)?;
                if !self.chair(&v.club, signers) {
                    return Err(Error::Denied);
                }
                self.verifiers.get_mut(id).ok_or(Error::NotFound)?.revoked = true;
            }
            TrustAction::RegisterService {
                service,
                audience,
                club,
            } => {
                identifier(service)?;
                audience.parse::<PeerId>().map_err(|_| Error::Denied)?;
                if !self.chair(club, signers)
                    || !signers.contains(audience)
                    || self.services.contains_key(service)
                    || self.services.len() >= MAX_FACTS
                {
                    return Err(Error::Denied);
                }
                self.services.insert(
                    service.clone(),
                    Service {
                        audience: audience.clone(),
                        club: club.clone(),
                    },
                );
            }
            TrustAction::GrantPermission {
                id,
                member,
                service,
                permission,
            } => {
                identifier(id)?;
                identifier(permission)?;
                let s = self.services.get(service).ok_or(Error::NotFound)?;
                if !self.chair(&s.club, signers)
                    || !self.members.contains_key(member)
                    || self.permissions.contains_key(id)
                    || self.permissions.len() >= MAX_FACTS
                {
                    return Err(Error::Denied);
                }
                self.permissions.insert(
                    id.clone(),
                    Permission {
                        member: member.clone(),
                        service: service.clone(),
                        permission: permission.clone(),
                        revoked: false,
                    },
                );
            }
            TrustAction::RevokePermission { id } => {
                let p = self.permissions.get(id).ok_or(Error::NotFound)?;
                let s = self.services.get(&p.service).ok_or(Error::NotFound)?;
                if !self.chair(&s.club, signers) {
                    return Err(Error::Denied);
                }
                self.permissions.get_mut(id).ok_or(Error::NotFound)?.revoked = true;
            }
        }
        Ok(())
    }
}
fn signing_bytes(record: &TrustRecord) -> Result<Vec<u8>> {
    let mut unsigned = record.clone();
    unsigned.signatures.clear();
    Ok([TRUST_SIGNING_DOMAIN, &json(&unsigned)?].concat())
}
pub fn sign(record: &mut TrustRecord, identity: &Identity) -> Result<()> {
    let public_key = identity.public_key().encode_protobuf();
    if record.signatures.iter().any(|s| s.public_key == public_key) {
        return Err(Error::Denied);
    }
    let signature = identity.sign(&signing_bytes(record)?)?;
    record.signatures.push(TrustSignature {
        public_key,
        signature,
    });
    record
        .signatures
        .sort_by(|a, b| a.public_key.cmp(&b.public_key));
    Ok(())
}
pub fn verify_signatures(record: &TrustRecord) -> Result<BTreeSet<String>> {
    if record.signatures.is_empty()
        || record.signatures.len() > MAX_CHAIRS + MAX_DEVICES
        || json(record)?.len() > MAX_TRUST_RECORD
    {
        return Err(Error::Denied);
    }
    let bytes = signing_bytes(record)?;
    let mut signers = BTreeSet::new();
    let mut previous = None;
    for signature in &record.signatures {
        if previous.is_some_and(|p| p >= &signature.public_key) {
            return Err(Error::Denied);
        }
        previous = Some(&signature.public_key);
        let key = key(&signature.public_key)?;
        if !key.verify(&bytes, &signature.signature)
            || !signers.insert(key.to_peer_id().to_string())
        {
            return Err(Error::Denied);
        }
    }
    Ok(signers)
}
