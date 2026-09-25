#![allow(dead_code)]
use authority::protocol::{TrustAction, TrustBusinessBinding, TrustFounder, TrustGenesis};
use authority::{
    journal::{Command, Journal, SignedCommand, TrustedCommand},
    trust::TrustLog,
};
use identity::{Identity, trust};
use state::{Domain, State, governance::Action};
use std::collections::BTreeMap;

pub struct Identities {
    pub log: TrustLog,
    pub binding: TrustBusinessBinding,
    roots: BTreeMap<String, Identity>,
    _dir: tempfile::TempDir,
}
impl Identities {
    pub fn new(members: &[(&Identity, &str, &str)], admin: &str) -> Self {
        let roots: BTreeMap<_, _> = members
            .iter()
            .map(|(_, _, club)| (club.to_string(), Identity::generate()))
            .collect();
        let genesis = TrustGenesis {
            federation: "test-federation".into(),
            quorum: roots.len(),
            founders: roots
                .iter()
                .map(|(club, key)| TrustFounder {
                    member: format!("chair-{club}"),
                    club: club.clone(),
                    public_key: key.public_key().encode_protobuf(),
                })
                .collect(),
        };
        let pin = trust::TrustState::genesis_digest(&genesis).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log = TrustLog::open(&dir.path().join("identity"), &genesis, &pin).unwrap();
        let host = members[0].0;
        let binding = TrustBusinessBinding {
            genesis: pin,
            namespace: "business".into(),
            audience: host.peer_id().to_string(),
            service: "business".into(),
            club: members[0].2.into(),
        };
        let mut result = Self {
            log,
            binding,
            roots,
            _dir: dir,
        };
        for (key, member, club) in members {
            let root = result.roots[*club].clone();
            result.append(
                TrustAction::ConfirmMember {
                    member: (*member).into(),
                    club: (*club).into(),
                    device: Some(key.peer_id().to_string()),
                    evidence: "manual".into(),
                    verifier: None,
                },
                &[&root, key],
            );
        }
        let root = result.roots[members[0].2].clone();
        result.append(
            TrustAction::RegisterService {
                service: result.binding.service.clone(),
                audience: result.binding.audience.clone(),
                club: result.binding.club.clone(),
            },
            &[&root, host],
        );
        for (_, member, _) in members {
            result.append(
                TrustAction::GrantPermission {
                    id: format!("permission-{member}"),
                    member: (*member).into(),
                    service: result.binding.service.clone(),
                    permission: if *member == admin { "admin" } else { "write" }.into(),
                },
                &[&root],
            );
        }
        result.log.mark_current().unwrap();
        result
    }
    pub fn append(&mut self, action: TrustAction, keys: &[&Identity]) {
        let mut record = self.log.state().draft(action);
        for key in keys {
            trust::sign(&mut record, key).unwrap();
        }
        self.log.append(record).unwrap();
    }
    pub fn root(&self, club: &str) -> Identity {
        self.roots[club].clone()
    }
    pub fn service(&mut self, host: &Identity, service: &str, member: &str, permission: &str) {
        let root = self.root(&self.binding.club);
        self.append(
            TrustAction::RegisterService {
                service: service.into(),
                audience: host.peer_id().to_string(),
                club: self.binding.club.clone(),
            },
            &[&root, host],
        );
        self.append(
            TrustAction::GrantPermission {
                id: format!("{service}-{member}"),
                member: member.into(),
                service: service.into(),
                permission: permission.into(),
            },
            &[&root],
        );
        self.log.mark_current().unwrap();
    }
    pub fn genesis<D: Domain>(&self) -> State<D> {
        State::new(self.binding.clone()).unwrap()
    }
    pub fn run<D: Domain>(
        &self,
        journal: &mut Journal<D>,
        key: &Identity,
        now: u64,
        action: Action<D>,
    ) -> authority::Result<()> {
        let command = SignedCommand::sign(
            key,
            TrustedCommand {
                genesis: journal.genesis_hash().into(),
                previous: journal.head()?,
                identity: self.log.state().checkpoint().clone(),
                command: Command {
                    revision: journal.state().revision,
                    expires_ms: now + 60_000,
                    action,
                },
            },
        )?;
        journal.execute(
            command,
            self.log.history_since(journal.identity_checkpoint())?,
            self.log.state(),
            now,
        )
    }
}

/// Domain tests use the same verified identity facts as the network handlers.
#[derive(Clone, Debug)]
pub struct Scenario<D: Domain> {
    state: State<D>,
    trust: trust::TrustState,
}
impl<D: Domain> std::ops::Deref for Scenario<D> {
    type Target = State<D>;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}
impl<D: Domain> std::ops::DerefMut for Scenario<D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}
impl<D: Domain> PartialEq for Scenario<D> {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}
impl<D: Domain> Scenario<D> {
    pub fn new(members: &[(&Identity, &str, &str)], admin: &str) -> Self {
        let identities = Identities::new(members, admin);
        let mut state: State<D> = identities.genesis();
        state.core = state.identity_core(identities.log.state()).unwrap();
        Self {
            state,
            trust: identities.log.state().clone(),
        }
    }
    pub fn apply(
        &mut self,
        actor: &str,
        revision: u64,
        now: u64,
        action: Action<D>,
    ) -> authority::Result<()> {
        self.state.apply(actor, revision, now, action, &self.trust)
    }
}
