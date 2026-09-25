use identity::{
    Identity,
    trust::{self, TrustState},
};
use journal::trust::TrustLog;
use std::{collections::BTreeMap, time::Duration};
use wire::protocol::*;
struct Fixture {
    roots: Vec<Identity>,
    genesis: TrustGenesis,
    state: TrustState,
}
impl Fixture {
    fn new() -> Self {
        let roots: Vec<_> = (0..3).map(|_| Identity::generate()).collect();
        let genesis = TrustGenesis {
            federation: "test-federation".into(),
            quorum: 2,
            founders: roots
                .iter()
                .enumerate()
                .map(|(i, k)| TrustFounder {
                    member: format!("founder-{i}"),
                    club: format!("club-{i}"),
                    public_key: k.public_key().encode_protobuf(),
                })
                .collect(),
        };
        let state =
            TrustState::new(&genesis, &TrustState::genesis_digest(&genesis).unwrap()).unwrap();
        Self {
            roots,
            genesis,
            state,
        }
    }
    fn record(&self, action: TrustAction, keys: &[&Identity]) -> TrustRecord {
        let mut r = self.state.draft(action);
        for k in keys {
            trust::sign(&mut r, k).unwrap();
        }
        r
    }
    fn member(&mut self, id: &str, key: &Identity) {
        let r = self.record(
            TrustAction::ConfirmMember {
                member: id.into(),
                club: "club-0".into(),
                device: Some(key.peer_id().to_string()),
                evidence: "manual".into(),
                verifier: None,
            },
            &[&self.roots[0], key],
        );
        self.state.apply(&r).unwrap();
    }
}
#[test]
fn stable_identity_separate_membership_permissions_and_chair_authority() {
    let mut f = Fixture::new();
    let old = Identity::generate();
    let new = Identity::generate();
    let host = Identity::generate();
    f.member("member-a", &old);
    let r = f.record(
        TrustAction::RegisterService {
            service: "ops".into(),
            audience: host.peer_id().to_string(),
            club: "club-0".into(),
        },
        &[&f.roots[0], &host],
    );
    f.state.apply(&r).unwrap();
    let r = f.record(
        TrustAction::GrantPermission {
            id: "admin-a".into(),
            member: "member-a".into(),
            service: "ops".into(),
            permission: "manage".into(),
        },
        &[&f.roots[0]],
    );
    f.state.apply(&r).unwrap();
    let r = f.record(
        TrustAction::BindDevice {
            member: "member-a".into(),
            device: new.peer_id().to_string(),
        },
        &[&old, &new],
    );
    f.state.apply(&r).unwrap();
    let r = f.record(
        TrustAction::RevokeDevice {
            member: "member-a".into(),
            device: old.peer_id().to_string(),
        },
        &[&new],
    );
    f.state.apply(&r).unwrap();
    assert_eq!(
        f.state.member_for_device(&new.peer_id().to_string()),
        Some("member-a")
    );
    assert_eq!(f.state.member_for_device(&old.peer_id().to_string()), None);
    assert!(f.state.permits(
        &new.peer_id().to_string(),
        &host.peer_id().to_string(),
        "ops",
        "manage"
    ));
    let r = f.record(
        TrustAction::RevokeMembership {
            member: "member-a".into(),
            club: "club-0".into(),
        },
        &[&f.roots[0]],
    );
    f.state.apply(&r).unwrap();
    assert!(f.state.permits(
        &new.peer_id().to_string(),
        &host.peer_id().to_string(),
        "ops",
        "manage"
    ));
    let r = f.record(
        TrustAction::RevokePermission {
            id: "admin-a".into(),
        },
        &[&f.roots[0]],
    );
    f.state.apply(&r).unwrap();
    assert!(!f.state.permits(
        &new.peer_id().to_string(),
        &host.peer_id().to_string(),
        "ops",
        "manage"
    ));
    assert_eq!(
        f.state.member_for_device(&new.peer_id().to_string()),
        Some("member-a")
    );
    let r = f.record(
        TrustAction::RevokeMembership {
            member: "founder-0".into(),
            club: "club-0".into(),
        },
        &[&f.roots[0]],
    );
    f.state.apply(&r).unwrap();
    assert_eq!(f.state.chairs()["club-0"], "founder-0");
    let chairs: BTreeMap<_, _> = [
        ("club-0".into(), "member-a".into()),
        ("club-1".into(), "founder-1".into()),
        ("club-2".into(), "founder-2".into()),
    ]
    .into();
    let action = TrustAction::ReplaceChairs { chairs, quorum: 2 };
    let r = f.record(action.clone(), &[&f.roots[0], &new]);
    assert!(f.state.apply(&r).is_err());
    let r = f.record(action, &[&f.roots[0], &f.roots[1], &new]);
    f.state.apply(&r).unwrap();
    assert_eq!(f.state.chairs()["club-0"], "member-a");
}
#[test]
fn signatures_bind_history_and_automatic_verifier_cannot_restore_revoked_membership() {
    let mut f = Fixture::new();
    let verifier = Identity::generate();
    let member = Identity::generate();
    let r = f.record(
        TrustAction::AuthorizeVerifier {
            id: "skin".into(),
            club: "club-0".into(),
            device: verifier.peer_id().to_string(),
            evidence: ["email".into()].into(),
        },
        &[&f.roots[0]],
    );
    f.state.apply(&r).unwrap();
    let action = TrustAction::ConfirmMember {
        member: "person".into(),
        club: "club-0".into(),
        device: Some(member.peer_id().to_string()),
        evidence: "email".into(),
        verifier: Some("skin".into()),
    };
    let r = f.record(action.clone(), &[&verifier, &member]);
    let mut altered = r.clone();
    altered.federation = "other".into();
    assert!(f.state.apply(&altered).is_err());
    let mut altered = r.clone();
    altered.previous = "0".repeat(64);
    assert!(f.state.apply(&altered).is_err());
    f.state.apply(&r).unwrap();
    assert!(f.state.apply(&r).is_err());
    let r = f.record(
        TrustAction::RevokeMembership {
            member: "person".into(),
            club: "club-0".into(),
        },
        &[&f.roots[0]],
    );
    f.state.apply(&r).unwrap();
    let r = f.record(action.clone(), &[&verifier, &member]);
    assert!(f.state.apply(&r).is_err());
    let r = f.record(action, &[&f.roots[0], &member]);
    f.state.apply(&r).unwrap();
    let r = f.record(
        TrustAction::BindDevice {
            member: "founder-1".into(),
            device: verifier.peer_id().to_string(),
        },
        &[&f.roots[0], &verifier],
    );
    assert!(f.state.apply(&r).is_err());
    let mut json = serde_json::to_value(&r).unwrap();
    json["action"]["expires_at"] = serde_json::json!(10);
    assert!(serde_json::from_value::<TrustRecord>(json).is_err());
}
#[test]
fn durable_prefix_rejects_rollback_fork_and_partial_tail() {
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.jsonl");
    let pin = f.state.checkpoint().genesis.clone();
    let mut log = TrustLog::open(&path, &f.genesis, &pin).unwrap();
    let view = log.view(Duration::from_secs(60)).unwrap();
    assert!(view.state().is_err());
    log.mark_current().unwrap();
    assert!(view.state().is_ok());
    let r = f.record(
        TrustAction::RevokeMembership {
            member: "founder-0".into(),
            club: "club-0".into(),
        },
        &[&f.roots[0]],
    );
    log.append(r).unwrap();
    log.mark_current().unwrap();
    let checkpoint = log.state().checkpoint().clone();
    let bytes = std::fs::read(&path).unwrap();
    drop(log);
    assert!(view.state().is_err());
    let log = TrustLog::open(&path, &f.genesis, &pin).unwrap();
    assert_eq!(log.state().checkpoint(), &checkpoint);
    drop(log);
    std::fs::write(&path, b"").unwrap();
    assert!(TrustLog::open(&path, &f.genesis, &pin).is_err());
    std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
    assert!(TrustLog::open(&path, &f.genesis, &pin).is_err());
    std::fs::write(&path, &bytes).unwrap();
    let log = TrustLog::open(&path, &f.genesis, &pin).unwrap();
    assert!(
        log.page(&TrustCheckpoint {
            head: "0".repeat(64),
            ..checkpoint
        })
        .is_err()
    );
}

#[test]
fn business_history_replays_identity_at_action_time() {
    use journal::journal::{Command, Journal, SignedCommand, TrustedCommand};
    use state::{EmptyDomain, State, governance::Action};
    let mut f = Fixture::new();
    let old = Identity::generate();
    let phone = Identity::generate();
    let host = Identity::generate();
    let dir = tempfile::tempdir().unwrap();
    let mut identity_log = TrustLog::open(
        &dir.path().join("identity.jsonl"),
        &f.genesis,
        &f.state.checkpoint().genesis,
    )
    .unwrap();
    let actions = [
        TrustAction::ConfirmMember {
            member: "person".into(),
            club: "club-0".into(),
            device: Some(phone.peer_id().to_string()),
            evidence: "manual".into(),
            verifier: None,
        },
        TrustAction::RegisterService {
            service: "office".into(),
            audience: host.peer_id().to_string(),
            club: "club-0".into(),
        },
        TrustAction::GrantPermission {
            id: "office-admin".into(),
            member: "person".into(),
            service: "office".into(),
            permission: "admin".into(),
        },
    ];
    for action in actions {
        let r = f.record(action, &[&f.roots[0], &phone, &host]);
        identity_log.append(r.clone()).unwrap();
        f.state.apply(&r).unwrap();
    }
    let binding = TrustBusinessBinding {
        genesis: f.state.checkpoint().genesis.clone(),
        namespace: "office".into(),
        audience: host.peer_id().to_string(),
        service: "office".into(),
        club: "club-0".into(),
    };
    let genesis = State::<EmptyDomain>::new(binding).unwrap();
    let path = dir.path().join("business.json");
    let mut business = Journal::open(&path, genesis.clone()).unwrap();
    let command = SignedCommand::sign::<EmptyDomain>(
        &phone,
        TrustedCommand {
            genesis: business.genesis_hash().into(),
            previous: business.head().unwrap(),
            identity: f.state.checkpoint().clone(),
            command: Command {
                revision: 0,
                expires_ms: 100,
                action: Action::SetMemberRoles {
                    member: "person".into(),
                    roles: ["reviewer".into()].into(),
                },
            },
        },
    )
    .unwrap();
    business
        .execute(
            command,
            identity_log
                .history_since(business.identity_checkpoint())
                .unwrap(),
            &f.state,
            3,
        )
        .unwrap();
    assert_eq!(
        business.state().members["person"].roles,
        ["reviewer".into()].into()
    );
    let unchanged_history = identity_log
        .history_since(business.identity_checkpoint())
        .unwrap();
    assert!(unchanged_history.records.is_empty());
    let second = SignedCommand::sign::<EmptyDomain>(
        &phone,
        TrustedCommand {
            genesis: business.genesis_hash().into(),
            previous: business.head().unwrap(),
            identity: f.state.checkpoint().clone(),
            command: Command {
                revision: 1,
                expires_ms: 100,
                action: Action::AnchorDigest {
                    id: "incremental".into(),
                    digest: "b".repeat(64),
                },
            },
        },
    )
    .unwrap();
    business
        .execute(second, unchanged_history, &f.state, 3)
        .unwrap();
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(
        !persisted[0]["identity"]["records"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        persisted[1]["identity"]["records"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let r = f.record(
        TrustAction::RevokePermission {
            id: "office-admin".into(),
        },
        &[&f.roots[0]],
    );
    identity_log.append(r.clone()).unwrap();
    f.state.apply(&r).unwrap();
    let denied = SignedCommand::sign::<EmptyDomain>(
        &phone,
        TrustedCommand {
            genesis: business.genesis_hash().into(),
            previous: business.head().unwrap(),
            identity: f.state.checkpoint().clone(),
            command: Command {
                revision: 2,
                expires_ms: 100,
                action: Action::AnchorDigest {
                    id: "denied".into(),
                    digest: "a".repeat(64),
                },
            },
        },
    )
    .unwrap();
    assert!(
        business
            .execute(
                denied,
                identity_log
                    .history_since(business.identity_checkpoint())
                    .unwrap(),
                &f.state,
                4
            )
            .is_err()
    );
    let expected = business.state().clone();
    drop(business);
    let replay = Journal::open(&path, genesis).unwrap();
    assert_eq!(replay.state(), &expected);
    assert!(
        !replay
            .state()
            .can_read(&old.peer_id().to_string(), &f.state)
    );
}

#[tokio::test]
async fn network_sync_and_live_permission_revocation_use_one_identity_log() {
    use futures::AsyncReadExt;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    let mut f = Fixture::new();
    let host_key = Identity::generate();
    let user = Identity::generate();
    let service = node::ServiceId::new();
    let dir = tempfile::tempdir().unwrap();
    let mut log = TrustLog::open(
        &dir.path().join("source.jsonl"),
        &f.genesis,
        &f.state.checkpoint().genesis,
    )
    .unwrap();
    for action in [
        TrustAction::ConfirmMember {
            member: "person".into(),
            club: "club-0".into(),
            device: Some(user.peer_id().to_string()),
            evidence: "manual".into(),
            verifier: None,
        },
        TrustAction::RegisterService {
            service: service.to_string(),
            audience: host_key.peer_id().to_string(),
            club: "club-0".into(),
        },
        TrustAction::GrantPermission {
            id: "manage".into(),
            member: "person".into(),
            service: service.to_string(),
            permission: "manage".into(),
        },
    ] {
        let r = f.record(action, &[&f.roots[0], &user, &host_key]);
        f.state.apply(&r).unwrap();
        log.append(r).unwrap();
    }
    log.mark_current().unwrap();
    let view = log.view(Duration::from_secs(60)).unwrap();
    let log = Arc::new(Mutex::new(log));
    let mut server = node::Node::start(host_key, node::NodeConfig::default())
        .await
        .unwrap();
    let mut incoming = server.take_incoming().unwrap();
    let server = Arc::new(server);
    let authority = server.clone();
    let source = log.clone();
    let task = tokio::spawn(async move { authority::trust::serve(&authority, source, true).await });
    server
        .publish(node::Service {
            id: service,
            name: "ops".into(),
            protocol: OPS_PROTOCOL.into(),
            metadata: vec![],
            access: node::AccessPolicy::Trust {
                view: view.clone(),
                requirement: TrustRequirement {
                    clubs: Default::default(),
                    permission: Some("manage".into()),
                },
            },
        })
        .await
        .unwrap();
    let client = node::Node::start(user, node::NodeConfig::default())
        .await
        .unwrap();
    client.dial(server.addresses()[0].clone()).await.unwrap();
    let cache = Mutex::new(
        TrustLog::open(
            &dir.path().join("cache.jsonl"),
            &f.genesis,
            &f.state.checkpoint().genesis,
        )
        .unwrap(),
    );
    authority::trust::synchronize(&client, server.peer_id(), &cache)
        .await
        .unwrap();
    assert_eq!(
        cache.lock().await.state().checkpoint(),
        f.state.checkpoint()
    );
    let mut stream = client
        .open_service(server.peer_id(), service)
        .await
        .unwrap();
    let mut accepted = incoming.recv().await.unwrap();
    let read = tokio::spawn(async move {
        let mut byte = [0];
        accepted.stream.read(&mut byte).await
    });
    let r = f.record(
        TrustAction::RevokePermission {
            id: "manage".into(),
        },
        &[&f.roots[0]],
    );
    log.lock().await.append(r).unwrap();
    log.lock().await.mark_current().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), read)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(
        client
            .open_service(server.peer_id(), service)
            .await
            .is_err()
    );
    let mut byte = [0];
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte)).await;
    log.lock().await.mark_stale();
    assert!(matches!(
        client.open_service(server.peer_id(), service).await,
        Err(node::Error::AuthorityUnavailable)
    ));
    task.abort();
    let _ = task.await;
    drop(stream);
    drop(incoming);
    drop(cache);
    drop(log);
    drop(view);
    client.shutdown().await.unwrap();
    Arc::try_unwrap(server)
        .ok()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
}

#[test]
fn identity_client_json_accepts_operations_and_rejects_unknown_fields() {
    let f = Fixture::new();
    let mut input = serde_json::json!({"config": {"genesis": f.genesis,
        "genesis_hash": f.state.checkpoint().genesis, "log": "/tmp/unused-identity-test",
        "peer": f.roots[0].peer_id().to_string(), "address": "/ip4/127.0.0.1/tcp/1"},
        "operation": "sync"});
    assert!(serde_json::from_value::<client::trust::Input>(input.clone()).is_ok());
    input["expires_at"] = serde_json::json!(1);
    assert!(serde_json::from_value::<client::trust::Input>(input).is_err());
}
#[test]
fn succession_votes_survive_interleaving_but_not_a_replaced_chair_epoch() {
    let mut f = Fixture::new();
    let successor = Identity::generate();
    f.member("successor", &successor);
    let mut chairs = f.state.chairs().clone();
    chairs.insert("club-0".into(), "successor".into());
    for id in ["election", "obsolete"] {
        let r = f.record(
            TrustAction::ProposeSuccession {
                id: id.into(),
                chairs: chairs.clone(),
                quorum: 2,
            },
            &[&f.roots[0]],
        );
        f.state.apply(&r).unwrap();
    }
    let vote = |id: &str| TrustAction::ApproveSuccession { id: id.into() };
    let r = f.record(vote("election"), &[&f.roots[0], &successor]);
    f.state.apply(&r).unwrap();
    let unrelated = Identity::generate();
    f.member("another-person", &unrelated);
    let execute = TrustAction::ExecuteSuccession {
        id: "election".into(),
    };
    let r = f.record(execute.clone(), &[&f.roots[0]]);
    assert!(f.state.apply(&r).is_err());
    // A second device of the same chair is not a second vote.
    let second_phone = Identity::generate();
    let r = f.record(
        TrustAction::BindDevice {
            member: "founder-0".into(),
            device: second_phone.peer_id().to_string(),
        },
        &[&f.roots[0], &second_phone],
    );
    f.state.apply(&r).unwrap();
    let r = f.record(vote("election"), &[&second_phone]);
    f.state.apply(&r).unwrap();
    let r = f.record(execute.clone(), &[&f.roots[0]]);
    assert!(f.state.apply(&r).is_err());
    let r = f.record(vote("election"), &[&f.roots[1]]);
    f.state.apply(&r).unwrap();
    let r = f.record(execute, &[&f.roots[1]]);
    f.state.apply(&r).unwrap();
    assert_eq!(f.state.chairs()["club-0"], "successor");
    assert!(f.state.is_member("founder-0", "club-0"));
    let r = f.record(vote("obsolete"), &[&f.roots[1]]);
    assert!(f.state.apply(&r).is_err());
}
#[test]
fn global_recovery_and_service_registration_require_independent_authority() {
    let mut f = Fixture::new();
    let member = Identity::generate();
    let replacement = Identity::generate();
    f.member("person", &member);
    let action = TrustAction::BindDevice {
        member: "person".into(),
        device: replacement.peer_id().to_string(),
    };
    let r = f.record(action.clone(), &[&f.roots[0], &replacement]);
    assert!(f.state.apply(&r).is_err());
    let r = f.record(action, &[&f.roots[0], &f.roots[1], &replacement]);
    f.state.apply(&r).unwrap();
    let action = TrustAction::RegisterService {
        service: "unclaimed".into(),
        audience: replacement.peer_id().to_string(),
        club: "club-0".into(),
    };
    let r = f.record(action.clone(), &[&f.roots[0]]);
    assert!(f.state.apply(&r).is_err());
    let r = f.record(action, &[&f.roots[0], &replacement]);
    f.state.apply(&r).unwrap();
}

#[cfg(feature = "consensus")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicated_business_replays_signatures_across_failover_and_revocation() {
    use authority::consensus::{Cluster, Peer, Store};
    use node::{Node, NodeConfig};
    use state::{EmptyDomain, State, governance::Action};
    use std::sync::Arc;
    use tokio::{
        sync::Mutex,
        time::{sleep, timeout},
    };
    let dir = tempfile::tempdir().unwrap();
    let old = Identity::generate();
    let phone = Identity::generate();
    let host = Identity::generate();
    let mut f = Fixture::new();
    let mut log = TrustLog::open(
        &dir.path().join("identity"),
        &f.genesis,
        &f.state.checkpoint().genesis,
    )
    .unwrap();
    for action in [
        TrustAction::ConfirmMember {
            member: "operator".into(),
            club: "club-0".into(),
            device: Some(phone.peer_id().to_string()),
            evidence: "manual".into(),
            verifier: None,
        },
        TrustAction::RegisterService {
            service: "office".into(),
            audience: host.peer_id().to_string(),
            club: "club-0".into(),
        },
        TrustAction::GrantPermission {
            id: "admin".into(),
            member: "operator".into(),
            service: "office".into(),
            permission: "admin".into(),
        },
    ] {
        let record = f.record(action, &[&f.roots[0], &phone, &host]);
        log.append(record.clone()).unwrap();
        f.state.apply(&record).unwrap();
    }
    log.mark_current().unwrap();
    let view = log.view(Duration::from_secs(120)).unwrap();
    let log = Arc::new(Mutex::new(log));
    let mut nodes = Vec::new();
    for key in [host.clone(), Identity::generate(), Identity::generate()] {
        nodes.push(Arc::new(
            Node::start(key, NodeConfig::default()).await.unwrap(),
        ));
    }
    let peers: BTreeMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            (
                (i + 1) as u64,
                Peer {
                    peer: n.peer_id().to_string(),
                    addresses: n.addresses().iter().map(ToString::to_string).collect(),
                },
            )
        })
        .collect();
    let genesis = State::<EmptyDomain>::new(TrustBusinessBinding {
        genesis: f.state.checkpoint().genesis.clone(),
        namespace: "office".into(),
        service: "office".into(),
        audience: host.peer_id().to_string(),
        club: "club-0".into(),
    })
    .unwrap();
    let mut clusters = Vec::new();
    let mut tasks = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let cluster = Cluster::start(
            (i + 1) as u64,
            node.clone(),
            &dir.path().join(format!("raft-{i}")),
            genesis.clone(),
            peers.clone(),
            (log.clone(), view.clone()),
        )
        .await
        .unwrap();
        tasks.push(tokio::spawn(cluster.clone().serve()));
        clusters.push(cluster);
    }
    clusters[0].initialize().await.unwrap();
    let leader = timeout(Duration::from_secs(15), async {
        loop {
            if let Some(c) = clusters
                .iter()
                .find(|c| c.raft.metrics().borrow().state == openraft::ServerState::Leader)
            {
                break c.clone();
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let follower = clusters.iter().find(|c| c.id != leader.id).unwrap();
    assert!(leader.response(old.peer_id()).await.is_err());
    let phone_node = Node::start(phone.clone(), NodeConfig::default())
        .await
        .unwrap();
    phone_node
        .dial(follower.node.addresses()[0].clone())
        .await
        .unwrap();
    let response = client::trust::execute::<EmptyDomain>(
        &phone_node,
        follower.node.peer_id(),
        &leader.cluster,
        &phone,
        &*log.lock().await,
        Action::AnchorDigest {
            id: "unified".into(),
            digest: "b".repeat(64),
        },
    )
    .await
    .unwrap();
    assert!(response.error.is_none(), "{:?}", response.error);
    let before_failover = leader.store.state().await;
    let stopped_id = leader.id;
    leader.raft.shutdown().await.unwrap();
    let successor = timeout(Duration::from_secs(15), async {
        loop {
            if let Some(c) = clusters.iter().find(|c| {
                c.id != stopped_id
                    && c.raft.metrics().borrow().state == openraft::ServerState::Leader
            }) {
                break c.clone();
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    phone_node
        .dial(successor.node.addresses()[0].clone())
        .await
        .unwrap();
    let response = client::trust::execute::<EmptyDomain>(
        &phone_node,
        successor.node.peer_id(),
        &successor.cluster,
        &phone,
        &*log.lock().await,
        Action::AnchorDigest {
            id: "after-election".into(),
            digest: "c".repeat(64),
        },
    )
    .await
    .unwrap();
    assert!(response.error.is_none(), "{:?}", response.error);
    let expected = successor.store.state().await;
    let revoke = f.record(
        TrustAction::RevokePermission { id: "admin".into() },
        &[&f.roots[0]],
    );
    {
        let mut log = log.lock().await;
        log.append(revoke).unwrap();
        log.mark_current().unwrap();
    }
    assert!(successor.response(phone.peer_id()).await.is_err());
    assert!(follower.response(phone.peer_id()).await.is_err());
    timeout(Duration::from_secs(5), async {
        loop {
            if futures::future::join_all(
                clusters
                    .iter()
                    .filter(|c| c.id != stopped_id)
                    .map(|c| c.store.state()),
            )
            .await
            .iter()
            .all(|s| s == &expected)
            {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    for c in &clusters {
        if c.id != stopped_id {
            c.raft.shutdown().await.unwrap();
        }
    }
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    drop(successor);
    drop(leader);
    drop(clusters);
    for (i, node) in nodes.into_iter().enumerate() {
        let reopened = Store::open(
            &dir.path().join(format!("raft-{i}")),
            Cluster::genesis(genesis.clone(), &peers).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reopened.state().await,
            if (i + 1) as u64 == stopped_id {
                before_failover.clone()
            } else {
                expected.clone()
            }
        );
        Arc::try_unwrap(node)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }
    phone_node.shutdown().await.unwrap();
}
