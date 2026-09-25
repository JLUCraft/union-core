#![cfg(feature = "consensus")]
#[path = "../support/mod.rs"]
mod support;
use authority::journal::{Command, SignedCommand, TrustedCommand};
use journal::consensus::{Replicated, Store};
use openraft::{RaftSnapshotBuilder, storage::RaftStateMachine};
use state::{EmptyDomain, governance::Action};
#[tokio::test]
async fn snapshots_replay_complete_signed_history_and_reject_modified_state_or_missing_audit() {
    let key = identity::Identity::generate();
    let ids = support::Identities::new(&[(&key, "admin", "club")], "admin");
    let genesis = ids.genesis::<EmptyDomain>();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raft");
    let mut store = Store::open(&path, genesis.clone()).unwrap();
    let cluster = store.cluster_id().await;
    let command = SignedCommand::sign(
        &key,
        TrustedCommand {
            genesis: cluster.clone(),
            previous: cluster.clone(),
            identity: ids.log.state().checkpoint().clone(),
            command: Command {
                revision: 0,
                expires_ms: 100,
                action: Action::<EmptyDomain>::AnchorDigest {
                    id: "report".into(),
                    digest: "a".repeat(64),
                },
            },
        },
    )
    .unwrap();
    let result = store
        .apply([openraft::Entry {
            log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
            payload: openraft::EntryPayload::Normal(Replicated {
                cluster,
                command,
                time_ms: 1,
                identity: ids.log.history_since(None).unwrap(),
            }),
        }])
        .await
        .unwrap();
    assert!(result[0].error.is_none());
    let snapshot = store.build_snapshot().await.unwrap();
    let mut replica = Store::open(&dir.path().join("replica"), genesis.clone()).unwrap();
    replica
        .install_snapshot(&snapshot.meta, snapshot.snapshot)
        .await
        .unwrap();
    assert_eq!(replica.state().await, store.state().await);
    let snapshot = store.build_snapshot().await.unwrap();
    let mut corrupt: serde_json::Value =
        serde_json::from_slice(snapshot.snapshot.get_ref()).unwrap();
    corrupt["state"]["revision"] = 99.into();
    assert!(
        replica
            .install_snapshot(
                &snapshot.meta,
                Box::new(std::io::Cursor::new(serde_json::to_vec(&corrupt).unwrap()))
            )
            .await
            .is_err()
    );
    let expected = store.state().await;
    drop(store);
    let reopened = Store::open(&path, genesis.clone()).unwrap();
    assert_eq!(reopened.state().await, expected);
    drop(reopened);
    let mut disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    disk["machine"].as_object_mut().unwrap().remove("audit");
    std::fs::write(&path, serde_json::to_vec(&disk).unwrap()).unwrap();
    assert!(Store::open(&path, genesis).is_err());
}

#[test]
fn consensus_node_ids_cannot_be_rebound_or_reused_after_retirement() {
    use state::governance::ConsensusPeer;
    use std::collections::BTreeMap;
    let admin = identity::Identity::generate();
    let other = identity::Identity::generate();
    let ids = support::Identities::new(&[(&admin, "admin", "club")], "admin");
    let mut state = ids.genesis::<EmptyDomain>();
    let actor = admin.peer_id().to_string();
    let peer = |key: &identity::Identity| {
        let peer = key.peer_id().to_string();
        ConsensusPeer {
            addresses: vec![format!("/ip4/127.0.0.1/tcp/12345/p2p/{peer}")],
            peer,
        }
    };
    let apply = |state: &mut state::State<EmptyDomain>, id, key: &identity::Identity| {
        state.apply(
            &actor,
            state.revision,
            state.clock_ms + 1,
            Action::SetConsensusMembers {
                members: BTreeMap::from([(id, peer(key))]),
            },
            ids.log.state(),
        )
    };
    apply(&mut state, 1, &admin).unwrap();
    let before = state.clone();
    assert!(apply(&mut state, 1, &other).is_err());
    assert_eq!(state, before);
    apply(&mut state, 2, &other).unwrap();
    assert!(state.retired_consensus_ids.contains(&1));
    let before = state.clone();
    assert!(apply(&mut state, 1, &admin).is_err());
    assert_eq!(state, before);
}
