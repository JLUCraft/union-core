#[path = "../support/mod.rs"]
mod support;
use authority::journal::{Command, Journal, SignedCommand, TrustedCommand};
use identity::Identity;
use state::{EmptyDomain, governance::Action};
#[test]
fn journal_locks_replays_and_rejects_tampering_and_unauthorized_anchors() {
    let admin = Identity::generate();
    let user = Identity::generate();
    let ids = support::Identities::new(
        &[(&admin, "admin", "club"), (&user, "user", "club")],
        "admin",
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("business");
    let genesis = ids.genesis::<EmptyDomain>();
    let mut journal = Journal::open(&path, genesis.clone()).unwrap();
    assert!(Journal::open(&path, genesis.clone()).is_err());
    let action = Action::AnchorDigest {
        id: "report".into(),
        digest: "a".repeat(64),
    };
    assert!(ids.run(&mut journal, &user, 1, action.clone()).is_err());
    let command = SignedCommand::sign(
        &admin,
        TrustedCommand {
            genesis: journal.genesis_hash().into(),
            previous: journal.head().unwrap(),
            identity: ids.log.state().checkpoint().clone(),
            command: Command {
                revision: 0,
                expires_ms: 100,
                action: action.clone(),
            },
        },
    )
    .unwrap();
    let history = ids.log.history_since(None).unwrap();
    journal
        .execute(command.clone(), history.clone(), ids.log.state(), 1)
        .unwrap();
    assert!(
        journal
            .execute(command, history, ids.log.state(), 2)
            .is_err()
    );
    assert!(ids.run(&mut journal, &admin, 2, action).is_err());
    let expected = journal.state().clone();
    drop(journal);
    let reopened = Journal::open(&path, genesis.clone()).unwrap();
    assert_eq!(reopened.state(), &expected);
    drop(reopened);
    let mut bytes: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    bytes[0]["state_hash"] = "0".repeat(64).into();
    std::fs::write(&path, serde_json::to_vec(&bytes).unwrap()).unwrap();
    assert!(Journal::open(path, genesis).is_err());
}
#[test]
fn business_schema_contains_only_service_actions_and_requires_identity_binding() {
    for kind in [
        "enroll",
        "grant_admin",
        "revoke_admin",
        "adopt_identity",
        "install_council",
        "rotate_member_device",
    ] {
        assert!(
            serde_json::from_value::<Action<EmptyDomain>>(serde_json::json!({"type":kind}))
                .is_err()
        );
    }
    for kind in ["map_legacy", "approve_migration"] {
        assert!(
            serde_json::from_value::<protocol::TrustAction>(serde_json::json!({"type":kind}))
                .is_err()
        );
    }
    assert!(
        serde_json::from_value::<state::State<EmptyDomain>>(
            serde_json::json!({"revision":0,"admins":[],"members":{},"clock_ms":0})
        )
        .is_err()
    );
}
