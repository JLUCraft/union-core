use client::management::{self, FieldKind, FounderInput, PublicIdentity};
use identity::Identity;
use protocol::{TrustAction, TrustGenesis};
use serde_json::{Value, json};

fn genesis(key: &Identity) -> TrustGenesis {
    serde_json::from_value(
        management::build_genesis(
            "test".into(),
            vec![FounderInput {
                member: "chair".into(),
                club: "school".into(),
                identity: PublicIdentity::from_identity(key),
            }],
            1,
        )
        .unwrap()["genesis"]
            .clone(),
    )
    .unwrap()
}
#[test]
fn every_administrative_protocol_action_has_a_native_form_and_builds_without_json_authoring() {
    let peer = Identity::generate().peer_id().to_string();
    let forms = management::forms().unwrap();
    assert_eq!(forms.len(), 14);
    for form in forms {
        let mut fields = serde_json::Map::new();
        for field in form.fields {
            fields.insert(
                field.name,
                match field.kind {
                    FieldKind::Text => json!("value"),
                    FieldKind::Peer => json!(peer),
                    FieldKind::Profile => json!("a".repeat(32)),
                    FieldKind::Number => json!(1),
                    FieldKind::Choices => json!(["institutional_email", "game_profile"]),
                    FieldKind::Chairs => json!({"school":"member"}),
                },
            );
        }
        let action = management::build_action(&form.action, fields).unwrap();
        let value = serde_json::to_value(action).unwrap();
        assert_eq!(value["type"], form.action);
        assert!(serde_json::from_value::<TrustAction>(value).is_ok());
    }
    let exact = management::build_action(
        "revoke_membership",
        json!({"member":" member ","club":" club "})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap();
    assert_eq!(serde_json::to_value(exact).unwrap()["member"], " member ");
    let human = management::build_action(
        "confirm_member",
        json!({"member":"m","club":"c"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap();
    assert!(
        matches!(human,TrustAction::ConfirmMember {device:None,verifier:None,evidence,..} if evidence=="manual")
    );
}
#[test]
fn forms_reject_undeclared_fields_bad_keys_and_invalid_quorum() {
    for (action, fields) in [
        (
            "confirm_member",
            json!({"member":"m","club":"c","verifier":"bypass"}),
        ),
        (
            "confirm_member",
            json!({"member":"m","club":"c","device":42}),
        ),
        (
            "register_service",
            json!({"service":"s","audience":"invalid","club":"c"}),
        ),
        (
            "authorize_verifier",
            json!({"id":"v","club":"c","device":Identity::generate().peer_id().to_string(),"evidence":["manual"]}),
        ),
    ] {
        assert!(
            management::build_action(action, fields.as_object().unwrap().clone()).is_err(),
            "{action}"
        );
    }
}
#[test]
fn retired_bulk_chair_replacement_is_not_offered_on_any_layer() {
    // The founder roster is server-source data; the only runtime chair transfer is the
    // multi-signature succession record, so the retired bulk replacement must be absent from the
    // client catalog and rejected when parsed.
    let actions: Vec<String> = management::forms()
        .unwrap()
        .into_iter()
        .map(|form| form.action)
        .collect();
    assert!(
        !actions.iter().any(|action| action == "replace_chairs"),
        "{actions:?}"
    );
    assert!(actions.iter().any(|action| action == "propose_succession"));
    assert!(actions.iter().any(|action| action == "bind_device"));
    assert!(actions.iter().any(|action| action == "revoke_device"));
    assert!(
        management::build_action(
            "replace_chairs",
            json!({"chairs": {"club-0": "founder-0"}, "quorum": 1})
                .as_object()
                .unwrap()
                .clone()
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<TrustAction>(json!({
            "type": "replace_chairs",
            "chairs": {"club-0": "founder-0"},
            "quorum": 1
        }))
        .is_err()
    );
}
#[test]
fn founder_exports_require_matching_public_identities_and_real_majority() {
    let key = Identity::generate();
    let mut public = PublicIdentity::from_identity(&key);
    public.peer = Identity::generate().peer_id().to_string();
    assert!(public.validate().is_err());
    assert!(management::build_genesis("test".into(), vec![], 0).is_err());
    let value = management::review_genesis(genesis(&key)).unwrap();
    assert!(value.get("genesis_hash").and_then(Value::as_str).is_some());
}
#[test]
fn public_identity_keys_round_trip_as_hex_and_still_accept_legacy_arrays() {
    let key = Identity::generate();
    let public = PublicIdentity::from_identity(&key);
    let value = serde_json::to_value(&public).unwrap();
    let hex = value["public_key"].as_str().unwrap();
    let expected: String = public
        .public_key
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hex, expected);
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    let decoded: PublicIdentity = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.peer, public.peer);
    assert_eq!(decoded.public_key, public.public_key);
    decoded.validate().unwrap();
}
#[test]
fn public_identity_keys_reject_malformed_hex() {
    let key = Identity::generate();
    let public = PublicIdentity::from_identity(&key);
    for hex in ["zz", "abc", "0g"] {
        let value = json!({"peer": public.peer, "public_key": hex});
        assert!(
            serde_json::from_value::<PublicIdentity>(value).is_err(),
            "{hex}"
        );
    }
}
#[test]
fn build_genesis_accepts_hex_encoded_founder_identities() {
    let key = Identity::generate();
    let public = PublicIdentity::from_identity(&key);
    let exported = serde_json::to_value(&public).unwrap();
    let imported: PublicIdentity = serde_json::from_value(exported).unwrap();
    let legacy = json!({
        "peer": public.peer,
        "public_key": public.public_key,
    });
    for identity in [imported, serde_json::from_value(legacy).unwrap()] {
        let value = management::build_genesis(
            "test".into(),
            vec![FounderInput {
                member: "chair".into(),
                club: "school".into(),
                identity,
            }],
            1,
        )
        .unwrap();
        assert!(value.get("genesis_hash").and_then(Value::as_str).is_some());
    }
}
#[test]
fn offline_co_signing_requires_the_pinned_genesis_and_valid_prior_signatures() {
    let key = Identity::generate();
    let other = Identity::generate();
    let genesis = genesis(&key);
    let pin = client::trust::TrustState::genesis_digest(&genesis).unwrap();
    let config = client::trust::Config {
        genesis: genesis.clone(),
        genesis_hash: pin.clone(),
        log: "private-cache".into(),
        address: format!("/ip4/127.0.0.1/tcp/1/p2p/{}", other.peer_id()),
        peer: other.peer_id().to_string(),
    };
    let state = client::trust::TrustState::new(&genesis, &pin).unwrap();
    let record = state.draft(TrustAction::BindDevice {
        member: "chair".into(),
        device: other.peer_id().to_string(),
    });
    let signed = management::sign_offline(&key, &config, record.clone()).unwrap();
    let jointly_signed =
        management::sign_offline(&other, &config, serde_json::from_value(signed).unwrap()).unwrap();
    let mut projected = state.clone();
    projected
        .apply(&serde_json::from_value(jointly_signed).unwrap())
        .unwrap();
    assert_eq!(
        projected.member_for_device(&other.peer_id().to_string()),
        Some("chair")
    );
    let mut foreign = record.clone();
    foreign.genesis = "0".repeat(64);
    assert!(management::sign_offline(&key, &config, foreign).is_err());
    let mut corrupt: client::trust::TrustRecord =
        serde_json::from_value(management::sign_offline(&key, &config, record).unwrap()).unwrap();
    corrupt.previous = "0".repeat(64);
    assert!(management::sign_offline(&other, &config, corrupt).is_err());
    let public = management::review_config(&config).unwrap();
    assert!(public.get("log").is_none());
    let mut bad = config;
    bad.peer = key.peer_id().to_string();
    assert!(management::review_config(&bad).is_err());
}

#[test]
fn business_management_builds_core_actions_and_rejects_invalid_replica_sets() {
    let action = management::build_anchor("audit".into(), "a".repeat(64)).unwrap();
    assert_eq!(action["type"], "anchor_digest");
    assert!(management::build_anchor("audit".into(), "A".repeat(64)).is_err());
    assert_eq!(
        management::build_roles("member".into(), vec![]).unwrap()["roles"],
        json!([])
    );
    let peer = Identity::generate().peer_id().to_string();
    let input = || management::ReplicaInput {
        id: "1".into(),
        node: state::governance::ConsensusPeer {
            peer: peer.clone(),
            addresses: vec![format!("/ip4/127.0.0.1/tcp/1/p2p/{peer}")],
        },
    };
    assert_eq!(
        management::build_consensus(vec![input()]).unwrap()["type"],
        "set_consensus_members"
    );
    let mut large = input();
    large.id = u64::MAX.to_string();
    let built = management::build_consensus(vec![large]).unwrap();
    assert!(built["members"].get(u64::MAX.to_string()).is_some());
    assert!(management::build_consensus(vec![input(), input()]).is_err());
    assert!(management::build_consensus(vec![]).is_err());
}

#[tokio::test]
async fn local_inspection_verifies_cached_history_without_contacting_a_source() {
    let key = Identity::generate();
    let genesis = genesis(&key);
    let pin = client::trust::TrustState::genesis_digest(&genesis).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = client::trust::Config {
        genesis,
        genesis_hash: pin.clone(),
        log: dir.path().join("history.jsonl"),
        address: "offline".into(),
        peer: "offline".into(),
    };
    let state = client::trust::execute_identity(
        key,
        client::trust::Input {
            config,
            operation: client::trust::Operation::Inspect,
        },
    )
    .await
    .unwrap();
    assert_eq!(state["checkpoint"]["genesis"], pin);
    assert_eq!(state["checkpoint"]["sequence"], 0);
}
