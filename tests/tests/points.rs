#[path = "../support/mod.rs"]
mod support;
use identity::Identity;

#[test]
fn point_statements_use_verified_members_exact_amounts_and_the_authority_observation_day() {
    let admin = Identity::generate();
    let alice = Identity::generate();
    let identities =
        support::Identities::new(&[(&admin, "admin", "a"), (&alice, "alice", "a")], "admin");
    let mut snapshot = identities.genesis::<client::application::Application>();
    snapshot
        .domain
        .inner
        .organization
        .points
        .insert("a".into(), [("alice".into(), u64::MAX)].into());
    snapshot.domain.inner.organization.activity_members.insert(
        "alice".into(),
        events::points::DayUsage {
            day_epoch: 0,
            points: 60,
            active_slices: 6,
            afk_slices: 0,
        },
    );
    snapshot.core.clock_ms = events::points::DAY_MS - 1;
    assert!(snapshot.core.members.is_empty());
    let view = snapshot
        .identity_presentation(identities.log.state())
        .unwrap();
    let point_view = client::points::present(
        &snapshot,
        &view,
        &alice,
        &"a".repeat(64),
        events::points::DAY_MS + 1,
    )
    .unwrap()
    .unwrap();
    assert_eq!(point_view.overview.account.member, "alice");
    assert_eq!(point_view.overview.available_points, u64::MAX.to_string());
    assert_eq!(point_view.overview.earned_today, "0");
    assert_eq!(point_view.overview.as_of_ms, events::points::DAY_MS + 1);
    assert_eq!(snapshot.core.clock_ms, events::points::DAY_MS - 1);
    assert!(alice.public_key().verify(
        point_view.statement.payload.as_bytes(),
        &point_view.statement.signature
    ));
    assert_eq!(point_view.statement.public_key.len(), 32);
    assert_eq!(point_view.statement.signature.len(), 64);
    let payload: serde_json::Value = serde_json::from_str(&point_view.statement.payload).unwrap();
    for private in ["files", "members", "identity", "ai_allowances"] {
        assert!(payload.get(private).is_none());
    }
    assert!(
        client::points::present(
            &snapshot,
            &view,
            &Identity::generate(),
            &"a".repeat(64),
            events::points::DAY_MS + 1
        )
        .unwrap()
        .is_none()
    );
}
#[test]
fn cached_result_reads_verify_cids_without_parsing_unrelated_ui_numbers() {
    let admin = Identity::generate();
    let identities = support::Identities::new(&[(&admin, "admin", "a")], "admin");
    let mut snapshot = identities.genesis::<client::application::Application>();
    let (cid, blocks) = snapshot
        .domain
        .inner
        .files
        .version(None, b"Verified output")
        .unwrap();
    for block in blocks {
        snapshot.domain.inner.files.put(block).unwrap();
    }
    let mut presented = serde_json::to_value(&snapshot).unwrap();
    presented["organization"]["points"] = serde_json::json!({"a":{"admin":1e100}});
    assert_eq!(
        client::files::cached_file(&presented, &cid.to_string()).unwrap(),
        b"Verified output"
    );
    let block = presented["files"]["blocks"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    *block = serde_json::json!("tampered");
    assert!(client::files::cached_file(&presented, &cid.to_string()).is_err());
}
