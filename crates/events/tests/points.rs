#[path = "../../../tests/support/mod.rs"]
mod support;
use events::{EventAction, EventsDomain, points::*, workflows::OrganizationAction as O};
use identity::Identity;
use protocol::{Error, Result};
use state::{State, governance::Action};
use std::collections::BTreeMap;

struct Harness {
    ids: support::Identities,
    keys: Vec<Identity>,
    state: State<EventsDomain>,
}
impl Harness {
    fn new(member_cap: u64, source_cap: u64) -> Self {
        let keys: Vec<_> = (0..5).map(|_| Identity::generate()).collect();
        let ids = support::Identities::new(
            &[
                (&keys[0], "admin", "a"),
                (&keys[1], "oracle", "a"),
                (&keys[2], "alice", "a"),
                (&keys[3], "bob", "a"),
                (&keys[4], "outsider", "b"),
            ],
            "admin",
        );
        let state = ids.genesis();
        let mut h = Self { ids, keys, state };
        h.apply(
            0,
            1,
            O::ActivityPolicy {
                policy: ActivityPolicy {
                    daily_member_cap: member_cap,
                },
            },
        )
        .unwrap();
        h.source("main", source_cap, 1);
        h
    }
    fn apply(&mut self, key: usize, now: u64, action: O) -> Result<()> {
        self.state.apply(
            &self.keys[key].peer_id().to_string(),
            self.state.revision,
            now,
            Action::Domain(EventAction::Organization(action)),
            self.ids.log.state(),
        )
    }
    fn source(&mut self, id: &str, cap: u64, now: u64) {
        self.apply(
            0,
            now,
            O::OracleSource {
                id: id.into(),
                source: OracleSourcePolicy {
                    title: id.into(),
                    club: "a".into(),
                    oracle_device: self.keys[1].peer_id().to_string(),
                    service: "verified-room".into(),
                    weight_bps: 10_000,
                    points_per_slice: 10,
                    max_bonus_per_slice: 0,
                    daily_source_cap: cap,
                    enabled: true,
                },
            },
        )
        .unwrap();
    }
    fn evidence(&self, attestation: &Attestation) -> protocol::IpldBlock {
        let bytes = serde_json::to_vec(&serde_json::json!({"attestation":attestation})).unwrap();
        let (cid, _) = events::files::FileStore::default()
            .version(None, &bytes)
            .unwrap();
        ActivityEvidence::block(attestation, cid).unwrap()
    }
    fn attest(
        &mut self,
        source: &str,
        start: u64,
        slices: u64,
        players: BTreeMap<String, ActivityTotals>,
        now: u64,
    ) -> Result<()> {
        let attestation = Attestation {
            source: source.into(),
            window_start_ms: start,
            window_end_ms: start + slices * ACTIVITY_SLICE_MS,
            players,
        };
        let evidence = self.evidence(&attestation);
        self.apply(
            1,
            now,
            O::ActivityAttest {
                source: attestation.source,
                window_start_ms: attestation.window_start_ms,
                window_end_ms: attestation.window_end_ms,
                players: attestation.players,
                evidence,
            },
        )
    }
}
fn active(count: u64) -> ActivityTotals {
    ActivityTotals {
        active_slices: count,
        ..Default::default()
    }
}

#[test]
fn per_member_and_source_caps_record_activity_without_excess_minting() {
    let mut h = Harness::new(20, 25);
    h.attest(
        "main",
        0,
        2,
        [("alice".into(), active(2)), ("bob".into(), active(2))].into(),
        2 * ACTIVITY_SLICE_MS,
    )
    .unwrap();
    let office = &h.state.domain.organization;
    assert_eq!(office.points["a"]["alice"], 20);
    assert_eq!(office.points["a"]["bob"], 5);
    assert_eq!(office.oracle_sources["main"].daily.points, 25);
    h.attest(
        "main",
        2 * ACTIVITY_SLICE_MS,
        1,
        [("alice".into(), active(1))].into(),
        3 * ACTIVITY_SLICE_MS,
    )
    .unwrap();
    assert_eq!(h.state.domain.organization.points["a"]["alice"], 20);
    assert_eq!(
        h.state.domain.organization.activity_members["alice"].active_slices,
        3
    );
}
#[test]
fn the_member_day_limit_is_shared_across_sources_and_policy_edits_do_not_reset_it() {
    let mut h = Harness::new(15, 100);
    h.source("second", 100, 1);
    h.attest(
        "main",
        0,
        1,
        [("alice".into(), active(1))].into(),
        ACTIVITY_SLICE_MS,
    )
    .unwrap();
    h.attest(
        "second",
        0,
        1,
        [("alice".into(), active(1))].into(),
        ACTIVITY_SLICE_MS,
    )
    .unwrap();
    assert_eq!(h.state.domain.organization.points["a"]["alice"], 15);
    h.source("main", 100, ACTIVITY_SLICE_MS);
    assert_eq!(
        h.state.domain.organization.oracle_sources["main"].last_window_end_ms,
        ACTIVITY_SLICE_MS
    );
    h.attest(
        "main",
        ACTIVITY_SLICE_MS,
        1,
        [("alice".into(), active(1))].into(),
        2 * ACTIVITY_SLICE_MS,
    )
    .unwrap();
    assert_eq!(h.state.domain.organization.points["a"]["alice"], 15);
    h.attest(
        "main",
        DAY_MS,
        1,
        [("alice".into(), active(1))].into(),
        DAY_MS + ACTIVITY_SLICE_MS,
    )
    .unwrap();
    assert_eq!(h.state.domain.organization.points["a"]["alice"], 25);
    assert_eq!(
        h.state.domain.organization.activity_members["alice"].day_epoch,
        1
    );
    assert_eq!(
        h.state.domain.organization.activity_members["alice"].points,
        10
    );
}
#[test]
fn physical_windows_bonus_bounds_membership_and_replays_are_enforced() {
    for (start, slices, member, total, now) in [
        (0, 1, "alice", active(2), ACTIVITY_SLICE_MS),
        (
            0,
            1,
            "alice",
            ActivityTotals {
                active_slices: 1,
                afk_slices: 0,
                bonus_points: 1,
            },
            ACTIVITY_SLICE_MS,
        ),
        (0, 1, "missing", active(1), ACTIVITY_SLICE_MS),
        (0, 1, "alice", active(1), ACTIVITY_SLICE_MS - 1),
        (1, 1, "alice", active(1), 2 * ACTIVITY_SLICE_MS),
    ] {
        let mut h = Harness::new(100, 1000);
        let before = h.state.domain.organization.clone();
        assert!(
            h.attest("main", start, slices, [(member.into(), total)].into(), now)
                .is_err()
        );
        assert_eq!(h.state.domain.organization, before);
    }
    let mut h = Harness::new(100, 1000);
    h.attest(
        "main",
        2 * ACTIVITY_SLICE_MS,
        1,
        [("alice".into(), active(1))].into(),
        3 * ACTIVITY_SLICE_MS,
    )
    .unwrap();
    let before = h.state.domain.organization.clone();
    assert!(
        h.attest(
            "main",
            2 * ACTIVITY_SLICE_MS,
            1,
            [("alice".into(), active(1))].into(),
            3 * ACTIVITY_SLICE_MS
        )
        .is_err()
    );
    assert_eq!(h.state.domain.organization, before);
}
#[test]
fn evidence_is_content_addressed_and_only_the_registered_oracle_can_mint() {
    let mut h = Harness::new(100, 1000);
    let attestation = Attestation {
        source: "main".into(),
        window_start_ms: 0,
        window_end_ms: ACTIVITY_SLICE_MS,
        players: [("alice".into(), active(1))].into(),
    };
    let evidence = h.evidence(&attestation);
    let action = O::ActivityAttest {
        source: "main".into(),
        window_start_ms: 0,
        window_end_ms: ACTIVITY_SLICE_MS,
        players: attestation.players.clone(),
        evidence: evidence.clone(),
    };
    assert!(matches!(
        h.apply(2, ACTIVITY_SLICE_MS, action.clone()),
        Err(Error::Denied)
    ));
    let wrong = O::ActivityAttest {
        source: "main".into(),
        window_start_ms: 0,
        window_end_ms: ACTIVITY_SLICE_MS,
        players: [("bob".into(), active(1))].into(),
        evidence: evidence.clone(),
    };
    assert!(h.apply(1, ACTIVITY_SLICE_MS, wrong).is_err());
    assert!(h.state.domain.organization.points.is_empty());
    h.apply(
        1,
        ACTIVITY_SLICE_MS,
        O::ActivityAttest {
            source: "main".into(),
            window_start_ms: 0,
            window_end_ms: ACTIVITY_SLICE_MS,
            players: attestation.players,
            evidence,
        },
    )
    .unwrap();
    assert_eq!(h.state.domain.organization.points["a"]["alice"], 10);
}
#[test]
fn weighted_overflow_is_rejected_without_partial_balance_or_window_updates() {
    let mut h = Harness::new(u64::MAX, u64::MAX);
    let mut source = h.state.domain.organization.oracle_sources["main"]
        .config
        .clone();
    source.points_per_slice = u64::MAX;
    source.weight_bps = 20_000;
    h.apply(
        0,
        1,
        O::OracleSource {
            id: "main".into(),
            source,
        },
    )
    .unwrap();
    let before = h.state.domain.organization.clone();
    assert!(matches!(
        h.attest(
            "main",
            0,
            1,
            [("alice".into(), active(1))].into(),
            ACTIVITY_SLICE_MS
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(h.state.domain.organization, before);
}
#[test]
fn cross_club_visitors_receive_points_in_their_verified_own_account() {
    let mut h = Harness::new(100, 1000);
    h.attest(
        "main",
        0,
        1,
        [("outsider".into(), active(1))].into(),
        ACTIVITY_SLICE_MS,
    )
    .unwrap();
    assert_eq!(h.state.domain.organization.points["b"]["outsider"], 10);
    assert!(!h.state.domain.organization.points.contains_key("a"));
    assert_eq!(
        h.state.domain.organization.activity_members["outsider"].points,
        10
    );
}
