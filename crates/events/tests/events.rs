use events::{EventAction as E, EventsDomain, Phase, Window};
use identity::Identity;
use state::{Domain, governance::Action as A};
#[path = "../../../tests/support/mod.rs"]
mod support;
type State = support::Scenario<EventsDomain>;
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
#[test]
fn identity_projection_exposes_the_current_club_president() {
    let admin = Identity::generate();
    let identities = support::Identities::new(&[(&admin, "admin", "a")], "admin");
    let state: state::State<EventsDomain> = identities.genesis();
    let core = state.identity_core(identities.log.state()).unwrap();
    assert!(core.members["chair-a"].roles.contains("president"));
    assert!(!core.members["admin"].roles.contains("president"));
    assert!(core.admins.contains(&admin.peer_id().to_string()));
}
#[test]
fn lifecycle_task_authorization_signup_boundaries_and_revision_binding() {
    let root = Identity::generate();
    let a = Identity::generate();
    let b = Identity::generate();
    let admin = root.peer_id().to_string();
    let alice = a.peer_id().to_string();
    let bob = b.peer_id().to_string();
    let mut state = State::new(
        &[(&root, "admin", "a"), (&a, "alice", "a"), (&b, "bob", "b")],
        "admin",
    );
    assert!(
        state
            .apply(
                &alice,
                state.revision,
                2,
                A::Domain(E::Create {
                    id: "unauthorized".into(),
                    title: "Draft".into(),
                    brief_hash: HASH.into(),
                    window: Window {
                        opens_ms: 100,
                        closes_ms: 200,
                        starts_ms: 300
                    },
                })
            )
            .is_err()
    );
    state
        .apply(
            &admin,
            state.revision,
            2,
            A::SetMemberRoles {
                member: "alice".into(),
                roles: ["president".into()].into(),
            },
        )
        .unwrap();
    state
        .apply(
            &alice,
            state.revision,
            3,
            A::Domain(E::Create {
                id: "event".into(),
                title: "event".into(),
                brief_hash: HASH.into(),
                window: Window {
                    opens_ms: 100,
                    closes_ms: 200,
                    starts_ms: 300,
                },
            }),
        )
        .unwrap();
    state
        .apply(
            &alice,
            state.revision,
            4,
            A::Domain(E::AddTask {
                event: "event".into(),
                id: "task".into(),
                title: "Prepare venue".into(),
                due_ms: Some(250),
            }),
        )
        .unwrap();
    assert!(
        state
            .apply(
                &alice,
                state.revision,
                5,
                A::Domain(E::Assign {
                    task: "task".into(),
                    member: "bob".into()
                })
            )
            .is_err()
    );
    state
        .apply(
            &alice,
            state.revision,
            5,
            A::Domain(E::Assign {
                task: "task".into(),
                member: "alice".into(),
            }),
        )
        .unwrap();
    assert!(
        state
            .apply(
                &bob,
                state.revision,
                6,
                A::Domain(E::Complete {
                    task: "task".into()
                })
            )
            .is_err()
    );
    state
        .apply(
            &alice,
            state.revision,
            6,
            A::Domain(E::Complete {
                task: "task".into(),
            }),
        )
        .unwrap();
    assert!(state.domain.tasks["task"].done);
    state
        .apply(
            &alice,
            state.revision,
            7,
            A::Domain(E::Submit { id: "event".into() }),
        )
        .unwrap();
    // Approval requires the completed workflow, even for a service administrator.
    assert!(
        state
            .apply(
                &admin,
                state.revision,
                8,
                A::Domain(E::Approve {
                    id: "event".into(),
                    epoch: 1,
                    co_organizers: Default::default()
                })
            )
            .is_err()
    );
    // Domain-level test: the flows wrapper supplies this context after approvals.
    let approve = |state: &mut State, _id: &str, epoch, now| {
        let core = state.core.clone();
        EventsDomain::transition(
            &mut state.domain,
            &state::Context {
                actor: &admin,
                now_ms: now,
                revision: core.revision,
                core: core.view(),
                approved: true,
            },
            E::Approve {
                id: "event".into(),
                epoch,
                co_organizers: ["b".into()].into(),
            },
        )
    };
    approve(&mut state, "approval", 1, 9).unwrap();
    state
        .apply(
            &alice,
            state.revision,
            11,
            A::Domain(E::Publish { id: "event".into() }),
        )
        .unwrap();
    assert!(
        state
            .apply(
                &bob,
                state.revision,
                99,
                A::Domain(E::Signup { id: "event".into() })
            )
            .is_err()
    );
    state
        .apply(
            &bob,
            state.revision,
            100,
            A::Domain(E::Signup { id: "event".into() }),
        )
        .unwrap();
    assert!(
        state
            .apply(
                &bob,
                state.revision,
                101,
                A::Domain(E::Signup { id: "event".into() })
            )
            .is_err()
    );
    state
        .apply(
            &bob,
            state.revision,
            102,
            A::Domain(E::CancelSignup { id: "event".into() }),
        )
        .unwrap();
    state
        .apply(
            &alice,
            state.revision,
            103,
            A::Domain(E::Amend {
                id: "event".into(),
                brief_hash: "b".repeat(64),
            }),
        )
        .unwrap();
    assert_eq!(state.domain.events["event"].phase, Phase::Draft);
    state
        .apply(
            &alice,
            state.revision,
            104,
            A::Domain(E::Submit { id: "event".into() }),
        )
        .unwrap();
    assert!(approve(&mut state, "stale", 1, 105).is_err());
    approve(&mut state, "fresh", 2, 107).unwrap();
    state
        .apply(
            &alice,
            state.revision,
            109,
            A::Domain(E::Publish { id: "event".into() }),
        )
        .unwrap();
    state
        .apply(
            &bob,
            state.revision,
            110,
            A::Domain(E::Signup { id: "event".into() }),
        )
        .unwrap();
    assert!(
        state
            .apply(
                &bob,
                state.revision,
                200,
                A::Domain(E::Signup { id: "event".into() })
            )
            .is_err()
    );
    assert!(
        state
            .apply(
                &alice,
                state.revision,
                299,
                A::Domain(E::Finish { id: "event".into() })
            )
            .is_err()
    );
    assert!(
        state
            .apply(
                &bob,
                state.revision,
                299,
                A::Domain(E::Checkin { id: "event".into() })
            )
            .is_err()
    );
    assert!(
        state
            .apply(
                &alice,
                state.revision,
                300,
                A::Domain(E::Checkin { id: "event".into() })
            )
            .is_err()
    );
    state
        .apply(
            &bob,
            state.revision,
            300,
            A::Domain(E::Checkin { id: "event".into() }),
        )
        .unwrap();
    assert!(state.domain.checkins["event"].contains("bob"));
    assert!(
        state
            .apply(
                &bob,
                state.revision,
                300,
                A::Domain(E::Checkin { id: "event".into() })
            )
            .is_err()
    );
    assert!(
        state
            .apply(
                &bob,
                state.revision,
                300,
                A::Domain(E::CancelSignup { id: "event".into() })
            )
            .is_err()
    );
    state
        .apply(
            &alice,
            state.revision,
            300,
            A::Domain(E::Finish { id: "event".into() }),
        )
        .unwrap();
    assert_eq!(state.domain.events["event"].phase, Phase::Done);
    assert!(
        state
            .apply(
                &bob,
                state.revision,
                301,
                A::Domain(E::Checkin { id: "event".into() })
            )
            .is_err()
    );
}
