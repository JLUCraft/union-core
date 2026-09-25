use authority::journal::Journal;
#[path = "../../../tests/support/mod.rs"]
mod support;
use events::{EventAction as E, EventsDomain, Phase, Window};
use flows::{Approver, FlowAction, Flows, Stage, Status, Template, TimeoutPolicy};
use identity::Identity;
use state::{State, governance::Action};
use wire::Result;

type Office = Flows<EventsDomain>;
type A = Action<Office>;
type F = FlowAction<EventsDomain>;
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn ai_receipts_pin_inputs_reject_duplicates_and_replay_without_inference() {
    let mut h = Harness::new();
    let (input, blocks) = h
        .journal
        .state()
        .domain
        .inner
        .files
        .version(None, b"notes")
        .unwrap();
    for block in blocks {
        h.run(1, A::Domain(F::Inner(E::PutBlock { block })))
            .unwrap();
    }
    h.install(vec![
        Stage {
            name: "summary".into(),
            approver: Approver::Ai {
                worker: "bob".into(),
                model: "local".into(),
                purpose: "events.summary".into(),
                privacy: wire::protocol::Privacy::Sensitive,
                max_tokens: 128,
            },
            timeout_ms: None,
            on_timeout: TimeoutPolicy::Reject,
        },
        Stage {
            name: "review".into(),
            approver: Approver::Member {
                member: "alice".into(),
            },
            timeout_ms: None,
            on_timeout: TimeoutPolicy::Reject,
        },
    ]);
    h.run(
        1,
        A::Domain(F::Start {
            id: "ai".into(),
            template: "joint".into(),
            input: Some(input.clone()),
            payload: E::Approve {
                id: "event".into(),
                epoch: 1,
                co_organizers: ["b".into()].into(),
            },
        }),
    )
    .unwrap();
    let job = flows::ai_job(&h.journal.state().domain, "ai")
        .unwrap()
        .unwrap();
    assert_eq!(job.input, input);
    assert!(
        h.run(
            1,
            A::Domain(F::Approve {
                instance: "ai".into(),
                comment_hash: HASH.into()
            })
        )
        .is_err()
    );
    assert!(
        h.run(
            1,
            A::Domain(F::ClaimAi {
                instance: "ai".into(),
                job: job.job.clone(),
                attempt: 0
            })
        )
        .is_err()
    );
    h.run(
        2,
        A::Domain(F::ClaimAi {
            instance: "ai".into(),
            job: job.job.clone(),
            attempt: 0,
        }),
    )
    .unwrap();
    assert!(
        flows::ai_job(&h.journal.state().domain, "ai")
            .unwrap()
            .is_none()
    );
    h.run(
        2,
        A::Domain(F::FinishAi {
            instance: "ai".into(),
            job: job.job.clone(),
            attempt: 0,
            output: None,
            error: Some("retry requested".into()),
        }),
    )
    .unwrap();
    assert_eq!(h.journal.state().domain.flows["ai"].current, 0);
    assert!(
        flows::ai_job(&h.journal.state().domain, "ai")
            .unwrap()
            .is_none()
    );
    assert!(
        h.run(
            2,
            A::Domain(F::RetryAi {
                instance: "ai".into()
            })
        )
        .is_err()
    );
    h.run(
        1,
        A::Domain(F::RetryAi {
            instance: "ai".into(),
        }),
    )
    .unwrap();
    h.run(
        2,
        A::Domain(F::ClaimAi {
            instance: "ai".into(),
            job: job.job.clone(),
            attempt: 1,
        }),
    )
    .unwrap();
    let (output, blocks) = h
        .journal
        .state()
        .domain
        .inner
        .files
        .version(Some(input.clone()), b"summary")
        .unwrap();
    for block in blocks {
        h.run(2, A::Domain(F::Inner(E::PutBlock { block })))
            .unwrap();
    }
    assert!(
        h.run(
            2,
            A::Domain(F::FinishAi {
                instance: "ai".into(),
                job: job.job.clone(),
                attempt: usize::MAX,
                output: Some(output.clone()),
                error: None
            })
        )
        .is_err()
    );
    h.run(
        2,
        A::Domain(F::FinishAi {
            instance: "ai".into(),
            job: job.job.clone(),
            attempt: 1,
            output: Some(output.clone()),
            error: None,
        }),
    )
    .unwrap();
    assert_eq!(h.journal.state().domain.flows["ai"].current, 1);
    assert!(
        h.run(
            2,
            A::Domain(F::FinishAi {
                instance: "ai".into(),
                job: job.job,
                attempt: 1,
                output: Some(output.clone()),
                error: None
            })
        )
        .is_err()
    );
    h.run(
        1,
        A::Domain(F::Approve {
            instance: "ai".into(),
            comment_hash: HASH.into(),
        }),
    )
    .unwrap();
    h.run(
        1,
        A::Domain(F::Execute {
            instance: "ai".into(),
        }),
    )
    .unwrap();
    let state = h.journal.state().clone();
    drop(h.journal);
    let replay = Journal::<Office>::open(&h.path, h.genesis).unwrap();
    assert_eq!(replay.state(), &state);
    assert_eq!(
        replay.state().domain.inner.files.read(&input).unwrap(),
        b"notes"
    );
    assert_eq!(
        replay.state().domain.inner.files.read(&output).unwrap(),
        b"summary"
    );
}

struct Harness {
    identities: support::Identities,
    keys: Vec<Identity>,
    journal: Journal<Office>,
    genesis: State<Office>,
    path: std::path::PathBuf,
    _dir: tempfile::TempDir,
    now: u64,
}
impl Harness {
    fn new() -> Self {
        let keys: Vec<_> = (0..5).map(|_| Identity::generate()).collect();
        let identities = support::Identities::new(
            &[
                (&keys[0], "admin", "a"),
                (&keys[1], "alice", "a"),
                (&keys[2], "bob", "a"),
                (&keys[3], "carol", "b"),
                (&keys[4], "dave", "a"),
            ],
            "admin",
        );
        let genesis = identities.genesis();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("office.json");
        let journal = Journal::open(&path, genesis.clone()).unwrap();
        let mut h = Self {
            identities,
            keys,
            journal,
            genesis,
            path,
            _dir: dir,
            now: 100,
        };
        h.run(
            0,
            A::SetMemberRoles {
                member: "bob".into(),
                roles: ["president".into()].into(),
            },
        )
        .unwrap();
        h.run(
            1,
            A::Domain(F::Inner(E::Create {
                id: "event".into(),
                title: "Joint event".into(),
                brief_hash: HASH.into(),
                window: Window {
                    opens_ms: 1000,
                    closes_ms: 2000,
                    starts_ms: 3000,
                },
            })),
        )
        .unwrap();
        h.run(1, A::Domain(F::Inner(E::Submit { id: "event".into() })))
            .unwrap();
        h
    }
    fn run(&mut self, signer: usize, action: A) -> Result<()> {
        self.now += 1;
        self.identities
            .run(&mut self.journal, &self.keys[signer], self.now, action)
    }
    fn policy(&mut self, action: F) {
        self.run(0, A::Domain(action)).unwrap();
    }
    fn install(&mut self, stages: Vec<Stage>) {
        self.policy(F::InstallTemplate {
            id: "joint".into(),
            template: Template {
                name: "Joint event".into(),
                stages,
                payload_kinds: ["events.approve".into()].into(),
            },
        });
    }
    fn start(&mut self, id: &str) {
        self.run(
            1,
            A::Domain(F::Start {
                input: None,
                id: id.into(),
                template: "joint".into(),
                payload: E::Approve {
                    epoch: 1,
                    id: "event".into(),
                    co_organizers: ["b".into()].into(),
                },
            }),
        )
        .unwrap();
    }
    fn vote(&mut self, signer: usize, id: &str) -> Result<()> {
        self.run(
            signer,
            A::Domain(F::Approve {
                instance: id.into(),
                comment_hash: HASH.into(),
            }),
        )
    }
    fn denied(&mut self, signer: usize, action: A) {
        let before = serde_json::to_vec(self.journal.state()).unwrap();
        assert!(self.run(signer, action).is_err());
        assert_eq!(before, serde_json::to_vec(self.journal.state()).unwrap());
    }
}
fn stage(approver: Approver, timeout: TimeoutPolicy) -> Stage {
    Stage {
        name: "review".into(),
        approver,
        timeout_ms: Some(1000),
        on_timeout: timeout,
    }
}
fn role() -> Approver {
    Approver::Role {
        club: "a".into(),
        role: "president".into(),
    }
}
fn quorum() -> Approver {
    Approver::ClubQuorum {
        clubs: ["a".into(), "b".into()].into(),
        quorum: 2,
    }
}

#[test]
fn multistage_authorization_execution_and_signed_replay() {
    let mut h = Harness::new();
    let template = Template {
        name: "forbidden direct install".into(),
        stages: vec![stage(role(), TimeoutPolicy::Reject)],
        payload_kinds: ["events.approve".into()].into(),
    };
    h.denied(
        1,
        A::Domain(F::InstallTemplate {
            id: "joint".into(),
            template,
        }),
    );
    h.install(vec![
        stage(role(), TimeoutPolicy::Reject),
        stage(quorum(), TimeoutPolicy::Reject),
        stage(
            Approver::Member {
                member: "admin".into(),
            },
            TimeoutPolicy::Reject,
        ),
    ]);
    h.start("flow");
    h.denied(
        1,
        A::Domain(F::Inner(E::Approve {
            epoch: 1,
            id: "event".into(),
            co_organizers: Default::default(),
        })),
    );
    assert!(h.vote(1, "flow").is_err());
    h.vote(2, "flow").unwrap();
    h.vote(1, "flow").unwrap();
    assert!(h.vote(2, "flow").is_err()); // same club cannot supply two seats
    h.vote(3, "flow").unwrap();
    h.vote(0, "flow").unwrap();
    assert_eq!(
        h.journal.state().domain.flows["flow"].status,
        Status::Approved
    );
    h.run(
        1,
        A::Domain(F::Execute {
            instance: "flow".into(),
        }),
    )
    .unwrap();
    assert_eq!(
        h.journal.state().domain.inner.events["event"].phase,
        Phase::Approved
    );
    h.denied(
        1,
        A::Domain(F::Execute {
            instance: "flow".into(),
        }),
    );
    let expected = serde_json::to_vec(h.journal.state()).unwrap();
    drop(h.journal);
    let restored = Journal::<Office>::open(&h.path, h.genesis).unwrap();
    assert_eq!(expected, serde_json::to_vec(restored.state()).unwrap());
}

#[test]
fn delegation_is_same_club_single_hop_and_current_roles_are_rechecked() {
    let mut h = Harness::new();
    h.install(vec![stage(role(), TimeoutPolicy::Reject)]);
    h.start("flow");
    h.denied(
        2,
        A::Domain(F::Delegate {
            instance: "flow".into(),
            to: "carol".into(),
        }),
    );
    h.run(
        2,
        A::Domain(F::Delegate {
            instance: "flow".into(),
            to: "dave".into(),
        }),
    )
    .unwrap();
    h.denied(
        4,
        A::Domain(F::Delegate {
            instance: "flow".into(),
            to: "alice".into(),
        }),
    );
    assert!(h.vote(2, "flow").is_err());
    h.vote(4, "flow").unwrap();
    h.run(
        0,
        A::SetMemberRoles {
            member: "bob".into(),
            roles: Default::default(),
        },
    )
    .unwrap();
    h.denied(
        1,
        A::Domain(F::Execute {
            instance: "flow".into(),
        }),
    );
}

#[test]
fn explicit_timeout_escalation_rejection_and_autoapproval() {
    for policy in [
        TimeoutPolicy::Escalate,
        TimeoutPolicy::Reject,
        TimeoutPolicy::AutoApprove,
    ] {
        let mut h = Harness::new();
        let mut stages = vec![stage(role(), policy.clone())];
        if policy == TimeoutPolicy::Escalate {
            stages.push(stage(
                Approver::Member {
                    member: "admin".into(),
                },
                TimeoutPolicy::Reject,
            ));
        }
        h.install(stages);
        h.start("flow");
        h.denied(
            1,
            A::Domain(F::Poke {
                instance: "flow".into(),
            }),
        );
        h.now = h.journal.state().domain.flows["flow"].deadline_ms.unwrap() - 1;
        h.run(
            1,
            A::Domain(F::Poke {
                instance: "flow".into(),
            }),
        )
        .unwrap(); // exact deadline
        match policy {
            TimeoutPolicy::Reject => assert_eq!(
                h.journal.state().domain.flows["flow"].status,
                Status::Rejected
            ),
            TimeoutPolicy::Escalate => {
                assert_eq!(h.journal.state().domain.flows["flow"].current, 1);
                h.vote(0, "flow").unwrap();
                h.run(
                    1,
                    A::Domain(F::Execute {
                        instance: "flow".into(),
                    }),
                )
                .unwrap();
            }
            TimeoutPolicy::AutoApprove => {
                h.run(
                    1,
                    A::Domain(F::Execute {
                        instance: "flow".into(),
                    }),
                )
                .unwrap();
                assert_eq!(
                    h.journal.state().domain.flows["flow"].status,
                    Status::Executed
                );
            }
        }
    }
}

#[test]
fn rejection_cancellation_versions_and_payload_whitelist() {
    let mut h = Harness::new();
    h.install(vec![stage(role(), TimeoutPolicy::Reject)]);
    h.start("old");
    h.install(vec![stage(
        Approver::Member {
            member: "admin".into(),
        },
        TimeoutPolicy::Reject,
    )]);
    assert_eq!(h.journal.state().domain.flows["old"].template_epoch, 1);
    h.run(
        2,
        A::Domain(F::Reject {
            instance: "old".into(),
            reason: HASH.into(),
        }),
    )
    .unwrap();
    h.denied(
        1,
        A::Domain(F::Execute {
            instance: "old".into(),
        }),
    );
    h.denied(
        1,
        A::Domain(F::Start {
            input: None,
            id: "bad".into(),
            template: "joint".into(),
            payload: E::CancelEvent { id: "event".into() },
        }),
    );
    let core_payload = serde_json::json!({"type":"flows.start","id":"bad","template":"joint","payload":{"type":"grant_admin","device":h.keys[1].peer_id().to_string()}});
    assert!(serde_json::from_value::<A>(core_payload).is_err());
    h.start("cancel");
    h.run(
        1,
        A::Domain(F::Cancel {
            instance: "cancel".into(),
        }),
    )
    .unwrap();
    assert_eq!(
        h.journal.state().domain.flows["cancel"].status,
        Status::Cancelled
    );
    h.policy(F::RetireTemplate { id: "joint".into() });
    h.denied(
        1,
        A::Domain(F::Start {
            input: None,
            id: "retired".into(),
            template: "joint".into(),
            payload: E::Approve {
                epoch: 1,
                id: "event".into(),
                co_organizers: Default::default(),
            },
        }),
    );
}

#[test]
fn payload_failure_is_atomic_and_revoked_approvals_cannot_execute() {
    let mut h = Harness::new();
    h.install(vec![stage(role(), TimeoutPolicy::Reject)]);
    h.start("flow");
    h.vote(2, "flow").unwrap();
    h.run(
        1,
        A::Domain(F::Inner(E::CancelEvent { id: "event".into() })),
    )
    .unwrap();
    h.denied(
        1,
        A::Domain(F::Execute {
            instance: "flow".into(),
        }),
    );
    assert_eq!(
        h.journal.state().domain.flows["flow"].status,
        Status::Approved
    );
    let mut h = Harness::new();
    h.install(vec![stage(role(), TimeoutPolicy::Reject)]);
    h.start("flow");
    h.vote(2, "flow").unwrap();
    let phone = Identity::generate();
    h.identities.append(
        wire::protocol::TrustAction::BindDevice {
            member: "bob".into(),
            device: phone.peer_id().to_string(),
        },
        &[&h.keys[2], &phone],
    );
    h.identities.append(
        wire::protocol::TrustAction::RevokeDevice {
            member: "bob".into(),
            device: h.keys[2].peer_id().to_string(),
        },
        &[&phone],
    );
    h.denied(
        1,
        A::Domain(F::Execute {
            instance: "flow".into(),
        }),
    );
}

#[test]
fn changing_the_brief_invalidates_an_already_approved_flow() {
    let mut h = Harness::new();
    h.install(vec![stage(role(), TimeoutPolicy::Reject)]);
    h.start("flow");
    h.vote(2, "flow").unwrap();
    h.run(
        1,
        A::Domain(F::Inner(E::Amend {
            id: "event".into(),
            brief_hash: "b".repeat(64),
        })),
    )
    .unwrap();
    h.run(1, A::Domain(F::Inner(E::Submit { id: "event".into() })))
        .unwrap();
    h.denied(
        1,
        A::Domain(F::Execute {
            instance: "flow".into(),
        }),
    );
    assert_eq!(h.journal.state().domain.inner.events["event"].epoch, 2);
    assert_eq!(
        h.journal.state().domain.inner.events["event"].phase,
        Phase::Review
    );
}
