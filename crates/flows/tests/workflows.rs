use authority::journal::Journal;
#[path = "../../../tests/support/mod.rs"]
mod support;
use events::{EventAction as E, EventsDomain, Phase, Window};
use flows::{Approver, FlowAction, Flows, Stage, Status, Template, TimeoutPolicy};
use identity::Identity;
use protocol::Result;
use state::{State, governance::Action};

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
                mode: flows::AiMode::Generate,
                worker: "bob".into(),
                model: "local".into(),
                purpose: "events.summary".into(),
                privacy: protocol::Privacy::Sensitive,
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
            max_points: 1_000_000,
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
            usage: None,
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
                usage: Some(protocol::LlmUsage {
                    prompt_tokens: 8,
                    completion_tokens: 4,
                    total_tokens: 12
                }),
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
            usage: Some(protocol::LlmUsage {
                prompt_tokens: 8,
                completion_tokens: 4,
                total_tokens: 12,
            }),
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
                usage: Some(protocol::LlmUsage {
                    prompt_tokens: 8,
                    completion_tokens: 4,
                    total_tokens: 12
                }),
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
    h.presidents("ai");
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
        let mut genesis = identities.genesis::<Office>();
        genesis.domain.ai_pricing.insert(
            "local".into(),
            flows::ai::AiPricing {
                base_points: 1,
                input_points_per_1k: 1,
                output_points_per_1k: 1,
                max_input_tokens: 1024,
                settlement: flows::ai::Settlement::Burn,
            },
        );
        genesis.domain.ai_workers.insert(
            "bob".into(),
            flows::ai::AiWorker {
                models: ["local".into()].into(),
                active: true,
            },
        );
        genesis.domain.inner.organization.points.insert(
            "a".into(),
            [
                ("alice".into(), 100_000),
                ("bob".into(), 100_000),
                ("admin".into(), 100_000),
            ]
            .into(),
        );
        genesis
            .domain
            .inner
            .organization
            .points
            .insert("b".into(), [("carol".into(), 100_000)].into());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("organization.json");
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
        for (member, role) in [("alice", "manager"), ("carol", "president")] {
            h.run(
                0,
                A::SetMemberRoles {
                    member: member.into(),
                    roles: [role.into()].into(),
                },
            )
            .unwrap();
        }
        h.run(
            2,
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
                max_points: 1_000_000,
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
    fn presidents(&mut self, id: &str) {
        assert_eq!(self.journal.state().domain.flows[id].status, Status::Active);
        assert!(self.vote(1, id).is_err());
        self.vote(2, id).unwrap();
        assert_eq!(self.journal.state().domain.flows[id].status, Status::Active);
        self.vote(3, id).unwrap();
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
    h.presidents("flow");
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
    h.presidents("flow");
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
                h.presidents("flow");
                h.run(
                    1,
                    A::Domain(F::Execute {
                        instance: "flow".into(),
                    }),
                )
                .unwrap();
            }
            TimeoutPolicy::AutoApprove => {
                h.presidents("flow");
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
            max_points: 1_000_000,
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
            max_points: 1_000_000,
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
    h.presidents("flow");
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
    h.presidents("flow");
    let phone = Identity::generate();
    h.identities.append(
        protocol::TrustAction::BindDevice {
            member: "bob".into(),
            device: phone.peer_id().to_string(),
        },
        &[&h.keys[2], &phone],
    );
    h.identities.append(
        protocol::TrustAction::RevokeDevice {
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
    h.presidents("flow");
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

fn review_stage(mode: flows::AiMode) -> Stage {
    Stage {
        name: "automatic".into(),
        approver: Approver::Ai {
            mode,
            worker: "bob".into(),
            model: "local".into(),
            purpose: "events.review".into(),
            privacy: protocol::Privacy::Sensitive,
            max_tokens: 512,
        },
        timeout_ms: Some(1000),
        on_timeout: TimeoutPolicy::Reject,
    }
}
impl Harness {
    fn file(&mut self, content: &[u8]) -> protocol::Cid {
        let (cid, blocks) = self
            .journal
            .state()
            .domain
            .inner
            .files
            .version(None, content)
            .unwrap();
        for block in blocks {
            self.run(1, A::Domain(F::Inner(E::PutBlock { block })))
                .unwrap();
        }
        cid
    }
    fn review_flow(&mut self) -> protocol::Cid {
        let input = self.file(b"Actual event plan");
        self.run(
            1,
            A::Domain(F::Inner(E::Amend {
                id: "event".into(),
                brief_hash: input.to_string(),
            })),
        )
        .unwrap();
        self.run(1, A::Domain(F::Inner(E::Submit { id: "event".into() })))
            .unwrap();
        self.install(vec![review_stage(flows::AiMode::Review)]);
        self.start_review("review", input.clone());
        input
    }
    fn start_review(&mut self, id: &str, input: protocol::Cid) {
        let epoch = self.journal.state().domain.inner.events["event"].epoch;
        self.run(
            1,
            A::Domain(F::Start {
                max_points: 1_000_000,
                id: id.into(),
                template: "joint".into(),
                input: Some(input),
                payload: E::Approve {
                    id: "event".into(),
                    epoch,
                    co_organizers: Default::default(),
                },
            }),
        )
        .unwrap();
    }
    fn claim(&mut self, id: &str) -> flows::AiJob {
        let job = flows::ai_job(&self.journal.state().domain, id)
            .unwrap()
            .unwrap();
        self.run(
            2,
            A::Domain(F::ClaimAi {
                instance: id.into(),
                job: job.job.clone(),
                attempt: job.attempt,
            }),
        )
        .unwrap();
        job
    }
    fn finish(&mut self, job: &flows::AiJob, output: protocol::Cid) -> Result<()> {
        self.run(
            2,
            A::Domain(F::FinishAi {
                instance: job.instance.clone(),
                job: job.job.clone(),
                attempt: job.attempt,
                output: Some(output),
                usage: Some(protocol::LlmUsage {
                    prompt_tokens: 8,
                    completion_tokens: 4,
                    total_tokens: 12,
                }),
                error: None,
            }),
        )
    }
}

#[test]
fn review_decisions_control_execution_and_survive_replay() {
    for (decision, expected) in [
        ("approve", Status::Active),
        ("changes_requested", Status::ChangesRequested),
        ("reject", Status::Rejected),
    ] {
        let mut h = Harness::new();
        h.review_flow();
        let job = h.claim("review");
        let output = h.file(serde_json::to_string(&serde_json::json!({"decision":decision,"summary":"Review result","issues":["Check consent documents"]})).unwrap().as_bytes());
        h.finish(&job, output.clone()).unwrap();
        assert_eq!(h.journal.state().domain.flows["review"].status, expected);
        assert!(h.finish(&job, output).is_err());
        assert!(
            h.run(
                1,
                A::Domain(F::RetryAi {
                    instance: "review".into()
                })
            )
            .is_err()
        );
        if decision == "approve" {
            h.vote(2, "review").unwrap();
        }
        let execution = h.run(
            1,
            A::Domain(F::Execute {
                instance: "review".into(),
            }),
        );
        assert_eq!(execution.is_ok(), decision == "approve");
        let state = h.journal.state().clone();
        drop(h.journal);
        assert_eq!(
            Journal::<Office>::open(&h.path, h.genesis).unwrap().state(),
            &state
        );
    }
}

#[test]
fn review_rejects_invalid_outputs_substituted_inputs_and_stale_material() {
    let mut h = Harness::new();
    let input = h.review_flow();
    let job = h.claim("review");
    h.denied(
        1,
        A::Domain(F::RetryAi {
            instance: "review".into(),
        }),
    );
    for body in [
        "approved",
        "{}",
        r#"{"decision":"approve","summary":"","issues":[]}"#,
        r#"{"decision":"reject","summary":"No","issues":[]}"#,
        r#"{"decision":"approve","summary":"OK","issues":[],"action":"events.approve"}"#,
    ] {
        let output = h.file(body.as_bytes());
        let before = h.journal.state().clone();
        assert!(h.finish(&job, output).is_err());
        assert_eq!(h.journal.state(), &before);
    }
    let other = h.file(b"Unrelated material");
    h.denied(
        1,
        A::Domain(F::Start {
            max_points: 1_000_000,
            id: "substituted".into(),
            template: "joint".into(),
            input: Some(other.clone()),
            payload: E::Approve {
                id: "event".into(),
                epoch: 2,
                co_organizers: Default::default(),
            },
        }),
    );
    let output = h.file(br#"{"decision":"approve","summary":"OK","issues":[]}"#);
    h.run(
        1,
        A::Domain(F::Inner(E::Amend {
            id: "event".into(),
            brief_hash: other.to_string(),
        })),
    )
    .unwrap();
    h.run(1, A::Domain(F::Inner(E::Submit { id: "event".into() })))
        .unwrap();
    assert!(h.finish(&job, output).is_err());
    h.denied(
        1,
        A::Domain(F::Start {
            max_points: 1_000_000,
            id: "stale".into(),
            template: "joint".into(),
            input: Some(input),
            payload: E::Approve {
                id: "event".into(),
                epoch: 2,
                co_organizers: Default::default(),
            },
        }),
    );
}

#[test]
fn review_uses_authoritative_plan_and_never_feeds_verdict_to_generation() {
    let mut h = Harness::new();
    let input = h.review_flow();
    h.install(vec![
        review_stage(flows::AiMode::Generate),
        review_stage(flows::AiMode::Review),
        review_stage(flows::AiMode::Generate),
    ]);
    h.start_review("pipeline", input.clone());
    let first = h.claim("pipeline");
    let generated = h.file(b"Generated draft");
    h.finish(&first, generated.clone()).unwrap();
    let review = h.claim("pipeline");
    assert_eq!(review.input, input);
    let verdict = h.file(br#"{"decision":"approve","summary":"OK","issues":[]}"#);
    h.finish(&review, verdict).unwrap();
    assert_eq!(h.claim("pipeline").input, generated);
}

#[test]
fn ai_timeouts_cannot_skip_review_and_cancelled_results_cannot_advance() {
    let mut h = Harness::new();
    h.review_flow();
    for policy in [TimeoutPolicy::AutoApprove, TimeoutPolicy::Escalate] {
        let mut automatic = review_stage(flows::AiMode::Review);
        automatic.on_timeout = policy;
        h.denied(
            0,
            A::Domain(F::InstallTemplate {
                id: "unsafe".into(),
                template: Template {
                    name: "Unsafe".into(),
                    stages: vec![automatic, stage(role(), TimeoutPolicy::Reject)],
                    payload_kinds: ["events.approve".into()].into(),
                },
            }),
        );
    }
    let job = h.claim("review");
    let output = h.file(br#"{"decision":"approve","summary":"OK","issues":[]}"#);
    h.run(
        1,
        A::Domain(F::Cancel {
            instance: "review".into(),
        }),
    )
    .unwrap();
    assert!(h.finish(&job, output).is_err());
}

#[test]
fn default_president_approval_revises_and_restarts_without_templates() {
    let mut h = Harness::new();
    let payload = |epoch| E::Approve {
        id: "event".into(),
        epoch,
        co_organizers: ["b".into()].into(),
    };
    h.run(
        1,
        A::Domain(F::StartPresidents {
            id: "initial".into(),
            payload: payload(1),
        }),
    )
    .unwrap();
    h.denied(
        1,
        A::Domain(F::Approve {
            instance: "initial".into(),
            comment_hash: HASH.into(),
        }),
    );
    h.denied(
        2,
        A::Domain(F::Delegate {
            instance: "initial".into(),
            to: "alice".into(),
        }),
    );
    h.vote(2, "initial").unwrap();
    h.denied(
        2,
        A::Domain(F::Approve {
            instance: "initial".into(),
            comment_hash: HASH.into(),
        }),
    );
    h.denied(
        1,
        A::Domain(F::Execute {
            instance: "initial".into(),
        }),
    );
    h.run(
        3,
        A::Domain(F::Reject {
            instance: "initial".into(),
            reason: HASH.into(),
        }),
    )
    .unwrap();
    h.run(
        1,
        A::Domain(F::Inner(E::Revise {
            id: "event".into(),
            title: "Revised event".into(),
            brief_hash: "b".repeat(64),
            window: Window {
                opens_ms: 1100,
                closes_ms: 2100,
                starts_ms: 3100,
            },
        })),
    )
    .unwrap();
    let event = &h.journal.state().domain.inner.events["event"];
    assert_eq!(event.phase, Phase::Draft);
    assert_eq!(event.epoch, 2);
    assert_eq!(event.title, "Revised event");
    assert_eq!(event.window.starts_ms, 3100);
    h.run(1, A::Domain(F::Inner(E::Submit { id: "event".into() })))
        .unwrap();
    h.denied(
        2,
        A::Domain(F::Approve {
            instance: "initial".into(),
            comment_hash: HASH.into(),
        }),
    );
    h.run(
        1,
        A::Domain(F::StartPresidents {
            id: "revised".into(),
            payload: payload(2),
        }),
    )
    .unwrap();
    h.presidents("revised");
    // A participating president can carry out the completed management request.
    h.run(
        3,
        A::Domain(F::Execute {
            instance: "revised".into(),
        }),
    )
    .unwrap();
    assert_eq!(
        h.journal.state().domain.inner.events["event"].phase,
        Phase::Approved
    );
    let state = h.journal.state().clone();
    drop(h.journal);
    assert_eq!(
        Journal::<Office>::open(&h.path, h.genesis).unwrap().state(),
        &state
    );
}

#[test]
fn managers_are_scoped_and_presidency_is_rechecked_after_signing() {
    let mut h = Harness::new();
    h.denied(
        1,
        A::Domain(F::Inner(E::Create {
            id: "manager-draft".into(),
            title: "Forbidden".into(),
            brief_hash: HASH.into(),
            window: Window {
                opens_ms: 1000,
                closes_ms: 2000,
                starts_ms: 3000,
            },
        })),
    );
    h.denied(
        3,
        A::Domain(F::Inner(E::Amend {
            id: "event".into(),
            brief_hash: "b".repeat(64),
        })),
    );
    h.run(
        1,
        A::Domain(F::StartPresidents {
            id: "presidents".into(),
            payload: E::Approve {
                id: "event".into(),
                epoch: 1,
                co_organizers: ["b".into()].into(),
            },
        }),
    )
    .unwrap();
    h.presidents("presidents");
    h.run(
        0,
        A::SetMemberRoles {
            member: "bob".into(),
            roles: ["manager".into()].into(),
        },
    )
    .unwrap();
    h.denied(
        1,
        A::Domain(F::Execute {
            instance: "presidents".into(),
        }),
    );
    assert_eq!(
        h.journal.state().domain.inner.events["event"].phase,
        Phase::Review
    );
}

#[test]
fn replacement_president_can_replace_an_invalid_signature_before_quorum() {
    let mut h = Harness::new();
    h.run(
        1,
        A::Domain(F::StartPresidents {
            id: "succession".into(),
            payload: E::Approve {
                id: "event".into(),
                epoch: 1,
                co_organizers: ["b".into()].into(),
            },
        }),
    )
    .unwrap();
    h.vote(2, "succession").unwrap();
    for (member, role) in [("bob", "manager"), ("dave", "president")] {
        h.run(
            0,
            A::SetMemberRoles {
                member: member.into(),
                roles: [role.into()].into(),
            },
        )
        .unwrap();
    }
    h.denied(
        2,
        A::Domain(F::Approve {
            instance: "succession".into(),
            comment_hash: HASH.into(),
        }),
    );
    h.vote(4, "succession").unwrap();
    h.vote(3, "succession").unwrap();
    h.run(
        4,
        A::Domain(F::Execute {
            instance: "succession".into(),
        }),
    )
    .unwrap();
    assert_eq!(
        h.journal.state().domain.inner.events["event"].phase,
        Phase::Approved
    );
    assert_eq!(
        h.journal.state().domain.flows["succession"].records[0].approvals["a"].device,
        h.keys[4].peer_id().to_string()
    );
}
