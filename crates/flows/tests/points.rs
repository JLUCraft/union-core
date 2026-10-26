#[path = "../../../tests/support/mod.rs"]
mod support;
use events::{
    EventAction as E, EventsDomain,
    workflows::{Automation, OrganizationAction as O, Report, ReportKind, ReportStatus},
};
use flows::{
    Approver, FlowAction as F, Flows, Stage, Status, Template, TimeoutPolicy,
    ai::{AiPricing, AiWorker, Settlement},
};
use identity::Identity;
use protocol::{Cid, Error, LlmUsage, Result};
use state::{State, governance::Action as A};
type Application = Flows<EventsDomain>;
struct Harness {
    ids: support::Identities,
    keys: Vec<Identity>,
    state: State<Application>,
    now: u64,
}
impl Harness {
    fn new(settlement: Settlement) -> Self {
        let keys: Vec<_> = (0..3).map(|_| Identity::generate()).collect();
        let ids = support::Identities::new(
            &[
                (&keys[0], "admin", "a"),
                (&keys[1], "alice", "a"),
                (&keys[2], "worker", "b"),
            ],
            "admin",
        );
        let mut state = ids.genesis::<Application>();
        state
            .domain
            .ai_pricing
            .insert("model".into(), pricing(settlement));
        state.domain.ai_workers.insert(
            "worker".into(),
            AiWorker {
                models: ["model".into()].into(),
                active: true,
            },
        );
        state
            .domain
            .inner
            .organization
            .points
            .insert("a".into(), [("alice".into(), 100)].into());
        Self {
            ids,
            keys,
            state,
            now: 10,
        }
    }
    fn run(&mut self, key: usize, action: F<EventsDomain>) -> Result<()> {
        self.now += 1;
        self.state.apply(
            &self.keys[key].peer_id().to_string(),
            self.state.revision,
            self.now,
            A::Domain(action),
            self.ids.log.state(),
        )
    }
    fn file(&mut self, content: &[u8]) -> Cid {
        let (cid, blocks) = self
            .state
            .domain
            .inner
            .files
            .version(None, content)
            .unwrap();
        for block in blocks {
            self.run(1, F::Inner(E::PutBlock { block })).unwrap();
        }
        cid
    }
    fn request(&mut self, id: &str, input: Cid, max_points: u64) -> Result<()> {
        self.run(
            1,
            F::RequestAi {
                id: id.into(),
                input,
                worker: "worker".into(),
                model: "model".into(),
                max_tokens: 1000,
                max_points,
            },
        )
    }
    fn claim(&mut self, id: &str) -> flows::AiJob {
        let job = flows::ai_job(&self.state.domain, id).unwrap().unwrap();
        self.run(
            2,
            F::ClaimAi {
                instance: id.into(),
                job: job.job.clone(),
                attempt: job.attempt,
            },
        )
        .unwrap();
        job
    }
    fn finish(
        &mut self,
        job: &flows::AiJob,
        output: Option<Cid>,
        usage: Option<LlmUsage>,
        error: Option<String>,
    ) -> Result<()> {
        self.run(
            2,
            F::FinishAi {
                instance: job.instance.clone(),
                job: job.job.clone(),
                attempt: job.attempt,
                output,
                usage,
                error,
            },
        )
    }
    fn balance(&self) -> u64 {
        self.state.domain.inner.organization.points["a"]["alice"]
    }
}
fn pricing(settlement: Settlement) -> AiPricing {
    AiPricing {
        base_points: 2,
        input_points_per_1k: 1,
        output_points_per_1k: 3,
        max_input_tokens: 1000,
        settlement,
    }
}
fn usage() -> LlmUsage {
    LlmUsage {
        prompt_tokens: 100,
        completion_tokens: 200,
        total_tokens: 300,
    }
}
fn stage() -> Stage {
    Stage {
        name: "Generate".into(),
        approver: Approver::Ai {
            mode: flows::AiMode::Generate,
            worker: "worker".into(),
            model: "model".into(),
            purpose: "member.assist".into(),
            privacy: protocol::Privacy::Sensitive,
            max_tokens: 1000,
        },
        timeout_ms: None,
        on_timeout: TimeoutPolicy::Reject,
    }
}

#[test]
fn fee_rounding_is_once_per_combined_usage_and_overflows_do_not_wrap() {
    let price = AiPricing {
        base_points: 0,
        input_points_per_1k: 1,
        output_points_per_1k: 1,
        max_input_tokens: 1,
        settlement: Settlement::Burn,
    };
    assert_eq!(price.cost(1, 1).unwrap(), 1);
    assert_eq!(pricing(Settlement::Burn).quote(1000).unwrap(), 6);
    let overflow = AiPricing {
        base_points: u64::MAX,
        input_points_per_1k: 1,
        output_points_per_1k: 1,
        max_input_tokens: 1,
        settlement: Settlement::Burn,
    };
    assert!(overflow.quote(1).is_err());
}
#[test]
fn requester_maximum_and_balance_are_checked_before_a_job_exists() {
    let mut h = Harness::new(Settlement::Burn);
    let input = h.file(b"paid task");
    assert!(h.request("too-expensive", input.clone(), 5).is_err());
    assert_eq!(h.balance(), 100);
    assert!(h.state.domain.flows.is_empty());
    h.state
        .domain
        .inner
        .organization
        .points
        .get_mut("a")
        .unwrap()
        .insert("alice".into(), 5);
    assert!(h.request("insufficient", input, 6).is_err());
    assert_eq!(h.balance(), 5);
    assert!(h.state.domain.flows.is_empty());
}
#[test]
fn a_price_snapshot_settles_actual_usage_and_rewards_or_burns_exactly_once() {
    for settlement in [Settlement::Burn, Settlement::ProviderReward] {
        let mut h = Harness::new(settlement);
        let input = h.file(b"paid task");
        h.request("job", input, 6).unwrap();
        assert_eq!(h.balance(), 94);
        assert_eq!(h.state.domain.flows["job"].records[0].escrowed_points, 6);
        let job = h.claim("job");
        let changed = AiPricing {
            base_points: 999,
            ..pricing(settlement)
        };
        h.run(
            0,
            F::AiPricing {
                model: "model".into(),
                pricing: changed,
            },
        )
        .unwrap();
        let output = h.file(b"generated result");
        h.finish(&job, Some(output.clone()), Some(usage()), None)
            .unwrap();
        assert_eq!(h.balance(), 97);
        let record = &h.state.domain.flows["job"].records[0];
        assert_eq!(record.escrowed_points, 0);
        assert_eq!(record.refunded_points, 3);
        assert_eq!(record.ai_runs[0].charged_points, 3);
        assert!(h.finish(&job, Some(output), Some(usage()), None).is_err());
        assert_eq!(h.balance(), 97);
        if settlement == Settlement::Burn {
            assert_eq!(h.state.domain.ai_burned_points, 3);
        } else {
            assert_eq!(h.state.domain.inner.organization.points["b"]["worker"], 3);
            assert_eq!(h.state.domain.ai_burned_points, 0);
        }
    }
}
#[test]
fn failed_calls_refund_in_full_and_retry_requires_a_new_reservation() {
    let mut h = Harness::new(Settlement::Burn);
    let input = h.file(b"paid task");
    h.request("job", input, 6).unwrap();
    let first = h.claim("job");
    h.finish(&first, None, None, Some("provider unavailable".into()))
        .unwrap();
    assert_eq!(h.balance(), 100);
    assert_eq!(
        h.state.domain.flows["job"].records[0].ai_runs[0].refunded_points,
        6
    );
    h.run(
        1,
        F::RetryAi {
            instance: "job".into(),
        },
    )
    .unwrap();
    assert_eq!(h.balance(), 94);
    let second = h.claim("job");
    assert_eq!(second.attempt, 1);
    let output = h.file(b"recovered result");
    h.finish(&second, Some(output), Some(usage()), None)
        .unwrap();
    assert_eq!(h.balance(), 97);
    assert_eq!(h.state.domain.flows["job"].records[0].refunded_points, 9);
}
#[test]
fn cancel_and_explicit_timeout_release_all_unspent_stages() {
    for claimed in [false, true] {
        let mut h = Harness::new(Settlement::Burn);
        let input = h.file(b"paid task");
        h.request("job", input, 6).unwrap();
        if claimed {
            h.claim("job");
        }
        h.run(
            1,
            F::Cancel {
                instance: "job".into(),
            },
        )
        .unwrap();
        assert_eq!(h.balance(), 100);
        assert!(
            h.run(
                1,
                F::Cancel {
                    instance: "job".into()
                }
            )
            .is_err()
        );
        assert_eq!(h.balance(), 100);
    }
    let mut h = Harness::new(Settlement::Burn);
    let input = h.file(b"paid task");
    h.request("timeout", input, 6).unwrap();
    h.claim("timeout");
    h.now = h.state.domain.flows["timeout"].deadline_ms.unwrap();
    h.run(
        1,
        F::Poke {
            instance: "timeout".into(),
        },
    )
    .unwrap();
    assert_eq!(h.balance(), 100);
    assert_eq!(h.state.domain.flows["timeout"].status, Status::Rejected);
    assert_eq!(
        h.state.domain.flows["timeout"].records[0].ai_runs[0].refunded_points,
        6
    );
}
#[test]
fn unmetered_receipts_and_reward_overflow_leave_the_reservation_atomic() {
    let mut h = Harness::new(Settlement::ProviderReward);
    let input = h.file(b"paid task");
    h.request("job", input, 6).unwrap();
    let job = h.claim("job");
    let output = h.file(b"result");
    assert!(h.finish(&job, Some(output.clone()), None, None).is_err());
    assert!(
        h.finish(
            &job,
            Some(output.clone()),
            Some(LlmUsage {
                total_tokens: 301,
                ..usage()
            }),
            None
        )
        .is_err()
    );
    assert_eq!(h.balance(), 94);
    assert_eq!(h.state.domain.flows["job"].records[0].escrowed_points, 6);
    h.state
        .domain
        .inner
        .organization
        .points
        .insert("b".into(), [("worker".into(), u64::MAX)].into());
    assert!(matches!(
        h.finish(&job, Some(output), Some(usage()), None),
        Err(Error::Capacity)
    ));
    assert_eq!(h.balance(), 94);
    assert_eq!(h.state.domain.flows["job"].records[0].escrowed_points, 6);
    h.run(
        1,
        F::Cancel {
            instance: "job".into(),
        },
    )
    .unwrap();
    assert_eq!(h.balance(), 100);
}
#[test]
fn multi_stage_prepayment_and_cancellation_conserve_the_original_balance() {
    let mut h = Harness::new(Settlement::Burn);
    let input = h.file(b"paid task");
    h.run(
        0,
        F::InstallTemplate {
            id: "two-stages".into(),
            template: Template {
                name: "Two paid stages".into(),
                stages: vec![stage(), stage()],
                payload_kinds: ["organization.ai_document".into()].into(),
            },
        },
    )
    .unwrap();
    h.run(
        1,
        F::Start {
            id: "job".into(),
            template: "two-stages".into(),
            max_points: 12,
            payload: E::Organization(O::AiDocument {
                id: "document".into(),
                member: "alice".into(),
                worker: "worker".into(),
            }),
            input: Some(input),
        },
    )
    .unwrap();
    assert_eq!(h.balance(), 88);
    let job = h.claim("job");
    let output = h.file(b"stage one");
    h.finish(&job, Some(output), Some(usage()), None).unwrap();
    assert_eq!(h.balance(), 91);
    assert_eq!(h.state.domain.flows["job"].current, 1);
    h.run(
        1,
        F::Cancel {
            instance: "job".into(),
        },
    )
    .unwrap();
    assert_eq!(h.balance(), 97);
    assert_eq!(h.state.domain.ai_burned_points, 3);
}
#[test]
fn automatic_work_cannot_charge_a_member_without_scoped_consent_or_revive_revoked_consent() {
    let mut h = Harness::new(Settlement::Burn);
    let input = h.file(b"scoped annual report evidence");
    h.state.domain.inner.organization.automation = Some(Automation {
        worker: "worker".into(),
        model: "model".into(),
        max_tokens: 1000,
        timeout_ms: 1000,
    });
    h.state.domain.inner.organization.reports.insert(
        "annual".into(),
        Report {
            club: "a".into(),
            creator: "alice".into(),
            kind: ReportKind::MuaAnnual,
            period_start_ms: 0,
            period_end_ms: 1,
            recipient: "mua".into(),
            requirements: input.clone(),
            evidence: input.clone(),
            output: None,
            status: ReportStatus::Generating,
            version: 1,
            worker: "worker".into(),
        },
    );
    h.now += 1;
    h.state
        .apply(
            &h.keys[0].peer_id().to_string(),
            h.state.revision,
            h.now,
            A::SetMemberRoles {
                member: "alice".into(),
                roles: ["manager".into()].into(),
            },
            h.ids.log.state(),
        )
        .unwrap();
    let action = F::StartRequirements {
        id: "automatic".into(),
        payload: E::Organization(O::ReportGenerated {
            id: "annual".into(),
            version: 1,
        }),
        input: input.clone(),
        stage: stage(),
    };
    assert!(h.run(2, action.clone()).is_err());
    assert_eq!(h.balance(), 100);
    h.run(
        1,
        F::Inner(E::Organization(O::AuthorizeAi {
            scope: "report:annual".into(),
            budget: 6,
        })),
    )
    .unwrap();
    h.run(2, action).unwrap();
    assert_eq!(h.balance(), 94);
    assert_eq!(h.state.domain.flows["automatic"].payer.member, "alice");
    h.run(
        1,
        F::Inner(E::Organization(O::AuthorizeAi {
            scope: "report:annual".into(),
            budget: 0,
        })),
    )
    .unwrap();
    h.run(
        1,
        F::Cancel {
            instance: "automatic".into(),
        },
    )
    .unwrap();
    assert_eq!(h.balance(), 100);
    assert_eq!(
        h.state.domain.inner.organization.ai_allowances["report:annual"].remaining_points,
        0
    );
}
#[test]
fn incoming_mints_cannot_make_an_existing_hold_unrefundable() {
    let mut h = Harness::new(Settlement::Burn);
    let input = h.file(b"paid task");
    h.request("job", input, 6).unwrap();
    h.state
        .domain
        .inner
        .organization
        .points
        .get_mut("a")
        .unwrap()
        .insert("alice".into(), u64::MAX - 6);
    h.run(
        0,
        F::Inner(E::Organization(O::ActivityPolicy {
            policy: events::points::ActivityPolicy {
                daily_member_cap: 100,
            },
        })),
    )
    .unwrap();
    h.run(
        0,
        F::Inner(E::Organization(O::OracleSource {
            id: "source".into(),
            source: events::points::OracleSourcePolicy {
                title: "Source".into(),
                club: "a".into(),
                oracle_device: h.keys[2].peer_id().to_string(),
                service: "source".into(),
                weight_bps: 10000,
                points_per_slice: 1,
                max_bonus_per_slice: 0,
                daily_source_cap: 100,
                enabled: true,
            },
        })),
    )
    .unwrap();
    let attestation = events::points::Attestation {
        source: "source".into(),
        window_start_ms: 0,
        window_end_ms: events::points::ACTIVITY_SLICE_MS,
        players: [(
            "alice".into(),
            events::points::ActivityTotals {
                active_slices: 1,
                ..Default::default()
            },
        )]
        .into(),
    };
    let telemetry =
        h.file(&serde_json::to_vec(&serde_json::json!({"attestation":attestation})).unwrap());
    let evidence = events::points::ActivityEvidence::block(&attestation, telemetry).unwrap();
    h.now = events::points::ACTIVITY_SLICE_MS;
    assert!(matches!(
        h.run(
            2,
            F::Inner(E::Organization(O::ActivityAttest {
                source: attestation.source,
                window_start_ms: attestation.window_start_ms,
                window_end_ms: attestation.window_end_ms,
                players: attestation.players,
                evidence
            }))
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(h.balance(), u64::MAX - 6);
    assert_eq!(
        h.state.domain.inner.organization.oracle_sources["source"].last_window_end_ms,
        0
    );
    h.run(
        1,
        F::Cancel {
            instance: "job".into(),
        },
    )
    .unwrap();
    assert_eq!(h.balance(), u64::MAX);
}
