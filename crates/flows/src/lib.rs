#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Versioned, deterministic approval workflows composed around another Domain.
pub mod ai;
use protocol::{Error, Result};
use serde::{Deserialize, Serialize};
use state::{Context, CoreView, Domain};
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

const MAX_RECORDS: usize = 10_000;
const MAX_STAGES: usize = 16;
const MAX_VERSIONS: usize = 32;
const MAX_TIMEOUT_MS: u64 = 30 * 86_400_000;
const MAX_APPROVAL_CLUBS: usize = 128;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Flows<D: Domain>(PhantomData<D>);
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "")]
pub struct FlowsState<D: Domain> {
    #[serde(flatten)]
    pub inner: D::State,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub flow_templates: BTreeMap<String, Versions>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub flows: BTreeMap<String, Instance<D>>,
    pub ai_pricing: BTreeMap<String, ai::AiPricing>,
    pub ai_workers: BTreeMap<String, ai::AiWorker>,
    pub ai_burned_points: u64,
}
impl<D: Domain> std::ops::Deref for FlowsState<D> {
    type Target = D::State;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl<D: Domain> std::ops::DerefMut for FlowsState<D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Versions {
    pub active: bool,
    pub versions: Vec<Template>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub name: String,
    pub stages: Vec<Stage>,
    pub payload_kinds: BTreeSet<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Stage {
    pub name: String,
    pub approver: Approver,
    pub timeout_ms: Option<u64>,
    pub on_timeout: TimeoutPolicy,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Approver {
    Ai {
        mode: AiMode,
        worker: String,
        model: String,
        purpose: String,
        privacy: protocol::Privacy,
        max_tokens: u32,
    },
    Member {
        member: String,
    },
    Role {
        club: String,
        role: String,
    },
    ClubQuorum {
        clubs: BTreeSet<String>,
        quorum: usize,
    },
    ClubPresidents {
        clubs: BTreeSet<String>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutPolicy {
    Escalate,
    Reject,
    AutoApprove,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,
    Approved,
    Executed,
    Rejected,
    ChangesRequested,
    Cancelled,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "")]
pub struct Instance<D: Domain> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<Template>,
    pub template: String,
    pub template_epoch: u64,
    pub payload: D::Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<protocol::Cid>,
    pub proposer: String,
    pub proposer_device: String,
    pub started_ms: u64,
    pub payer: protocol::PointAccount,
    pub allowance: Option<protocol::AiAllowance>,
    pub current: usize,
    pub records: Vec<StageRecord>,
    pub status: Status,
    pub deadline_ms: Option<u64>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageRecord {
    pub billing: Option<ai::Billing>,
    pub escrowed_points: u64,
    pub refunded_points: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ai_runs: Vec<AiRun>,
    pub approvals: BTreeMap<String, Approval>,
    pub delegations: BTreeMap<String, Delegation>,
    pub rejected: Option<Approval>,
    pub escalated: bool,
    pub auto_approved: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AiRun {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<AiReview>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub retry_requested: bool,
    pub job: String,
    pub device: String,
    pub usage: Option<protocol::LlmUsage>,
    pub charged_points: u64,
    pub refunded_points: u64,
    pub output: Option<protocol::Cid>,
    pub error: Option<String>,
}
#[derive(Clone, Debug)]
pub struct AiJob {
    pub mode: AiMode,
    pub instance: String,
    pub job: String,
    pub attempt: usize,
    pub input: protocol::Cid,
    pub worker: String,
    pub model: String,
    pub purpose: String,
    pub privacy: protocol::Privacy,
    pub max_tokens: u32,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AiMode {
    Generate,
    Review,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AiDecision {
    Approve,
    ChangesRequested,
    Reject,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AiReview {
    pub decision: AiDecision,
    pub summary: String,
    pub issues: Vec<String>,
}
const MAX_REVIEW_TEXT_BYTES: usize = 4096;
const MAX_REVIEW_ISSUES: usize = 32;

/// The worker and deterministic replay use the same output contract.
pub fn validate_ai_output(mode: AiMode, bytes: &[u8]) -> Result<Option<AiReview>> {
    let content = std::str::from_utf8(bytes).map_err(|_| Error::Denied)?;
    if content.trim().is_empty() {
        return Err(Error::Denied);
    }
    if mode == AiMode::Generate {
        return Ok(None);
    }
    let review: AiReview = serde_json::from_str(content).map_err(|_| Error::Denied)?;
    let valid_text = |s: &str| !s.trim().is_empty() && s.len() <= MAX_REVIEW_TEXT_BYTES;
    if !valid_text(&review.summary)
        || review.issues.len() > MAX_REVIEW_ISSUES
        || review.issues.iter().any(|s| !valid_text(s))
        || (review.decision != AiDecision::Approve && review.issues.is_empty())
    {
        return Err(Error::Denied);
    }
    Ok(Some(review))
}

pub const MAX_AI_OUTPUT_TOKENS: u32 = 8192;
const MAX_AI_ATTEMPTS: usize = 8;
fn is_false(value: &bool) -> bool {
    !*value
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Approval {
    pub device: String,
    pub comment_hash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Delegation {
    pub from_device: String,
    pub to_member: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", bound = "")]
pub enum FlowAction<D: Domain> {
    #[serde(rename = "flows.ai_pricing")]
    AiPricing {
        model: String,
        pricing: ai::AiPricing,
    },
    #[serde(rename = "flows.ai_worker")]
    AiWorker {
        models: BTreeSet<String>,
        active: bool,
    },
    #[serde(rename = "flows.request_ai")]
    RequestAi {
        id: String,
        input: protocol::Cid,
        worker: String,
        model: String,
        max_tokens: u32,
        max_points: u64,
    },
    #[serde(rename = "flows.claim_ai")]
    ClaimAi {
        instance: String,
        job: String,
        attempt: usize,
    },
    #[serde(rename = "flows.finish_ai")]
    FinishAi {
        instance: String,
        job: String,
        attempt: usize,
        output: Option<protocol::Cid>,
        usage: Option<protocol::LlmUsage>,
        error: Option<String>,
    },
    #[serde(rename = "flows.retry_ai")]
    RetryAi { instance: String },
    #[serde(rename = "flows.install_template")]
    InstallTemplate { id: String, template: Template },
    #[serde(rename = "flows.retire_template")]
    RetireTemplate { id: String },
    #[serde(rename = "flows.start_requirements")]
    StartRequirements {
        id: String,
        payload: D::Action,
        input: protocol::Cid,
        stage: Stage,
    },
    #[serde(rename = "flows.start_presidents")]
    StartPresidents { id: String, payload: D::Action },
    #[serde(rename = "flows.start")]
    Start {
        id: String,
        template: String,
        max_points: u64,
        payload: D::Action,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input: Option<protocol::Cid>,
    },
    #[serde(rename = "flows.approve")]
    Approve {
        instance: String,
        comment_hash: String,
    },
    #[serde(rename = "flows.reject")]
    Reject { instance: String, reason: String },
    #[serde(rename = "flows.delegate")]
    Delegate { instance: String, to: String },
    #[serde(rename = "flows.poke")]
    Poke { instance: String },
    #[serde(rename = "flows.cancel")]
    Cancel { instance: String },
    #[serde(rename = "flows.execute")]
    Execute { instance: String },
    #[serde(untagged)]
    Inner(D::Action),
}
fn text(s: &str) -> Result<()> {
    state::governance::identifier(s)
}
fn administer(ctx: &Context<'_>) -> bool {
    ctx.core.admins.contains(ctx.actor)
        || ctx
            .member()
            .is_ok_and(|(_, m)| m.roles.contains("president"))
}
fn kind<A: Serialize>(action: &A) -> Result<String> {
    serde_json::to_value(action)
        .map_err(|e| Error::Protocol(e.to_string()))?
        .get("type")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(Error::Denied)
}
fn member<'a>(
    core: CoreView<'a>,
    device: &str,
) -> Option<(&'a str, &'a state::governance::Member)> {
    core.members
        .iter()
        .find(|(_, m)| m.owns(device))
        .map(|(id, m)| (id.as_str(), m))
}
fn eligible(approver: &Approver, core: CoreView<'_>, device: &str) -> Option<String> {
    let (id, m) = member(core, device)?;
    match approver {
        Approver::Member { member } if member == id => Some("member".into()),
        Approver::Role { club, role } if club == &m.club && m.roles.contains(role) => {
            Some("role".into())
        }
        Approver::ClubQuorum { clubs, .. } if clubs.contains(&m.club) => Some(m.club.clone()),
        Approver::ClubPresidents { clubs }
            if clubs.contains(&m.club) && m.roles.contains("president") =>
        {
            Some(m.club.clone())
        }
        _ => None,
    }
}

fn authorized(
    approver: &Approver,
    core: CoreView<'_>,
    record: &StageRecord,
    device: &str,
) -> Result<String> {
    if let Some((id, target)) = member(core, device) {
        for (slot, delegation) in &record.delegations {
            if delegation.to_member == id
                && eligible(approver, core, &delegation.from_device).as_ref() == Some(slot)
                && member(core, &delegation.from_device)
                    .is_some_and(|(_, owner)| owner.club == target.club)
            {
                return Ok(slot.clone());
            }
        }
    }
    eligible(approver, core, device)
        .filter(|slot| !record.delegations.contains_key(slot))
        .ok_or(Error::Denied)
}
fn threshold(approver: &Approver) -> Result<usize> {
    Ok(match approver {
        Approver::ClubQuorum { quorum, .. } => *quorum,
        Approver::ClubPresidents { clubs } => clubs.len(),
        _ => 1,
    })
}
fn approved(stage: &Stage, record: &StageRecord, core: CoreView<'_>) -> Result<bool> {
    if let Approver::Ai { worker, mode, .. } = &stage.approver {
        return Ok(record.ai_runs.last().is_some_and(|run| {
            run.output.is_some()
                && match mode {
                    AiMode::Generate => run.review.is_none(),
                    AiMode::Review => run
                        .review
                        .as_ref()
                        .is_some_and(|r| r.decision == AiDecision::Approve),
                }
                && run.error.is_none()
                && member(core, &run.device).is_some_and(|(id, _)| id == worker)
        }));
    }
    let valid = record
        .approvals
        .iter()
        .filter(|(slot, approval)| {
            authorized(&stage.approver, core, record, &approval.device)
                .is_ok_and(|actual| &actual == *slot)
        })
        .count();
    Ok(valid >= threshold(&stage.approver)?)
}
fn validate_template(template: &Template, core: CoreView<'_>) -> Result<()> {
    text(&template.name)?;
    if template.stages.is_empty()
        || template.stages.len() > MAX_STAGES
        || template.payload_kinds.is_empty()
        || template.payload_kinds.len() > 64
    {
        return Err(Error::Denied);
    }
    for name in &template.payload_kinds {
        text(name)?;
        if !name.contains('.') || name.starts_with("flows.") {
            return Err(Error::Denied);
        }
    }
    for (i, stage) in template.stages.iter().enumerate() {
        text(&stage.name)?;
        if stage
            .timeout_ms
            .is_some_and(|ms| ms == 0 || ms > MAX_TIMEOUT_MS)
            || (stage.on_timeout == TimeoutPolicy::Escalate && i + 1 == template.stages.len())
        {
            return Err(Error::Denied);
        }
        match &stage.approver {
            Approver::ClubPresidents { clubs } => {
                if clubs.is_empty()
                    || clubs.len() > MAX_APPROVAL_CLUBS
                    || stage.timeout_ms.is_some()
                    || stage.on_timeout != TimeoutPolicy::Reject
                    || clubs.iter().any(|club| {
                        !core
                            .members
                            .values()
                            .any(|m| &m.club == club && m.roles.contains("president"))
                    })
                {
                    return Err(Error::Denied);
                }
            }
            Approver::Ai {
                worker,
                model,
                purpose,
                max_tokens,
                ..
            } => {
                if !core.members.contains_key(worker)
                    || *max_tokens == 0
                    || *max_tokens > MAX_AI_OUTPUT_TOKENS
                    || stage.on_timeout != TimeoutPolicy::Reject
                {
                    return Err(Error::Denied);
                }
                text(model)?;
                text(purpose)?;
            }
            Approver::Member { member } if !core.members.contains_key(member) => {
                return Err(Error::Denied);
            }
            Approver::Role { club, role } => {
                text(role)?;
                if !core.members.values().any(|m| &m.club == club) {
                    return Err(Error::Denied);
                }
            }
            Approver::ClubQuorum { clubs, quorum }
                if (*quorum == 0
                    || *quorum > clubs.len()
                    || clubs.len() > MAX_APPROVAL_CLUBS
                    || clubs
                        .iter()
                        .any(|club| !core.members.values().any(|m| &m.club == club))) =>
            {
                return Err(Error::Denied);
            }
            _ => {}
        }
    }
    Ok(())
}
/// An active flow whose stage deadline has not yet passed.
fn live_flow<'a, D: Domain>(
    flows: &'a mut BTreeMap<String, Instance<D>>,
    id: &str,
    now_ms: u64,
) -> Result<&'a mut Instance<D>> {
    let flow = flows.get_mut(id).ok_or(Error::NotFound)?;
    if flow.status != Status::Active || flow.deadline_ms.is_some_and(|t| now_ms >= t) {
        return Err(Error::Denied);
    }
    Ok(flow)
}
pub fn template_for<'a, D: Domain>(
    templates: &'a BTreeMap<String, Versions>,
    flow: &'a Instance<D>,
) -> Result<&'a Template> {
    if let Some(workflow) = &flow.workflow {
        return Ok(workflow);
    }
    let index = usize::try_from(flow.template_epoch)
        .map_err(|_| Error::Denied)?
        .checked_sub(1)
        .ok_or(Error::Denied)?;
    templates
        .get(&flow.template)
        .and_then(|v| v.versions.get(index))
        .ok_or(Error::NotFound)
}
fn deadline(stage: &Stage, now: u64) -> Result<Option<u64>> {
    stage
        .timeout_ms
        .map(|ms| now.checked_add(ms).ok_or(Error::Capacity))
        .transpose()
}
fn advance<D: Domain>(flow: &mut Instance<D>, template: &Template, now: u64) -> Result<()> {
    flow.current = flow.current.checked_add(1).ok_or(Error::Capacity)?;
    if let Some(stage) = template.stages.get(flow.current) {
        flow.deadline_ms = deadline(stage, now)?;
    } else {
        flow.status = Status::Approved;
        flow.deadline_ms = None;
    }
    Ok(())
}
impl<D: Domain> Domain for Flows<D> {
    fn artifact(state: &Self::State, cid: &str) -> Result<Vec<u8>> {
        D::artifact(&state.inner, cid)
    }
    type State = FlowsState<D>;
    type Action = FlowAction<D>;
    fn transition(state: &mut Self::State, ctx: &Context<'_>, action: Self::Action) -> Result<()> {
        match action {
            FlowAction::AiPricing { model, pricing } => {
                if !ctx.core.admins.contains(ctx.actor) {
                    return Err(Error::Denied);
                }
                text(&model)?;
                pricing.validate()?;
                if !state.ai_pricing.contains_key(&model) && state.ai_pricing.len() >= MAX_RECORDS {
                    return Err(Error::Capacity);
                }
                state.ai_pricing.insert(model, pricing);
            }
            FlowAction::AiWorker { models, active } => {
                let worker = ctx.member()?.0.to_owned();
                if models.is_empty() || models.len() > MAX_RECORDS {
                    return Err(Error::Denied);
                }
                for model in &models {
                    text(model)?;
                }
                if !state.ai_workers.contains_key(&worker) && state.ai_workers.len() >= MAX_RECORDS
                {
                    return Err(Error::Capacity);
                }
                state
                    .ai_workers
                    .insert(worker, ai::AiWorker { models, active });
            }
            FlowAction::RequestAi {
                id,
                input,
                worker,
                model,
                max_tokens,
                max_points,
            } => {
                let payload = D::ai_document_action(&id, ctx.member()?.0, &worker)?;
                let definition = Template {
                    name: "Member AI request".into(),
                    payload_kinds: [kind(&payload)?].into(),
                    stages: vec![Stage {
                        name: "Generate document".into(),
                        approver: Approver::Ai {
                            mode: AiMode::Generate,
                            worker,
                            model,
                            purpose: "member.assist".into(),
                            privacy: protocol::Privacy::Sensitive,
                            max_tokens,
                        },
                        timeout_ms: Some(ai::MEMBER_REQUEST_TIMEOUT_MS),
                        on_timeout: TimeoutPolicy::Reject,
                    }],
                };
                begin(
                    state,
                    ctx,
                    StartDefinition {
                        id,
                        payload,
                        input: Some(input),
                        definition,
                        reference: None,
                        automatic: false,
                        max_points: Some(max_points),
                    },
                )?;
            }
            FlowAction::Inner(action) => D::transition(&mut state.inner, ctx, action)?,
            FlowAction::InstallTemplate { id, template } => {
                if !administer(ctx) {
                    return Err(Error::Denied);
                }
                text(&id)?;
                validate_template(&template, ctx.core)?;
                if !state.flow_templates.contains_key(&id)
                    && state.flow_templates.len() >= MAX_RECORDS
                {
                    return Err(Error::Capacity);
                }
                let versions = state.flow_templates.entry(id).or_insert(Versions {
                    active: false,
                    versions: vec![],
                });
                if versions.versions.len() >= MAX_VERSIONS {
                    return Err(Error::Capacity);
                }
                versions.versions.push(template);
                versions.active = true;
            }
            FlowAction::RetireTemplate { id } => {
                if !administer(ctx) {
                    return Err(Error::Denied);
                }
                let versions = state.flow_templates.get_mut(&id).ok_or(Error::NotFound)?;
                if !versions.active {
                    return Err(Error::Denied);
                }
                versions.active = false;
            }
            FlowAction::Start {
                id,
                template,
                max_points,
                payload,
                input,
            } => {
                let versions = state.flow_templates.get(&template).ok_or(Error::NotFound)?;
                if !versions.active {
                    return Err(Error::Denied);
                }
                let definition = versions.versions.last().ok_or(Error::NotFound)?.clone();
                let epoch = versions.versions.len() as u64;
                begin(
                    state,
                    ctx,
                    StartDefinition {
                        id,
                        payload,
                        input,
                        definition,
                        reference: Some((template, epoch)),
                        automatic: false,
                        max_points: Some(max_points),
                    },
                )?;
            }
            FlowAction::StartRequirements {
                id,
                payload,
                input,
                stage,
            } => {
                let worker = D::workflow_worker(&state.inner, &payload).ok_or(Error::Denied)?;
                if ctx.member()?.0 != worker
                    || !matches!(&stage.approver,Approver::Ai{worker:owner,..} if owner==&worker)
                {
                    return Err(Error::Denied);
                }
                if D::workflow_input(&state.inner, &payload)?
                    != D::artifact(&state.inner, &input.to_string())?
                {
                    return Err(Error::Denied);
                }
                let definition = Template {
                    name: kind(&payload)?,
                    payload_kinds: [kind(&payload)?].into(),
                    stages: vec![stage],
                };
                begin(
                    state,
                    ctx,
                    StartDefinition {
                        id,
                        payload,
                        input: Some(input),
                        definition,
                        reference: None,
                        automatic: true,
                        max_points: None,
                    },
                )?;
            }
            FlowAction::StartPresidents { id, payload } => {
                let clubs = D::approval_clubs(&state.inner, &payload)?;
                let (_, member) = ctx.member()?;
                if clubs.is_empty()
                    || !clubs.contains(&member.club)
                    || !(ctx.core.admins.contains(ctx.actor)
                        || ["president", "admin", "manager"]
                            .iter()
                            .any(|role| member.roles.contains(*role)))
                    || D::requires_ai_review(&state.inner, &payload)
                {
                    return Err(Error::Denied);
                }
                begin(
                    state,
                    ctx,
                    StartDefinition {
                        id,
                        payload: payload.clone(),
                        input: None,
                        definition: Template {
                            name: "Club president approval".into(),
                            stages: Vec::new(),
                            payload_kinds: [kind(&payload)?].into(),
                        },
                        reference: None,
                        automatic: false,
                        max_points: Some(0),
                    },
                )?;
            }
            FlowAction::ClaimAi {
                instance,
                job,
                attempt,
            } => {
                let expected = ai_job(state, &instance)?.ok_or(Error::Denied)?;
                if expected.job != job
                    || expected.attempt != attempt
                    || ctx.member()?.0 != expected.worker
                {
                    return Err(Error::Denied);
                }
                if !state
                    .ai_workers
                    .get(&expected.worker)
                    .is_some_and(|w| w.active && w.models.contains(&expected.model))
                {
                    return Err(Error::Denied);
                }
                let flow = state.flows.get_mut(&instance).ok_or(Error::NotFound)?;
                if flow.records[flow.current].escrowed_points == 0
                    || flow.deadline_ms.is_some_and(|t| ctx.now_ms >= t)
                {
                    return Err(Error::Denied);
                }
                flow.records[flow.current].ai_runs.push(AiRun {
                    review: None,
                    usage: None,
                    charged_points: 0,
                    refunded_points: 0,
                    retry_requested: false,
                    job,
                    device: ctx.actor.into(),
                    output: None,
                    error: None,
                });
            }
            FlowAction::FinishAi {
                instance,
                job,
                attempt,
                output,
                usage,
                error,
            } => {
                if output.is_some() != usage.is_some()
                    || output.is_some() == error.is_some()
                    || error
                        .as_ref()
                        .is_some_and(|e| e.is_empty() || e.len() > 256)
                {
                    return Err(Error::Denied);
                }
                let flow = state.flows.get(&instance).ok_or(Error::NotFound)?;
                let template = template_for(&state.flow_templates, flow)?.clone();
                let Approver::Ai { mode, .. } = template
                    .stages
                    .get(flow.current)
                    .ok_or(Error::Denied)?
                    .approver
                else {
                    return Err(Error::Denied);
                };
                if output.is_some()
                    && flow.allowance.is_some()
                    && D::workflow_input(&state.inner, &flow.payload)?
                        != D::artifact(
                            &state.inner,
                            &flow.input.as_ref().ok_or(Error::Denied)?.to_string(),
                        )?
                {
                    return Err(Error::Denied);
                }
                let review = output
                    .as_ref()
                    .map(|cid| {
                        if mode == AiMode::Review
                            && D::review_artifact(&state.inner, &flow.payload)?
                                != flow.input.as_ref().ok_or(Error::Denied)?.to_string()
                        {
                            return Err(Error::Denied);
                        }
                        validate_ai_output(mode, &D::artifact(&state.inner, &cid.to_string())?)
                    })
                    .transpose()?
                    .flatten();
                ai::settle::<D>(state, ctx, &instance, &job, attempt, usage.as_ref())?;
                let flow = live_flow(&mut state.flows, &instance, ctx.now_ms)?;
                let template = template_for(&state.flow_templates, flow)?.clone();
                let Approver::Ai { worker, .. } = &template.stages[flow.current].approver else {
                    return Err(Error::Denied);
                };
                if ctx.member()?.0 != worker {
                    return Err(Error::Denied);
                }
                let record = &mut flow.records[flow.current];
                if record.ai_runs.len().checked_sub(1) != Some(attempt) {
                    return Err(Error::Denied);
                }
                let run = record.ai_runs.last_mut().ok_or(Error::Denied)?;
                if run.job != job
                    || run.device != ctx.actor
                    || run.output.is_some()
                    || run.retry_requested
                    || run.error.is_some()
                {
                    return Err(Error::Denied);
                }
                let success = output.is_some();
                let decision = review.as_ref().map(|r| r.decision);
                run.review = review;
                run.output = output;
                run.error = error;
                if success {
                    if matches!(
                        decision,
                        Some(AiDecision::ChangesRequested | AiDecision::Reject)
                    ) {
                        for future in flow.records.iter_mut().skip(flow.current + 1) {
                            ai::refund::<D>(&mut state.inner, future)?;
                        }
                    }
                    match decision {
                        Some(AiDecision::ChangesRequested) => {
                            flow.status = Status::ChangesRequested;
                            flow.deadline_ms = None;
                        }
                        Some(AiDecision::Reject) => {
                            flow.status = Status::Rejected;
                            flow.deadline_ms = None;
                        }
                        _ => advance(flow, &template, ctx.now_ms)?,
                    }
                }
            }
            FlowAction::RetryAi { instance } => {
                let flow = state.flows.get_mut(&instance).ok_or(Error::NotFound)?;
                if flow.status != Status::Active
                    || !(ctx.core.admins.contains(ctx.actor)
                        || ctx
                            .member()
                            .is_ok_and(|(id, _)| id == flow.proposer || id == flow.payer.member))
                {
                    return Err(Error::Denied);
                }
                let template = template_for(&state.flow_templates, flow)?.clone();
                if !matches!(template.stages[flow.current].approver, Approver::Ai { .. }) {
                    return Err(Error::Denied);
                }
                let runs = &mut flow.records[flow.current].ai_runs;
                if runs.len() >= MAX_AI_ATTEMPTS {
                    return Err(Error::Capacity);
                }
                let run = runs.last_mut().ok_or(Error::Denied)?;
                if run.output.is_some() || run.error.is_none() || run.retry_requested {
                    return Err(Error::Denied);
                }
                run.retry_requested = true;
                ai::reserve_retry::<D>(&mut state.inner, &mut flow.records[flow.current])?;
            }
            action @ (FlowAction::Approve { .. } | FlowAction::Reject { .. }) => {
                let (instance, comment_hash, reject) = match action {
                    FlowAction::Approve {
                        instance,
                        comment_hash,
                    } => (instance, comment_hash, false),
                    FlowAction::Reject { instance, reason } => (instance, reason, true),
                    _ => return Err(Error::Denied),
                };
                protocol::validate_digest(&comment_hash)?;
                let existing = state.flows.get(&instance).ok_or(Error::NotFound)?;
                D::approval_clubs(&state.inner, &existing.payload)?;
                let flow = live_flow(&mut state.flows, &instance, ctx.now_ms)?;
                let template = template_for(&state.flow_templates, flow)?.clone();
                let stage = template.stages.get(flow.current).ok_or(Error::Denied)?;
                let record = flow.records.get_mut(flow.current).ok_or(Error::Denied)?;
                let slot = authorized(&stage.approver, ctx.core, record, ctx.actor)?;
                let receipt = Approval {
                    device: ctx.actor.into(),
                    comment_hash,
                };
                if reject {
                    record.rejected = Some(receipt);
                    for record in &mut flow.records {
                        ai::refund::<D>(&mut state.inner, record)?;
                    }
                    flow.status = Status::Rejected;
                    flow.deadline_ms = None;
                } else {
                    if record.approvals.get(&slot).is_some_and(|old| {
                        authorized(&stage.approver, ctx.core, record, &old.device)
                            .is_ok_and(|old_slot| old_slot == slot)
                    }) {
                        return Err(Error::Denied);
                    }
                    record.approvals.insert(slot, receipt);
                    if approved(stage, record, ctx.core)? {
                        advance(flow, &template, ctx.now_ms)?;
                    }
                }
            }
            FlowAction::Delegate { instance, to } => {
                let flow = live_flow(&mut state.flows, &instance, ctx.now_ms)?;
                let template = template_for(&state.flow_templates, flow)?.clone();
                let stage = template.stages.get(flow.current).ok_or(Error::Denied)?;
                if matches!(stage.approver, Approver::ClubPresidents { .. }) {
                    return Err(Error::Denied);
                }
                let record = flow.records.get_mut(flow.current).ok_or(Error::Denied)?;
                let (from_id, from) = ctx.member()?;
                let target = ctx.core.members.get(&to).ok_or(Error::NotFound)?;
                let slot = eligible(&stage.approver, ctx.core, ctx.actor).ok_or(Error::Denied)?;
                if from.club != target.club
                    || to == from_id
                    || record.delegations.contains_key(&slot)
                    || record.approvals.contains_key(&slot)
                    || record.delegations.values().any(|d| d.to_member == from_id)
                {
                    return Err(Error::Denied);
                }
                record.delegations.insert(
                    slot,
                    Delegation {
                        from_device: ctx.actor.into(),
                        to_member: to,
                    },
                );
            }
            FlowAction::Poke { instance } => {
                ctx.member()?;
                let flow = state.flows.get_mut(&instance).ok_or(Error::NotFound)?;
                if flow.status != Status::Active || flow.deadline_ms.is_none_or(|t| ctx.now_ms < t)
                {
                    return Err(Error::Denied);
                }
                let template = template_for(&state.flow_templates, flow)?.clone();
                let stage = template.stages.get(flow.current).ok_or(Error::Denied)?;
                let record = flow.records.get_mut(flow.current).ok_or(Error::Denied)?;
                if let Some(run) = record.ai_runs.last_mut()
                    && run.output.is_none()
                    && run.error.is_none()
                {
                    run.error = Some("stage timed out".into());
                }
                ai::refund::<D>(&mut state.inner, record)?;
                match stage.on_timeout {
                    TimeoutPolicy::Reject => {
                        for future in flow.records.iter_mut().skip(flow.current + 1) {
                            ai::refund::<D>(&mut state.inner, future)?;
                        }
                        flow.status = Status::Rejected;
                        flow.deadline_ms = None;
                    }
                    TimeoutPolicy::Escalate => {
                        record.escalated = true;
                        advance(flow, &template, ctx.now_ms)?;
                    }
                    TimeoutPolicy::AutoApprove => {
                        record.auto_approved = true;
                        advance(flow, &template, ctx.now_ms)?;
                    }
                }
            }
            FlowAction::Cancel { instance } => {
                let flow = state.flows.get_mut(&instance).ok_or(Error::NotFound)?;
                if !matches!(flow.status, Status::Active | Status::Approved)
                    || !(ctx.core.admins.contains(ctx.actor)
                        || ctx
                            .member()
                            .is_ok_and(|(id, _)| id == flow.proposer || id == flow.payer.member))
                {
                    return Err(Error::Denied);
                }
                if let Some(run) = flow
                    .records
                    .get_mut(flow.current)
                    .and_then(|r| r.ai_runs.last_mut())
                    && run.output.is_none()
                    && run.error.is_none()
                {
                    run.error = Some("flow cancelled".into());
                }
                for record in &mut flow.records {
                    ai::refund::<D>(&mut state.inner, record)?;
                }
                flow.status = Status::Cancelled;
                flow.deadline_ms = None;
            }
            FlowAction::Execute { instance } => {
                let existing = state.flows.get(&instance).ok_or(Error::NotFound)?;
                let clubs = D::approval_clubs(&state.inner, &existing.payload)?;
                let worker = D::workflow_worker(&state.inner, &existing.payload);
                let flow = state.flows.get_mut(&instance).ok_or(Error::NotFound)?;
                if flow.status != Status::Approved
                    || !(ctx.core.admins.contains(ctx.actor)
                        || ctx.member().is_ok_and(|(id, m)| {
                            id == flow.proposer
                                || worker.as_deref() == Some(id)
                                || (m.roles.contains("president") && clubs.contains(&m.club))
                        }))
                    || !member(ctx.core, &flow.proposer_device)
                        .is_some_and(|(id, _)| id == flow.proposer)
                {
                    return Err(Error::Denied);
                }
                let template = template_for(&state.flow_templates, flow)?.clone();
                if !template.payload_kinds.contains(&kind(&flow.payload)?) {
                    return Err(Error::Denied);
                }
                for (stage, record) in template.stages.iter().zip(&flow.records) {
                    if !record.escalated
                        && !record.auto_approved
                        && !approved(stage, record, ctx.core)?
                    {
                        return Err(Error::Denied);
                    }
                }
                let approved_ctx = Context {
                    actor: &flow.proposer_device,
                    now_ms: ctx.now_ms,
                    revision: ctx.revision,
                    core: ctx.core,
                    approved: true,
                };
                let artifact = flow.records.iter().rev().find_map(|r| {
                    r.ai_runs
                        .last()
                        .filter(|r| r.review.is_none())
                        .and_then(|r| r.output.as_ref())
                        .map(ToString::to_string)
                });
                D::transition_with_artifact(
                    &mut state.inner,
                    &approved_ctx,
                    flow.payload.clone(),
                    artifact,
                )?;
                flow.status = Status::Executed;
            }
        }
        ai::validate_balances::<D>(state)?;
        Ok(())
    }
}

/// Pending tasks are derived from committed state, including after an executor restart.
pub fn ai_job<D: Domain>(state: &FlowsState<D>, id: &str) -> Result<Option<AiJob>> {
    let flow = state.flows.get(id).ok_or(Error::NotFound)?;
    if flow.status != Status::Active {
        return Ok(None);
    }
    let template = template_for(&state.flow_templates, flow)?.clone();
    let Approver::Ai {
        mode,
        worker,
        model,
        purpose,
        privacy,
        max_tokens,
    } = &template.stages[flow.current].approver
    else {
        return Ok(None);
    };
    let runs = &flow.records[flow.current].ai_runs;
    if runs.len() >= MAX_AI_ATTEMPTS || runs.last().is_some_and(|r| !r.retry_requested) {
        return Ok(None);
    }
    let input = if *mode == AiMode::Review {
        let expected = D::review_artifact(&state.inner, &flow.payload)?;
        let input = flow.input.clone().ok_or(Error::Denied)?;
        if input.to_string() != expected {
            return Err(Error::Denied);
        }
        input
    } else {
        flow.records[..flow.current]
            .iter()
            .rev()
            .find_map(|r| {
                r.ai_runs
                    .last()
                    .filter(|r| r.review.is_none())
                    .and_then(|r| r.output.clone())
            })
            .or_else(|| flow.input.clone())
            .ok_or(Error::Denied)?
    };
    let bytes = serde_json::to_vec(&(
        id,
        &flow.template,
        flow.template_epoch,
        flow.current,
        &flow.payload,
        &input,
        &template.stages[flow.current],
    ))
    .map_err(|e| Error::Protocol(e.to_string()))?;
    Ok(Some(AiJob {
        mode: *mode,
        instance: id.into(),
        job: protocol::digest(&bytes),
        attempt: runs.len(),
        input,
        worker: worker.clone(),
        model: model.clone(),
        purpose: purpose.clone(),
        privacy: *privacy,
        max_tokens: *max_tokens,
    }))
}

struct StartDefinition<D: Domain> {
    id: String,
    payload: D::Action,
    input: Option<protocol::Cid>,
    definition: Template,
    reference: Option<(String, u64)>,
    automatic: bool,
    max_points: Option<u64>,
}
fn begin<D: Domain>(
    state: &mut FlowsState<D>,
    ctx: &Context<'_>,
    spec: StartDefinition<D>,
) -> Result<()> {
    let StartDefinition {
        id,
        payload,
        input,
        mut definition,
        reference,
        automatic,
        max_points,
    } = spec;
    let (proposer, _) = ctx.member()?;
    text(&id)?;
    if state.flows.contains_key(&id) || state.flows.len() >= MAX_RECORDS {
        return Err(Error::Capacity);
    }
    let clubs = D::approval_clubs(&state.inner, &payload)?;
    let presidential = !clubs.is_empty();
    if presidential {
        definition.stages.push(Stage {
            name: "Club president signatures".into(),
            approver: Approver::ClubPresidents { clubs },
            timeout_ms: None,
            on_timeout: TimeoutPolicy::Reject,
        });
    }
    let version = &definition;
    validate_template(version, ctx.core)?;
    if !version.payload_kinds.contains(&kind(&payload)?) {
        return Err(Error::Denied);
    }
    if D::requires_ai_review(&state.inner, &payload)
        && !version.stages.iter().any(|s| {
            matches!(
                s.approver,
                Approver::Ai {
                    mode: AiMode::Review,
                    ..
                }
            )
        })
    {
        return Err(Error::Denied);
    }
    if version
        .stages
        .iter()
        .any(|s| matches!(s.approver, Approver::Ai { .. }))
    {
        D::artifact(
            &state.inner,
            &input.as_ref().ok_or(Error::Denied)?.to_string(),
        )?;
    }
    if version.stages.iter().any(|s| {
        matches!(
            s.approver,
            Approver::Ai {
                mode: AiMode::Review,
                ..
            }
        )
    }) {
        let expected = D::review_artifact(&state.inner, &payload)?;
        if input.as_ref().map(ToString::to_string).as_deref() != Some(expected.as_str()) {
            return Err(Error::Denied);
        }
    }
    let first = version.stages.first().ok_or(Error::Denied)?;
    let (payer, allowance) = if automatic {
        let (account, allowance) = D::workflow_payer(&state.inner, &payload)?;
        if !ctx
            .core
            .members
            .get(&account.member)
            .is_some_and(|m| m.club == account.club)
        {
            return Err(Error::Denied);
        }
        (account, Some(allowance))
    } else {
        (
            protocol::PointAccount {
                club: ctx.member()?.1.club.clone(),
                member: proposer.into(),
            },
            None,
        )
    };
    let records = ai::reserve_records::<D>(
        state,
        ctx,
        version,
        payer.clone(),
        allowance.clone(),
        max_points,
    )?;
    state.flows.insert(
        id,
        Instance {
            workflow: (reference.is_none() || presidential).then(|| definition.clone()),
            template: reference.as_ref().map_or_else(String::new, |r| r.0.clone()),
            template_epoch: reference.as_ref().map_or(0, |r| r.1),
            payload,
            input,
            proposer: proposer.into(),
            proposer_device: ctx.actor.into(),
            started_ms: ctx.now_ms,
            payer,
            allowance,
            current: 0,
            records,
            status: Status::Active,
            deadline_ms: deadline(first, ctx.now_ms)?,
        },
    );
    Ok(())
}
