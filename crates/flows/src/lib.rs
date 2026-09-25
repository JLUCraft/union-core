//! Versioned, deterministic approval workflows composed around another Domain.
use serde::{Deserialize, Serialize};
use state::{Context, CoreView, Domain};
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};
use wire::{Error, Result};

const MAX_RECORDS: usize = 10_000;
const MAX_STAGES: usize = 16;
const MAX_VERSIONS: usize = 32;
const MAX_TIMEOUT_MS: u64 = 30 * 86_400_000;

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
        worker: String,
        model: String,
        purpose: String,
        privacy: wire::protocol::Privacy,
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
    Cancelled,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "")]
pub struct Instance<D: Domain> {
    pub template: String,
    pub template_epoch: u64,
    pub payload: D::Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<wire::protocol::Cid>,
    pub proposer: String,
    pub proposer_device: String,
    pub current: usize,
    pub records: Vec<StageRecord>,
    pub status: Status,
    pub deadline_ms: Option<u64>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageRecord {
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
    #[serde(default, skip_serializing_if = "is_false")]
    pub retry_requested: bool,
    pub job: String,
    pub device: String,
    pub output: Option<wire::protocol::Cid>,
    pub error: Option<String>,
}
#[derive(Clone, Debug)]
pub struct AiJob {
    pub instance: String,
    pub job: String,
    pub attempt: usize,
    pub input: wire::protocol::Cid,
    pub worker: String,
    pub model: String,
    pub purpose: String,
    pub privacy: wire::protocol::Privacy,
    pub max_tokens: u32,
}
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
        output: Option<wire::protocol::Cid>,
        error: Option<String>,
    },
    #[serde(rename = "flows.retry_ai")]
    RetryAi { instance: String },
    #[serde(rename = "flows.install_template")]
    InstallTemplate { id: String, template: Template },
    #[serde(rename = "flows.retire_template")]
    RetireTemplate { id: String },
    #[serde(rename = "flows.start")]
    Start {
        id: String,
        template: String,
        payload: D::Action,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input: Option<wire::protocol::Cid>,
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
fn hash(s: &str) -> Result<()> {
    if s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(Error::Denied)
    }
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
        _ => 1,
    })
}
fn approved(stage: &Stage, record: &StageRecord, core: CoreView<'_>) -> Result<bool> {
    if let Approver::Ai { worker, .. } = &stage.approver {
        return Ok(record.ai_runs.last().is_some_and(|run| {
            run.output.is_some()
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
            Approver::Ai {
                worker,
                model,
                purpose,
                max_tokens,
                ..
            } => {
                if !core.members.contains_key(worker)
                    || *max_tokens == 0
                    || *max_tokens > 8192
                    || stage.on_timeout == TimeoutPolicy::AutoApprove
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
                    || clubs.len() > 128
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
fn template_for<'a, D: Domain>(
    templates: &'a BTreeMap<String, Versions>,
    flow: &Instance<D>,
) -> Result<&'a Template> {
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
            FlowAction::Inner(action) => D::transition(&mut state.inner, ctx, action)?,
            FlowAction::InstallTemplate { id, template } => {
                if !ctx.core.admins.contains(ctx.actor) {
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
                if !ctx.core.admins.contains(ctx.actor) {
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
                payload,
                input,
            } => {
                let (proposer, _) = ctx.member()?;
                text(&id)?;
                if state.flows.contains_key(&id) || state.flows.len() >= MAX_RECORDS {
                    return Err(Error::Capacity);
                }
                let versions = state.flow_templates.get(&template).ok_or(Error::NotFound)?;
                let version = versions.versions.last().ok_or(Error::NotFound)?;
                if !versions.active || !version.payload_kinds.contains(&kind(&payload)?) {
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
                let first = version.stages.first().ok_or(Error::Denied)?;
                state.flows.insert(
                    id,
                    Instance {
                        template,
                        template_epoch: versions.versions.len() as u64,
                        payload,
                        input,
                        proposer: proposer.into(),
                        proposer_device: ctx.actor.into(),
                        current: 0,
                        records: vec![StageRecord::default(); version.stages.len()],
                        status: Status::Active,
                        deadline_ms: deadline(first, ctx.now_ms)?,
                    },
                );
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
                let flow = state.flows.get_mut(&instance).ok_or(Error::NotFound)?;
                if flow.deadline_ms.is_some_and(|t| ctx.now_ms >= t) {
                    return Err(Error::Denied);
                }
                flow.records[flow.current].ai_runs.push(AiRun {
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
                error,
            } => {
                if output.is_some() == error.is_some()
                    || error
                        .as_ref()
                        .is_some_and(|e| e.is_empty() || e.len() > 256)
                {
                    return Err(Error::Denied);
                }
                if let Some(cid) = &output {
                    D::artifact(&state.inner, &cid.to_string())?;
                }
                let flow = state.flows.get_mut(&instance).ok_or(Error::NotFound)?;
                if flow.status != Status::Active
                    || flow.deadline_ms.is_some_and(|t| ctx.now_ms >= t)
                {
                    return Err(Error::Denied);
                }
                let template = template_for(&state.flow_templates, flow)?;
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
                run.output = output;
                run.error = error;
                if success {
                    advance(flow, template, ctx.now_ms)?;
                }
            }
            FlowAction::RetryAi { instance } => {
                let flow = state.flows.get_mut(&instance).ok_or(Error::NotFound)?;
                if flow.status != Status::Active
                    || !(ctx.core.admins.contains(ctx.actor)
                        || ctx.member().is_ok_and(|(id, _)| id == flow.proposer))
                {
                    return Err(Error::Denied);
                }
                let template = template_for(&state.flow_templates, flow)?;
                if !matches!(template.stages[flow.current].approver, Approver::Ai { .. }) {
                    return Err(Error::Denied);
                }
                let runs = &mut flow.records[flow.current].ai_runs;
                if runs.len() >= MAX_AI_ATTEMPTS {
                    return Err(Error::Capacity);
                }
                let run = runs.last_mut().ok_or(Error::Denied)?;
                if run.output.is_some() || run.retry_requested {
                    return Err(Error::Denied);
                }
                run.retry_requested = true;
                if run.error.is_none() {
                    run.error = Some("superseded by an explicit retry".into());
                }
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
                hash(&comment_hash)?;
                let flow = state.flows.get_mut(&instance).ok_or(Error::NotFound)?;
                if flow.status != Status::Active
                    || flow.deadline_ms.is_some_and(|t| ctx.now_ms >= t)
                {
                    return Err(Error::Denied);
                }
                let template = template_for(&state.flow_templates, flow)?;
                let stage = template.stages.get(flow.current).ok_or(Error::Denied)?;
                let record = flow.records.get_mut(flow.current).ok_or(Error::Denied)?;
                let slot = authorized(&stage.approver, ctx.core, record, ctx.actor)?;
                let receipt = Approval {
                    device: ctx.actor.into(),
                    comment_hash,
                };
                if reject {
                    record.rejected = Some(receipt);
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
                        advance(flow, template, ctx.now_ms)?;
                    }
                }
            }
            FlowAction::Delegate { instance, to } => {
                let flow = state.flows.get_mut(&instance).ok_or(Error::NotFound)?;
                if flow.status != Status::Active
                    || flow.deadline_ms.is_some_and(|t| ctx.now_ms >= t)
                {
                    return Err(Error::Denied);
                }
                let template = template_for(&state.flow_templates, flow)?;
                let stage = template.stages.get(flow.current).ok_or(Error::Denied)?;
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
                let template = template_for(&state.flow_templates, flow)?;
                let stage = template.stages.get(flow.current).ok_or(Error::Denied)?;
                let record = flow.records.get_mut(flow.current).ok_or(Error::Denied)?;
                if let Some(run) = record.ai_runs.last_mut()
                    && run.output.is_none()
                    && run.error.is_none()
                {
                    run.error = Some("stage timed out".into());
                }
                match stage.on_timeout {
                    TimeoutPolicy::Reject => {
                        flow.status = Status::Rejected;
                        flow.deadline_ms = None;
                    }
                    TimeoutPolicy::Escalate => {
                        record.escalated = true;
                        advance(flow, template, ctx.now_ms)?;
                    }
                    TimeoutPolicy::AutoApprove => {
                        record.auto_approved = true;
                        advance(flow, template, ctx.now_ms)?;
                    }
                }
            }
            FlowAction::Cancel { instance } => {
                let flow = state.flows.get_mut(&instance).ok_or(Error::NotFound)?;
                if !matches!(flow.status, Status::Active | Status::Approved)
                    || !(ctx.core.admins.contains(ctx.actor)
                        || ctx.member().is_ok_and(|(id, _)| id == flow.proposer))
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
                flow.status = Status::Cancelled;
                flow.deadline_ms = None;
            }
            FlowAction::Execute { instance } => {
                let flow = state.flows.get_mut(&instance).ok_or(Error::NotFound)?;
                if flow.status != Status::Approved
                    || !(ctx.core.admins.contains(ctx.actor)
                        || ctx.member().is_ok_and(|(id, _)| id == flow.proposer))
                    || !member(ctx.core, &flow.proposer_device)
                        .is_some_and(|(id, _)| id == flow.proposer)
                {
                    return Err(Error::Denied);
                }
                let template = template_for(&state.flow_templates, flow)?;
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
                D::transition(&mut state.inner, &approved_ctx, flow.payload.clone())?;
                flow.status = Status::Executed;
            }
        }
        Ok(())
    }
}

/// Pending tasks are derived from committed state, including after an executor restart.
pub fn ai_job<D: Domain>(state: &FlowsState<D>, id: &str) -> Result<Option<AiJob>> {
    let flow = state.flows.get(id).ok_or(Error::NotFound)?;
    if flow.status != Status::Active {
        return Ok(None);
    }
    let template = template_for(&state.flow_templates, flow)?;
    let Approver::Ai {
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
    let input = flow.records[..flow.current]
        .iter()
        .rev()
        .find_map(|r| r.ai_runs.last().and_then(|r| r.output.clone()))
        .or_else(|| flow.input.clone())
        .ok_or(Error::Denied)?;
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
        instance: id.into(),
        job: wire::protocol::digest(&bytes),
        attempt: runs.len(),
        input,
        worker: worker.clone(),
        model: model.clone(),
        purpose: purpose.clone(),
        privacy: *privacy,
        max_tokens: *max_tokens,
    }))
}
