#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Deterministic event planning and replicated IPLD file history.
pub mod files;
pub mod points;
pub mod workflows;
use protocol::{Error, Result};
use serde::{Deserialize, Serialize};
use state::{Context, Domain};
use std::collections::{BTreeMap, BTreeSet};

const MAX_RECORDS: usize = 10_000;
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventsDomain;
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventsState {
    #[serde(default)]
    pub organization: workflows::OrganizationState,
    #[serde(flatten)]
    pub competitions: league::LeagueState,
    #[serde(default, skip_serializing_if = "files::FileStore::is_empty")]
    pub files: files::FileStore,
    #[serde(default)]
    pub events: BTreeMap<String, Event>,
    #[serde(default)]
    pub tasks: BTreeMap<String, Task>,
    #[serde(default)]
    pub signups: BTreeMap<String, BTreeSet<String>>,
    #[serde(default)]
    pub checkins: BTreeMap<String, BTreeSet<String>>,
}
impl std::ops::Deref for EventsState {
    type Target = league::LeagueState;
    fn deref(&self) -> &Self::Target {
        &self.competitions
    }
}
impl std::ops::DerefMut for EventsState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.competitions
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Window {
    pub opens_ms: u64,
    pub closes_ms: u64,
    pub starts_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Draft,
    Review,
    Approved,
    Open,
    Done,
    Cancelled,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub title: String,
    pub brief_hash: String,
    pub organizer: String,
    pub creator: String,
    pub co_organizers: BTreeSet<String>,
    pub window: Window,
    pub phase: Phase,
    pub epoch: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Task {
    pub event: String,
    pub title: String,
    pub assignee: Option<String>,
    pub done: bool,
    pub due_ms: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum EventAction {
    #[serde(rename = "files.put")]
    PutBlock { block: protocol::IpldBlock },
    #[serde(rename = "files.commit")]
    CommitFiles {
        branch: String,
        expected: Option<protocol::Cid>,
        commit: protocol::Cid,
    },
    #[serde(rename = "events.create")]
    Create {
        id: String,
        title: String,
        brief_hash: String,
        window: Window,
    },
    #[serde(rename = "events.submit")]
    Submit { id: String },
    #[serde(rename = "events.approve")]
    Approve {
        id: String,
        epoch: u64,
        co_organizers: BTreeSet<String>,
    },
    #[serde(rename = "events.publish")]
    Publish { id: String },
    #[serde(rename = "events.amend")]
    Amend { id: String, brief_hash: String },
    #[serde(rename = "events.revise")]
    Revise {
        id: String,
        title: String,
        brief_hash: String,
        window: Window,
    },
    #[serde(rename = "events.finish")]
    Finish { id: String },
    #[serde(rename = "events.cancel_event")]
    CancelEvent { id: String },
    #[serde(rename = "events.add_task")]
    AddTask {
        event: String,
        id: String,
        title: String,
        due_ms: Option<u64>,
    },
    #[serde(rename = "events.assign")]
    Assign { task: String, member: String },
    #[serde(rename = "events.complete")]
    Complete { task: String },
    #[serde(rename = "events.signup")]
    Signup { id: String },
    #[serde(rename = "events.checkin")]
    Checkin { id: String },
    #[serde(rename = "events.cancel")]
    CancelSignup { id: String },
    #[serde(untagged)]
    Organization(workflows::OrganizationAction),
    #[serde(untagged)]
    Competition(league::LeagueAction),
}
fn text(s: &str, max: usize) -> Result<()> {
    if s.trim().is_empty() || s.len() > max || s.chars().any(char::is_control) {
        Err(Error::Denied)
    } else {
        Ok(())
    }
}
fn club_manager(ctx: &Context<'_>, club: &str) -> bool {
    ctx.core.admins.contains(ctx.actor)
        || ctx.member().is_ok_and(|(_, m)| {
            m.club == club
                && ["president", "admin", "manager"]
                    .iter()
                    .any(|role| m.roles.contains(*role))
        })
}
fn manage(event: &Event, ctx: &Context<'_>) -> bool {
    club_manager(ctx, &event.organizer)
}
fn active(event: &Event) -> Result<()> {
    if matches!(event.phase, Phase::Done | Phase::Cancelled) {
        Err(Error::Denied)
    } else {
        Ok(())
    }
}
impl Domain for EventsDomain {
    fn point_balance(state: &Self::State, account: &protocol::PointAccount) -> Result<u64> {
        Ok(points::balance(state, account))
    }
    fn debit_points(
        state: &mut Self::State,
        account: &protocol::PointAccount,
        amount: u64,
    ) -> Result<()> {
        points::debit(state, account, amount)
    }
    fn credit_points(
        state: &mut Self::State,
        account: &protocol::PointAccount,
        amount: u64,
    ) -> Result<()> {
        points::credit(state, account, amount)
    }
    fn workflow_payer(
        state: &Self::State,
        action: &Self::Action,
    ) -> Result<(protocol::PointAccount, protocol::AiAllowance)> {
        points::workflow_payer(state, action)
    }
    fn debit_ai_allowance(
        state: &mut Self::State,
        account: &protocol::PointAccount,
        allowance: &protocol::AiAllowance,
        amount: u64,
    ) -> Result<()> {
        points::debit_allowance(state, account, allowance, amount)
    }
    fn refund_ai_allowance(
        state: &mut Self::State,
        account: &protocol::PointAccount,
        allowance: &protocol::AiAllowance,
        amount: u64,
    ) -> Result<()> {
        points::refund_allowance(state, account, allowance, amount)
    }
    fn ai_document_action(id: &str, member: &str, worker: &str) -> Result<Self::Action> {
        Ok(EventAction::Organization(
            workflows::OrganizationAction::AiDocument {
                id: id.into(),
                member: member.into(),
                worker: worker.into(),
            },
        ))
    }
    fn approval_clubs(state: &Self::State, action: &Self::Action) -> Result<BTreeSet<String>> {
        let EventAction::Approve {
            id,
            epoch,
            co_organizers,
        } = action
        else {
            return Ok(BTreeSet::new());
        };
        let event = state.events.get(id).ok_or(Error::NotFound)?;
        if event.phase != Phase::Review || event.epoch != *epoch {
            return Err(Error::Denied);
        }
        let mut clubs = co_organizers.clone();
        clubs.insert(event.organizer.clone());
        if let Some(plan) = state.organization.plans.get(id)
            && plan.schools.keys().cloned().collect::<BTreeSet<_>>() != clubs
        {
            return Err(Error::Denied);
        }
        Ok(clubs)
    }
    fn artifact(state: &Self::State, cid: &str) -> Result<Vec<u8>> {
        state.files.read(&cid.parse()?)
    }
    fn review_artifact(state: &Self::State, action: &Self::Action) -> Result<String> {
        let EventAction::Approve { id, epoch, .. } = action else {
            return Err(Error::Denied);
        };
        let event = state.events.get(id).ok_or(Error::NotFound)?;
        if event.epoch != *epoch || event.phase != Phase::Review {
            return Err(Error::Denied);
        }
        let cid: protocol::Cid = if let Some(plan) = state.organization.plans.get(id) {
            plan.review_input.clone().ok_or(Error::Denied)?
        } else {
            event.brief_hash.parse()?
        };
        state.files.read(&cid)?;
        Ok(cid.to_string())
    }
    fn workflow_input(state: &Self::State, action: &Self::Action) -> Result<Vec<u8>> {
        match action {
            EventAction::Approve { .. } => {
                Self::artifact(state, &Self::review_artifact(state, action)?)
            }
            EventAction::Organization(action) => workflows::evidence(state, action),
            _ => Err(Error::Denied),
        }
    }
    fn workflow_worker(state: &Self::State, action: &Self::Action) -> Option<String> {
        if let EventAction::Organization(workflows::OrganizationAction::AiDocument {
            worker, ..
        }) = action
        {
            return Some(worker.clone());
        }
        match action {
            EventAction::Approve { id, epoch, .. }
                if state.organization.plans.contains_key(id)
                    && state
                        .events
                        .get(id)
                        .is_some_and(|e| e.phase == Phase::Review && e.epoch == *epoch) => {}
            EventAction::Organization(workflows::OrganizationAction::Polish { event, epoch })
                if state
                    .events
                    .get(event)
                    .is_some_and(|e| e.phase == Phase::Draft && e.epoch == *epoch)
                    && state
                        .organization
                        .plans
                        .get(event)
                        .is_some_and(|p| p.final_epoch == Some(*epoch) && p.polished.is_none()) => {
            }
            EventAction::Organization(workflows::OrganizationAction::Summary { event, epoch })
                if state
                    .events
                    .get(event)
                    .is_some_and(|e| e.phase == Phase::Done && e.epoch == *epoch)
                    && state
                        .organization
                        .plans
                        .get(event)
                        .is_some_and(|p| p.settled && p.summary.is_none()) => {}
            EventAction::Organization(workflows::OrganizationAction::ReportGenerated {
                id,
                version,
            }) if state.organization.reports.get(id).is_some_and(|r| {
                r.status == workflows::ReportStatus::Generating && r.version == *version
            }) => {}
            _ => return None,
        }
        state
            .organization
            .automation
            .as_ref()
            .map(|a| a.worker.clone())
    }
    fn requires_ai_review(state: &Self::State, action: &Self::Action) -> bool {
        matches!(action,EventAction::Approve{id,..} if state.organization.plans.contains_key(id))
    }
    fn transition_with_artifact(
        state: &mut Self::State,
        ctx: &Context<'_>,
        action: Self::Action,
        artifact: Option<String>,
    ) -> Result<()> {
        match action {
            EventAction::Organization(
                action @ (workflows::OrganizationAction::Polish { .. }
                | workflows::OrganizationAction::Summary { .. }
                | workflows::OrganizationAction::ReportGenerated { .. }
                | workflows::OrganizationAction::AiDocument { .. }),
            ) => workflows::generated(state, ctx, action, artifact.ok_or(Error::Denied)?.parse()?),
            action => Self::transition(state, ctx, action),
        }
    }
    type State = EventsState;
    type Action = EventAction;
    fn transition(state: &mut Self::State, ctx: &Context<'_>, action: Self::Action) -> Result<()> {
        match action {
            EventAction::Organization(action) => workflows::transition(state, ctx, action)?,
            EventAction::Competition(action) => {
                league::LeagueDomain::transition(&mut state.competitions, ctx, action)?;
            }
            EventAction::PutBlock { block } => {
                ctx.member()?;
                state.files.put(block)?;
            }
            EventAction::CommitFiles {
                branch,
                expected,
                commit,
            } => {
                let (_, member) = ctx.member()?;
                state.files.advance(
                    branch,
                    expected,
                    commit,
                    &member.club,
                    ctx.actor,
                    ctx.revision,
                )?;
            }
            EventAction::Create {
                id,
                title,
                brief_hash,
                window,
            } => {
                let (creator, member) = ctx.member()?;
                if !member.roles.contains("president") {
                    return Err(Error::Denied);
                }
                text(&id, 128)?;
                text(&title, 256)?;
                if let Ok(cid) = brief_hash.parse::<protocol::Cid>() {
                    state.files.read(&cid)?;
                } else {
                    protocol::validate_digest(&brief_hash)?;
                }
                if state.events.len() >= MAX_RECORDS
                    || state.events.contains_key(&id)
                    || window.opens_ms >= window.closes_ms
                    || window.closes_ms > window.starts_ms
                    || window.closes_ms <= ctx.now_ms
                {
                    return Err(Error::Denied);
                }
                state.events.insert(
                    id,
                    Event {
                        title,
                        brief_hash,
                        organizer: member.club.clone(),
                        creator: creator.into(),
                        co_organizers: BTreeSet::new(),
                        window,
                        phase: Phase::Draft,
                        epoch: 1,
                    },
                );
            }
            EventAction::Approve {
                id,
                epoch,
                co_organizers,
            } => {
                if !ctx.approved
                    || co_organizers.len() > 128
                    || co_organizers
                        .iter()
                        .any(|club| !ctx.core.members.values().any(|m| &m.club == club))
                {
                    return Err(Error::Denied);
                }
                workflows::ready(state, &id)?;
                if state.organization.plans.get(&id).is_some_and(|p| {
                    p.schools
                        .keys()
                        .filter(|c| **c != state.events[&id].organizer)
                        .cloned()
                        .collect::<BTreeSet<_>>()
                        != co_organizers
                }) {
                    return Err(Error::Denied);
                }
                let event = state.events.get_mut(&id).ok_or(Error::NotFound)?;
                if event.phase != Phase::Review || event.epoch != epoch {
                    return Err(Error::Denied);
                }
                event.co_organizers = co_organizers;
                event.phase = Phase::Approved;
            }
            action @ (EventAction::Submit { .. }
            | EventAction::Publish { .. }
            | EventAction::Finish { .. }
            | EventAction::CancelEvent { .. }) => {
                let (id, target) = match action {
                    EventAction::Submit { id } => (id, Phase::Review),
                    EventAction::Publish { id } => (id, Phase::Open),
                    EventAction::Finish { id } => (id, Phase::Done),
                    EventAction::CancelEvent { id } => (id, Phase::Cancelled),
                    _ => return Err(Error::Denied),
                };
                if target == Phase::Review {
                    workflows::ready(state, &id)?;
                }
                if target == Phase::Done
                    && state.organization.plans.get(&id).is_some_and(|p| {
                        p.kind == workflows::Kind::Online
                            && p.selected
                                .iter()
                                .any(|g| p.games.get(g).is_none_or(|r| r.results.is_none()))
                    })
                {
                    return Err(Error::Denied);
                }
                let event = state.events.get_mut(&id).ok_or(Error::NotFound)?;
                active(event)?;
                let worker = state
                    .organization
                    .plans
                    .get(&id)
                    .is_some_and(|p| ctx.member().is_ok_and(|(m, _)| m == p.worker));
                if !manage(event, ctx)
                    && !(worker && matches!(target, Phase::Done | Phase::Review | Phase::Open))
                {
                    return Err(Error::Denied);
                }
                let valid = match target {
                    Phase::Review => event.phase == Phase::Draft,
                    Phase::Open => {
                        event.phase == Phase::Approved && ctx.now_ms < event.window.closes_ms
                    }
                    Phase::Done => {
                        event.phase == Phase::Open && ctx.now_ms >= event.window.starts_ms
                    }
                    Phase::Cancelled => true,
                    _ => false,
                };
                if !valid {
                    return Err(Error::Denied);
                }
                event.phase = target;
            }
            action @ (EventAction::Amend { .. } | EventAction::Revise { .. }) => {
                let (id, brief_hash, details) = match action {
                    EventAction::Amend { id, brief_hash } => (id, brief_hash, None),
                    EventAction::Revise {
                        id,
                        title,
                        brief_hash,
                        window,
                    } => {
                        text(&title, 256)?;
                        if window.opens_ms >= window.closes_ms
                            || window.closes_ms > window.starts_ms
                            || window.closes_ms <= ctx.now_ms
                        {
                            return Err(Error::Denied);
                        }
                        (id, brief_hash, Some((title, window)))
                    }
                    _ => return Err(Error::Denied),
                };
                if let Ok(cid) = brief_hash.parse::<protocol::Cid>() {
                    state.files.read(&cid)?;
                } else {
                    protocol::validate_digest(&brief_hash)?;
                }
                let event = state.events.get_mut(&id).ok_or(Error::NotFound)?;
                active(event)?;
                if !manage(event, ctx)
                    || (event.brief_hash == brief_hash
                        && details.as_ref().is_none_or(|(title, window)| {
                            *title == event.title && *window == event.window
                        }))
                {
                    return Err(Error::Denied);
                }
                event.brief_hash = brief_hash;
                if let Some((title, window)) = details {
                    event.title = title;
                    event.window = window;
                }
                event.epoch = event.epoch.checked_add(1).ok_or(Error::Capacity)?;
                // Material changes always require a fresh review, including already-published events.
                event.phase = Phase::Draft;
                if let Some(plan) = state.organization.plans.get_mut(&id) {
                    if plan.games.values().any(|g| g.reserved || g.started) {
                        return Err(Error::Denied);
                    }
                    plan.final_epoch = None;
                    plan.polished = None;
                    plan.review_input = None;
                    plan.summary = None;
                    plan.games.clear();
                }
            }
            EventAction::AddTask {
                event,
                id,
                title,
                due_ms,
            } => {
                let parent = state.events.get(&event).ok_or(Error::NotFound)?;
                active(parent)?;
                text(&id, 128)?;
                text(&title, 256)?;
                if !manage(parent, ctx)
                    || state.tasks.contains_key(&id)
                    || state.tasks.len() >= MAX_RECORDS
                    || due_ms.is_some_and(|due| due <= ctx.now_ms)
                {
                    return Err(Error::Denied);
                }
                state.tasks.insert(
                    id,
                    Task {
                        event,
                        title,
                        assignee: None,
                        done: false,
                        due_ms,
                    },
                );
            }
            EventAction::Assign { task, member } => {
                let task = state.tasks.get_mut(&task).ok_or(Error::NotFound)?;
                let event = state.events.get(&task.event).ok_or(Error::NotFound)?;
                active(event)?;
                let target = ctx.core.members.get(&member).ok_or(Error::NotFound)?;
                if !manage(event, ctx)
                    || task.done
                    || (target.club != event.organizer
                        && !event.co_organizers.contains(&target.club))
                {
                    return Err(Error::Denied);
                }
                task.assignee = Some(member);
            }
            EventAction::Complete { task } => {
                let task = state.tasks.get_mut(&task).ok_or(Error::NotFound)?;
                let event = state.events.get(&task.event).ok_or(Error::NotFound)?;
                active(event)?;
                if task.done
                    || !(manage(event, ctx)
                        || ctx
                            .member()
                            .is_ok_and(|(id, _)| task.assignee.as_deref() == Some(id)))
                {
                    return Err(Error::Denied);
                }
                task.done = true;
            }
            EventAction::Signup { id } => {
                let (member, affiliation) = ctx.member()?;
                let event = state.events.get(&id).ok_or(Error::NotFound)?;
                if event.phase != Phase::Open
                    || ctx.now_ms < event.window.opens_ms
                    || ctx.now_ms >= event.window.closes_ms
                {
                    return Err(Error::Denied);
                }
                if let Some(p) = state.organization.plans.get(&id) {
                    let school = p.schools.get(&affiliation.club).ok_or(Error::Denied)?;
                    if p.kind == workflows::Kind::Meeting && !school.participants.contains(member) {
                        return Err(Error::Denied);
                    }
                    state
                        .organization
                        .enrollment
                        .entry(id.clone())
                        .or_default()
                        .insert(member.into(), affiliation.club.clone());
                }
                let members = state.signups.entry(id).or_default();
                if members.len() >= MAX_RECORDS || !members.insert(member.into()) {
                    return Err(Error::Denied);
                }
            }
            EventAction::Checkin { id } => {
                let (member, _) = ctx.member()?;
                let event = state.events.get(&id).ok_or(Error::NotFound)?;
                let checkin_window = state
                    .organization
                    .plans
                    .get(&id)
                    .map(|p| (p.checkin_opens_ms, p.checkin_closes_ms));
                if event.phase != Phase::Open
                    || checkin_window
                        .map_or(ctx.now_ms < event.window.starts_ms, |(opens, closes)| {
                            ctx.now_ms < opens || ctx.now_ms >= closes
                        })
                    || !state
                        .signups
                        .get(&id)
                        .is_some_and(|members| members.contains(member))
                {
                    return Err(Error::Denied);
                }
                if !state.checkins.entry(id).or_default().insert(member.into()) {
                    return Err(Error::Denied);
                }
            }
            EventAction::CancelSignup { id } => {
                let (member, _) = ctx.member()?;
                let event = state.events.get(&id).ok_or(Error::NotFound)?;
                active(event)?;
                if state.checkins.get(&id).is_some_and(|s| s.contains(member)) {
                    return Err(Error::Denied);
                }
                if !state.signups.get_mut(&id).is_some_and(|s| s.remove(member)) {
                    return Err(Error::NotFound);
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "documents")]
pub mod documents;
