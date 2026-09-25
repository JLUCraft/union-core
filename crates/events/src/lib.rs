#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Deterministic event planning and replicated IPLD file history.
pub mod files;
use serde::{Deserialize, Serialize};
use state::{Context, Domain};
use std::collections::{BTreeMap, BTreeSet};
use wire::{Error, Result};

const MAX_RECORDS: usize = 10_000;
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventsDomain;
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventsState {
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
    PutBlock { block: wire::protocol::IpldBlock },
    #[serde(rename = "files.commit")]
    CommitFiles {
        branch: String,
        expected: Option<wire::protocol::Cid>,
        commit: wire::protocol::Cid,
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
}
fn text(s: &str, max: usize) -> Result<()> {
    if s.trim().is_empty() || s.len() > max || s.chars().any(char::is_control) {
        Err(Error::Denied)
    } else {
        Ok(())
    }
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
fn manage(event: &Event, ctx: &Context<'_>) -> bool {
    ctx.core.admins.contains(ctx.actor)
        || ctx.member().is_ok_and(|(id, m)| {
            id == event.creator || (m.club == event.organizer && m.roles.contains("president"))
        })
}
fn active(event: &Event) -> Result<()> {
    if matches!(event.phase, Phase::Done | Phase::Cancelled) {
        Err(Error::Denied)
    } else {
        Ok(())
    }
}
impl Domain for EventsDomain {
    fn artifact(state: &Self::State, cid: &str) -> Result<Vec<u8>> {
        state.files.read(&cid.parse()?)
    }
    type State = EventsState;
    type Action = EventAction;
    fn transition(state: &mut Self::State, ctx: &Context<'_>, action: Self::Action) -> Result<()> {
        match action {
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
                text(&id, 128)?;
                text(&title, 256)?;
                if let Ok(cid) = brief_hash.parse::<wire::protocol::Cid>() {
                    state.files.read(&cid)?;
                } else {
                    hash(&brief_hash)?;
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
                let event = state.events.get_mut(&id).ok_or(Error::NotFound)?;
                active(event)?;
                if !manage(event, ctx) {
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
            EventAction::Amend { id, brief_hash } => {
                if let Ok(cid) = brief_hash.parse::<wire::protocol::Cid>() {
                    state.files.read(&cid)?;
                } else {
                    hash(&brief_hash)?;
                }
                let event = state.events.get_mut(&id).ok_or(Error::NotFound)?;
                active(event)?;
                if !manage(event, ctx) || event.brief_hash == brief_hash {
                    return Err(Error::Denied);
                }
                event.brief_hash = brief_hash;
                event.epoch = event.epoch.checked_add(1).ok_or(Error::Capacity)?;
                // Material changes always require a fresh review, including already-published events.
                event.phase = Phase::Draft;
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
                let (member, _) = ctx.member()?;
                let event = state.events.get(&id).ok_or(Error::NotFound)?;
                if event.phase != Phase::Open
                    || ctx.now_ms < event.window.opens_ms
                    || ctx.now_ms >= event.window.closes_ms
                {
                    return Err(Error::Denied);
                }
                let members = state.signups.entry(id).or_default();
                if members.len() >= MAX_RECORDS || !members.insert(member.into()) {
                    return Err(Error::Denied);
                }
            }
            EventAction::Checkin { id } => {
                let (member, _) = ctx.member()?;
                let event = state.events.get(&id).ok_or(Error::NotFound)?;
                if event.phase != Phase::Open
                    || ctx.now_ms < event.window.starts_ms
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

pub mod documents;
