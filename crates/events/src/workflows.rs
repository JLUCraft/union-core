//! Office business workflows. All decisions are derived from signed state and server time.
use crate::{EventsState, Phase, active, manage, text};
use serde::{Deserialize, Serialize};
use state::Context;
use std::collections::{BTreeMap, BTreeSet};
use wire::{Error, Result, protocol::Cid};

pub const MAX_ITEMS: usize = 128;
const MAX_TEXT: usize = 4096;
pub const MAX_PUSH_CHECKPOINT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OfficeState {
    pub automation: Option<Automation>,
    pub resources: BTreeMap<String, GameResource>,
    pub schools: BTreeMap<String, SchoolProfile>,
    pub enrollment: BTreeMap<String, BTreeMap<String, String>>,
    pub plans: BTreeMap<String, Plan>,
    pub reports: BTreeMap<String, Report>,
    pub points: BTreeMap<String, BTreeMap<String, u64>>,
    pub notices: BTreeMap<String, Notice>,
    pub publications: BTreeMap<String, PublicReport>,
    pub push_checkpoints: BTreeMap<String, PushCheckpoint>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicReport {
    pub club: String,
    pub kind: ReportKind,
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub version: u64,
    pub output: Cid,
    pub published_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PushCheckpoint {
    pub revision: u64,
    pub ciphertext: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Automation {
    pub worker: String,
    pub model: String,
    pub max_tokens: u32,
    pub timeout_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GameResource {
    pub title: String,
    pub address: String,
    pub peer: String,
    pub genesis: String,
    pub host: String,
    pub scorer: String,
    pub seats: usize,
    pub cross_school: bool,
    pub automatic_teams: bool,
    pub operations_service: String,
    pub instance: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Online,
    Meeting,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClubKind {
    Official,
    Independent,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchoolProfile {
    pub kind: ClubKind,
    pub mua_requirements: Cid,
    pub mua_recipient: String,
    pub annual_requirements: Option<Cid>,
    pub annual_recipient: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct School {
    pub kind: ClubKind,
    pub participants: BTreeSet<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Opinion {
    pub member: String,
    pub epoch: u64,
    pub document: Cid,
    pub games: BTreeSet<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Consent {
    pub transcript: Option<Cid>,
    pub member: String,
    pub epoch: u64,
    pub document: Cid,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardRule {
    pub points: u64,
    pub material: Option<String>,
    /// None rewards every participant; otherwise rewards the first N places (ties included).
    pub top_places: Option<usize>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Award {
    pub club: String,
    pub member: String,
    pub points: u64,
    pub material: Option<String>,
    pub delivered_by: Option<String>,
    pub received_ms: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GameRun {
    pub reserved: bool,
    pub stopped: bool,
    pub resource: String,
    pub league: String,
    pub started: bool,
    pub results: Option<BTreeMap<String, i64>>,
    pub evidence: Option<Cid>,
    pub error: Option<String>,
}
impl GameRun {
    fn new(event: &str, game: &str) -> Self {
        Self {
            reserved: false,
            stopped: false,
            resource: game.into(),
            league: league_id(event, game),
            started: false,
            results: None,
            evidence: None,
            error: None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Plan {
    pub kind: Kind,
    pub schools: BTreeMap<String, School>,
    pub candidates: BTreeSet<String>,
    pub selected: BTreeSet<String>,
    pub opinions: BTreeMap<String, Opinion>,
    /// School ID for official consent, stable member ID for individual consent.
    pub consents: BTreeMap<String, Consent>,
    pub rewards: BTreeMap<String, RewardRule>,
    pub final_epoch: Option<u64>,
    pub polished: Option<Cid>,
    pub review_input: Option<Cid>,
    pub summary: Option<Cid>,
    pub awards: BTreeMap<String, Award>,
    pub settled: bool,
    pub games: BTreeMap<String, GameRun>,
    pub checkin_opens_ms: u64,
    pub checkin_closes_ms: u64,
    pub ends_ms: u64,
    pub worker: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    MuaAnnual,
    ClubAnnualReview,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Generating,
    Draft,
    Published,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    pub club: String,
    pub creator: String,
    pub kind: ReportKind,
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub recipient: String,
    pub requirements: Cid,
    pub evidence: Cid,
    pub output: Option<Cid>,
    pub status: ReportStatus,
    pub version: u64,
    pub worker: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Notice {
    pub event: String,
    pub task: String,
    pub member: String,
    pub due_ms: u64,
    pub acknowledged_ms: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum OfficeAction {
    #[serde(rename = "office.automation")]
    Automation { config: Automation },
    #[serde(rename = "office.resource")]
    Resource { id: String, resource: GameResource },
    #[serde(rename = "office.school_profile")]
    SchoolProfile {
        club: String,
        profile: SchoolProfile,
    },
    #[serde(rename = "office.plan")]
    Plan {
        event: String,
        kind: Kind,
        schools: BTreeMap<String, School>,
        candidates: BTreeSet<String>,
        checkin_opens_ms: u64,
        checkin_closes_ms: u64,
        ends_ms: u64,
        worker: String,
    },
    #[serde(rename = "office.opinion")]
    Opinion {
        event: String,
        document: Cid,
        games: BTreeSet<String>,
    },
    #[serde(rename = "office.consent")]
    Consent {
        event: String,
        document: Cid,
        transcript: Option<Cid>,
    },
    #[serde(rename = "office.rewards")]
    Rewards { event: String, rule: RewardRule },
    #[serde(rename = "office.finalize")]
    Finalize {
        event: String,
        selected: BTreeSet<String>,
    },
    #[serde(rename = "office.polish")]
    Polish { event: String, epoch: u64 },
    #[serde(rename = "office.summary")]
    Summary { event: String, epoch: u64 },
    #[serde(rename = "office.game_claim")]
    GameClaim { event: String, game: String },
    #[serde(rename = "office.game_receipt")]
    GameReceipt {
        event: String,
        game: String,
        started: bool,
        stopped: bool,
        results: Option<BTreeMap<String, i64>>,
        evidence: Option<Cid>,
        error: Option<String>,
    },
    #[serde(rename = "office.settle")]
    Settle { event: String },
    #[serde(rename = "office.deliver")]
    Deliver { event: String, member: String },
    #[serde(rename = "office.receive")]
    Receive { event: String },
    #[serde(rename = "office.notify")]
    Notify { task: String, due_ms: u64 },
    #[serde(rename = "office.acknowledge")]
    Acknowledge { notice: String },
    #[serde(rename = "office.report")]
    Report {
        id: String,
        kind: ReportKind,
        period_start_ms: u64,
        period_end_ms: u64,
        recipient: String,
        requirements: Cid,
        worker: String,
    },
    #[serde(rename = "office.report_generated")]
    ReportGenerated { id: String, version: u64 },
    #[serde(rename = "office.report_revise")]
    ReportRevise { id: String, document: Cid },
    #[serde(rename = "office.report_publish")]
    ReportPublish { id: String },
    #[serde(rename = "office.push_checkpoint")]
    PushCheckpoint {
        group: String,
        expected: u64,
        ciphertext: String,
    },
}
fn club_manager(ctx: &Context<'_>, club: &str) -> bool {
    ctx.core.admins.contains(ctx.actor)
        || ctx
            .member()
            .is_ok_and(|(_, m)| m.club == club && m.roles.contains("president"))
}
fn file(state: &EventsState, cid: &Cid) -> Result<()> {
    state.files.read(cid).map(|_| ())
}
fn plan<'a>(state: &'a EventsState, id: &str) -> Result<&'a Plan> {
    state.office.plans.get(id).ok_or(Error::NotFound)
}
fn editable(state: &EventsState, ctx: &Context<'_>, id: &str) -> Result<()> {
    let event = state.events.get(id).ok_or(Error::NotFound)?;
    if event.phase != Phase::Draft || !manage(event, ctx) {
        return Err(Error::Denied);
    }
    Ok(())
}
pub fn ready(state: &EventsState, id: &str) -> Result<()> {
    let event = state.events.get(id).ok_or(Error::NotFound)?;
    let Some(plan) = state.office.plans.get(id) else {
        return Ok(());
    };
    if plan.final_epoch != Some(event.epoch) || plan.polished.is_none() {
        return Err(Error::Denied);
    }
    if plan.kind == Kind::Meeting {
        consents_ready(state, id)?;
    }
    Ok(())
}
fn consents_ready(state: &EventsState, id: &str) -> Result<()> {
    let event = state.events.get(id).ok_or(Error::NotFound)?;
    for (club, school) in &plan(state, id)?.schools {
        let keys: Vec<&str> = match school.kind {
            ClubKind::Official => vec![club],
            ClubKind::Independent => school.participants.iter().map(String::as_str).collect(),
        };
        if keys.is_empty()
            || keys.iter().any(|key| {
                plan(state, id)
                    .ok()
                    .and_then(|p| p.consents.get(*key))
                    .is_none_or(|c| c.epoch != event.epoch)
            })
        {
            return Err(Error::Denied);
        }
    }
    Ok(())
}
/// Snapshot of the exact evidence used by automatic workflow stages.
pub fn evidence(state: &EventsState, action: &OfficeAction) -> Result<Vec<u8>> {
    let value = match action {
        OfficeAction::Polish { event, epoch } | OfficeAction::Summary { event, epoch } => {
            let e = state.events.get(event).ok_or(Error::NotFound)?;
            if e.epoch != *epoch {
                return Err(Error::Denied);
            }
            let p = plan(state, event)?;
            serde_json::json!({"event":e,"plan":p,"planning_document":document_evidence(state,&e.brief_hash.parse()?)?,"opinions":p.opinions.iter().map(|(club,o)|Ok((club,document_evidence(state,&o.document)?))).collect::<Result<BTreeMap<_,_>>>()?,"consents":p.consents.iter().map(|(subject,c)|Ok((subject,consent_evidence(state,c)?))).collect::<Result<BTreeMap<_,_>>>()?,"signups":state.signups.get(event),"checkins":state.checkins.get(event),"tasks":state.tasks.iter().filter(|(_,t)|&t.event==event).collect::<BTreeMap<_,_>>()})
        }
        OfficeAction::ReportGenerated { id, version } => {
            let r = state.office.reports.get(id).ok_or(Error::NotFound)?;
            if r.version != *version {
                return Err(Error::Denied);
            }
            return state.files.read(&r.evidence);
        }
        _ => return Err(Error::Denied),
    };
    serde_json::to_vec(&value).map_err(|e| Error::Protocol(e.to_string()))
}
fn store(state: &mut EventsState, bytes: &[u8]) -> Result<Cid> {
    let (cid, blocks) = state.files.version(None, bytes)?;
    for block in blocks {
        state.files.put(block)?;
    }
    Ok(cid)
}
pub fn generated(
    state: &mut EventsState,
    ctx: &Context<'_>,
    action: OfficeAction,
    output: Cid,
) -> Result<()> {
    if !ctx.approved {
        return Err(Error::Denied);
    }
    file(state, &output)?;
    match action {
        OfficeAction::Polish { event, epoch } => {
            let e = state.events.get(&event).ok_or(Error::NotFound)?;
            let p = state.office.plans.get_mut(&event).ok_or(Error::NotFound)?;
            if e.epoch != epoch
                || p.final_epoch != Some(epoch)
                || p.polished.is_some()
                || ctx.member()?.0 != p.worker
            {
                return Err(Error::Denied);
            }
            p.polished = Some(output);
        }
        OfficeAction::Summary { event, epoch } => {
            let e = state.events.get(&event).ok_or(Error::NotFound)?;
            let p = state.office.plans.get_mut(&event).ok_or(Error::NotFound)?;
            if e.epoch != epoch
                || e.phase != Phase::Done
                || !p.settled
                || p.summary.is_some()
                || ctx.member()?.0 != p.worker
            {
                return Err(Error::Denied);
            }
            p.summary = Some(output);
        }
        OfficeAction::ReportGenerated { id, version } => {
            let r = state.office.reports.get_mut(&id).ok_or(Error::NotFound)?;
            if r.version != version
                || r.status != ReportStatus::Generating
                || ctx.member()?.0 != r.worker
            {
                return Err(Error::Denied);
            }
            r.output = Some(output);
            r.status = ReportStatus::Draft;
        }
        _ => return Err(Error::Denied),
    }
    Ok(())
}
pub fn transition(state: &mut EventsState, ctx: &Context<'_>, action: OfficeAction) -> Result<()> {
    let (actor, member) = ctx.member()?;
    match action {
        OfficeAction::Automation { config } => {
            if !ctx.core.admins.contains(ctx.actor)
                || !ctx.core.members.contains_key(&config.worker)
            {
                return Err(Error::Denied);
            }
            text(&config.model, 128)?;
            if config.max_tokens == 0
                || config.max_tokens > 8192
                || config.timeout_ms == 0
                || config.timeout_ms > 30 * 86_400_000
            {
                return Err(Error::Denied);
            }
            state.office.automation = Some(config);
        }
        OfficeAction::Resource { id, resource } => {
            if !ctx.core.admins.contains(ctx.actor)
                || state.office.resources.len() >= MAX_ITEMS
                || state
                    .office
                    .plans
                    .values()
                    .any(|p| p.final_epoch.is_some() && p.selected.contains(&id))
            {
                return Err(Error::Denied);
            }
            text(&id, 128)?;
            text(&resource.title, 256)?;
            text(&resource.address, 1024)?;
            text(&resource.peer, 128)?;
            text(&resource.instance, 128)?;
            if resource.seats == 0 || resource.seats > MAX_ITEMS {
                return Err(Error::Denied);
            }
            state.office.resources.insert(id, resource);
        }
        OfficeAction::SchoolProfile { club, profile } => {
            if !ctx.core.admins.contains(ctx.actor)
                || !ctx.core.members.values().any(|m| m.club == club)
            {
                return Err(Error::Denied);
            }
            file(state, &profile.mua_requirements)?;
            text(&profile.mua_recipient, 256)?;
            if let Some(cid) = &profile.annual_requirements {
                file(state, cid)?;
            }
            if let Some(recipient) = &profile.annual_recipient {
                text(recipient, 256)?;
            }
            if profile.kind == ClubKind::Official
                && (profile.annual_requirements.is_none() || profile.annual_recipient.is_none())
            {
                return Err(Error::Denied);
            }
            state.office.schools.insert(club, profile);
        }
        OfficeAction::Plan {
            event,
            kind,
            schools,
            candidates,
            checkin_opens_ms,
            checkin_closes_ms,
            ends_ms,
            worker,
        } => {
            editable(state, ctx, &event)?;
            let e = state.events.get(&event).ok_or(Error::NotFound)?;
            if state
                .office
                .automation
                .as_ref()
                .is_none_or(|a| a.worker != worker)
                || candidates
                    .iter()
                    .any(|id| !state.office.resources.contains_key(id))
                || state.office.plans.contains_key(&event)
                || schools.is_empty()
                || schools.len() > MAX_ITEMS
                || !schools.contains_key(&e.organizer)
                || !ctx.core.members.contains_key(&worker)
                || candidates.len() > MAX_ITEMS
                || (kind == Kind::Online && candidates.is_empty())
                || checkin_opens_ms >= checkin_closes_ms
                || checkin_closes_ms > e.window.starts_ms
                || e.window.starts_ms >= ends_ms
            {
                return Err(Error::Denied);
            }
            for (club, s) in &schools {
                if state
                    .office
                    .schools
                    .get(club)
                    .is_none_or(|p| p.kind != s.kind)
                    || !ctx.core.members.values().any(|m| &m.club == club)
                    || s.participants.len() > MAX_ITEMS
                    || s.participants
                        .iter()
                        .any(|id| ctx.core.members.get(id).is_none_or(|m| &m.club != club))
                {
                    return Err(Error::Denied);
                }
            }
            for id in &candidates {
                text(id, 128)?;
            }
            state.office.plans.insert(
                event,
                Plan {
                    kind,
                    schools,
                    candidates,
                    selected: Default::default(),
                    opinions: Default::default(),
                    consents: Default::default(),
                    rewards: Default::default(),
                    final_epoch: None,
                    polished: None,
                    review_input: None,
                    summary: None,
                    awards: Default::default(),
                    settled: false,
                    games: Default::default(),
                    checkin_opens_ms,
                    checkin_closes_ms,
                    ends_ms,
                    worker,
                },
            );
        }
        OfficeAction::Opinion {
            event,
            document,
            games,
        } => {
            file(state, &document)?;
            let e = state.events.get(&event).ok_or(Error::NotFound)?;
            let p = state.office.plans.get_mut(&event).ok_or(Error::NotFound)?;
            if e.phase != Phase::Draft
                || p.final_epoch.is_some()
                || !p.schools.contains_key(&member.club)
                || !club_manager(ctx, &member.club)
                || !games.is_subset(&p.candidates)
            {
                return Err(Error::Denied);
            }
            p.opinions.insert(
                member.club.clone(),
                Opinion {
                    member: actor.into(),
                    epoch: e.epoch,
                    document,
                    games,
                },
            );
        }
        OfficeAction::Consent {
            event,
            document,
            transcript,
        } => {
            file(state, &document)?;
            if let Some(cid) = &transcript {
                file(state, cid)?;
            }
            file(state, &document)?;
            let e = state.events.get(&event).ok_or(Error::NotFound)?;
            let p = state.office.plans.get_mut(&event).ok_or(Error::NotFound)?;
            let s = p.schools.get(&member.club).ok_or(Error::Denied)?;
            if e.phase != Phase::Draft || p.final_epoch.is_some() {
                return Err(Error::Denied);
            }
            let key = match s.kind {
                ClubKind::Official if club_manager(ctx, &member.club) => member.club.clone(),
                ClubKind::Independent if s.participants.contains(actor) => actor.to_string(),
                _ => return Err(Error::Denied),
            };
            p.consents.insert(
                key,
                Consent {
                    transcript,
                    member: actor.into(),
                    epoch: e.epoch,
                    document,
                },
            );
        }
        OfficeAction::Rewards { event, rule } => {
            let e = state.events.get(&event).ok_or(Error::NotFound)?;
            let p = state.office.plans.get_mut(&event).ok_or(Error::NotFound)?;
            if e.phase != Phase::Draft
                || p.final_epoch.is_some()
                || !p.schools.contains_key(&member.club)
                || !club_manager(ctx, &member.club)
                || rule.top_places == Some(0)
            {
                return Err(Error::Denied);
            }
            if let Some(material) = &rule.material {
                text(material, MAX_TEXT)?;
            }
            p.rewards.insert(member.club.clone(), rule);
        }
        OfficeAction::Finalize { event, selected } => {
            editable(state, ctx, &event)?;
            let e = state.events.get(&event).ok_or(Error::NotFound)?;
            let p = plan(state, &event)?;
            if p.final_epoch.is_some()
                || !selected.is_subset(&p.candidates)
                || (p.kind == Kind::Online && selected.is_empty())
                || (p.schools.len() > 1
                    && p.schools
                        .keys()
                        .any(|c| p.opinions.get(c).is_none_or(|o| o.epoch != e.epoch)))
                || p.schools.keys().any(|c| !p.rewards.contains_key(c))
            {
                return Err(Error::Denied);
            }
            if p.kind == Kind::Meeting {
                consents_ready(state, &event)?;
            }
            let mut instances = BTreeSet::new();
            for game in &selected {
                let r = state.office.resources.get(game).ok_or(Error::Denied)?;
                if !instances.insert((&r.peer, &r.operations_service, &r.instance)) {
                    return Err(Error::Denied);
                }
            }
            if selected.iter().any(|game| {
                state.office.plans.iter().any(|(other_id, other)| {
                    other_id != &event
                        && other.final_epoch.is_some()
                        && state
                            .events
                            .get(other_id)
                            .is_some_and(|e| !matches!(e.phase, Phase::Done | Phase::Cancelled))
                        && p.checkin_opens_ms < other.ends_ms
                        && other.checkin_opens_ms < p.ends_ms
                        && other.selected.iter().any(|g| {
                            state
                                .office
                                .resources
                                .get(g)
                                .zip(state.office.resources.get(game))
                                .is_some_and(|(a, b)| {
                                    a.peer == b.peer
                                        && a.operations_service == b.operations_service
                                        && a.instance == b.instance
                                })
                        })
                })
            }) {
                return Err(Error::Denied);
            }

            let epoch = e.epoch;
            let p = state.office.plans.get_mut(&event).ok_or(Error::NotFound)?;
            p.selected = selected;
            p.final_epoch = Some(epoch);
            let bytes = evidence(
                state,
                &OfficeAction::Polish {
                    event: event.clone(),
                    epoch,
                },
            )?;
            let cid = store(state, &bytes)?;
            state
                .office
                .plans
                .get_mut(&event)
                .ok_or(Error::NotFound)?
                .review_input = Some(cid);
        }
        OfficeAction::GameClaim { event, game } => {
            let e = state.events.get(&event).ok_or(Error::NotFound)?;
            let p = state.office.plans.get_mut(&event).ok_or(Error::NotFound)?;
            if e.phase != Phase::Open
                || actor != p.worker
                || !p.selected.contains(&game)
                || ctx.now_ms < p.checkin_opens_ms
                || ctx.now_ms >= p.ends_ms
            {
                return Err(Error::Denied);
            }
            let run = p
                .games
                .entry(game.clone())
                .or_insert(GameRun::new(&event, &game));
            if run.stopped {
                return Err(Error::Denied);
            }
            run.reserved = true;
        }
        OfficeAction::GameReceipt {
            event,
            game,
            started,
            stopped,
            results,
            evidence,
            error,
        } => {
            if let Some(cid) = &evidence {
                file(state, cid)?;
            }
            if let Some(err) = &error {
                text(err, MAX_TEXT)?;
            }
            if results.as_ref().is_some_and(|r| {
                r.keys()
                    .any(|m| state.checkins.get(&event).is_none_or(|s| !s.contains(m)))
            }) {
                return Err(Error::Denied);
            }
            let e = state.events.get(&event).ok_or(Error::NotFound)?;
            let p = state.office.plans.get_mut(&event).ok_or(Error::NotFound)?;
            if actor != p.worker
                || !p.selected.contains(&game)
                || !matches!(e.phase, Phase::Open | Phase::Cancelled)
                || p.kind != Kind::Online
                || results.as_ref().is_some_and(|r| {
                    r.len() > crate::MAX_RECORDS
                        || evidence.is_none()
                        || !started
                        || error.is_some()
                })
            {
                return Err(Error::Denied);
            }
            let run = p
                .games
                .entry(game.clone())
                .or_insert(GameRun::new(&event, &game));
            if (run.results.is_some() && results != run.results)
                || (run.started && !started)
                || (run.stopped && !stopped)
            {
                return Err(Error::Denied);
            }
            run.started = started;
            run.stopped = stopped;
            run.results = results;
            run.evidence = evidence;
            run.error = error;
        }
        OfficeAction::Settle { event } => {
            settle(state, ctx, &event)?;
        }
        OfficeAction::Deliver {
            event,
            member: target,
        } => {
            let award = state
                .office
                .plans
                .get_mut(&event)
                .and_then(|p| p.awards.get_mut(&target))
                .ok_or(Error::NotFound)?;
            if !club_manager(ctx, &award.club)
                || award.material.is_none()
                || award.delivered_by.is_some()
            {
                return Err(Error::Denied);
            }
            award.delivered_by = Some(actor.into());
        }
        OfficeAction::Receive { event } => {
            let award = state
                .office
                .plans
                .get_mut(&event)
                .and_then(|p| p.awards.get_mut(actor))
                .ok_or(Error::NotFound)?;
            if award.delivered_by.is_none() || award.received_ms.is_some() {
                return Err(Error::Denied);
            }
            award.received_ms = Some(ctx.now_ms);
        }
        OfficeAction::Notify { task, due_ms } => {
            let t = state.tasks.get(&task).ok_or(Error::NotFound)?;
            let e = state.events.get(&t.event).ok_or(Error::NotFound)?;
            active(e)?;
            if !manage(e, ctx)
                || t.done
                || due_ms < ctx.now_ms
                || state.office.notices.len() >= crate::MAX_RECORDS
            {
                return Err(Error::Denied);
            }
            let member = t.assignee.clone().ok_or(Error::Denied)?;
            state.office.notices.insert(
                task.clone(),
                Notice {
                    event: t.event.clone(),
                    task,
                    member,
                    due_ms,
                    acknowledged_ms: None,
                },
            );
        }
        OfficeAction::Acknowledge { notice } => {
            let n = state
                .office
                .notices
                .get_mut(&notice)
                .ok_or(Error::NotFound)?;
            if n.member != actor || n.acknowledged_ms.is_some() || ctx.now_ms < n.due_ms {
                return Err(Error::Denied);
            }
            n.acknowledged_ms = Some(ctx.now_ms);
        }
        OfficeAction::Report {
            id,
            kind,
            period_start_ms,
            period_end_ms,
            recipient,
            requirements,
            worker,
        } => {
            text(&id, 128)?;
            text(&recipient, 256)?;
            file(state, &requirements)?;
            if state
                .office
                .automation
                .as_ref()
                .is_none_or(|a| a.worker != worker)
                || !club_manager(ctx, &member.club)
                || period_start_ms >= period_end_ms
                || period_end_ms > ctx.now_ms
                || state.office.reports.contains_key(&id)
                || state.office.reports.len() >= crate::MAX_RECORDS
                || !ctx.core.members.contains_key(&worker)
            {
                return Err(Error::Denied);
            }
            let profile = state
                .office
                .schools
                .get(&member.club)
                .ok_or(Error::Denied)?;
            if kind == ReportKind::ClubAnnualReview && profile.kind != ClubKind::Official {
                return Err(Error::Denied);
            }
            let evidence = report_evidence(
                state,
                &member.club,
                period_start_ms,
                period_end_ms,
                &requirements,
                &kind,
                &recipient,
            )?;
            let evidence = store(state, &evidence)?;
            state.office.reports.insert(
                id,
                Report {
                    club: member.club.clone(),
                    creator: actor.into(),
                    kind,
                    period_start_ms,
                    period_end_ms,
                    recipient,
                    requirements,
                    evidence,
                    output: None,
                    status: ReportStatus::Generating,
                    version: 1,
                    worker,
                },
            );
        }
        OfficeAction::ReportRevise { id, document } => {
            std::str::from_utf8(&state.files.read(&document)?).map_err(|_| Error::Denied)?;
            let r = state.office.reports.get_mut(&id).ok_or(Error::NotFound)?;
            if !club_manager(ctx, &r.club)
                || !matches!(r.status, ReportStatus::Draft | ReportStatus::Published)
            {
                return Err(Error::Denied);
            }
            r.output = Some(document);
            r.version = r.version.checked_add(1).ok_or(Error::Capacity)?;
            r.status = ReportStatus::Draft;
        }
        OfficeAction::ReportPublish { id } => {
            let output = state
                .office
                .reports
                .get(&id)
                .and_then(|r| r.output.as_ref())
                .ok_or(Error::NotFound)?;
            std::str::from_utf8(&state.files.read(output)?).map_err(|_| Error::Denied)?;
            let r = state.office.reports.get_mut(&id).ok_or(Error::NotFound)?;
            if !club_manager(ctx, &r.club) || r.status != ReportStatus::Draft {
                return Err(Error::Denied);
            }
            let output = r.output.clone().ok_or(Error::Denied)?;
            r.status = ReportStatus::Published;
            state.office.publications.insert(
                id,
                PublicReport {
                    club: r.club.clone(),
                    kind: r.kind.clone(),
                    period_start_ms: r.period_start_ms,
                    period_end_ms: r.period_end_ms,
                    version: r.version,
                    output,
                    published_ms: ctx.now_ms,
                },
            );
        }
        OfficeAction::PushCheckpoint {
            group,
            expected,
            ciphertext,
        } => {
            if state
                .office
                .automation
                .as_ref()
                .is_none_or(|a| a.worker != actor)
                || ciphertext.len() > MAX_PUSH_CHECKPOINT_BYTES
            {
                return Err(Error::Denied);
            }
            text(&group, 128)?;
            if !state.office.push_checkpoints.contains_key(&group)
                && state.office.push_checkpoints.len() >= crate::MAX_RECORDS
            {
                return Err(Error::Capacity);
            }
            let revision = state
                .office
                .push_checkpoints
                .get(&group)
                .map_or(0, |p| p.revision);
            if revision != expected {
                return Err(Error::Denied);
            }
            state.office.push_checkpoints.insert(
                group,
                PushCheckpoint {
                    revision: revision.checked_add(1).ok_or(Error::Capacity)?,
                    ciphertext,
                },
            );
        }
        OfficeAction::Polish { .. }
        | OfficeAction::Summary { .. }
        | OfficeAction::ReportGenerated { .. } => return Err(Error::Denied),
    }
    Ok(())
}
fn settle(state: &mut EventsState, ctx: &Context<'_>, id: &str) -> Result<()> {
    let e = state.events.get(id).ok_or(Error::NotFound)?;
    let p = plan(state, id)?;
    if e.phase != Phase::Done || p.settled || !(manage(e, ctx) || ctx.member()?.0 == p.worker) {
        return Err(Error::Denied);
    }
    let mut scores = BTreeMap::<String, i64>::new();
    if p.kind == Kind::Online {
        for game in &p.selected {
            let results = p
                .games
                .get(game)
                .and_then(|g| g.results.as_ref())
                .ok_or(Error::Denied)?;
            for (member, score) in results {
                let value = scores.entry(member.clone()).or_default();
                *value = value.checked_add(*score).ok_or(Error::Capacity)?;
            }
        }
    } else {
        for member in state.checkins.get(id).into_iter().flatten() {
            scores.insert(member.clone(), 0);
        }
    }
    let mut awards = BTreeMap::new();
    for (member, score) in &scores {
        let club = state
            .office
            .enrollment
            .get(id)
            .and_then(|m| m.get(member))
            .ok_or(Error::Denied)?;
        let rule = p.rewards.get(club).ok_or(Error::Denied)?;
        let rank = 1 + scores.values().filter(|s| *s > score).count();
        if rule.top_places.is_some_and(|n| rank > n) {
            continue;
        }
        awards.insert(
            member.clone(),
            Award {
                club: club.clone(),
                member: member.clone(),
                points: rule.points,
                material: rule.material.clone(),
                delivered_by: None,
                received_ms: None,
            },
        );
    }
    for award in awards.values() {
        let balance = state
            .office
            .points
            .entry(award.club.clone())
            .or_default()
            .entry(award.member.clone())
            .or_default();
        *balance = balance.checked_add(award.points).ok_or(Error::Capacity)?;
    }
    let p = state.office.plans.get_mut(id).ok_or(Error::NotFound)?;
    p.awards = awards;
    p.settled = true;
    Ok(())
}
fn report_evidence(
    state: &EventsState,
    club: &str,
    start: u64,
    end: u64,
    requirements: &Cid,
    kind: &ReportKind,
    recipient: &str,
) -> Result<Vec<u8>> {
    let records = state.events.iter()
        .filter(|(_,e)| e.window.starts_ms >= start && e.window.starts_ms < end && (e.organizer == club || e.co_organizers.contains(club)))
        .map(|(id,e)| {
            let plan=state.office.plans.get(id);
            let summary=plan.and_then(|p|p.summary.as_ref()).map(|cid|document_evidence(state,cid)).transpose()?;
            let planning_document=document_evidence(state,&e.brief_hash.parse()?)?;
            Ok(serde_json::json!({"id":id,"event":e,"plan":plan,"planning_document":planning_document,"summary":summary,"attendance":state.checkins.get(id),"tasks":state.tasks.iter().filter(|(_,t)|&t.event==id).collect::<BTreeMap<_,_>>()}))
        }).collect::<Result<Vec<_>>>()?;
    let requirements = document_evidence(state, requirements)?;
    serde_json::to_vec(&serde_json::json!({"club":club,"period_start_ms":start,"period_end_ms":end,"requirements":requirements,"kind":kind,"audience":recipient,"activities":records})).map_err(|e|Error::Protocol(e.to_string()))
}

pub fn league_id(event: &str, game: &str) -> String {
    format!(
        "office-{}",
        wire::protocol::digest(format!("{}:{event}{game}", event.len()).as_bytes())
    )
}

fn document_evidence(state: &EventsState, cid: &Cid) -> Result<serde_json::Value> {
    let bytes = state.files.read(cid)?;
    if let Some(mime) = wire::protocol::llm_document_mime(&bytes) {
        return Ok(serde_json::json!({"cid":cid,"mime":mime,"requires_document_review":true}));
    }
    Ok(match String::from_utf8(bytes) {
        Ok(text) => serde_json::json!({"cid":cid,"text":text}),
        Err(_) => serde_json::json!({"cid":cid,"requires_document_review":true,"text":null}),
    })
}

fn consent_evidence(state: &EventsState, consent: &Consent) -> Result<serde_json::Value> {
    Ok(
        serde_json::json!({"original":document_evidence(state,&consent.document)?,"transcript":consent.transcript.as_ref().map(|cid|document_evidence(state,cid)).transpose()?}),
    )
}
