use crate::{Error, Result};
pub use protocol::digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use state::{Context, Domain};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rules {
    pub cross_club: bool,
    pub seats: usize,
    pub reconnect_min_ms: u64,
    pub reconnect_max_ms: u64,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            cross_club: false,
            seats: 4,
            reconnect_min_ms: 15_000,
            reconnect_max_ms: 90_000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Team {
    pub captain: String,
    pub members: BTreeSet<String>,
    pub invited: BTreeSet<String>,
    pub registered: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    Registration,
    Playing,
    Finished,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Seat {
    pub player: String,
    pub epoch: u64,
    pub disconnected_until: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct League {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted: Option<BTreeSet<String>>,
    pub rules: Rules,
    pub organizer: String,
    pub host: String,
    pub scorer: String,
    pub phase: Phase,
    pub teams: BTreeMap<String, Team>,
    pub online: BTreeSet<String>,
    pub seats: BTreeMap<String, Vec<Seat>>,
    pub played: BTreeSet<String>,
    pub player_scores: BTreeMap<String, i64>,
    pub team_scores: BTreeMap<String, i64>,
    pub score_events: BTreeMap<String, String>,
    pub paused_since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<crate::season::Schedule>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub manual_pause: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub infrastructure_down: bool,
    pub random_seed: [u8; 32],
    pub draw: u64,
    pub epoch: u64,
    pub health: BTreeMap<String, ConnectionHealth>,
}

/// Measured by the authoritative game proxy, not self-reported by players.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionHealth {
    pub rtt_ms: u64,
    pub jitter_ms: u64,
    pub recovery_ms: u64,
}

impl ConnectionHealth {
    pub fn grace(&self, rules: &Rules) -> u64 {
        // Include observed game-session recovery time; RTT alone is insufficient.
        self.rtt_ms
            .saturating_mul(8)
            .saturating_add(self.jitter_ms.saturating_mul(4))
            .saturating_add(self.recovery_ms.saturating_mul(2))
            .clamp(rules.reconnect_min_ms, rules.reconnect_max_ms)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeagueState {
    pub leagues: BTreeMap<String, League>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub seasons: BTreeMap<String, crate::season::Season>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub disputes: BTreeMap<String, crate::season::Dispute>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LeagueAction {
    SetAttendance {
        league: String,
        members: BTreeSet<String>,
        automatic: bool,
    },
    CreateSeason {
        id: String,
        title: String,
    },
    ScheduleLeague {
        season: String,
        league: String,
        schedule: crate::season::Schedule,
    },
    PauseLeague {
        league: String,
        paused: bool,
    },
    DisputeResult {
        id: String,
        league: String,
        reason: String,
    },
    ResolveDispute {
        id: String,
        response: String,
        players: BTreeMap<String, i64>,
        teams: BTreeMap<String, i64>,
    },
    CreateLeague {
        league: String,
        rules: Rules,
        host: String,
        scorer: String,
    },
    CreateTeam {
        league: String,
        team: String,
    },
    Invite {
        league: String,
        team: String,
        member: String,
    },
    Accept {
        league: String,
        team: String,
    },
    Register {
        league: String,
        team: String,
    },
    Presence {
        league: String,
        member: String,
        online: bool,
        health: ConnectionHealth,
    },
    Start {
        league: String,
        seed: [u8; 32],
    },
    Tick {
        league: String,
    },
    Infrastructure {
        league: String,
        healthy: bool,
    },
    Score {
        league: String,
        event: String,
        players: BTreeMap<String, i64>,
        teams: BTreeMap<String, i64>,
    },
    Finish {
        league: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "destination", rename_all = "snake_case")]
pub enum Route {
    Match { team: String, epoch: u64 },
    Waiting,
    Unavailable,
}

fn invalid(message: &str) -> Error {
    Error::Protocol(message.into())
}
fn identifier(value: &str) -> Result<()> {
    state::governance::identifier(value)
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeagueDomain;
impl Domain for LeagueDomain {
    type State = LeagueState;
    type Action = LeagueAction;
    fn transition(state: &mut Self::State, ctx: &Context<'_>, action: Self::Action) -> Result<()> {
        state.transition(ctx, action)
    }
}
/// League-bound governance state.
pub type State = state::State<LeagueDomain>;
/// League-bound signed command payload.
pub type Action = state::governance::Action<LeagueDomain>;
impl LeagueState {
    fn transition(&mut self, ctx: &Context<'_>, action: LeagueAction) -> Result<()> {
        let actor = ctx.actor;
        let now = ctx.now_ms;
        let is_admin = ctx.approved || ctx.core.admins.contains(actor);
        let player = ctx
            .core
            .members
            .iter()
            .find(|(_, m)| m.owns(actor))
            .map(|(id, _)| id.clone());
        match action {
            action @ (LeagueAction::CreateSeason { .. }
            | LeagueAction::ScheduleLeague { .. }
            | LeagueAction::PauseLeague { .. }
            | LeagueAction::DisputeResult { .. }
            | LeagueAction::ResolveDispute { .. }) => {
                self.season_transition(ctx, action, is_admin)?
            }
            LeagueAction::CreateLeague {
                league,
                rules,
                host,
                scorer,
            } => {
                if !is_admin {
                    return Err(Error::Denied);
                }
                identifier(&league)?;
                for peer in [&host, &scorer] {
                    peer.parse::<crate::PeerId>()
                        .map_err(|_| invalid("invalid authority PeerId"))?;
                }
                if rules.seats == 0
                    || rules.seats > 256
                    || rules.reconnect_min_ms == 0
                    || rules.reconnect_max_ms < rules.reconnect_min_ms
                    || rules.reconnect_max_ms > 600_000
                {
                    return Err(invalid("invalid league rules"));
                }
                if self.leagues.contains_key(&league) {
                    return Err(invalid("league already exists"));
                }
                self.leagues.insert(
                    league,
                    League {
                        admitted: None,
                        rules,
                        organizer: actor.into(),
                        host,
                        scorer,
                        phase: Phase::Registration,
                        teams: BTreeMap::new(),
                        online: BTreeSet::new(),
                        seats: BTreeMap::new(),
                        played: BTreeSet::new(),
                        player_scores: BTreeMap::new(),
                        team_scores: BTreeMap::new(),
                        score_events: BTreeMap::new(),
                        paused_since: None,
                        schedule: None,
                        manual_pause: false,
                        infrastructure_down: false,
                        random_seed: [0; 32],
                        draw: 0,
                        epoch: 0,
                        health: BTreeMap::new(),
                    },
                );
            }
            action => {
                let id = match &action {
                    LeagueAction::SetAttendance { league, .. }
                    | LeagueAction::CreateTeam { league, .. }
                    | LeagueAction::Invite { league, .. }
                    | LeagueAction::Accept { league, .. }
                    | LeagueAction::Register { league, .. }
                    | LeagueAction::Presence { league, .. }
                    | LeagueAction::Start { league, .. }
                    | LeagueAction::Tick { league }
                    | LeagueAction::Infrastructure { league, .. }
                    | LeagueAction::Score { league, .. }
                    | LeagueAction::Finish { league } => league,
                    _ => return Err(invalid("unsupported action")),
                };
                if let LeagueAction::CreateTeam { team, .. } = &action {
                    for season in self.seasons.values().filter(|s| s.leagues.contains(id)) {
                        for other in season.leagues.iter().filter(|other| *other != id) {
                            if self
                                .leagues
                                .get(other)
                                .and_then(|l| l.teams.get(team))
                                .is_some_and(|t| Some(&t.captain) != player.as_ref())
                            {
                                return Err(invalid("season team name belongs to another captain"));
                            }
                        }
                    }
                }
                let league = self.leagues.get_mut(id).ok_or(Error::NotFound)?;
                match action {
                    LeagueAction::SetAttendance {
                        members, automatic, ..
                    } => {
                        league.registration()?;
                        if actor != league.organizer
                            || members.len() > 10000
                            || members.iter().any(|m| !ctx.core.members.contains_key(m))
                        {
                            return Err(Error::Denied);
                        }
                        if automatic {
                            if !league.teams.is_empty() {
                                return Err(Error::Denied);
                            }
                            let mut groups = BTreeMap::<String, Vec<String>>::new();
                            for member in &members {
                                let club = if league.rules.cross_club {
                                    String::new()
                                } else {
                                    ctx.core.members[member].club.clone()
                                };
                                groups.entry(club).or_default().push(member.clone());
                            }
                            for group in groups.values() {
                                for chunk in group.chunks(league.rules.seats) {
                                    let captain = chunk.first().ok_or(Error::Denied)?.clone();
                                    let team = format!("auto-{}", digest(captain.as_bytes()));
                                    league.teams.insert(
                                        team,
                                        Team {
                                            captain,
                                            members: chunk.iter().cloned().collect(),
                                            invited: Default::default(),
                                            registered: true,
                                        },
                                    );
                                }
                            }
                        }
                        league.admitted = Some(members);
                    }
                    LeagueAction::CreateTeam { team, .. } => {
                        league.registration()?;
                        league.registration_window(now)?;
                        identifier(&team)?;
                        let player = player.ok_or(Error::Denied)?;
                        if league.team_of(&player).is_some() || league.teams.contains_key(&team) {
                            return Err(invalid("already in a team or team exists"));
                        }
                        league.teams.insert(
                            team,
                            Team {
                                captain: player.clone(),
                                members: [player].into(),
                                invited: BTreeSet::new(),
                                registered: false,
                            },
                        );
                    }
                    LeagueAction::Invite { team, member, .. } => {
                        league.registration()?;
                        league.registration_window(now)?;
                        if !ctx.core.members.contains_key(&member) {
                            return Err(Error::NotFound);
                        }
                        let team = league.teams.get_mut(&team).ok_or(Error::NotFound)?;
                        if Some(&team.captain) != player.as_ref() {
                            return Err(Error::Denied);
                        }
                        team.invited.insert(member);
                    }
                    LeagueAction::Accept { team, .. } => {
                        league.registration()?;
                        league.registration_window(now)?;
                        let player = player.ok_or(Error::Denied)?;
                        if league.team_of(&player).is_some() {
                            return Err(invalid("member already belongs to a team"));
                        }
                        let team = league.teams.get_mut(&team).ok_or(Error::NotFound)?;
                        if !team.invited.contains(&player) {
                            return Err(Error::Denied);
                        }
                        if !league.rules.cross_club
                            && ctx.core.members[&player].club
                                != ctx.core.members[&team.captain].club
                        {
                            return Err(invalid("cross-club teams disabled"));
                        }
                        team.invited.remove(&player);
                        team.members.insert(player);
                        // Changed rosters require the captain to submit again.
                        team.registered = false;
                    }
                    LeagueAction::Register { team, .. } => {
                        league.registration()?;
                        league.registration_window(now)?;
                        let team = league.teams.get_mut(&team).ok_or(Error::NotFound)?;
                        if Some(&team.captain) != player.as_ref() {
                            return Err(Error::Denied);
                        }
                        team.registered = true;
                    }
                    LeagueAction::Presence {
                        member,
                        online,
                        health,
                        ..
                    } => {
                        if actor != league.host || !ctx.core.members.contains_key(&member) {
                            return Err(Error::Denied);
                        }
                        if league.phase == Phase::Finished {
                            return Err(invalid("league finished"));
                        }
                        if health.rtt_ms > 60_000
                            || health.jitter_ms > 60_000
                            || health.recovery_ms > 600_000
                        {
                            return Err(invalid("invalid measured health"));
                        }
                        league.health.insert(member.clone(), health.clone());
                        // Expired seats are resolved before accepting a late reconnect.
                        if league.phase == Phase::Playing && league.paused_since.is_none() {
                            league.replace_expired(now)?;
                        }
                        if online {
                            league.online.insert(member.clone());
                        } else {
                            league.online.remove(&member);
                        }
                        let grace = health.grace(&league.rules);
                        for seats in league.seats.values_mut() {
                            for seat in seats.iter_mut().filter(|s| s.player == member) {
                                if online {
                                    seat.disconnected_until = None;
                                } else if seat.disconnected_until.is_none() {
                                    seat.disconnected_until = Some(now.saturating_add(grace));
                                }
                            }
                        }
                        if online && league.phase == Phase::Playing && league.paused_since.is_none()
                        {
                            league.fill_vacancies()?;
                        }
                    }
                    LeagueAction::Start { seed, .. } => {
                        if actor != league.organizer {
                            return Err(Error::Denied);
                        }
                        league.registration()?;
                        if league.schedule.as_ref().is_some_and(|s| now < s.starts_ms) {
                            return Err(Error::Denied);
                        }
                        league.random_seed = seed;
                        league.phase = Phase::Playing;
                        for (id, team) in &league.teams {
                            if team.registered
                                && team.members.iter().any(|m| {
                                    league.admitted.as_ref().is_none_or(|set| set.contains(m))
                                })
                            {
                                league.seats.insert(id.clone(), Vec::new());
                                league.team_scores.insert(id.clone(), 0);
                                for player in &team.members {
                                    if league
                                        .admitted
                                        .as_ref()
                                        .is_none_or(|set| set.contains(player))
                                    {
                                        league.player_scores.insert(player.clone(), 0);
                                    }
                                }
                            }
                        }
                        league.fill_vacancies()?;
                    }
                    LeagueAction::Tick { .. } => {
                        if actor != league.host {
                            return Err(Error::Denied);
                        }
                        if league.phase != Phase::Playing {
                            return Err(invalid("not playing"));
                        }
                        if league.paused_since.is_none() {
                            league.replace_expired(now)?;
                        }
                    }
                    LeagueAction::Infrastructure { healthy, .. } => {
                        if actor != league.host {
                            return Err(Error::Denied);
                        }
                        league.infrastructure_down = !healthy;
                        league.update_pause(now);
                    }
                    LeagueAction::Score {
                        event,
                        players,
                        teams,
                        ..
                    } => {
                        if actor != league.scorer {
                            return Err(Error::Denied);
                        }
                        identifier(&event)?;
                        let digest = digest(
                            &serde_json::to_vec(&(&players, &teams))
                                .map_err(|e| invalid(&e.to_string()))?,
                        );
                        if let Some(previous) = league.score_events.get(&event) {
                            if previous != &digest {
                                return Err(invalid(
                                    "score event id reused with different payload",
                                ));
                            }
                            return Ok(());
                        }
                        if league.phase != Phase::Playing {
                            return Err(invalid("not playing"));
                        }
                        for (player, delta) in players {
                            if !league.played.contains(&player) {
                                return Err(invalid("player has not participated"));
                            }
                            let score = league
                                .player_scores
                                .get_mut(&player)
                                .ok_or(Error::NotFound)?;
                            *score = score
                                .checked_add(delta)
                                .ok_or_else(|| invalid("score overflow"))?;
                        }
                        for (team, delta) in teams {
                            let score = league.team_scores.get_mut(&team).ok_or(Error::NotFound)?;
                            *score = score
                                .checked_add(delta)
                                .ok_or_else(|| invalid("score overflow"))?;
                        }
                        league.score_events.insert(event, digest);
                    }
                    LeagueAction::Finish { .. } => {
                        if actor != league.scorer {
                            return Err(Error::Denied);
                        }
                        if league.phase == Phase::Registration {
                            return Err(invalid("not started"));
                        }
                        league.phase = Phase::Finished;
                    }
                    _ => return Err(invalid("unsupported action")),
                }
            }
        }
        Ok(())
    }
}
impl League {
    fn registration(&self) -> Result<()> {
        if self.phase != Phase::Registration {
            Err(invalid("registration closed"))
        } else {
            Ok(())
        }
    }
    pub fn team_of(&self, member: &str) -> Option<&str> {
        self.teams
            .iter()
            .find(|(_, t)| t.members.contains(member))
            .map(|(id, _)| id.as_str())
    }
    pub fn route(&self, member: &str) -> Route {
        if self.phase != Phase::Playing {
            return Route::Unavailable;
        }
        for (team, seats) in &self.seats {
            for seat in seats {
                if seat.player == member {
                    return Route::Match {
                        team: team.clone(),
                        epoch: seat.epoch,
                    };
                }
            }
        }
        if self
            .team_of(member)
            .is_some_and(|team| self.teams[team].registered)
        {
            Route::Waiting
        } else {
            Route::Unavailable
        }
    }
    fn replace_expired(&mut self, now: u64) -> Result<()> {
        for seats in self.seats.values_mut() {
            seats.retain(|s| s.disconnected_until.is_none_or(|until| until > now));
        }
        self.fill_vacancies()
    }
    fn fill_vacancies(&mut self) -> Result<()> {
        for (team_id, seats) in &mut self.seats {
            while seats.len() < self.rules.seats {
                let selected: BTreeSet<_> = seats.iter().map(|s| &s.player).collect();
                let mut candidates: Vec<_> = self.teams[team_id]
                    .members
                    .iter()
                    .filter(|p| {
                        self.online.contains(*p)
                            && !selected.contains(p)
                            && self.admitted.as_ref().is_none_or(|set| set.contains(*p))
                    })
                    .cloned()
                    .collect();
                if candidates.is_empty() {
                    break;
                }
                let draw = self.draw.to_be_bytes();
                candidates.sort_by_cached_key(|p| {
                    let mut hash = Sha256::new();
                    hash.update(self.random_seed);
                    hash.update(draw);
                    hash.update(p.as_bytes());
                    hash.finalize().to_vec()
                });
                self.draw = self
                    .draw
                    .checked_add(1)
                    .ok_or_else(|| invalid("draw overflow"))?;
                self.epoch = self
                    .epoch
                    .checked_add(1)
                    .ok_or_else(|| invalid("seat epoch overflow"))?;
                let player = candidates.remove(0);
                self.played.insert(player.clone());
                seats.push(Seat {
                    player,
                    epoch: self.epoch,
                    disconnected_until: None,
                });
            }
        }
        Ok(())
    }
}
