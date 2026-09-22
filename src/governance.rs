//! Authoritative league state machine. Hosting resources do not confer authority.
//! All external effects (routing, game plugins, notifications) consume this state.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusPeer {
    pub peer: String,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub club: String,
    pub device: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub additional_devices: BTreeSet<String>,
}
impl Member {
    pub fn owns(&self, device: &str) -> bool {
        self.device == device || self.additional_devices.contains(device)
    }
    pub fn devices(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.device).chain(self.additional_devices.iter())
    }
}

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub revision: u64,
    pub admins: BTreeSet<String>,
    pub members: BTreeMap<String, Member>,
    pub leagues: BTreeMap<String, League>,
    pub clock_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub council: Option<crate::council::Council>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub consensus_members: BTreeMap<u64, ConsensusPeer>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub retired_consensus_ids: BTreeSet<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub proposals: BTreeMap<String, crate::council::Proposal>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ballots: BTreeMap<String, crate::council::Ballot>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub feedback: BTreeMap<String, crate::council::Feedback>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub seasons: BTreeMap<String, crate::season::Season>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub disputes: BTreeMap<String, crate::season::Dispute>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub device_invitations: BTreeMap<String, crate::devices::Invitation>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub revoked_devices: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    InviteMemberDevice {
        id: String,
        device: String,
        expires_ms: u64,
    },
    AcceptMemberDevice {
        id: String,
    },
    RevokeMemberDevice {
        device: String,
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
    SetConsensusMembers {
        #[serde(deserialize_with = "consensus_map")]
        members: BTreeMap<u64, ConsensusPeer>,
    },
    InstallCouncil {
        council: crate::council::Council,
    },
    UpdateCouncil {
        council: crate::council::Council,
    },
    Propose {
        id: String,
        action: Box<Action>,
        expires_ms: u64,
    },
    ApproveProposal {
        id: String,
    },
    ExecuteProposal {
        id: String,
    },
    CancelProposal {
        id: String,
    },
    CreateBallot {
        id: String,
        title: String,
        options: Vec<String>,
        closes_ms: u64,
    },
    MemberVote {
        id: String,
        option: usize,
    },
    SubmitFeedback {
        id: String,
        category: String,
        text: String,
    },
    RespondFeedback {
        id: String,
        text: String,
    },
    GrantAdmin {
        device: String,
    },
    RevokeAdmin {
        device: String,
    },
    RotateMemberDevice {
        member: String,
        device: String,
    },
    Enroll {
        member: String,
        club: String,
        device: String,
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
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(invalid("invalid identifier"));
    }
    Ok(())
}

impl State {
    pub fn can_read(&self, actor: &str) -> bool {
        if self.revoked_devices.contains(actor) {
            return false;
        }
        self.admins.contains(actor)
            || self.members.values().any(|m| m.owns(actor))
            || self
                .leagues
                .values()
                .any(|l| l.host == actor || l.scorer == actor)
            || self
                .council
                .as_ref()
                .is_some_and(|c| c.schools.values().any(|devices| devices.contains(actor)))
    }

    pub fn new(admins: BTreeSet<String>) -> Result<Self> {
        if admins.is_empty() {
            return Err(invalid("at least one explicit administrator required"));
        }
        for admin in &admins {
            admin
                .parse::<crate::PeerId>()
                .map_err(|_| invalid("invalid admin PeerId"))?;
        }
        Ok(Self {
            revision: 0,
            admins,
            members: BTreeMap::new(),
            leagues: BTreeMap::new(),
            clock_ms: 0,
            council: None,
            consensus_members: BTreeMap::new(),
            retired_consensus_ids: BTreeSet::new(),
            proposals: BTreeMap::new(),
            ballots: BTreeMap::new(),
            feedback: BTreeMap::new(),
            seasons: BTreeMap::new(),
            disputes: BTreeMap::new(),
            device_invitations: BTreeMap::new(),
            revoked_devices: BTreeSet::new(),
        })
    }

    /// Atomic optimistic transition. Errors leave the original state unchanged.
    pub fn apply(&mut self, actor: &str, revision: u64, now_ms: u64, action: Action) -> Result<()> {
        if self.revoked_devices.contains(actor) {
            return Err(Error::Denied);
        }
        if revision != self.revision {
            return Err(invalid("revision conflict"));
        }
        if now_ms < self.clock_ms {
            return Err(invalid("clock moved backwards"));
        }
        let mut next = self.clone();
        next.transition(actor, now_ms, action)?;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("revision overflow"))?;
        next.clock_ms = now_ms;
        *self = next;
        Ok(())
    }

    fn transition(&mut self, actor: &str, now: u64, action: Action) -> Result<()> {
        self.transition_authorized(actor, now, action, false)
    }
    pub(crate) fn transition_authorized(
        &mut self,
        actor: &str,
        now: u64,
        action: Action,
        approved: bool,
    ) -> Result<()> {
        if self.council.is_some() && crate::council::protected(&action) && !approved {
            return Err(Error::Denied);
        }
        let is_admin = approved || self.admins.contains(actor);
        let player = self
            .members
            .iter()
            .find(|(_, m)| m.owns(actor))
            .map(|(id, _)| id.clone());
        match action {
            action @ (Action::InviteMemberDevice { .. }
            | Action::AcceptMemberDevice { .. }
            | Action::RevokeMemberDevice { .. }) => self.device_transition(actor, now, action)?,
            action @ (Action::CreateSeason { .. }
            | Action::ScheduleLeague { .. }
            | Action::PauseLeague { .. }
            | Action::DisputeResult { .. }
            | Action::ResolveDispute { .. }) => {
                self.season_transition(actor, now, action, is_admin)?;
            }
            Action::SetConsensusMembers { members } => {
                if !is_admin {
                    return Err(Error::Denied);
                }
                validate_consensus_members(&members)?;
                for (id, peer) in &members {
                    if self.retired_consensus_ids.contains(id)
                        || self
                            .consensus_members
                            .get(id)
                            .is_some_and(|old| old.peer != peer.peer)
                    {
                        return Err(Error::Denied);
                    }
                }
                self.retired_consensus_ids.extend(
                    self.consensus_members
                        .keys()
                        .filter(|id| !members.contains_key(id))
                        .copied(),
                );
                self.consensus_members = members;
            }
            action @ (Action::InstallCouncil { .. }
            | Action::UpdateCouncil { .. }
            | Action::Propose { .. }
            | Action::ApproveProposal { .. }
            | Action::ExecuteProposal { .. }
            | Action::CancelProposal { .. }
            | Action::CreateBallot { .. }
            | Action::MemberVote { .. }
            | Action::SubmitFeedback { .. }
            | Action::RespondFeedback { .. }) => {
                self.council_transition(actor, now, action, approved)?
            }
            Action::GrantAdmin { device } => {
                if !is_admin {
                    return Err(Error::Denied);
                }
                device
                    .parse::<crate::PeerId>()
                    .map_err(|_| invalid("invalid administrator device"))?;
                if !self.admins.insert(device) {
                    return Err(invalid("administrator already exists"));
                }
            }
            Action::RevokeAdmin { device } => {
                if !is_admin {
                    return Err(Error::Denied);
                }
                if self.admins.len() <= 1 {
                    return Err(invalid("cannot remove last administrator"));
                }
                if !self.admins.remove(&device) {
                    return Err(Error::NotFound);
                }
            }
            Action::RotateMemberDevice { member, device } => {
                if !is_admin {
                    return Err(Error::Denied);
                }
                device
                    .parse::<crate::PeerId>()
                    .map_err(|_| invalid("invalid member device"))?;
                if self.revoked_devices.contains(&device)
                    || self.members.values().any(|m| m.owns(&device))
                {
                    return Err(invalid("device already enrolled"));
                }
                if self
                    .leagues
                    .values()
                    .any(|l| l.phase == Phase::Playing && l.team_of(&member).is_some())
                {
                    return Err(invalid("cannot replace member device during a match"));
                }
                let m = self.members.get_mut(&member).ok_or(Error::NotFound)?;
                self.revoked_devices.extend(m.devices().cloned());
                m.additional_devices.clear();
                m.device = device;
                for league in self.leagues.values_mut() {
                    league.online.remove(&member);
                    league.health.remove(&member);
                }
            }
            Action::Enroll {
                member,
                club,
                device,
            } => {
                if !is_admin {
                    return Err(Error::Denied);
                }
                identifier(&member)?;
                identifier(&club)?;
                device
                    .parse::<crate::PeerId>()
                    .map_err(|_| invalid("invalid member device"))?;
                if self.members.contains_key(&member)
                    || self.revoked_devices.contains(&device)
                    || self.members.values().any(|m| m.owns(&device))
                {
                    return Err(invalid("member/device already enrolled"));
                }
                self.members.insert(
                    member,
                    Member {
                        club,
                        device,
                        additional_devices: BTreeSet::new(),
                    },
                );
            }
            Action::CreateLeague {
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
                    Action::CreateTeam { league, .. }
                    | Action::Invite { league, .. }
                    | Action::Accept { league, .. }
                    | Action::Register { league, .. }
                    | Action::Presence { league, .. }
                    | Action::Start { league, .. }
                    | Action::Tick { league }
                    | Action::Infrastructure { league, .. }
                    | Action::Score { league, .. }
                    | Action::Finish { league } => league,
                    _ => return Err(invalid("unsupported action")),
                };
                if let Action::CreateTeam { team, .. } = &action {
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
                    Action::CreateTeam { team, .. } => {
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
                    Action::Invite { team, member, .. } => {
                        league.registration()?;
                        league.registration_window(now)?;
                        if !self.members.contains_key(&member) {
                            return Err(Error::NotFound);
                        }
                        let team = league.teams.get_mut(&team).ok_or(Error::NotFound)?;
                        if Some(&team.captain) != player.as_ref() {
                            return Err(Error::Denied);
                        }
                        team.invited.insert(member);
                    }
                    Action::Accept { team, .. } => {
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
                            && self.members[&player].club != self.members[&team.captain].club
                        {
                            return Err(invalid("cross-club teams disabled"));
                        }
                        team.invited.remove(&player);
                        team.members.insert(player);
                        // Changed rosters require the captain to submit again.
                        team.registered = false;
                    }
                    Action::Register { team, .. } => {
                        league.registration()?;
                        league.registration_window(now)?;
                        let team = league.teams.get_mut(&team).ok_or(Error::NotFound)?;
                        if Some(&team.captain) != player.as_ref() {
                            return Err(Error::Denied);
                        }
                        team.registered = true;
                    }
                    Action::Presence {
                        member,
                        online,
                        health,
                        ..
                    } => {
                        if actor != league.host || !self.members.contains_key(&member) {
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
                    Action::Start { seed, .. } => {
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
                            if team.registered {
                                league.seats.insert(id.clone(), Vec::new());
                                league.team_scores.insert(id.clone(), 0);
                                for player in &team.members {
                                    league.player_scores.insert(player.clone(), 0);
                                }
                            }
                        }
                        league.fill_vacancies()?;
                    }
                    Action::Tick { .. } => {
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
                    Action::Infrastructure { healthy, .. } => {
                        if actor != league.host {
                            return Err(Error::Denied);
                        }
                        league.infrastructure_down = !healthy;
                        league.update_pause(now);
                    }
                    Action::Score {
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
                    Action::Finish { .. } => {
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

pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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
                    .filter(|p| self.online.contains(*p) && !selected.contains(p))
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

/// Node IDs and authenticated transport identities are explicit, never inferred from addresses.
pub fn validate_consensus_members(peers: &BTreeMap<u64, ConsensusPeer>) -> Result<()> {
    if !matches!(peers.len(), 1 | 3 | 5 | 7) {
        return Err(Error::Denied);
    }
    let mut unique = BTreeSet::new();
    for (id, peer) in peers {
        let parsed: crate::PeerId = peer.peer.parse().map_err(|_| Error::Denied)?;
        if *id == 0
            || !unique.insert(parsed)
            || peer.addresses.is_empty()
            || peer.addresses.len() > 8
        {
            return Err(Error::Denied);
        }
        for address in &peer.addresses {
            if address.len() > 2048 {
                return Err(Error::Capacity);
            }
            let addr: crate::Multiaddr = address.parse().map_err(|_| Error::Denied)?;
            if !matches!(addr.iter().last(), Some(crate::AddressProtocol::P2p(p)) if p == parsed) {
                return Err(Error::Denied);
            }
        }
    }
    Ok(())
}

fn consensus_map<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<u64, ConsensusPeer>, D::Error> {
    let values = BTreeMap::<String, ConsensusPeer>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|(key, value)| {
            let id: u64 = key.parse().map_err(serde::de::Error::custom)?;
            if id.to_string() != key {
                return Err(serde::de::Error::custom("noncanonical node id"));
            }
            Ok((id, value))
        })
        .collect()
}
