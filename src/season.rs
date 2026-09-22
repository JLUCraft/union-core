//! Game-independent schedules, result review and the two public rankings.
use crate::{
    Error, Result,
    governance::{Action, League, Phase, State},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    pub opens_ms: u64,
    pub closes_ms: u64,
    pub starts_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Season {
    pub title: String,
    pub leagues: BTreeSet<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dispute {
    pub league: String,
    pub member: String,
    pub reason: String,
    pub created_ms: u64,
    pub resolution: Option<Resolution>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
    pub reviewer: String,
    pub time_ms: u64,
    pub response: String,
    pub players: BTreeMap<String, i64>,
    pub teams: BTreeMap<String, i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rankings {
    pub teams: Vec<(String, i64)>,
    pub players: Vec<(String, i64)>,
}
fn text(value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > max
        || value.chars().any(|c| c.is_control() && c != '\n')
    {
        Err(Error::Denied)
    } else {
        Ok(())
    }
}
impl League {
    pub(crate) fn registration_window(&self, now: u64) -> Result<()> {
        if self
            .schedule
            .as_ref()
            .is_some_and(|s| now < s.opens_ms || now >= s.closes_ms)
        {
            Err(Error::Denied)
        } else {
            Ok(())
        }
    }
    pub(crate) fn update_pause(&mut self, now: u64) {
        if self.manual_pause || self.infrastructure_down {
            self.paused_since.get_or_insert(now);
        } else if let Some(start) = self.paused_since.take() {
            for seat in self.seats.values_mut().flatten() {
                if let Some(deadline) = &mut seat.disconnected_until {
                    *deadline = deadline.saturating_add(now.saturating_sub(start));
                }
            }
        }
    }
}
impl State {
    pub(crate) fn season_transition(
        &mut self,
        actor: &str,
        now: u64,
        action: Action,
        admin: bool,
    ) -> Result<()> {
        match action {
            Action::CreateSeason { id, title } => {
                if !admin || self.seasons.contains_key(&id) || self.seasons.len() >= 1024 {
                    return Err(Error::Denied);
                }
                text(&id, 128)?;
                text(&title, 256)?;
                self.seasons.insert(
                    id,
                    Season {
                        title,
                        leagues: BTreeSet::new(),
                    },
                );
            }
            Action::ScheduleLeague {
                season,
                league,
                schedule,
            } => {
                if !admin
                    || schedule.opens_ms >= schedule.closes_ms
                    || schedule.closes_ms > schedule.starts_ms
                    || schedule.closes_ms <= now
                {
                    return Err(Error::Denied);
                }
                if self
                    .seasons
                    .iter()
                    .any(|(id, s)| id != &season && s.leagues.contains(&league))
                {
                    return Err(Error::Denied);
                }
                let l = self.leagues.get_mut(&league).ok_or(Error::NotFound)?;
                if l.phase != Phase::Registration || l.teams.values().any(|t| t.registered) {
                    return Err(Error::Denied);
                }
                self.seasons
                    .get_mut(&season)
                    .ok_or(Error::NotFound)?
                    .leagues
                    .insert(league);
                l.schedule = Some(schedule);
            }
            Action::PauseLeague { league, paused } => {
                let l = self.leagues.get_mut(&league).ok_or(Error::NotFound)?;
                if actor != l.organizer || l.phase != Phase::Playing {
                    return Err(Error::Denied);
                }
                l.manual_pause = paused;
                l.update_pause(now);
            }
            Action::DisputeResult { id, league, reason } => {
                text(&id, 128)?;
                text(&reason, 4096)?;
                if self.disputes.contains_key(&id) || self.disputes.len() >= 10000 {
                    return Err(Error::Denied);
                }
                let member = self
                    .members
                    .iter()
                    .find(|(_, m)| m.owns(actor))
                    .map(|(id, _)| id.clone())
                    .ok_or(Error::Denied)?;
                let l = self.leagues.get(&league).ok_or(Error::NotFound)?;
                if l.phase != Phase::Finished
                    || !l.team_of(&member).is_some_and(|t| l.teams[t].registered)
                {
                    return Err(Error::Denied);
                }
                if self
                    .disputes
                    .values()
                    .any(|d| d.member == member && d.league == league && d.resolution.is_none())
                {
                    return Err(Error::Denied);
                }
                self.disputes.insert(
                    id,
                    Dispute {
                        league,
                        member,
                        reason,
                        created_ms: now,
                        resolution: None,
                    },
                );
            }
            Action::ResolveDispute {
                id,
                response,
                players,
                teams,
            } => {
                if !admin {
                    return Err(Error::Denied);
                }
                text(&response, 4096)?;
                let d = self.disputes.get_mut(&id).ok_or(Error::NotFound)?;
                if d.resolution.is_some() {
                    return Err(Error::Denied);
                }
                let l = self.leagues.get_mut(&d.league).ok_or(Error::NotFound)?;
                if l.phase != Phase::Finished {
                    return Err(Error::Denied);
                }
                // Deltas preserve the original scorer's events. Rejected claims use empty maps.
                for (id, delta) in &players {
                    if !l.played.contains(id) {
                        return Err(Error::Denied);
                    }
                    let score = l.player_scores.get_mut(id).ok_or(Error::NotFound)?;
                    *score = score.checked_add(*delta).ok_or(Error::Capacity)?;
                }
                for (id, delta) in &teams {
                    let score = l.team_scores.get_mut(id).ok_or(Error::NotFound)?;
                    *score = score.checked_add(*delta).ok_or(Error::Capacity)?;
                }
                d.resolution = Some(Resolution {
                    reviewer: actor.into(),
                    time_ms: now,
                    response,
                    players,
                    teams,
                });
            }
            _ => return Err(Error::Denied),
        }
        Ok(())
    }
    pub fn season_rankings(&self, id: &str) -> Result<Rankings> {
        let season = self.seasons.get(id).ok_or(Error::NotFound)?;
        let (mut players, mut teams) = (
            BTreeMap::<String, i64>::new(),
            BTreeMap::<String, i64>::new(),
        );
        for id in &season.leagues {
            let l = self.leagues.get(id).ok_or(Error::NotFound)?;
            if l.phase != Phase::Finished {
                continue;
            }
            for (target, scores) in [
                (&mut teams, &l.team_scores),
                (&mut players, &l.player_scores),
            ] {
                for (id, score) in scores {
                    let total = target.entry(id.clone()).or_default();
                    *total = total.checked_add(*score).ok_or(Error::Capacity)?;
                }
            }
        }
        fn sorted(map: BTreeMap<String, i64>) -> Vec<(String, i64)> {
            let mut v: Vec<_> = map.into_iter().collect();
            v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            v
        }
        Ok(Rankings {
            teams: sorted(teams),
            players: sorted(players),
        })
    }
}
