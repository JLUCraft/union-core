//! Federation decisions count schools, not devices or hosting machines.
use crate::{
    Error, Result,
    governance::{Action, State},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Council {
    pub epoch: u64,
    pub schools: BTreeMap<String, BTreeSet<String>>,
    pub quorum: usize,
    pub change_quorum: usize,
    pub cooldown_ms: u64,
}
impl Council {
    pub fn validate(&self) -> Result<()> {
        let n = self.schools.len();
        if n == 0
            || n > 128
            || self.quorum < n.saturating_mul(2).div_ceil(3)
            || self.quorum > n
            || self.change_quorum < n.saturating_mul(3).div_ceil(4)
            || self.change_quorum < self.quorum
            || self.change_quorum > n
            || self.cooldown_ms < 172_800_000
            || self.cooldown_ms > 604_800_000
        {
            return Err(Error::Denied);
        }
        let mut devices = BTreeSet::new();
        for (school, representatives) in &self.schools {
            if school.is_empty()
                || school.len() > 128
                || representatives.is_empty()
                || representatives.len() > 16
            {
                return Err(Error::Denied);
            }
            for device in representatives {
                device.parse::<crate::PeerId>().map_err(|_| Error::Denied)?;
                if !devices.insert(device) {
                    return Err(Error::Denied);
                }
            }
        }
        Ok(())
    }
    fn school(&self, device: &str) -> Result<String> {
        self.schools
            .iter()
            .find(|(_, devices)| devices.contains(device))
            .map(|(id, _)| id.clone())
            .ok_or(Error::Denied)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proposal {
    pub proposer: String,
    pub action: Action,
    pub epoch: u64,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub approvals: BTreeMap<String, String>,
    pub executed: bool,
    pub cancelled: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ballot {
    pub title: String,
    pub options: Vec<String>,
    pub closes_ms: u64,
    pub electorate: BTreeSet<String>,
    pub votes: BTreeMap<String, usize>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Feedback {
    pub member: String,
    pub category: String,
    pub text: String,
    pub created_ms: u64,
    pub response: Option<String>,
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
pub(crate) fn protected(action: &Action) -> bool {
    matches!(
        action,
        Action::CreateSeason { .. }
            | Action::ScheduleLeague { .. }
            | Action::ResolveDispute { .. }
            | Action::SetConsensusMembers { .. }
            | Action::GrantAdmin { .. }
            | Action::RevokeAdmin { .. }
            | Action::RotateMemberDevice { .. }
            | Action::Enroll { .. }
            | Action::CreateLeague { .. }
            | Action::UpdateCouncil { .. }
    )
}

impl State {
    pub(crate) fn council_transition(
        &mut self,
        actor: &str,
        now: u64,
        action: Action,
        approved: bool,
    ) -> Result<()> {
        match action {
            Action::InstallCouncil { mut council } => {
                if self.council.is_some() || !self.admins.contains(actor) {
                    return Err(Error::Denied);
                }
                council.validate()?;
                council.epoch = 1;
                self.council = Some(council);
            }
            Action::UpdateCouncil { mut council } => {
                if !approved {
                    return Err(Error::Denied);
                }
                council.validate()?;
                council.epoch = self
                    .council
                    .as_ref()
                    .ok_or(Error::Denied)?
                    .epoch
                    .checked_add(1)
                    .ok_or(Error::Capacity)?;
                self.council = Some(council);
            }
            Action::Propose {
                id,
                action,
                expires_ms,
            } => {
                text(&id, 128)?;
                if !protected(&action)
                    || expires_ms <= now
                    || expires_ms > now.saturating_add(604_800_000)
                    || self.proposals.contains_key(&id)
                    || self.proposals.len() >= 10000
                {
                    return Err(Error::Denied);
                }
                let council = self.council.as_ref().ok_or(Error::Denied)?;
                let school = council.school(actor)?;
                if matches!(*action, Action::UpdateCouncil { .. })
                    && expires_ms <= now.saturating_add(council.cooldown_ms)
                {
                    return Err(Error::Denied);
                }
                self.proposals.insert(
                    id,
                    Proposal {
                        proposer: actor.into(),
                        action: *action,
                        epoch: council.epoch,
                        created_ms: now,
                        expires_ms,
                        approvals: [(school, actor.into())].into(),
                        executed: false,
                        cancelled: false,
                    },
                );
            }
            Action::ApproveProposal { id } => {
                let council = self.council.as_ref().ok_or(Error::Denied)?;
                let school = council.school(actor)?;
                let proposal = self.proposals.get_mut(&id).ok_or(Error::NotFound)?;
                if proposal.epoch != council.epoch
                    || proposal.expires_ms <= now
                    || proposal.executed
                    || proposal.cancelled
                    || proposal.approvals.contains_key(&school)
                {
                    return Err(Error::Denied);
                }
                proposal.approvals.insert(school, actor.into());
            }
            Action::CancelProposal { id } => {
                let proposal = self.proposals.get_mut(&id).ok_or(Error::NotFound)?;
                if proposal.proposer != actor || proposal.executed || proposal.cancelled {
                    return Err(Error::Denied);
                }
                proposal.cancelled = true;
            }
            Action::ExecuteProposal { id } => {
                if !self.can_read(actor) {
                    return Err(Error::Denied);
                }
                let council = self.council.as_ref().ok_or(Error::Denied)?;
                let proposal = self.proposals.get(&id).ok_or(Error::NotFound)?.clone();
                let change = matches!(proposal.action, Action::UpdateCouncil { .. });
                let threshold = if change {
                    council.change_quorum
                } else {
                    council.quorum
                };
                if proposal.executed
                    || proposal.cancelled
                    || proposal.expires_ms <= now
                    || proposal.epoch != council.epoch
                    || proposal.approvals.len() < threshold
                    || (change && now < proposal.created_ms.saturating_add(council.cooldown_ms))
                {
                    return Err(Error::Denied);
                }
                for (school, device) in &proposal.approvals {
                    if council.school(device)? != *school {
                        return Err(Error::Denied);
                    }
                }
                self.transition_authorized(&proposal.proposer, now, proposal.action, true)?;
                self.proposals.get_mut(&id).ok_or(Error::NotFound)?.executed = true;
            }
            Action::CreateBallot {
                id,
                title,
                options,
                closes_ms,
            } => {
                if !self.admins.contains(actor)
                    && self
                        .council
                        .as_ref()
                        .is_none_or(|c| c.school(actor).is_err())
                {
                    return Err(Error::Denied);
                }
                text(&id, 128)?;
                text(&title, 2048)?;
                if options.len() < 2
                    || options.len() > 20
                    || options.iter().collect::<BTreeSet<_>>().len() != options.len()
                    || closes_ms <= now
                    || closes_ms > now.saturating_add(2_592_000_000)
                    || self.ballots.contains_key(&id)
                    || self.ballots.len() >= 10000
                {
                    return Err(Error::Denied);
                }
                for option in &options {
                    text(option, 256)?;
                }
                self.ballots.insert(
                    id,
                    Ballot {
                        title,
                        options,
                        closes_ms,
                        electorate: self.members.keys().cloned().collect(),
                        votes: BTreeMap::new(),
                    },
                );
            }
            Action::MemberVote { id, option } => {
                let member = self
                    .members
                    .iter()
                    .find(|(_, m)| m.owns(actor))
                    .map(|(id, _)| id.clone())
                    .ok_or(Error::Denied)?;
                let ballot = self.ballots.get_mut(&id).ok_or(Error::NotFound)?;
                if now >= ballot.closes_ms
                    || option >= ballot.options.len()
                    || !ballot.electorate.contains(&member)
                    || ballot.votes.contains_key(&member)
                {
                    return Err(Error::Denied);
                }
                ballot.votes.insert(member, option);
            }
            Action::SubmitFeedback {
                id,
                category,
                text: body,
            } => {
                let member = self
                    .members
                    .iter()
                    .find(|(_, m)| m.owns(actor))
                    .map(|(id, _)| id.clone())
                    .ok_or(Error::Denied)?;
                text(&id, 128)?;
                text(&category, 128)?;
                text(&body, 4096)?;
                if self.feedback.contains_key(&id) || self.feedback.len() >= 10000 {
                    return Err(Error::Capacity);
                }
                self.feedback.insert(
                    id,
                    Feedback {
                        member,
                        category,
                        text: body,
                        created_ms: now,
                        response: None,
                    },
                );
            }
            Action::RespondFeedback { id, text: body } => {
                if !self.admins.contains(actor) {
                    return Err(Error::Denied);
                }
                text(&body, 4096)?;
                self.feedback.get_mut(&id).ok_or(Error::NotFound)?.response = Some(body);
            }
            _ => return Err(Error::Protocol("not a council action".into())),
        }
        Ok(())
    }
}
