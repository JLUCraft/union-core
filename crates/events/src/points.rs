//! Deterministic point balances, oracle limits, and signed AI spending budgets.
use crate::{EventAction, EventsState, workflows::OrganizationAction};
use protocol::{AiAllowance, Cid, Error, PointAccount, Result};
use serde::{Deserialize, Serialize};
use state::Context;
use std::collections::BTreeMap;

pub const ACTIVITY_SLICE_MS: u64 = 300_000;
pub const DAY_MS: u64 = 86_400_000;
pub const WEIGHT_DENOMINATOR: u64 = 10_000;
const MAX_WEIGHT_BPS: u64 = 20_000;
const MAX_BATCH_SLICES: u64 = 12;
const MAX_PLAYERS: usize = 256;
const MAX_RECORDS: usize = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivityPolicy {
    pub daily_member_cap: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleSourcePolicy {
    pub title: String,
    pub club: String,
    pub oracle_device: String,
    pub service: String,
    pub weight_bps: u64,
    pub points_per_slice: u64,
    pub max_bonus_per_slice: u64,
    pub daily_source_cap: u64,
    pub enabled: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DayUsage {
    pub day_epoch: u64,
    pub points: u64,
    pub active_slices: u64,
    pub afk_slices: u64,
}
impl DayUsage {
    fn at(&mut self, day: u64) {
        if self.day_epoch != day {
            *self = Self {
                day_epoch: day,
                ..Self::default()
            };
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleSource {
    pub config: OracleSourcePolicy,
    pub last_window_end_ms: u64,
    pub daily: DayUsage,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivityTotals {
    pub active_slices: u64,
    pub afk_slices: u64,
    pub bonus_points: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub source: String,
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub players: BTreeMap<String, ActivityTotals>,
}
/// The compact on-chain block binds a batch summary to its full IPLD telemetry file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivityEvidence {
    pub attestation_hash: String,
    pub telemetry: Cid,
}
impl ActivityEvidence {
    pub fn block(attestation: &Attestation, telemetry: Cid) -> Result<protocol::IpldBlock> {
        let summary = serde_json::to_vec(attestation).map_err(Error::protocol)?;
        let header = Self {
            attestation_hash: protocol::digest(&summary),
            telemetry,
        };
        protocol::IpldBlock::raw(&serde_json::to_vec(&header).map_err(Error::protocol)?)
    }
    pub fn verify(block: &protocol::IpldBlock, attestation: &Attestation) -> Result<Self> {
        if !block.cid.is_raw() {
            return Err(Error::Denied);
        }
        let header: Self = serde_json::from_slice(&block.bytes()?).map_err(|_| Error::Denied)?;
        let summary = serde_json::to_vec(attestation).map_err(Error::protocol)?;
        if header.attestation_hash != protocol::digest(&summary) {
            return Err(Error::Denied);
        }
        Ok(header)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivityReceipt {
    pub accounts: BTreeMap<String, String>,
    pub credited_ms: u64,
    pub attestation: Attestation,
    pub evidence: Cid,
    pub credited_day: u64,
    pub awarded: BTreeMap<String, u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BudgetAuthorization {
    pub account: PointAccount,
    pub epoch: u64,
    pub remaining_points: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiDocument {
    pub member: String,
    pub worker: String,
    pub output: Cid,
    pub created_ms: u64,
}

pub fn balance(state: &EventsState, account: &PointAccount) -> u64 {
    state
        .organization
        .points
        .get(&account.club)
        .and_then(|m| m.get(&account.member))
        .copied()
        .unwrap_or(0)
}
pub fn debit(state: &mut EventsState, account: &PointAccount, amount: u64) -> Result<()> {
    let value = balance(state, account)
        .checked_sub(amount)
        .ok_or(Error::Denied)?;
    state
        .organization
        .points
        .entry(account.club.clone())
        .or_default()
        .insert(account.member.clone(), value);
    Ok(())
}
pub fn credit(state: &mut EventsState, account: &PointAccount, amount: u64) -> Result<()> {
    let value = balance(state, account)
        .checked_add(amount)
        .ok_or(Error::Capacity)?;
    state
        .organization
        .points
        .entry(account.club.clone())
        .or_default()
        .insert(account.member.clone(), value);
    Ok(())
}
pub fn workflow_payer(
    state: &EventsState,
    action: &EventAction,
) -> Result<(PointAccount, AiAllowance)> {
    let scope = match action {
        EventAction::Approve { id, .. }
        | EventAction::Organization(
            OrganizationAction::Polish { event: id, .. }
            | OrganizationAction::Summary { event: id, .. },
        ) => format!("event:{id}"),
        EventAction::Organization(OrganizationAction::ReportGenerated { id, .. }) => {
            format!("report:{id}")
        }
        _ => return Err(Error::Denied),
    };
    let budget = state
        .organization
        .ai_allowances
        .get(&scope)
        .filter(|b| b.remaining_points > 0)
        .ok_or(Error::Denied)?;
    Ok((
        budget.account.clone(),
        AiAllowance {
            scope,
            epoch: budget.epoch,
        },
    ))
}
pub fn debit_allowance(
    state: &mut EventsState,
    account: &PointAccount,
    allowance: &AiAllowance,
    amount: u64,
) -> Result<()> {
    let budget = state
        .organization
        .ai_allowances
        .get_mut(&allowance.scope)
        .ok_or(Error::Denied)?;
    if budget.epoch != allowance.epoch || &budget.account != account {
        return Err(Error::Denied);
    }
    budget.remaining_points = budget
        .remaining_points
        .checked_sub(amount)
        .ok_or(Error::Denied)?;
    Ok(())
}
pub fn refund_allowance(
    state: &mut EventsState,
    account: &PointAccount,
    allowance: &AiAllowance,
    amount: u64,
) -> Result<()> {
    // Replacing or revoking a consent never restores an older spending authorization.
    if let Some(budget) = state.organization.ai_allowances.get_mut(&allowance.scope)
        && budget.epoch == allowance.epoch
        && &budget.account == account
    {
        budget.remaining_points = budget
            .remaining_points
            .checked_add(amount)
            .ok_or(Error::Capacity)?;
    }
    Ok(())
}
fn administrator(ctx: &Context<'_>) -> Result<()> {
    if ctx.core.admins.contains(ctx.actor) {
        Ok(())
    } else {
        Err(Error::Denied)
    }
}
pub fn transition(
    state: &mut EventsState,
    ctx: &Context<'_>,
    action: OrganizationAction,
) -> Result<()> {
    match action {
        OrganizationAction::ActivityPolicy { policy } => {
            administrator(ctx)?;
            if policy.daily_member_cap == 0 {
                return Err(Error::Denied);
            }
            state.organization.activity_policy = Some(policy);
        }
        OrganizationAction::OracleSource { id, source } => {
            administrator(ctx)?;
            protocol::validate_identifier(&id)?;
            for value in [
                &source.title,
                &source.club,
                &source.oracle_device,
                &source.service,
            ] {
                protocol::validate_identifier(value)?;
            }
            if source.weight_bps == 0
                || source.weight_bps > MAX_WEIGHT_BPS
                || source.points_per_slice == 0
                || source.daily_source_cap == 0
                || !ctx
                    .core
                    .members
                    .values()
                    .any(|m| m.owns(&source.oracle_device))
                || !ctx.core.members.values().any(|m| m.club == source.club)
            {
                return Err(Error::Denied);
            }
            if let Some(existing) = state.organization.oracle_sources.get_mut(&id) {
                existing.config = source;
            } else {
                if state.organization.oracle_sources.len() >= crate::workflows::MAX_ITEMS {
                    return Err(Error::Capacity);
                }
                state.organization.oracle_sources.insert(
                    id,
                    OracleSource {
                        config: source,
                        last_window_end_ms: 0,
                        daily: DayUsage::default(),
                    },
                );
            }
        }
        OrganizationAction::ActivityAttest {
            source,
            window_start_ms,
            window_end_ms,
            players,
            evidence,
        } => {
            attest(
                state,
                ctx,
                Attestation {
                    source,
                    window_start_ms,
                    window_end_ms,
                    players,
                },
                evidence,
            )?;
        }
        OrganizationAction::AuthorizeAi { scope, budget } => {
            let (member, record) = ctx.member()?;
            let allowed = if let Some(id) = scope.strip_prefix("event:") {
                let event = state.events.get(id).ok_or(Error::NotFound)?;
                crate::manage(event, ctx)
            } else if let Some(id) = scope.strip_prefix("report:") {
                let report = state.organization.reports.get(id).ok_or(Error::NotFound)?;
                crate::club_manager(ctx, &report.club)
            } else {
                false
            };
            if !allowed {
                return Err(Error::Denied);
            }
            let account = PointAccount {
                club: record.club.clone(),
                member: member.into(),
            };
            if budget > balance(state, &account) {
                return Err(Error::Denied);
            }
            if !state.organization.ai_allowances.contains_key(&scope)
                && state.organization.ai_allowances.len() >= MAX_RECORDS
            {
                return Err(Error::Capacity);
            }
            state.organization.ai_allowances.insert(
                scope,
                BudgetAuthorization {
                    account,
                    epoch: ctx.revision.checked_add(1).ok_or(Error::Capacity)?,
                    remaining_points: budget,
                },
            );
        }
        _ => return Err(Error::Denied),
    }
    Ok(())
}
fn attest(
    state: &mut EventsState,
    ctx: &Context<'_>,
    attestation: Attestation,
    evidence: protocol::IpldBlock,
) -> Result<()> {
    let source = state
        .organization
        .oracle_sources
        .get(&attestation.source)
        .ok_or(Error::NotFound)?;
    let policy = state
        .organization
        .activity_policy
        .as_ref()
        .ok_or(Error::Denied)?;
    let start = attestation.window_start_ms;
    let end = attestation.window_end_ms;
    let duration = end.checked_sub(start).ok_or(Error::Denied)?;
    if !source.config.enabled
        || source.config.oracle_device != ctx.actor
        || duration == 0
        || duration > ACTIVITY_SLICE_MS * MAX_BATCH_SLICES
        || !start.is_multiple_of(ACTIVITY_SLICE_MS)
        || !end.is_multiple_of(ACTIVITY_SLICE_MS)
        || start < source.last_window_end_ms
        || end > ctx.now_ms
        || attestation.players.len() > MAX_PLAYERS
    {
        return Err(Error::Denied);
    }
    state
        .organization
        .activity_receipts
        .retain(|_, receipt| receipt.credited_ms.saturating_add(DAY_MS) >= ctx.now_ms);
    if state.organization.activity_receipts.len() >= MAX_RECORDS {
        return Err(Error::Capacity);
    }
    let config = source.config.clone();
    let daily_cap = policy.daily_member_cap;
    let slices = duration / ACTIVITY_SLICE_MS;
    for (member, total) in &attestation.players {
        if !ctx.core.members.contains_key(member)
            || total
                .active_slices
                .checked_add(total.afk_slices)
                .is_none_or(|v| v > slices)
            || total
                .active_slices
                .checked_mul(config.max_bonus_per_slice)
                .is_none_or(|limit| total.bonus_points > limit)
        {
            return Err(Error::Denied);
        }
    }
    ActivityEvidence::verify(&evidence, &attestation)?;
    let evidence = evidence.cid;
    let day = ctx.now_ms / DAY_MS;
    let source = state
        .organization
        .oracle_sources
        .get_mut(&attestation.source)
        .ok_or(Error::NotFound)?;
    source.daily.at(day);
    let mut remaining = config.daily_source_cap.saturating_sub(source.daily.points);
    let mut awarded = BTreeMap::new();
    let mut accounts = BTreeMap::new();
    for (member, total) in &attestation.players {
        let club = ctx
            .core
            .members
            .get(member)
            .ok_or(Error::Denied)?
            .club
            .clone();
        let usage = state
            .organization
            .activity_members
            .entry(member.clone())
            .or_default();
        usage.at(day);
        let raw = u128::from(total.active_slices)
            .checked_mul(u128::from(config.points_per_slice))
            .and_then(|v| v.checked_add(u128::from(total.bonus_points)))
            .and_then(|v| v.checked_mul(u128::from(config.weight_bps)))
            .ok_or(Error::Capacity)?
            / u128::from(WEIGHT_DENOMINATOR);
        let raw = u64::try_from(raw).map_err(|_| Error::Capacity)?;
        let points = raw
            .min(daily_cap.saturating_sub(usage.points))
            .min(remaining);
        remaining -= points;
        usage.points = usage.points.checked_add(points).ok_or(Error::Capacity)?;
        usage.active_slices = usage
            .active_slices
            .checked_add(total.active_slices)
            .ok_or(Error::Capacity)?;
        usage.afk_slices = usage
            .afk_slices
            .checked_add(total.afk_slices)
            .ok_or(Error::Capacity)?;
        source.daily.points = source
            .daily
            .points
            .checked_add(points)
            .ok_or(Error::Capacity)?;
        source.daily.active_slices = source
            .daily
            .active_slices
            .checked_add(total.active_slices)
            .ok_or(Error::Capacity)?;
        source.daily.afk_slices = source
            .daily
            .afk_slices
            .checked_add(total.afk_slices)
            .ok_or(Error::Capacity)?;
        let balance = state
            .organization
            .points
            .entry(club.clone())
            .or_default()
            .entry(member.clone())
            .or_default();
        *balance = balance.checked_add(points).ok_or(Error::Capacity)?;
        awarded.insert(member.clone(), points);
        accounts.insert(member.clone(), club);
    }
    source.last_window_end_ms = end;
    let id = format!("{}:{start}:{end}", attestation.source);
    state.organization.activity_receipts.insert(
        id,
        ActivityReceipt {
            accounts,
            credited_ms: ctx.now_ms,
            attestation,
            evidence,
            credited_day: day,
            awarded,
        },
    );
    Ok(())
}
