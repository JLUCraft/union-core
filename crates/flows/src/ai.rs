//! Journal-owned AI pricing, escrow, refunds, and provider rewards.
use crate::{Approver, FlowsState, StageRecord, Template};
use protocol::{AiAllowance, Error, LlmUsage, PointAccount, Result};
use serde::{Deserialize, Serialize};
use state::{Context, Domain};
use std::collections::BTreeSet;

pub const MEMBER_REQUEST_TIMEOUT_MS: u64 = 180_000;
const TOKENS_PER_UNIT: u128 = 1000;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Settlement {
    Burn,
    ProviderReward,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AiPricing {
    pub base_points: u64,
    pub input_points_per_1k: u64,
    pub output_points_per_1k: u64,
    pub max_input_tokens: u64,
    pub settlement: Settlement,
}
impl AiPricing {
    pub fn validate(&self) -> Result<()> {
        if self.max_input_tokens == 0
            || (self.base_points == 0
                && self.input_points_per_1k == 0
                && self.output_points_per_1k == 0)
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    pub fn quote(&self, max_tokens: u32) -> Result<u64> {
        self.cost(self.max_input_tokens, u64::from(max_tokens))
    }
    pub fn cost(&self, input: u64, output: u64) -> Result<u64> {
        let rate = u128::from(input)
            .checked_mul(u128::from(self.input_points_per_1k))
            .and_then(|v| {
                u128::from(output)
                    .checked_mul(u128::from(self.output_points_per_1k))
                    .and_then(|o| v.checked_add(o))
            })
            .ok_or(Error::Capacity)?;
        let variable = rate
            .checked_add(TOKENS_PER_UNIT - 1)
            .ok_or(Error::Capacity)?
            / TOKENS_PER_UNIT;
        self.base_points
            .checked_add(u64::try_from(variable).map_err(|_| Error::Capacity)?)
            .ok_or(Error::Capacity)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiWorker {
    pub models: BTreeSet<String>,
    pub active: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Billing {
    pub payer: PointAccount,
    pub provider: PointAccount,
    pub pricing: AiPricing,
    pub max_tokens: u32,
    pub allowance: Option<AiAllowance>,
}
fn debit<D: Domain>(inner: &mut D::State, billing: &Billing, amount: u64) -> Result<()> {
    if let Some(allowance) = &billing.allowance {
        D::debit_ai_allowance(inner, &billing.payer, allowance, amount)?;
    }
    D::debit_points(inner, &billing.payer, amount)
}
pub(crate) fn reserve_records<D: Domain>(
    state: &mut FlowsState<D>,
    ctx: &Context<'_>,
    template: &Template,
    payer: PointAccount,
    allowance: Option<AiAllowance>,
    max_points: Option<u64>,
) -> Result<Vec<StageRecord>> {
    let mut records = Vec::with_capacity(template.stages.len());
    let mut total = 0u64;
    for stage in &template.stages {
        let mut record = StageRecord::default();
        if let Approver::Ai {
            worker,
            model,
            max_tokens,
            ..
        } = &stage.approver
        {
            let provider = ctx.core.members.get(worker).ok_or(Error::Denied)?;
            if !state
                .ai_workers
                .get(worker)
                .is_some_and(|w| w.active && w.models.contains(model))
            {
                return Err(Error::Denied);
            }
            let pricing = state.ai_pricing.get(model).ok_or(Error::Denied)?.clone();
            pricing.validate()?;
            let points = pricing.quote(*max_tokens)?;
            total = total.checked_add(points).ok_or(Error::Capacity)?;
            record.billing = Some(Billing {
                payer: payer.clone(),
                provider: PointAccount {
                    club: provider.club.clone(),
                    member: worker.clone(),
                },
                pricing,
                max_tokens: *max_tokens,
                allowance: allowance.clone(),
            });
            record.escrowed_points = points;
        }
        records.push(record);
    }
    if max_points.is_some_and(|max| total > max) {
        return Err(Error::Denied);
    }
    for record in &records {
        if let Some(billing) = &record.billing {
            debit::<D>(&mut state.inner, billing, record.escrowed_points)?;
        }
    }
    Ok(records)
}
pub(crate) fn refund<D: Domain>(inner: &mut D::State, record: &mut StageRecord) -> Result<()> {
    let points = record.escrowed_points;
    if points == 0 {
        return Ok(());
    }
    let billing = record.billing.as_ref().ok_or(Error::Denied)?;
    D::credit_points(inner, &billing.payer, points)?;
    if let Some(allowance) = &billing.allowance {
        D::refund_ai_allowance(inner, &billing.payer, allowance, points)?;
    }
    record.escrowed_points = 0;
    record.refunded_points = record
        .refunded_points
        .checked_add(points)
        .ok_or(Error::Capacity)?;
    if let Some(run) = record.ai_runs.last_mut()
        && run.output.is_none()
        && run.charged_points == 0
        && run.refunded_points == 0
    {
        run.refunded_points = points;
    }
    Ok(())
}
pub(crate) fn settle<D: Domain>(
    state: &mut FlowsState<D>,
    ctx: &Context<'_>,
    instance: &str,
    job: &str,
    attempt: usize,
    usage: Option<&LlmUsage>,
) -> Result<()> {
    let flow = state.flows.get_mut(instance).ok_or(Error::NotFound)?;
    if flow.status != crate::Status::Active || flow.deadline_ms.is_some_and(|t| ctx.now_ms >= t) {
        return Err(Error::Denied);
    }
    let record = flow.records.get_mut(flow.current).ok_or(Error::Denied)?;
    let billing = record.billing.as_ref().ok_or(Error::Denied)?.clone();
    if ctx.member()?.0 != billing.provider.member
        || record.ai_runs.len().checked_sub(1) != Some(attempt)
    {
        return Err(Error::Denied);
    }
    let run = record.ai_runs.last().ok_or(Error::Denied)?;
    if run.device != ctx.actor
        || run.job != job
        || run.retry_requested
        || run.output.is_some()
        || run.error.is_some()
    {
        return Err(Error::Denied);
    }
    let charged = if let Some(usage) = usage {
        if usage.prompt_tokens.checked_add(usage.completion_tokens) != Some(usage.total_tokens) {
            return Err(Error::Denied);
        }
        billing
            .pricing
            .cost(usage.prompt_tokens, usage.completion_tokens)?
            .min(record.escrowed_points)
    } else {
        0
    };
    let refund = record
        .escrowed_points
        .checked_sub(charged)
        .ok_or(Error::Denied)?;
    D::credit_points(&mut state.inner, &billing.payer, refund)?;
    if let Some(allowance) = &billing.allowance {
        D::refund_ai_allowance(&mut state.inner, &billing.payer, allowance, refund)?;
    }
    match billing.pricing.settlement {
        Settlement::Burn => {
            state.ai_burned_points = state
                .ai_burned_points
                .checked_add(charged)
                .ok_or(Error::Capacity)?
        }
        Settlement::ProviderReward => {
            D::credit_points(&mut state.inner, &billing.provider, charged)?
        }
    }
    record.escrowed_points = 0;
    record.refunded_points = record
        .refunded_points
        .checked_add(refund)
        .ok_or(Error::Capacity)?;
    let run = record.ai_runs.last_mut().ok_or(Error::Denied)?;
    run.usage = usage.cloned();
    run.charged_points = charged;
    run.refunded_points = refund;
    Ok(())
}
pub(crate) fn reserve_retry<D: Domain>(
    inner: &mut D::State,
    record: &mut StageRecord,
) -> Result<()> {
    if record.escrowed_points != 0 {
        return Err(Error::Denied);
    }
    let billing = record.billing.as_ref().ok_or(Error::Denied)?;
    let points = billing.pricing.quote(billing.max_tokens)?;
    debit::<D>(inner, billing, points)?;
    record.escrowed_points = points;
    Ok(())
}

/// Newly minted credits or provider rewards must never make an existing escrow unrefundable.
pub(crate) fn validate_balances<D: Domain>(state: &FlowsState<D>) -> Result<()> {
    let mut held = std::collections::BTreeMap::<PointAccount, u64>::new();
    for flow in state.flows.values() {
        for record in &flow.records {
            if record.escrowed_points == 0 {
                continue;
            }
            let payer = &record.billing.as_ref().ok_or(Error::Denied)?.payer;
            let total = held.entry(payer.clone()).or_default();
            *total = total
                .checked_add(record.escrowed_points)
                .ok_or(Error::Capacity)?;
        }
    }
    for (account, frozen) in held {
        D::point_balance(&state.inner, &account)?
            .checked_add(frozen)
            .ok_or(Error::Capacity)?;
    }
    Ok(())
}
