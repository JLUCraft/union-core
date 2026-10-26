//! Exact point presentation shared by native clients and exported member statements.
use crate::{Identity, Result, application::Snapshot};
use protocol::PointAccount;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PriceView {
    pub base_points: String,
    pub input_points_per_1k: String,
    pub output_points_per_1k: String,
    pub max_input_tokens: String,
    pub settlement: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActivityRow {
    pub id: String,
    pub source: String,
    pub credited_ms: u64,
    pub points: String,
    pub active_slices: u64,
    pub afk_slices: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AiRow {
    pub quote_points: String,
    pub id: String,
    pub stage: usize,
    pub flow_status: String,
    pub status: String,
    pub started_ms: u64,
    pub model: String,
    pub purpose: String,
    pub frozen_points: String,
    pub charged_points: String,
    pub refunded_points: String,
    pub input_tokens: String,
    pub output_tokens: String,
    pub output: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PointOverview {
    pub genesis: String,
    pub revision: u64,
    pub as_of_ms: u64,
    pub day_ends_ms: u64,
    pub account: PointAccount,
    pub available_points: String,
    pub frozen_points: String,
    pub earned_today: String,
    pub active_slices: u64,
    pub afk_slices: u64,
    pub daily_member_cap: Option<String>,
    pub activity: Vec<ActivityRow>,
    pub ai: Vec<AiRow>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPointStatement {
    pub kind: String,
    pub payload: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Serialize)]
pub struct Presentation {
    pub max_output_tokens: u32,
    #[serde(flatten)]
    pub overview: PointOverview,
    pub prices: BTreeMap<String, PriceView>,
    pub statement: SignedPointStatement,
}
impl SignedPointStatement {
    pub const KIND: &'static str = "jlucraft.points.statement";
    pub fn sign(overview: &PointOverview, identity: &Identity) -> Result<Self> {
        let payload = serde_json::to_string(overview).map_err(crate::Error::protocol)?;
        let public_key = identity
            .public_key()
            .try_into_ed25519()
            .map_err(crate::Error::protocol)?
            .to_bytes()
            .to_vec();
        let signature = identity.sign(payload.as_bytes())?;
        Ok(Self {
            kind: Self::KIND.into(),
            payload,
            public_key,
            signature,
        })
    }
}
pub fn present(
    snapshot: &Snapshot,
    view: &state::governance::IdentityPresentation,
    identity: &Identity,
    genesis: &str,
    observed_ms: u64,
) -> Result<Option<Presentation>> {
    let peer = identity.peer_id().to_string();
    let Some((member, record)) = view.members.iter().find(|(_, m)| m.owns(&peer)) else {
        return Ok(None);
    };
    let account = PointAccount {
        member: member.clone(),
        club: record.club.clone(),
    };
    let current_day = observed_ms / events::points::DAY_MS;
    let usage = snapshot
        .domain
        .organization
        .activity_members
        .get(member)
        .filter(|d| d.day_epoch == current_day);
    let mut activity = Vec::new();
    for (id, receipt) in &snapshot.domain.organization.activity_receipts {
        if receipt.credited_ms.saturating_add(events::points::DAY_MS) >= observed_ms
            && receipt.accounts.get(member) == Some(&account.club)
            && let Some(points) = receipt.awarded.get(member)
        {
            let total = receipt.attestation.players.get(member);
            activity.push(ActivityRow {
                id: id.clone(),
                source: snapshot
                    .domain
                    .organization
                    .oracle_sources
                    .get(&receipt.attestation.source)
                    .map(|s| s.config.title.clone())
                    .unwrap_or_else(|| receipt.attestation.source.clone()),
                credited_ms: receipt.credited_ms,
                points: points.to_string(),
                active_slices: total.map_or(0, |t| t.active_slices),
                afk_slices: total.map_or(0, |t| t.afk_slices),
            });
        }
    }
    activity.sort_by(|a, b| {
        b.credited_ms
            .cmp(&a.credited_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut ai = Vec::new();
    let mut frozen = 0u64;
    for (id, flow) in &snapshot.domain.flows {
        if flow.payer != account {
            continue;
        }
        let template = flows::template_for(&snapshot.domain.flow_templates, flow)?;
        for (index, stage) in template.stages.iter().enumerate() {
            let flows::Approver::Ai { model, purpose, .. } = &stage.approver else {
                continue;
            };
            let record = flow.records.get(index).ok_or(crate::Error::Denied)?;
            let billing = record.billing.as_ref().ok_or(crate::Error::Denied)?;
            frozen = frozen
                .checked_add(record.escrowed_points)
                .ok_or(crate::Error::Capacity)?;
            let mut charged = 0u64;
            let mut input = 0u64;
            let mut output_tokens = 0u64;
            for run in &record.ai_runs {
                charged = charged
                    .checked_add(run.charged_points)
                    .ok_or(crate::Error::Capacity)?;
                if let Some(usage) = &run.usage {
                    input = input
                        .checked_add(usage.prompt_tokens)
                        .ok_or(crate::Error::Capacity)?;
                    output_tokens = output_tokens
                        .checked_add(usage.completion_tokens)
                        .ok_or(crate::Error::Capacity)?;
                }
            }
            let flow_status = serde_json::to_value(&flow.status)
                .map_err(crate::Error::protocol)?
                .as_str()
                .unwrap_or("active")
                .to_owned();
            let last = record.ai_runs.last();
            let status = if last.is_some_and(|r| r.output.is_some()) {
                "completed"
            } else if flow.status == flows::Status::Cancelled {
                "cancelled"
            } else if flow.status != flows::Status::Active || index < flow.current {
                "refunded"
            } else if last.is_some_and(|r| r.error.is_some() && !r.retry_requested) {
                "failed"
            } else if last.is_some_and(|r| !r.retry_requested && r.error.is_none()) {
                "running"
            } else {
                "queued"
            }
            .to_owned();
            ai.push(AiRow {
                quote_points: billing.pricing.quote(billing.max_tokens)?.to_string(),
                id: id.clone(),
                stage: index,
                flow_status,
                status,
                started_ms: flow.started_ms,
                model: model.clone(),
                purpose: purpose.clone(),
                frozen_points: record.escrowed_points.to_string(),
                charged_points: charged.to_string(),
                refunded_points: record.refunded_points.to_string(),
                input_tokens: input.to_string(),
                output_tokens: output_tokens.to_string(),
                output: record
                    .ai_runs
                    .last()
                    .and_then(|r| r.output.as_ref())
                    .map(ToString::to_string),
            });
        }
    }
    ai.sort_by(|a, b| {
        b.started_ms
            .cmp(&a.started_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    let overview = PointOverview {
        genesis: genesis.into(),
        revision: snapshot.core.revision,
        as_of_ms: observed_ms,
        day_ends_ms: current_day
            .checked_add(1)
            .and_then(|day| day.checked_mul(events::points::DAY_MS))
            .ok_or(crate::Error::Capacity)?,
        account: account.clone(),
        available_points: events::points::balance(&snapshot.domain.inner, &account).to_string(),
        frozen_points: frozen.to_string(),
        earned_today: usage.map_or(0, |d| d.points).to_string(),
        active_slices: usage.map_or(0, |d| d.active_slices),
        afk_slices: usage.map_or(0, |d| d.afk_slices),
        daily_member_cap: snapshot
            .domain
            .organization
            .activity_policy
            .as_ref()
            .map(|p| p.daily_member_cap.to_string()),
        activity,
        ai,
    };
    let statement = SignedPointStatement::sign(&overview, identity)?;
    let prices = snapshot
        .domain
        .ai_pricing
        .iter()
        .map(|(model, p)| {
            (
                model.clone(),
                PriceView {
                    base_points: p.base_points.to_string(),
                    input_points_per_1k: p.input_points_per_1k.to_string(),
                    output_points_per_1k: p.output_points_per_1k.to_string(),
                    max_input_tokens: p.max_input_tokens.to_string(),
                    settlement: match p.settlement {
                        flows::ai::Settlement::Burn => "burn",
                        flows::ai::Settlement::ProviderReward => "provider_reward",
                    }
                    .into(),
                },
            )
        })
        .collect();
    Ok(Some(Presentation {
        max_output_tokens: flows::MAX_AI_OUTPUT_TOKENS,
        overview,
        prices,
        statement,
    }))
}

/// Convert a local text form into replicated input material and one funded AI request.
pub async fn request_text(
    identity: Identity,
    mut value: serde_json::Value,
) -> Result<crate::journal::Response<crate::application::Application>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LocalRequest {
        #[serde(rename = "type")]
        kind: String,
        id: String,
        text: String,
        worker: String,
        model: String,
        max_tokens: u32,
        max_points: u64,
    }
    let request: LocalRequest =
        serde_json::from_value(value["action"].take()).map_err(crate::Error::protocol)?;
    if request.kind != "local.points.request_ai"
        || request.text.trim().is_empty()
        || request.text.len() > events::files::MAX_FILE_BYTES
    {
        return Err(crate::Error::Denied);
    }
    protocol::validate_identifier(&request.id)?;
    let input: crate::application::Input =
        serde_json::from_value(value).map_err(crate::Error::protocol)?;
    let (address, peer) = crate::endpoint(&input.address, &input.peer)?;
    let node = crate::Node::start(identity.clone(), crate::NodeConfig::default()).await?;
    let result = async {
        node.dial(address).await?;
        let log = tokio::sync::Mutex::new(input.identity.open()?);
        input.identity.synchronize(&node, &log).await?;
        let trust = log.into_inner();
        let branch =
            protocol::digest(format!("ai:{}:{}", identity.peer_id(), request.id).as_bytes());
        let cid = crate::files::upload(
            &node,
            peer,
            &input.genesis_hash,
            &identity,
            crate::files::Upload {
                branch: &branch,
                path: "request.txt",
                message: "AI request",
                bytes: request.text.as_bytes(),
            },
            &trust,
        )
        .await?;
        let action = state::governance::Action::Domain(flows::FlowAction::RequestAi {
            id: request.id,
            input: cid,
            worker: request.worker,
            model: request.model,
            max_tokens: request.max_tokens,
            max_points: request.max_points,
        });
        let mut response = crate::trust::execute(
            &node,
            peer,
            &input.genesis_hash,
            &identity,
            &trust,
            action,
            crate::journal::PROTOCOL,
        )
        .await?;
        if let Some(state) = &response.state {
            response.identity_view = Some(state.identity_presentation(trust.state())?);
        }
        Ok(response)
    }
    .await;
    node.shutdown().await?;
    result
}

pub fn output(snapshot: &Snapshot, instance: &str, stage: usize) -> Result<String> {
    let record = snapshot
        .domain
        .flows
        .get(instance)
        .and_then(|flow| flow.records.get(stage))
        .ok_or(crate::Error::NotFound)?;
    let cid = record
        .ai_runs
        .last()
        .and_then(|run| run.output.as_ref())
        .ok_or(crate::Error::NotFound)?;
    String::from_utf8(snapshot.domain.inner.files.read(cid)?).map_err(crate::Error::protocol)
}

pub fn output_value(snapshot: &serde_json::Value, instance: &str, stage: usize) -> Result<String> {
    let cid = snapshot
        .get("flows")
        .and_then(|f| f.get(instance))
        .and_then(|f| f.get("records"))
        .and_then(|r| r.get(stage))
        .and_then(|r| r.get("ai_runs"))
        .and_then(serde_json::Value::as_array)
        .and_then(|runs| runs.last())
        .and_then(|run| run.get("output"))
        .and_then(serde_json::Value::as_str)
        .ok_or(crate::Error::NotFound)?;
    String::from_utf8(crate::files::cached_file(snapshot, cid)?).map_err(crate::Error::protocol)
}
