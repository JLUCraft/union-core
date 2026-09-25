#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Identity-authorized LLM service. No provider secrets or prompts enter the usage ledger.
mod ledger;
mod provider;
use authority::journal::now_ms;
use futures::{AsyncReadExt, AsyncWrite};
pub use ledger::{Ledger, Quotas, Reservation, UsageSummary, UsageTotals};
use node::IncomingSession;
use serde::Deserialize;
use state::Domain;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use tokio::sync::{Mutex, Semaphore};
use wire::protocol::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("union: {0}")]
    Union(#[from] wire::Error),
    // Never expose reqwest errors, URLs, provider bodies or API keys to clients/logs.
    #[error("provider request failed")]
    Provider,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub url: String,
    pub key_env: Option<String>,
    pub sensitive: bool,
    pub self_hosted: bool,
    pub models: BTreeSet<String>,
    /// Actual upper bound for combined input/output tokens of the configured model.
    pub context_tokens: u64,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberPolicy {
    pub tokens_per_day: u64,
    pub models: BTreeSet<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub providers: Vec<Provider>,
    pub members: BTreeMap<String, MemberPolicy>,
    #[serde(default)]
    pub clubs: BTreeMap<String, MemberPolicy>,
    pub purposes: BTreeSet<String>,
    /// Prompt templates keyed by purpose, composed server-side so the
    /// instructions never reach clients. Each template must be non-empty
    /// after trimming and contain exactly one `{context}` placeholder.
    #[serde(default)]
    pub templates: BTreeMap<String, String>,
    pub max_tokens: u32,
    pub max_messages: usize,
    pub max_input_bytes: usize,
    pub concurrency: usize,
}
pub struct Gateway<D: Domain> {
    config: Config,
    providers: Vec<provider::Backend>,
    ledger: Mutex<Ledger>,
    authority: authority::authority::Authority<D>,
    permits: Semaphore,
}
impl<D: Domain> Gateway<D> {
    pub fn new(
        config: Config,
        ledger: Ledger,
        authority: authority::authority::Authority<D>,
    ) -> Result<Self> {
        if config.providers.is_empty()
            || config.providers.len() > 32
            || config.concurrency == 0
            || config.concurrency > 128
            || config.max_messages == 0
            || config.max_messages > 128
            || config.max_tokens == 0
            || config.max_input_bytes == 0
            || config.max_input_bytes > MAX_FRAME / 2
            || config.purposes.is_empty()
        {
            return Err(Error::Invalid("invalid gateway limits"));
        }
        for (purpose, template) in &config.templates {
            if !config.purposes.contains(purpose)
                || template.trim().is_empty()
                || template.matches("{context}").count() != 1
            {
                return Err(Error::Invalid("invalid prompt template configuration"));
            }
        }
        let providers = config
            .providers
            .iter()
            .map(provider::Backend::new)
            .collect::<Result<_>>()?;
        Ok(Self {
            permits: Semaphore::new(config.concurrency),
            config,
            providers,
            ledger: Mutex::new(ledger),
            authority,
        })
    }
    fn route(&self, request: &LlmRequest, member: &str, club: &str) -> Result<(usize, Quotas)> {
        let member_policy = self.config.members.get(member);
        let club_policy = self.config.clubs.get(club);
        if member_policy.is_none() && club_policy.is_none() {
            return Err(Error::Invalid("member and institution not enabled"));
        }
        let bytes = if self.config.templates.contains_key(&request.purpose) {
            if !request.messages.is_empty() {
                return Err(Error::Invalid(
                    "messages not accepted for templated purpose",
                ));
            }
            let context = request
                .context
                .as_deref()
                .filter(|context| !context.is_empty())
                .ok_or(Error::Invalid("missing context for templated purpose"))?;
            context.len()
        } else {
            if request.context.is_some() {
                return Err(Error::Invalid("context not accepted for this purpose"));
            }
            let bytes = request
                .messages
                .iter()
                .try_fold(0usize, |n, m| n.checked_add(m.content.len()))
                .ok_or(Error::Invalid("request too large"))?;
            if request.messages.is_empty()
                || request.messages.len() > self.config.max_messages
                || request.messages.iter().any(|m| {
                    !matches!(m.role.as_str(), "system" | "user" | "assistant")
                        || m.content.is_empty()
                })
            {
                return Err(Error::Invalid("request outside member policy"));
            }
            bytes
        };
        if bytes > self.config.max_input_bytes
            || request.max_tokens == 0
            || request.max_tokens > self.config.max_tokens
            || member_policy.is_some_and(|p| !p.models.contains(&request.model))
            || club_policy.is_some_and(|p| !p.models.contains(&request.model))
            || !self.config.purposes.contains(&request.purpose)
        {
            return Err(Error::Invalid("request outside member policy"));
        }
        let route = self
            .config
            .providers
            .iter()
            .position(|p| {
                p.models.contains(&request.model)
                    && p.context_tokens >= u64::from(request.max_tokens)
                    && (request.privacy != Privacy::Sensitive || (p.sensitive && p.self_hosted))
            })
            .ok_or(Error::Invalid(
                "no provider for requested privacy and model",
            ))?;
        Ok((
            route,
            Quotas {
                member: member_policy.map(|p| p.tokens_per_day),
                club: club_policy.map(|p| p.tokens_per_day),
            },
        ))
    }
    pub async fn serve(&self, session: IncomingSession) -> Result<()> {
        let mut stream = session.stream;
        let permit = self
            .permits
            .try_acquire()
            .map_err(|_| Error::Invalid("gateway busy"));
        let _permit = match permit {
            Ok(permit) => permit,
            Err(error) => {
                send_error(&mut stream, &error).await?;
                return Ok(());
            }
        };
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            read_frame::<JsonFrame>(&mut stream),
        )
        .await;
        let request: LlmRequest = match result {
            Ok(Ok(frame)) if frame.sequence == 0 && frame.last => {
                match serde_json::from_slice(&frame.json) {
                    Ok(request) => request,
                    Err(_) => {
                        send_error(&mut stream, &Error::Invalid("invalid request")).await?;
                        return Ok(());
                    }
                }
            }
            _ => return Err(Error::Invalid("request timeout or invalid frame")),
        };
        let state = self.authority.operational_state(session.peer).await?;
        let member = state
            .members
            .iter()
            .find(|(_, m)| m.owns(&session.peer.to_string()))
            .map(|(id, m)| (id.clone(), m.club.clone()));
        let Some((member, club)) = member else {
            send_error(&mut stream, &Error::Invalid("device is not a member")).await?;
            return Ok(());
        };
        let (mut reader, mut writer) = stream.split();
        let work = self.complete(&member, &club, request, &mut writer);
        // A pending guarded read wakes on identity revocation or freshness loss, cancelling HTTP work.
        let mut unexpected = [0u8; 1];
        let result = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(150), work) =>
                result.unwrap_or(Err(Error::Invalid("provider timed out"))),
            _ = reader.read(&mut unexpected) => Err(Error::Invalid("session closed or revoked")),
        };
        if let Err(error) = result {
            send_error(&mut writer, &error).await?;
        }
        Ok(())
    }
    async fn complete(
        &self,
        member: &str,
        club: &str,
        request: LlmRequest,
        writer: &mut (impl AsyncWrite + Unpin),
    ) -> Result<()> {
        let (index, quotas) = self.route(&request, member, club)?;
        let mut request = request;
        if let Some(template) = self.config.templates.get(&request.purpose) {
            let context = request
                .context
                .take()
                .filter(|context| !context.is_empty())
                .ok_or(Error::Invalid("missing context for templated purpose"))?;
            request.messages = vec![LlmMessage {
                role: "user".into(),
                content: template.replace("{context}", &context),
            }];
        }
        let reservation = self.ledger.lock().await.reserve(
            Reservation {
                member,
                club,
                model: &request.model,
                purpose: &request.purpose,
                tokens: self.config.providers[index].context_tokens,
            },
            quotas,
            now_ms()?,
        )?;
        let (usage, truncated) = self.providers[index].complete(&request, writer).await?;
        if let Some(usage) = &usage {
            self.ledger
                .lock()
                .await
                .settle(reservation, usage.total_tokens, now_ms()?)?;
        }
        send(writer, &LlmFrame::Done { usage, truncated }).await
    }
}
pub(crate) async fn send(writer: &mut (impl AsyncWrite + Unpin), frame: &LlmFrame) -> Result<()> {
    write_frame(
        writer,
        &JsonFrame {
            json: serde_json::to_vec(frame)?,
            last: true,
            sequence: 0,
        },
    )
    .await?;
    Ok(())
}
async fn send_error(writer: &mut (impl AsyncWrite + Unpin), error: &Error) -> Result<()> {
    send(
        writer,
        &LlmFrame::Error {
            error: error.to_string(),
            truncated: true,
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/support/mod.rs"]
mod support;
#[cfg(test)]
mod tests {
    use super::*;
    use authority::{authority::Authority, journal::Journal};
    use std::sync::Arc;
    #[test]
    fn routing_never_downgrades_sensitive_requests() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let identity = identity::Identity::generate();
        let ids = support::Identities::new(&[(&identity, "admin", "jlu")], "admin");
        let view = ids.log.view(Duration::from_secs(60))?;
        let journal = Journal::open(
            dir.path().join("journal"),
            ids.genesis::<league::LeagueDomain>(),
        )?;
        let config = Config {
            clubs: Default::default(),
            providers: vec![Provider {
                url: "http://127.0.0.1:1/v1/chat/completions".into(),
                key_env: None,
                sensitive: false,
                self_hosted: true,
                models: ["local".into()].into(),
                context_tokens: 128,
            }],
            members: [(
                "alice".into(),
                MemberPolicy {
                    tokens_per_day: 1024,
                    models: ["local".into()].into(),
                },
            )]
            .into(),
            purposes: ["assistant.ask".into()].into(),
            templates: Default::default(),
            max_tokens: 32,
            max_messages: 2,
            max_input_bytes: 128,
            concurrency: 1,
        };
        let mut gateway = Gateway::new(
            config,
            Ledger::open(dir.path().join("usage"))?,
            Authority::Local {
                journal: Arc::new(Mutex::new(journal)),
                log: Arc::new(Mutex::new(ids.log)),
                view,
            },
        )?;
        let mut request = LlmRequest {
            model: "local".into(),
            messages: vec![LlmMessage {
                role: "user".into(),
                content: "hello".into(),
            }],
            context: None,
            stream: true,
            max_tokens: 32,
            purpose: "assistant.ask".into(),
            privacy: Privacy::Sensitive,
        };
        assert!(gateway.route(&request, "alice", "jlu").is_err());
        request.privacy = Privacy::Public;
        assert!(gateway.route(&request, "alice", "jlu").is_ok());
        assert!(gateway.route(&request, "unknown", "jlu").is_err());
        request.model = "unapproved".into();
        assert!(gateway.route(&request, "alice", "jlu").is_err());
        request.model = "local".into();
        request.max_tokens = 33;
        assert!(gateway.route(&request, "alice", "jlu").is_err());
        request.max_tokens = 32;
        gateway.config.clubs.insert(
            "jlu".into(),
            MemberPolicy {
                tokens_per_day: 2048,
                models: ["local".into()].into(),
            },
        );
        let (_, quotas) = gateway.route(&request, "unknown", "jlu")?;
        assert_eq!(quotas.member, None);
        assert_eq!(quotas.club, Some(2048));
        assert!(gateway.route(&request, "unknown", "other").is_err());
        gateway
            .config
            .clubs
            .get_mut("jlu")
            .ok_or(Error::Invalid("missing test policy"))?
            .models
            .clear();
        assert!(gateway.route(&request, "alice", "jlu").is_err());
        gateway.config.clubs.clear();
        request.purpose = "user supplied prompt masquerading as metadata".into();
        assert!(gateway.route(&request, "alice", "jlu").is_err());
        Ok(())
    }
}
