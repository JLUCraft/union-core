//! One application interface for local journals and replicated governance.
use crate::{
    Identity, Result,
    governance::{Action, State},
    journal::{Command, Journal, SignedCommand, now_ms},
};
use state::Domain;
use std::sync::Arc;
use tokio::sync::Mutex;
#[derive(Clone)]
pub enum Authority<D: Domain> {
    Local {
        journal: Arc<Mutex<Journal<D>>>,
        log: Arc<Mutex<crate::trust::TrustLog>>,
        view: crate::trust::TrustView,
    },
    #[cfg(feature = "consensus")]
    Replicated(Arc<crate::consensus::Cluster<D>>),
}
impl<D: Domain> Authority<D> {
    pub async fn serve(self, node: Arc<crate::Node>) -> Result<()> {
        match self {
            Self::Local { journal, view, .. } => crate::journal::serve(&node, journal, view).await,
            #[cfg(feature = "consensus")]
            Self::Replicated(cluster) => cluster.serve().await,
        }
    }
    /// Only the elected replica runs external side effects; commits still require quorum.
    pub fn effect_epoch(&self) -> Option<u64> {
        match self {
            #[cfg(feature = "consensus")]
            Self::Replicated(cluster) => {
                let metrics = cluster.raft.metrics().borrow().clone();
                (metrics.state == openraft::ServerState::Leader).then_some(metrics.current_term)
            }
            _ => Some(0),
        }
    }
    /// Local durable state for host assembly; network callers must use state/response authorization.
    pub async fn stored_state(&self) -> State<D> {
        match self {
            Self::Local { journal, .. } => journal.lock().await.state().clone(),
            #[cfg(feature = "consensus")]
            Self::Replicated(cluster) => cluster.store.state().await,
        }
    }
    pub fn identity_view(&self) -> crate::trust::TrustView {
        match self {
            Self::Local { view, .. } => view.clone(),
            #[cfg(feature = "consensus")]
            Self::Replicated(cluster) => cluster.identity.1.clone(),
        }
    }
    pub async fn genesis_hash(&self) -> String {
        match self {
            Self::Local { journal, .. } => journal.lock().await.genesis_hash().to_owned(),
            #[cfg(feature = "consensus")]
            Self::Replicated(cluster) => cluster.cluster.clone(),
        }
    }
    pub async fn watch(&self) -> tokio::sync::watch::Receiver<crate::events::Event> {
        match self {
            Self::Local { journal, .. } => journal.lock().await.watch(),
            #[cfg(feature = "consensus")]
            Self::Replicated(cluster) => cluster.store.watch(),
        }
    }
    pub async fn state(&self, actor: crate::PeerId) -> Result<State<D>> {
        match self {
            Self::Local { journal, view, .. } => {
                let trust = view.state()?;
                let journal = journal.lock().await;
                if !journal.state().can_read(&actor.to_string(), &trust) {
                    return Err(crate::Error::Denied);
                }
                Ok(journal.state().clone())
            }
            #[cfg(feature = "consensus")]
            Self::Replicated(cluster) => cluster.snapshot(actor).await,
        }
    }
    /// Verified local projection for service runtimes; never use this as a persisted snapshot.
    pub async fn operational_state(&self, actor: crate::PeerId) -> Result<State<D>> {
        let mut state = self.state(actor).await?;
        state.core = state.identity_core(self.identity_view().state()?.as_ref())?;
        Ok(state)
    }
    /// Local effects must only follow a successful durable commit.
    pub async fn apply(&self, identity: &Identity, action: Action<D>) -> Result<()> {
        match self {
            Self::Local { journal, log, view } => {
                let mut journal = journal.lock().await;
                let log = log.lock().await;
                let current = view.state()?;
                let now = now_ms()?;
                let command = SignedCommand::sign(
                    identity,
                    crate::journal::TrustedCommand {
                        genesis: journal.genesis_hash().into(),
                        previous: journal.head()?,
                        identity: current.checkpoint().clone(),
                        command: Command {
                            revision: journal.state().revision,
                            expires_ms: now.saturating_add(30_000),
                            action,
                        },
                    },
                )?;
                let history = log.history_since(journal.identity_checkpoint())?;
                journal.execute(command, history, &current, now)
            }
            #[cfg(feature = "consensus")]
            Self::Replicated(cluster) => {
                let (log, view) = &cluster.identity;
                let response = cluster.response(identity.peer_id()).await?;
                let state = response.state.ok_or(crate::Error::Denied)?;
                let proof = response.proof.ok_or(crate::Error::Denied)?;
                let (command, history) = {
                    let log = log.lock().await;
                    let current = view.state()?;
                    let command = SignedCommand::sign(
                        identity,
                        crate::journal::TrustedCommand {
                            genesis: cluster.cluster.clone(),
                            previous: proof.head.ok_or(crate::Error::Denied)?,
                            identity: current.checkpoint().clone(),
                            command: Command {
                                revision: state.revision,
                                expires_ms: now_ms()?.saturating_add(30_000),
                                action,
                            },
                        },
                    )?;
                    (command, log.history_since(proof.identity.as_ref())?)
                };
                let result = cluster
                    .execute(identity.peer_id(), command, history)
                    .await?;
                match result.error {
                    Some(e) => Err(crate::Error::Protocol(e)),
                    None => Ok(()),
                }
            }
        }
    }
}
