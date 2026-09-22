//! One application interface for local journals and replicated governance.
use crate::{
    Identity, Result,
    governance::{Action, State},
    journal::{Command, Journal, SignedCommand, now_ms},
};
use std::sync::Arc;
use tokio::sync::Mutex;
#[derive(Clone)]
pub enum Authority {
    Local(Arc<Mutex<Journal>>),
    #[cfg(feature = "consensus")]
    Replicated(Arc<crate::consensus::Cluster>),
}
impl From<Arc<Mutex<Journal>>> for Authority {
    fn from(value: Arc<Mutex<Journal>>) -> Self {
        Self::Local(value)
    }
}
impl Authority {
    pub async fn watch(&self) -> tokio::sync::watch::Receiver<crate::events::Event> {
        match self {
            Self::Local(journal) => journal.lock().await.watch(),
            #[cfg(feature = "consensus")]
            Self::Replicated(cluster) => cluster.store.watch(),
        }
    }
    pub async fn state(&self, actor: crate::PeerId) -> Result<State> {
        match self {
            Self::Local(journal) => {
                let journal = journal.lock().await;
                if !journal.state().can_read(&actor.to_string()) {
                    return Err(crate::Error::Denied);
                }
                Ok(journal.state().clone())
            }
            #[cfg(feature = "consensus")]
            Self::Replicated(cluster) => cluster.snapshot(actor).await,
        }
    }
    /// Local effects must only follow a successful durable commit.
    pub async fn apply(&self, identity: &Identity, action: Action) -> Result<()> {
        match self {
            Self::Local(journal) => {
                let mut journal = journal.lock().await;
                let now = now_ms()?;
                let command = SignedCommand::sign(
                    identity,
                    Command {
                        revision: journal.state().revision,
                        expires_ms: now.saturating_add(30_000),
                        action,
                    },
                )?;
                journal.execute(command, now)
            }
            #[cfg(feature = "consensus")]
            Self::Replicated(cluster) => {
                let state = cluster.snapshot(identity.peer_id()).await?;
                let now = now_ms()?;
                let command = SignedCommand::sign(
                    identity,
                    Command {
                        revision: state.revision,
                        expires_ms: now.saturating_add(30_000),
                        action,
                    },
                )?;
                let result = cluster.execute(identity.peer_id(), command).await?;
                match result.error {
                    Some(error) => Err(crate::Error::Protocol(error)),
                    None => Ok(()),
                }
            }
        }
    }
}
