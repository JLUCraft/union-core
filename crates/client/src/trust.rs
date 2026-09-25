//! Shared CLI/JNI/Tauri identity client. The caller owns the Node and durable cache.
use crate::{Identity, Node, PeerId, Result};
use authority::journal::{self, Command, Request, SignedCommand, TrustedCommand};
pub use authority::trust::{TrustLog, TrustView, request, synchronize};
pub use identity::trust::{TrustState, sign};
use state::{Domain, governance::Action};
pub use wire::protocol::{
    TrustAction, TrustCheckpoint, TrustGenesis, TrustRecord, TrustRequest, TrustResponse,
};
/// Use the business response's anchored identity position to send only missing identity history.
pub async fn execute<D: Domain>(
    node: &Node,
    peer: PeerId,
    genesis: &str,
    identity: &Identity,
    log: &TrustLog,
    action: Action<D>,
) -> Result<journal::Response<D>> {
    let snapshot = journal::request::<D>(node, peer, genesis, Request::Snapshot).await?;
    let state = snapshot.state.ok_or(crate::Error::Denied)?;
    let proof = snapshot.proof.ok_or(crate::Error::Denied)?;
    let command = SignedCommand::sign(
        identity,
        TrustedCommand {
            genesis: genesis.into(),
            previous: proof.head.ok_or(crate::Error::Denied)?,
            identity: log.state().checkpoint().clone(),
            command: Command {
                revision: state.revision,
                expires_ms: journal::now_ms()?.saturating_add(30_000),
                action,
            },
        },
    )?;
    let mut response = journal::request(
        node,
        peer,
        genesis,
        Request::Execute {
            command,
            history: log.history_since(proof.identity.as_ref())?,
        },
    )
    .await?;
    if let Some(state) = &response.state {
        response.identity_view = Some(state.identity_presentation(log.state())?);
    }
    Ok(response)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub genesis: TrustGenesis,
    pub genesis_hash: String,
    #[serde(default)]
    pub log: std::path::PathBuf,
    pub address: String,
    pub peer: String,
}
impl Config {
    pub fn open(&self) -> Result<TrustLog> {
        TrustLog::open(&self.log, &self.genesis, &self.genesis_hash)
    }
    pub async fn synchronize(&self, node: &Node, log: &tokio::sync::Mutex<TrustLog>) -> Result<()> {
        let peer: PeerId = self.peer.parse().map_err(|_| crate::Error::Denied)?;
        let address: crate::Multiaddr = self.address.parse().map_err(|_| crate::Error::Denied)?;
        if !matches!(address.iter().last(),Some(crate::AddressProtocol::P2p(id)) if id==peer) {
            return Err(crate::Error::Denied);
        }
        node.dial(address).await?;
        synchronize(node, peer, log).await
    }
}
#[derive(serde::Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Sync,
    Draft { action: TrustAction },
    Sign { record: TrustRecord },
    Submit { record: TrustRecord },
}
pub struct Input {
    pub config: Config,
    pub operation: Operation,
}
impl<'de> serde::Deserialize<'de> for Input {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
        enum Request {
            Sync { config: Config },
            Draft { config: Config, action: TrustAction },
            Sign { config: Config, record: TrustRecord },
            Submit { config: Config, record: TrustRecord },
        }
        let (config, operation) = match Request::deserialize(deserializer)? {
            Request::Sync { config } => (config, Operation::Sync),
            Request::Draft { config, action } => (config, Operation::Draft { action }),
            Request::Sign { config, record } => (config, Operation::Sign { record }),
            Request::Submit { config, record } => (config, Operation::Submit { record }),
        };
        Ok(Self { config, operation })
    }
}
pub async fn execute_identity(identity: Identity, input: Input) -> Result<serde_json::Value> {
    let log = tokio::sync::Mutex::new(input.config.open()?);
    let node = Node::start(identity.clone(), crate::NodeConfig::default()).await?;
    let result = async {
        input.config.synchronize(&node, &log).await?;
        match input.operation {
            Operation::Sync => serde_json::to_value(log.lock().await.state())
                .map_err(|e| crate::Error::Protocol(e.to_string())),
            Operation::Draft { action } => {
                serde_json::to_value(log.lock().await.state().draft(action))
                    .map_err(|e| crate::Error::Protocol(e.to_string()))
            }
            Operation::Sign { mut record } => {
                let checkpoint = log.lock().await.state().checkpoint().clone();
                if record.genesis != checkpoint.genesis
                    || record.previous != checkpoint.head
                    || Some(record.sequence) != checkpoint.sequence.checked_add(1)
                {
                    return Err(crate::Error::Denied);
                }
                if !record.signatures.is_empty() {
                    identity::trust::verify_signatures(&record)?;
                }
                sign(&mut record, &identity)?;
                serde_json::to_value(record).map_err(|e| crate::Error::Protocol(e.to_string()))
            }
            Operation::Submit { record } => {
                let mut projected = log.lock().await.state().clone();
                projected.apply(&record)?;
                let response = request(
                    &node,
                    input
                        .config
                        .peer
                        .parse()
                        .map_err(|_| crate::Error::Denied)?,
                    TrustRequest::Append { record },
                )
                .await?;
                if let Some(error) = response.error {
                    return Err(crate::Error::Protocol(error));
                }
                input.config.synchronize(&node, &log).await?;
                let log = log.lock().await;
                if log.state().checkpoint().sequence < projected.checkpoint().sequence {
                    return Err(crate::Error::Denied);
                }
                serde_json::to_value(log.state()).map_err(|e| crate::Error::Protocol(e.to_string()))
            }
        }
    }
    .await;
    node.shutdown().await?;
    result
}

/// Offline audit only: this proves a prefix, never that no later revocation exists.
pub fn review(genesis: TrustGenesis, pinned: &str, records: &[TrustRecord]) -> Result<TrustState> {
    let mut state = TrustState::new(&genesis, pinned)?;
    for record in records {
        state.apply(record)?;
    }
    Ok(state)
}
