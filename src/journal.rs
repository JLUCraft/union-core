//! Signed, revision-checked governance journal. Single authoritative writer per league
//! deployment; this is deliberately not a Byzantine consensus implementation.
use crate::{
    Error, Identity, Result,
    governance::{Action, State, digest},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const PROTOCOL: &str = "/jlucraft/union/governance/2";
pub const MAX_SNAPSHOT: usize = 8 * 1024 * 1024;
const CHUNK_SIZE: usize = crate::protocol::MAX_FRAME - 64;
const DOMAIN: &[u8] = b"jlucraft/governance/1\0";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Command {
    pub revision: u64,
    pub expires_ms: u64,
    pub action: Action,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCommand {
    pub payload: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedCommand {
    pub fn sign(identity: &Identity, command: Command) -> Result<Self> {
        let payload = serde_json::to_vec(&command).map_err(protocol)?;
        let signature = identity
            .0
            .sign(&[DOMAIN, &payload].concat())
            .map_err(protocol)?;
        Ok(Self {
            payload,
            public_key: identity.0.public().encode_protobuf(),
            signature,
        })
    }
    pub fn verify(&self) -> Result<(String, Command)> {
        if self.payload.len() > crate::protocol::MAX_FRAME {
            return Err(Error::Capacity);
        }
        let key = libp2p::identity::PublicKey::try_decode_protobuf(&self.public_key)
            .map_err(|_| Error::Denied)?;
        if !key.verify(&[DOMAIN, &self.payload].concat(), &self.signature) {
            return Err(Error::Denied);
        }
        Ok((
            key.to_peer_id().to_string(),
            serde_json::from_slice(&self.payload).map_err(protocol)?,
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    version: u8,
    previous: String,
    command: SignedCommand,
    time_ms: u64,
    state_hash: String,
}

pub struct Journal {
    path: PathBuf,
    _lock: File,
    entries: Vec<Entry>,
    state: State,
    genesis_hash: String,
    events: tokio::sync::watch::Sender<crate::events::Event>,
}

impl Journal {
    pub fn open(path: impl AsRef<Path>, genesis: State) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path.with_extension("lock"))?;
        lock.try_lock().map_err(protocol)?;
        let genesis_hash = digest(&serde_json::to_vec(&genesis).map_err(protocol)?);
        let entries: Vec<Entry> = if path.exists() {
            if path.metadata()?.len() > 64 * 1024 * 1024 {
                return Err(Error::Capacity);
            }
            serde_json::from_slice(&std::fs::read(&path)?).map_err(protocol)?
        } else {
            Vec::new()
        };
        let mut state = genesis;
        let mut previous = genesis_hash.clone();
        for entry in &entries {
            if entry.previous != previous {
                return Err(protocol("journal chain mismatch"));
            }
            let (actor, command) = entry.command.verify()?;
            if command.expires_ms < entry.time_ms {
                return Err(Error::Denied);
            }
            state.apply(&actor, command.revision, entry.time_ms, command.action)?;
            if entry.version != 1 {
                return Err(protocol("unsupported journal version"));
            }
            if digest(&serde_json::to_vec(&state).map_err(protocol)?) != entry.state_hash {
                return Err(protocol("journal state mismatch"));
            }
            previous = digest(&serde_json::to_vec(entry).map_err(protocol)?);
        }
        let (events, _) = tokio::sync::watch::channel(crate::events::Event {
            revision: state.revision,
            state_hash: digest(&serde_json::to_vec(&state).map_err(protocol)?),
            resync: true,
        });
        Ok(Self {
            events,
            path,
            _lock: lock,
            entries,
            state,
            genesis_hash,
        })
    }
    pub fn watch(&self) -> tokio::sync::watch::Receiver<crate::events::Event> {
        self.events.subscribe()
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn execute(&mut self, command: SignedCommand, now: u64) -> Result<()> {
        let (actor, decoded) = command.verify()?;
        if decoded.expires_ms < now {
            return Err(Error::Denied);
        }
        let mut next = self.state.clone();
        next.apply(&actor, decoded.revision, now, decoded.action)?;
        // Never commit a state that clients cannot retrieve through the bounded protocol.
        if serde_json::to_vec(&next).map_err(protocol)?.len() > MAX_SNAPSHOT - 1024 {
            return Err(Error::Capacity);
        }
        let previous = match self.entries.last() {
            Some(entry) => digest(&serde_json::to_vec(entry).map_err(protocol)?),
            None => self.genesis_hash.clone(),
        };
        let entry = Entry {
            version: 1,
            previous,
            command,
            time_ms: now,
            state_hash: digest(&serde_json::to_vec(&next).map_err(protocol)?),
        };
        let mut entries = self.entries.clone();
        entries.push(entry);
        let bytes = serde_json::to_vec(&entries).map_err(protocol)?;
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(Error::Capacity);
        }
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist(&self.path).map_err(|e| Error::Io(e.error))?;
        // Rename is the logical commit point. Keep memory consistent even when the
        // subsequent directory fsync reports uncertain crash durability.
        self.entries = entries;
        self.state = next;
        self.events.send_replace(crate::events::Event {
            revision: self.state.revision,
            state_hash: digest(&serde_json::to_vec(&self.state).map_err(protocol)?),
            resync: false,
        });
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Snapshot,
    Execute { command: SignedCommand },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Response {
    pub state: Option<State>,
    pub error: Option<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct JsonFrame {
    #[prost(bytes = "vec", tag = "1")]
    pub json: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub sequence: u32,
    #[prost(bool, tag = "3")]
    pub last: bool,
}

pub fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(protocol)?
        .as_millis()
        .try_into()
        .map_err(protocol)
}
fn protocol(error: impl std::fmt::Display) -> Error {
    Error::Protocol(error.to_string())
}

/// One bounded exchange; the caller owns the Node and its lifecycle.
pub async fn request(
    node: &crate::Node,
    peer: crate::PeerId,
    request: Request,
) -> Result<Response> {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let mut stream = node.open_protocol(peer, PROTOCOL).await?;
        crate::protocol::write_frame(
            &mut stream,
            &JsonFrame {
                json: serde_json::to_vec(&request).map_err(protocol)?,
                sequence: 0,
                last: true,
            },
        )
        .await?;
        let mut json = Vec::new();
        for sequence in 0..=MAX_SNAPSHOT / CHUNK_SIZE {
            let reply: JsonFrame = crate::protocol::read_frame(&mut stream).await?;
            if reply.sequence as usize != sequence
                || reply.json.is_empty()
                || json.len().saturating_add(reply.json.len()) > MAX_SNAPSHOT
            {
                return Err(protocol("invalid snapshot chunks"));
            }
            json.extend_from_slice(&reply.json);
            if reply.last {
                return serde_json::from_slice(&json).map_err(protocol);
            }
        }
        Err(Error::Capacity)
    })
    .await
    .map_err(|_| Error::Timeout)?
}

pub async fn serve(
    node: &crate::Node,
    journal: std::sync::Arc<tokio::sync::Mutex<Journal>>,
) -> Result<()> {
    use futures::StreamExt;
    let mut incoming = node.accept_protocol(PROTOCOL)?;
    let mut tasks = tokio::task::JoinSet::new();
    let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(32));
    loop {
        tokio::select! {
            Some((peer, mut stream)) = incoming.next() => {
                let Ok(permit) = limit.clone().try_acquire_owned() else { continue; };
                let journal = journal.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = tokio::time::timeout(std::time::Duration::from_secs(15), async {
                        let frame: JsonFrame = crate::protocol::read_frame(&mut stream).await?;
                        if frame.sequence != 0 || !frame.last { return Err(protocol("request must be one frame")); }
                        let request: Request = serde_json::from_slice(&frame.json).map_err(protocol)?;
                        let mut journal = journal.lock().await;
                        let actor = peer.to_string();
                        let reply = match request {
                            Request::Snapshot if journal.state.can_read(&actor) => Response { state: Some(journal.state.clone()), error: None },
                            Request::Snapshot => Response { state: None, error: Some("access denied".into()) },
                            Request::Execute { command } => {
                                let result = match command.verify() {
                                    Ok((signer, _)) if signer == actor => journal.execute(command, now_ms()?),
                                    _ => Err(Error::Denied),
                                };
                                match result {
                                    Ok(()) => Response { state: Some(journal.state.clone()), error: None },
                                    Err(error) => Response { state: None, error: Some(error.to_string()) },
                                }
                            }
                        };
                        drop(journal);
                        let bytes=serde_json::to_vec(&reply).map_err(protocol)?;
                        if bytes.len()>MAX_SNAPSHOT { return Err(Error::Capacity); }
                        let count=bytes.len().div_ceil(CHUNK_SIZE);
                        for (sequence,chunk) in bytes.chunks(CHUNK_SIZE).enumerate() {
                            crate::protocol::write_frame(&mut stream,&JsonFrame {json:chunk.to_vec(),sequence:sequence as u32,last:sequence+1==count}).await?;
                        }
                        Ok::<(),Error>(())
                    }).await;
                    if !matches!(result, Ok(Ok(()))) { tracing::debug!(%peer, "governance exchange failed"); }
                });
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => { if let Err(error) = result { tracing::error!(%error, "governance task failed"); } }
            else => return Ok(()),
        }
    }
}
