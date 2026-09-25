//! Append-only identity history with pinned genesis and durable anti-rollback checkpoints.
use crate::{Error, Result};
use identity::trust::TrustState;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;
use wire::protocol::{
    MAX_TRUST_PAGE, MAX_TRUST_RECORD, TrustCheckpoint, TrustGenesis, TrustRecord, TrustRequirement,
};
const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CHECKPOINT_BYTES: u64 = 1024;

fn protocol(e: impl std::fmt::Display) -> Error {
    Error::Protocol(e.to_string())
}
fn bytes<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(protocol)
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
fn save_checkpoint(path: &Path, checkpoint: &TrustCheckpoint) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(parent(path))?;
    file.write_all(&bytes(checkpoint)?)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| Error::Io(e.error))?;
    #[cfg(unix)]
    File::open(parent(path))?.sync_all()?;
    Ok(())
}
#[derive(Clone, Debug)]
struct Verified {
    state: Arc<TrustState>,
    synced: Instant,
    current: bool,
}
#[derive(Clone, Debug)]
pub struct TrustView {
    receiver: watch::Receiver<Verified>,
    max_staleness: Duration,
}
impl TrustView {
    pub fn state(&self) -> Result<Arc<TrustState>> {
        let current = self.receiver.borrow();
        if self.receiver.has_changed().is_err()
            || !current.current
            || current.synced.elapsed() >= self.max_staleness
        {
            return Err(Error::AuthorityUnavailable);
        }
        Ok(current.state.clone())
    }
    pub fn authorize(
        &self,
        device: &str,
        audience: &str,
        service: &str,
        requirement: &TrustRequirement,
    ) -> Result<String> {
        let state = self.state()?;
        let member = state.member_for_device(device).ok_or(Error::Denied)?;
        if !requirement.clubs.is_empty()
            && !requirement.clubs.iter().any(|c| state.is_member(member, c))
        {
            return Err(Error::Denied);
        }
        if let Some(permission) = &requirement.permission {
            if !state.permits(device, audience, service, permission) {
                return Err(Error::Denied);
            }
        } else if requirement.clubs.is_empty() {
            return Err(Error::Denied);
        }
        Ok(member.into())
    }
    pub fn mark_seen(&mut self) {
        self.receiver.borrow_and_update();
    }
    pub async fn changed(&mut self) -> Result<()> {
        self.receiver
            .changed()
            .await
            .map_err(|_| Error::AuthorityUnavailable)
    }
    pub fn remaining(&self) -> Duration {
        self.max_staleness
            .saturating_sub(self.receiver.borrow().synced.elapsed())
    }
}
/// The log owner publishes views only after durable verification. A replica starts stale.
pub struct TrustLog {
    genesis: TrustGenesis,
    file: File,
    _lock: File,
    checkpoint_path: PathBuf,
    state: TrustState,
    records: Vec<TrustRecord>,
    heads: Vec<String>,
    bytes: u64,
    poisoned: bool,
    updates: watch::Sender<Verified>,
}
impl TrustLog {
    pub fn open(path: &Path, genesis: &TrustGenesis, pinned: &str) -> Result<Self> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path.with_extension("trust-lock"))?;
        lock.try_lock().map_err(protocol)?;
        let mut state = TrustState::new(genesis, pinned)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .append(true)
            .open(path)?;
        if file.metadata()?.len() > MAX_LOG_BYTES {
            return Err(Error::Capacity);
        }
        let mut records = Vec::new();
        let mut heads = vec![state.checkpoint().head.clone()];
        let mut reader = BufReader::new(file.try_clone()?);
        loop {
            let mut line = Vec::new();
            let size = std::io::Read::take(&mut reader, (MAX_TRUST_RECORD + 2) as u64)
                .read_until(b'\n', &mut line)?;
            if size == 0 {
                break;
            }
            if size > MAX_TRUST_RECORD + 1 || line.last() != Some(&b'\n') {
                return Err(protocol(
                    "incomplete identity log; preserve it for recovery",
                ));
            }
            let record: TrustRecord = serde_json::from_slice(&line).map_err(protocol)?;
            state.apply(&record)?;
            heads.push(state.checkpoint().head.clone());
            records.push(record);
        }
        let checkpoint_path = path.with_extension("trust-checkpoint");
        if checkpoint_path.exists() {
            if checkpoint_path.metadata()?.len() > MAX_CHECKPOINT_BYTES {
                return Err(Error::Capacity);
            }
            let checkpoint: TrustCheckpoint =
                serde_json::from_slice(&std::fs::read(&checkpoint_path)?).map_err(protocol)?;
            if checkpoint.genesis != pinned
                || heads.get(usize::try_from(checkpoint.sequence).map_err(protocol)?)
                    != Some(&checkpoint.head)
            {
                return Err(protocol("identity rollback or fork detected"));
            }
        } else if !records.is_empty() {
            // Explicit import is required; deleting the checkpoint is not a reset switch.
            return Err(protocol("identity checkpoint missing for nonempty log"));
        }
        save_checkpoint(&checkpoint_path, state.checkpoint())?;
        let (updates, _) = watch::channel(Verified {
            state: Arc::new(state.clone()),
            synced: Instant::now(),
            current: false,
        });
        Ok(Self {
            genesis: genesis.clone(),
            bytes: file.metadata()?.len(),
            file,
            _lock: lock,
            checkpoint_path,
            state,
            records,
            heads,
            poisoned: false,
            updates,
        })
    }
    pub fn state(&self) -> &TrustState {
        &self.state
    }
    pub fn history_since(
        &self,
        checkpoint: Option<&TrustCheckpoint>,
    ) -> Result<crate::journal::TrustHistory> {
        let initial = TrustCheckpoint {
            genesis: self.state.checkpoint().genesis.clone(),
            sequence: 0,
            head: self.state.checkpoint().genesis.clone(),
        };
        let checkpoint = checkpoint.unwrap_or(&initial);
        self.page(checkpoint)?;
        Ok(crate::journal::TrustHistory {
            genesis: self.genesis.clone(),
            records: self
                .records
                .iter()
                .skip(checkpoint.sequence as usize)
                .cloned()
                .collect(),
        })
    }
    pub fn view(&self, max_staleness: Duration) -> Result<TrustView> {
        if max_staleness.is_zero() {
            return Err(Error::Denied);
        }
        Ok(TrustView {
            receiver: self.updates.subscribe(),
            max_staleness,
        })
    }
    /// Call only after reaching the authenticated source's complete head, or as the configured writer.
    pub fn mark_current(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Stopped);
        }
        self.updates.send_replace(Verified {
            state: Arc::new(self.state.clone()),
            synced: Instant::now(),
            current: true,
        });
        Ok(())
    }
    pub fn mark_stale(&self) {
        self.updates.send_modify(|v| v.current = false);
    }
    pub fn page(&self, checkpoint: &TrustCheckpoint) -> Result<Vec<TrustRecord>> {
        if self.poisoned || checkpoint.genesis != self.state.checkpoint().genesis {
            return Err(Error::Denied);
        }
        let position = usize::try_from(checkpoint.sequence).map_err(protocol)?;
        if self.heads.get(position) != Some(&checkpoint.head) {
            return Err(protocol("identity rollback or fork detected"));
        }
        Ok(self
            .records
            .iter()
            .skip(position)
            .take(MAX_TRUST_PAGE)
            .cloned()
            .collect())
    }
    pub fn append(&mut self, record: TrustRecord) -> Result<()> {
        if self.poisoned {
            return Err(Error::Stopped);
        }
        let mut next = self.state.clone();
        next.apply(&record)?;
        let mut line = bytes(&record)?;
        line.push(b'\n');
        if self.bytes.saturating_add(line.len() as u64) > MAX_LOG_BYTES {
            return Err(Error::Capacity);
        }
        // Any uncertain write forces reopen and verified recovery; never overwrite or truncate history.
        self.poisoned = true;
        let previous = self.updates.borrow().clone();
        let persisted = (|| -> Result<()> {
            self.file.write_all(&line)?;
            self.file.sync_all()?;
            save_checkpoint(&self.checkpoint_path, next.checkpoint())
        })();
        if let Err(error) = persisted {
            self.mark_stale();
            return Err(error);
        }
        self.bytes += line.len() as u64;
        self.heads.push(next.checkpoint().head.clone());
        self.records.push(record);
        self.state = next;
        self.poisoned = false;
        self.updates.send_replace(Verified {
            state: Arc::new(self.state.clone()),
            synced: previous.synced,
            current: previous.current,
        });
        Ok(())
    }
}
