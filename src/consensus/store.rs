// OpenRaft trait signatures require its concrete, unboxed error types.
#![allow(clippy::result_large_err)]
use crate::consensus::{Applied, TypeConfig};
use crate::governance::State;
use openraft::storage::{LogFlushed, RaftLogStorage, RaftStateMachine};
use openraft::{
    Entry, EntryPayload, LogId, LogState, RaftLogReader, RaftSnapshotBuilder, Snapshot,
    SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::Debug,
    fs::{File, OpenOptions},
    io::{Cursor, Write},
    ops::RangeBounds,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;
type R<T> = Result<T, StorageError<u64>>;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Machine {
    pub applied: Option<LogId<u64>>,
    pub membership: StoredMembership<u64, super::Peer>,
    pub state: State,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredSnapshot {
    meta: SnapshotMeta<u64, super::Peer>,
    data: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Disk {
    version: u8,
    genesis: String,
    vote: Option<Vote<u64>>,
    committed: Option<LogId<u64>>,
    purged: Option<LogId<u64>>,
    logs: BTreeMap<u64, Entry<TypeConfig>>,
    machine: Machine,
    snapshot: Option<StoredSnapshot>,
}
#[derive(Clone)]
pub struct Store {
    inner: Arc<Mutex<Disk>>,
    path: Arc<PathBuf>,
    _lock: Arc<File>,
    events: tokio::sync::watch::Sender<crate::events::Event>,
}
fn io(error: impl std::error::Error + 'static) -> StorageError<u64> {
    StorageIOError::write_state_machine(&error).into()
}
impl Store {
    pub fn open(path: &Path, genesis: State) -> crate::Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path.with_extension("lock"))?;
        lock.try_lock()
            .map_err(|e| crate::Error::Protocol(e.to_string()))?;
        let hash = crate::governance::digest(
            &serde_json::to_vec(&genesis).map_err(|e| crate::Error::Protocol(e.to_string()))?,
        );
        let disk = if path.exists() {
            if std::fs::metadata(path)?.len() > 64 * 1024 * 1024 {
                return Err(crate::Error::Capacity);
            }
            let disk: Disk = serde_json::from_slice(&std::fs::read(path)?)
                .map_err(|e| crate::Error::Protocol(e.to_string()))?;
            if disk.version != 1 || disk.genesis != hash {
                return Err(crate::Error::Denied);
            }
            disk
        } else {
            Disk {
                version: 1,
                genesis: hash,
                vote: None,
                committed: None,
                purged: None,
                logs: BTreeMap::new(),
                machine: Machine {
                    applied: None,
                    membership: StoredMembership::default(),
                    state: genesis,
                },
                snapshot: None,
            }
        };
        let state_hash = crate::governance::digest(
            &serde_json::to_vec(&disk.machine.state)
                .map_err(|e| crate::Error::Protocol(e.to_string()))?,
        );
        let (events, _) = tokio::sync::watch::channel(crate::events::Event {
            revision: disk.machine.state.revision,
            state_hash,
            resync: true,
        });
        Ok(Self {
            events,
            inner: Arc::new(Mutex::new(disk)),
            path: Arc::new(path.to_owned()),
            _lock: Arc::new(lock),
        })
    }
    async fn update<T>(&self, change: impl FnOnce(&mut Disk) -> R<T>) -> R<T> {
        let mut guard = self.inner.lock().await;
        let mut next = guard.clone();
        let result = change(&mut next)?;
        let bytes = serde_json::to_vec(&next).map_err(io)?;
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(io(std::io::Error::other("raft store capacity exceeded")));
        }
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent).map_err(io)?;
        file.write_all(&bytes).map_err(io)?;
        file.as_file().sync_all().map_err(io)?;
        file.persist(self.path.as_ref()).map_err(|e| io(e.error))?;
        let notify = next.machine.state != guard.machine.state;
        *guard = next;
        if notify {
            let state_hash =
                crate::governance::digest(&serde_json::to_vec(&guard.machine.state).map_err(io)?);
            self.events.send_replace(crate::events::Event {
                revision: guard.machine.state.revision,
                state_hash,
                resync: false,
            });
        }
        #[cfg(unix)]
        File::open(parent).and_then(|f| f.sync_all()).map_err(io)?;
        Ok(result)
    }
    pub fn watch(&self) -> tokio::sync::watch::Receiver<crate::events::Event> {
        self.events.subscribe()
    }
    pub async fn state(&self) -> State {
        self.inner.lock().await.machine.state.clone()
    }
    pub async fn cluster_id(&self) -> String {
        self.inner.lock().await.genesis.clone()
    }
}
impl RaftLogReader<TypeConfig> for Store {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> R<Vec<Entry<TypeConfig>>> {
        Ok(self
            .inner
            .lock()
            .await
            .logs
            .range(range)
            .map(|(_, e)| e.clone())
            .collect())
    }
}
impl RaftLogStorage<TypeConfig> for Store {
    type LogReader = Self;
    async fn get_log_state(&mut self) -> R<LogState<TypeConfig>> {
        let d = self.inner.lock().await;
        Ok(LogState {
            last_purged_log_id: d.purged,
            last_log_id: d.logs.last_key_value().map(|(_, e)| e.log_id).or(d.purged),
        })
    }
    async fn save_vote(&mut self, vote: &Vote<u64>) -> R<()> {
        self.update(|d| {
            d.vote = Some(*vote);
            Ok(())
        })
        .await
    }
    async fn read_vote(&mut self) -> R<Option<Vote<u64>>> {
        Ok(self.inner.lock().await.vote)
    }
    async fn save_committed(&mut self, value: Option<LogId<u64>>) -> R<()> {
        self.update(|d| {
            d.committed = value;
            Ok(())
        })
        .await
    }
    async fn read_committed(&mut self) -> R<Option<LogId<u64>>> {
        Ok(self.inner.lock().await.committed)
    }
    async fn append<I>(&mut self, entries: I, callback: LogFlushed<TypeConfig>) -> R<()>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        self.update(|d| {
            for entry in entries {
                d.logs.insert(entry.log_id.index, entry);
            }
            Ok(())
        })
        .await?;
        callback.log_io_completed(Ok(()));
        Ok(())
    }
    async fn truncate(&mut self, id: LogId<u64>) -> R<()> {
        self.update(|d| {
            d.logs.retain(|index, _| *index < id.index);
            Ok(())
        })
        .await
    }
    async fn purge(&mut self, id: LogId<u64>) -> R<()> {
        self.update(|d| {
            if d.purged.is_some_and(|old| old > id) {
                return Err(io(std::io::Error::other("purge moved backwards")));
            }
            d.purged = Some(id);
            d.logs.retain(|index, _| *index > id.index);
            Ok(())
        })
        .await
    }
    async fn get_log_reader(&mut self) -> Self {
        self.clone()
    }
}
impl RaftSnapshotBuilder<TypeConfig> for Store {
    async fn build_snapshot(&mut self) -> R<Snapshot<TypeConfig>> {
        self.update(|d| {
            let data = serde_json::to_vec(&d.machine).map_err(io)?;
            let meta = SnapshotMeta {
                last_log_id: d.machine.applied,
                last_membership: d.machine.membership.clone(),
                snapshot_id: uuid::Uuid::new_v4().to_string(),
            };
            d.snapshot = Some(StoredSnapshot {
                meta: meta.clone(),
                data: data.clone(),
            });
            Ok(Snapshot {
                meta,
                snapshot: Box::new(Cursor::new(data)),
            })
        })
        .await
    }
}
impl RaftStateMachine<TypeConfig> for Store {
    type SnapshotBuilder = Self;
    async fn applied_state(
        &mut self,
    ) -> R<(Option<LogId<u64>>, StoredMembership<u64, super::Peer>)> {
        let d = self.inner.lock().await;
        Ok((d.machine.applied, d.machine.membership.clone()))
    }
    async fn apply<I>(&mut self, entries: I) -> R<Vec<Applied>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        self.update(|d| {
            let mut results = Vec::new();
            for entry in entries {
                let mut error = None;
                match entry.payload {
                    EntryPayload::Blank => {}
                    EntryPayload::Membership(m) => {
                        d.machine.membership = StoredMembership::new(Some(entry.log_id), m)
                    }
                    EntryPayload::Normal(request) => {
                        let result = (|| {
                            if request.cluster != d.genesis {
                                return Err(crate::Error::Denied);
                            }
                            let (actor, command) = request.command.verify()?;
                            if command.expires_ms < request.time_ms {
                                return Err(crate::Error::Denied);
                            }
                            let mut next = d.machine.state.clone();
                            next.apply(&actor, command.revision, request.time_ms, command.action)?;
                            if serde_json::to_vec(&next)
                                .map_err(|e| crate::Error::Protocol(e.to_string()))?
                                .len()
                                > crate::journal::MAX_SNAPSHOT - 1024
                            {
                                return Err(crate::Error::Capacity);
                            }
                            d.machine.state = next;
                            Ok(())
                        })();
                        if let Err(e) = result {
                            error = Some(e.to_string());
                        }
                    }
                }
                d.machine.applied = Some(entry.log_id);
                results.push(Applied {
                    revision: d.machine.state.revision,
                    error,
                });
            }
            Ok(results)
        })
        .await
    }
    async fn begin_receiving_snapshot(&mut self) -> R<Box<Cursor<Vec<u8>>>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }
    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, super::Peer>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> R<()> {
        let data = snapshot.into_inner();
        if data.len() > 16 * 1024 * 1024 {
            return Err(io(std::io::Error::other("snapshot too large")));
        }
        let machine: Machine = serde_json::from_slice(&data).map_err(io)?;
        if machine.applied != meta.last_log_id || machine.membership != meta.last_membership {
            return Err(io(std::io::Error::other("snapshot metadata mismatch")));
        }
        self.update(|d| {
            d.machine = machine;
            d.snapshot = Some(StoredSnapshot {
                meta: meta.clone(),
                data,
            });
            Ok(())
        })
        .await
    }
    async fn get_current_snapshot(&mut self) -> R<Option<Snapshot<TypeConfig>>> {
        Ok(self.inner.lock().await.snapshot.as_ref().map(|s| Snapshot {
            meta: s.meta.clone(),
            snapshot: Box::new(Cursor::new(s.data.clone())),
        }))
    }
    async fn get_snapshot_builder(&mut self) -> Self {
        self.clone()
    }
}
