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
use state::Domain;
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
#[serde(bound = "")]
pub struct Machine<D: Domain> {
    pub applied: Option<LogId<u64>>,
    pub membership: StoredMembership<u64, super::Peer>,
    pub state: State<D>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<crate::journal::TrustHistory>,
    pub audit: Audit<D>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "", deny_unknown_fields)]
pub struct Audit<D: Domain> {
    pub baseline: State<D>,
    pub records: Vec<super::Replicated>,
}
fn protocol(e: impl std::fmt::Display) -> crate::Error {
    crate::Error::Protocol(e.to_string())
}
fn state_hash<D: Domain>(state: &State<D>) -> crate::Result<String> {
    Ok(crate::protocol::digest(
        &serde_json::to_vec(state).map_err(protocol)?,
    ))
}
impl<D: Domain> Machine<D> {
    fn apply_request(&mut self, request: &super::Replicated, cluster: &str) -> crate::Result<()> {
        use crate::Error;
        if request.cluster != cluster {
            return Err(Error::Denied);
        }
        let mut next = self.state.clone();
        let mut history = self.identity.clone();
        {
            let delta = &request.identity;
            let binding = &self.state.core.identity;
            let history = history.get_or_insert_with(|| crate::journal::TrustHistory {
                genesis: delta.genesis.clone(),
                records: Vec::new(),
            });
            if identity::trust::TrustState::genesis_digest(&history.genesis)? != binding.genesis
                || identity::trust::TrustState::genesis_digest(&delta.genesis)? != binding.genesis
            {
                return Err(Error::Denied);
            }
            history.records.extend(delta.records.clone());
            let mut trust = identity::trust::TrustState::new(&history.genesis, &binding.genesis)?;
            for record in &history.records {
                trust.apply(record)?;
            }
            let (actor, bound) = request.command.verify::<D>()?;
            if bound.genesis != cluster
                || bound.previous != state_hash(&self.state)?
                || bound.identity != *trust.checkpoint()
                || !crate::journal::valid_expiry(bound.command.expires_ms, request.time_ms)
            {
                return Err(Error::Denied);
            }
            next.apply(
                &actor,
                bound.command.revision,
                request.time_ms,
                bound.command.action,
                &trust,
            )?;
        }
        if serde_json::to_vec(&next).map_err(protocol)?.len() > crate::journal::MAX_SNAPSHOT - 1024
        {
            return Err(Error::Capacity);
        }
        self.audit.records.push(request.clone());
        self.state = next;
        self.identity = history;
        Ok(())
    }
    fn validate(&self, cluster: &str) -> crate::Result<()> {
        let audit = &self.audit;
        if state_hash(&audit.baseline)? != cluster {
            return Err(crate::Error::Denied);
        }
        let mut replay = Self {
            applied: None,
            membership: Default::default(),
            state: audit.baseline.clone(),
            identity: None,
            audit: Audit {
                baseline: audit.baseline.clone(),
                records: Vec::new(),
            },
        };
        for request in &audit.records {
            replay.apply_request(request, cluster)?;
        }
        if replay.state != self.state
            || serde_json::to_vec(&replay.identity).map_err(protocol)?
                != serde_json::to_vec(&self.identity).map_err(protocol)?
        {
            return Err(crate::Error::Denied);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredSnapshot {
    meta: SnapshotMeta<u64, super::Peer>,
    data: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
struct Disk<D: Domain> {
    version: u8,
    genesis: String,
    vote: Option<Vote<u64>>,
    committed: Option<LogId<u64>>,
    purged: Option<LogId<u64>>,
    logs: BTreeMap<u64, Entry<TypeConfig>>,
    machine: Machine<D>,
    snapshot: Option<StoredSnapshot>,
}
#[derive(Clone)]
pub struct Store<D: Domain> {
    inner: Arc<Mutex<Disk<D>>>,
    path: Arc<PathBuf>,
    _lock: Arc<File>,
    events: tokio::sync::watch::Sender<crate::events::Event>,
}
fn io(error: impl std::error::Error + 'static) -> StorageError<u64> {
    StorageIOError::write_state_machine(&error).into()
}
impl<D: Domain> Store<D> {
    pub fn open(path: &Path, genesis: State<D>) -> crate::Result<Self> {
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
        let hash = crate::protocol::digest(
            &serde_json::to_vec(&genesis).map_err(|e| crate::Error::Protocol(e.to_string()))?,
        );
        let disk = if path.exists() {
            if std::fs::metadata(path)?.len() > 64 * 1024 * 1024 {
                return Err(crate::Error::Capacity);
            }
            let disk: Disk<D> = serde_json::from_slice(&std::fs::read(path)?)
                .map_err(|e| crate::Error::Protocol(e.to_string()))?;
            if disk.version != 1 || disk.genesis != hash {
                return Err(crate::Error::Denied);
            }
            disk
        } else {
            Disk {
                version: 1,
                genesis: hash.clone(),
                vote: None,
                committed: None,
                purged: None,
                logs: BTreeMap::new(),
                machine: Machine {
                    applied: None,
                    membership: StoredMembership::default(),
                    state: genesis.clone(),
                    identity: None,
                    audit: Audit {
                        baseline: genesis,
                        records: Vec::new(),
                    },
                },
                snapshot: None,
            }
        };
        disk.machine.validate(&hash)?;
        let state_hash = crate::protocol::digest(
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
    async fn update<T>(&self, change: impl FnOnce(&mut Disk<D>) -> R<T>) -> R<T> {
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
                crate::protocol::digest(&serde_json::to_vec(&guard.machine.state).map_err(io)?);
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
    pub async fn state(&self) -> State<D> {
        self.inner.lock().await.machine.state.clone()
    }
    pub async fn preflight(&self, request: &super::Replicated) -> crate::Result<()> {
        let disk = self.inner.lock().await;
        disk.machine.clone().apply_request(request, &disk.genesis)
    }
    pub async fn response(&self) -> crate::Result<crate::journal::Response<D>> {
        let disk = self.inner.lock().await;
        let mut response =
            crate::journal::Response::snapshot(disk.machine.state.clone(), &disk.genesis)?;
        if let Some(proof) = &mut response.proof {
            proof.head = Some(state_hash(&disk.machine.state)?);
            if let Some(history) = &disk.machine.identity {
                let binding = &disk.machine.state.core.identity;
                let mut trust =
                    identity::trust::TrustState::new(&history.genesis, &binding.genesis)?;
                for record in &history.records {
                    trust.apply(record)?;
                }
                proof.identity = Some(trust.checkpoint().clone());
            }
        }
        Ok(response)
    }
    pub async fn cluster_id(&self) -> String {
        self.inner.lock().await.genesis.clone()
    }
}
impl<D: Domain> RaftLogReader<TypeConfig> for Store<D> {
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
impl<D: Domain> RaftLogStorage<TypeConfig> for Store<D> {
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
impl<D: Domain> RaftSnapshotBuilder<TypeConfig> for Store<D> {
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
impl<D: Domain> RaftStateMachine<TypeConfig> for Store<D> {
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
                        let result = d.machine.apply_request(&request, &d.genesis);
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
        let machine: Machine<D> = serde_json::from_slice(&data).map_err(io)?;
        if machine.applied != meta.last_log_id || machine.membership != meta.last_membership {
            return Err(io(std::io::Error::other("snapshot metadata mismatch")));
        }
        self.update(|d| {
            machine.validate(&d.genesis).map_err(io)?;
            if machine.applied < d.machine.applied {
                return Err(io(crate::Error::Denied));
            }
            {
                let old = &d.machine.audit;
                let incoming = &machine.audit;
                if incoming.baseline != old.baseline
                    || incoming.records.len() < old.records.len()
                    || serde_json::to_vec(&incoming.records[..old.records.len()]).map_err(io)?
                        != serde_json::to_vec(&old.records).map_err(io)?
                {
                    return Err(io(crate::Error::Denied));
                }
            }
            if let Some(old) = &d.machine.identity {
                let incoming = machine
                    .identity
                    .as_ref()
                    .ok_or_else(|| io(crate::Error::Denied))?;
                if incoming.records.len() < old.records.len()
                    || serde_json::to_vec(&incoming.records[..old.records.len()]).map_err(io)?
                        != serde_json::to_vec(&old.records).map_err(io)?
                {
                    return Err(io(crate::Error::Denied));
                }
            }
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
