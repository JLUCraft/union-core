//! Signed, revision-checked governance journal. One writer per organization
//! deployment; this is deliberately not a Byzantine consensus implementation.
use crate::{
    Error, Identity, Result,
    governance::{Action, State},
    protocol::digest,
};
use serde::{Deserialize, Serialize};
use state::Domain;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub use crate::protocol::{GOVERNANCE_PROTOCOL as PROTOCOL, JsonFrame};
/// Upper bound for a signed one-shot command, independent of permanent membership.
pub const MAX_COMMAND_TTL_MS: u64 = 5 * 60 * 1000;

pub(crate) fn valid_expiry(expires: u64, now: u64) -> bool {
    expires
        .checked_sub(now)
        .is_some_and(|ttl| ttl <= MAX_COMMAND_TTL_MS)
}

pub const MAX_SNAPSHOT: usize = 8 * 1024 * 1024;
const TRUSTED_DOMAIN: &[u8] = b"jlucraft/governance/trusted/1\0";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Command<D: Domain> {
    pub revision: u64,
    pub expires_ms: u64,
    pub action: Action<D>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCommand {
    pub payload: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    identity: TrustHistory,
    version: u8,
    previous: String,
    command: SignedCommand,
    time_ms: u64,
    state_hash: String,
}

pub struct Journal<D: Domain> {
    path: PathBuf,
    _lock: File,
    entries: Vec<Entry>,
    genesis: State<D>,
    state: State<D>,
    genesis_hash: String,
    trust: Option<identity::trust::TrustState>,
    events: tokio::sync::watch::Sender<crate::events::Event>,
}

impl<D: Domain> Journal<D> {
    pub fn open(path: impl AsRef<Path>, genesis: State<D>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path.with_extension("lock"))?;
        lock.try_lock().map_err(Error::protocol)?;
        let genesis_hash = digest(&serde_json::to_vec(&genesis).map_err(Error::protocol)?);
        let entries: Vec<Entry> = if path.exists() {
            if path.metadata()?.len() > 64 * 1024 * 1024 {
                return Err(Error::Capacity);
            }
            serde_json::from_slice(&std::fs::read(&path)?).map_err(Error::protocol)?
        } else {
            Vec::new()
        };
        let mut state = genesis.clone();
        let mut trust = None;
        let mut previous = genesis_hash.clone();
        for entry in &entries {
            if entry.previous != previous {
                return Err(Error::protocol("journal chain mismatch"));
            }
            {
                let history = &entry.identity;
                advance_identity(&state, &mut trust, history)?;
                let (actor, bound) = entry.command.verify::<D>()?;
                let identity = trust.as_ref().ok_or(Error::Denied)?;
                if bound.genesis != genesis_hash
                    || bound.previous != previous
                    || bound.identity != *identity.checkpoint()
                    || !valid_expiry(bound.command.expires_ms, entry.time_ms)
                {
                    return Err(Error::Denied);
                }
                state.apply(
                    &actor,
                    bound.command.revision,
                    entry.time_ms,
                    bound.command.action,
                    identity,
                )?;
            }
            if entry.version != 1 {
                return Err(Error::protocol("unsupported journal version"));
            }
            if digest(&serde_json::to_vec(&state).map_err(Error::protocol)?) != entry.state_hash {
                return Err(Error::protocol("journal state mismatch"));
            }
            previous = digest(&serde_json::to_vec(entry).map_err(Error::protocol)?);
        }
        let (events, _) = tokio::sync::watch::channel(crate::events::Event {
            revision: state.revision,
            state_hash: digest(&serde_json::to_vec(&state).map_err(Error::protocol)?),
            resync: true,
        });
        Ok(Self {
            trust,
            events,
            path,
            _lock: lock,
            entries,
            genesis,
            state,
            genesis_hash,
        })
    }
    pub fn watch(&self) -> tokio::sync::watch::Receiver<crate::events::Event> {
        self.events.subscribe()
    }
    pub fn genesis_hash(&self) -> &str {
        &self.genesis_hash
    }
    pub fn genesis(&self) -> &State<D> {
        &self.genesis
    }
    pub fn state(&self) -> &State<D> {
        &self.state
    }
    fn commit(&mut self, entry: Entry, next: State<D>) -> Result<()> {
        let mut entries = self.entries.clone();
        entries.push(entry);
        let bytes = serde_json::to_vec(&entries).map_err(Error::protocol)?;
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
            state_hash: digest(&serde_json::to_vec(&self.state).map_err(Error::protocol)?),
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
    Genesis,
    Snapshot,
    Execute {
        command: SignedCommand,
        history: TrustHistory,
    },
}

#[derive(Serialize, Deserialize)]
#[doc(hidden)]
pub struct Exchange {
    pub genesis_hash: String,
    #[serde(flatten)]
    pub request: Request,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SnapshotProof {
    /// Observation time supplied by the authenticated authority, independent of ledger writes.
    pub observed_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<crate::protocol::TrustCheckpoint>,
    pub genesis_hash: String,
    pub state_hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Response<D: Domain> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_view: Option<state::governance::IdentityPresentation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis: Option<State<D>>,
    pub state: Option<State<D>>,
    pub error: Option<String>,
    pub error_code: Option<protocol::ClientErrorCode>,
    pub proof: Option<SnapshotProof>,
}

impl<D: Domain> Response<D> {
    #[doc(hidden)]
    pub fn snapshot(state: State<D>, genesis_hash: &str) -> Result<Self> {
        let state_hash = digest(&serde_json::to_vec(&state).map_err(Error::protocol)?);
        Ok(Self {
            identity_view: None,
            genesis: None,
            state: Some(state),
            error: None,
            error_code: None,
            proof: Some(SnapshotProof {
                observed_ms: now_ms()?,
                head: None,
                identity: None,
                genesis_hash: genesis_hash.into(),
                state_hash,
            }),
        })
    }
    #[doc(hidden)]
    pub fn genesis(genesis: State<D>) -> Self {
        // The caller has no pinned hash yet; local digest recomputation is the pin.
        Self {
            identity_view: None,
            genesis: Some(genesis),
            state: None,
            error: None,
            error_code: None,
            proof: None,
        }
    }
    #[doc(hidden)]
    pub fn rejected(error: Error) -> Self {
        Self {
            identity_view: None,
            genesis: None,
            state: None,
            error_code: Some(error.failure().code),
            error: Some(error.to_string()),
            proof: None,
        }
    }
    /// Integrity and deployment binding over an authenticated authority connection.
    /// This is not a Byzantine validity proof or a substitute for journal replay.
    pub fn verify(&self, genesis_hash: &str) -> Result<()> {
        match (&self.genesis, &self.state, &self.error, &self.proof) {
            (None, Some(state), None, Some(proof))
                if proof.genesis_hash == genesis_hash
                    && proof.state_hash
                        == digest(&serde_json::to_vec(state).map_err(Error::protocol)?) =>
            {
                Ok(())
            }
            (None, None, Some(_), None) => Ok(()),
            _ => Err(Error::Denied),
        }
    }
}

pub fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(Error::protocol)?
        .as_millis()
        .try_into()
        .map_err(Error::protocol)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustHistory {
    pub genesis: crate::protocol::TrustGenesis,
    pub records: Vec<crate::protocol::TrustRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "", deny_unknown_fields)]
pub struct TrustedCommand<D: Domain> {
    pub genesis: String,
    pub previous: String,
    pub identity: crate::protocol::TrustCheckpoint,
    pub command: Command<D>,
}
impl SignedCommand {
    pub fn sign<D: Domain>(identity: &Identity, command: TrustedCommand<D>) -> Result<Self> {
        let payload = serde_json::to_vec(&command).map_err(Error::protocol)?;
        let signature = identity.sign(&[TRUSTED_DOMAIN, &payload].concat())?;
        Ok(Self {
            payload,
            signature,
            public_key: identity.public_key().encode_protobuf(),
        })
    }
    pub fn verify<D: Domain>(&self) -> Result<(String, TrustedCommand<D>)> {
        if self.payload.len() > crate::protocol::MAX_FRAME {
            return Err(Error::Capacity);
        }
        let key = identity::PublicKey::try_decode_protobuf(&self.public_key)
            .map_err(|_| Error::Denied)?;
        if !key.verify(&[TRUSTED_DOMAIN, &self.payload].concat(), &self.signature) {
            return Err(Error::Denied);
        }
        Ok((
            key.to_peer_id().to_string(),
            serde_json::from_slice(&self.payload).map_err(Error::protocol)?,
        ))
    }
}
fn advance_identity<D: Domain>(
    state: &State<D>,
    trust: &mut Option<identity::trust::TrustState>,
    history: &TrustHistory,
) -> Result<()> {
    let binding = &state.core.identity;
    let genesis = identity::trust::TrustState::new(&history.genesis, &binding.genesis)?;
    let current = trust.get_or_insert(genesis);
    for record in &history.records {
        current.apply(record)?;
    }
    Ok(())
}
impl<D: Domain> Journal<D> {
    pub fn head(&self) -> Result<String> {
        self.entries
            .last()
            .map(|entry| {
                serde_json::to_vec(entry)
                    .map(|b| digest(&b))
                    .map_err(Error::protocol)
            })
            .unwrap_or_else(|| Ok(self.genesis_hash.clone()))
    }
    pub fn identity_checkpoint(&self) -> Option<&crate::protocol::TrustCheckpoint> {
        self.trust.as_ref().map(|s| s.checkpoint())
    }
    pub fn snapshot(&self) -> Result<Response<D>> {
        let mut response = Response::snapshot(self.state.clone(), &self.genesis_hash)?;
        if let Some(proof) = &mut response.proof {
            proof.head = Some(self.head()?);
            proof.identity = self.identity_checkpoint().cloned();
        }
        Ok(response)
    }
    pub fn execute(
        &mut self,
        command: SignedCommand,
        history: TrustHistory,
        current: &identity::trust::TrustState,
        now: u64,
    ) -> Result<()> {
        let mut trust = self.trust.clone();
        advance_identity(&self.state, &mut trust, &history)?;
        let trust = trust.ok_or(Error::Denied)?;
        let (actor, bound) = command.verify::<D>()?;
        if trust.checkpoint() != current.checkpoint()
            || bound.identity != *trust.checkpoint()
            || bound.genesis != self.genesis_hash
            || bound.previous != self.head()?
            || !valid_expiry(bound.command.expires_ms, now)
        {
            return Err(Error::Denied);
        }
        let mut next = self.state.clone();
        next.apply(
            &actor,
            bound.command.revision,
            now,
            bound.command.action,
            &trust,
        )?;
        if serde_json::to_vec(&next).map_err(Error::protocol)?.len() > MAX_SNAPSHOT - 1024 {
            return Err(Error::Capacity);
        }
        let entry = Entry {
            version: 1,
            previous: self.head()?,
            command,
            time_ms: now,
            state_hash: digest(&serde_json::to_vec(&next).map_err(Error::protocol)?),
            identity: history,
        };
        let revision = next.revision;
        let result = self.commit(entry, next);
        if self.state.revision == revision {
            self.trust = Some(trust);
        }
        result
    }
}

#[cfg(test)]
mod expiry_tests {
    use super::{MAX_COMMAND_TTL_MS, valid_expiry};
    #[test]
    fn commands_have_bounded_lifetimes_without_overflow() {
        assert!(!valid_expiry(9, 10));
        assert!(valid_expiry(10, 10));
        assert!(valid_expiry(10 + MAX_COMMAND_TTL_MS, 10));
        assert!(!valid_expiry(11 + MAX_COMMAND_TTL_MS, 10));
        assert!(!valid_expiry(u64::MAX, 10));
        assert!(valid_expiry(u64::MAX, u64::MAX));
    }
}
