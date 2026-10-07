use crate::{Error, Result};
use protocol::digest;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const DAY_MS: u64 = 86_400_000;
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const GENESIS: &str = "jlucraft/llm/usage/1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Event {
    Reserve {
        member: String,
        club: String,
        model: String,
        purpose: String,
        tokens: u64,
    },
    Settle {
        reservation: usize,
        tokens: u64,
    },
}
#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    previous: String,
    time_ms: u64,
    event: Event,
}

pub struct Reservation<'a> {
    pub member: &'a str,
    pub club: &'a str,
    pub model: &'a str,
    pub purpose: &'a str,
    pub tokens: u64,
}
#[derive(Clone, Copy)]
pub struct Quotas {
    pub member: Option<u64>,
    pub club: Option<u64>,
}
pub struct Ledger {
    path: PathBuf,
    _lock: File,
    entries: Vec<Entry>,
    failed: bool,
}
fn read_entries(path: &Path) -> Result<Vec<Entry>> {
    // Read one immutable inode. The writer publishes by rename, so a running
    // gateway needs no pause or second writer lock for an audit snapshot.
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_LEDGER_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LEDGER_BYTES {
        return Err(Error::Invalid("ledger full"));
    }
    let entries: Vec<Entry> = serde_json::from_slice(&bytes)?;
    let mut previous = digest(GENESIS.as_bytes());
    let mut time = 0;
    let mut reservations = BTreeMap::new();
    for (i, entry) in entries.iter().enumerate() {
        if entry.previous != previous || entry.time_ms < time {
            return Err(Error::Invalid("invalid ledger chain or clock"));
        }
        match &entry.event {
            Event::Reserve { tokens, .. } => {
                reservations.insert(i, *tokens);
            }
            Event::Settle {
                reservation,
                tokens,
            } => {
                if !reservations
                    .remove(reservation)
                    .is_some_and(|limit| *tokens <= limit)
                {
                    return Err(Error::Invalid("invalid ledger settlement"));
                }
            }
        }
        previous = digest(&serde_json::to_vec(entry)?);
        time = entry.time_ms;
    }
    Ok(entries)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UsageTotals {
    pub requests: u64,
    pub settled_tokens: u64,
    pub reserved_tokens: u64,
    pub unsettled_requests: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UsageSummary {
    pub version: u32,
    pub entries: usize,
    pub head: String,
    pub last_time_ms: Option<u64>,
    pub totals: UsageTotals,
    pub purposes: BTreeMap<String, UsageTotals>,
}
impl UsageSummary {
    pub fn digest(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }
    /// Verify the independently pinned commitment and the corresponding ledger prefix.
    pub fn verify(&self, path: impl AsRef<Path>, pinned_digest: &str) -> Result<()> {
        if self.digest()? != pinned_digest || Ledger::audit(path, Some(self.entries))? != *self {
            return Err(Error::Invalid("audit commitment mismatch"));
        }
        Ok(())
    }
}
fn add_total(total: &mut UsageTotals, tokens: u64, settled: bool) -> Result<()> {
    let add = |a: u64, b: u64| {
        a.checked_add(b)
            .ok_or(Error::Invalid("audit total overflow"))
    };
    total.requests = add(total.requests, 1)?;
    if settled {
        total.settled_tokens = add(total.settled_tokens, tokens)?;
    } else {
        total.reserved_tokens = add(total.reserved_tokens, tokens)?;
        total.unsettled_requests = add(total.unsettled_requests, 1)?;
    }
    Ok(())
}
impl Ledger {
    pub fn audit(path: impl AsRef<Path>, prefix: Option<usize>) -> Result<UsageSummary> {
        let entries = read_entries(path.as_ref())?;
        let count = prefix.unwrap_or(entries.len());
        let entries = entries
            .get(..count)
            .ok_or(Error::Invalid("ledger shorter than audit commitment"))?;
        let settlements: BTreeMap<_, _> = entries
            .iter()
            .filter_map(|e| match e.event {
                Event::Settle {
                    reservation,
                    tokens,
                } => Some((reservation, tokens)),
                _ => None,
            })
            .collect();
        let mut summary = UsageSummary {
            version: 1,
            entries: count,
            head: match entries.last() {
                Some(entry) => digest(&serde_json::to_vec(entry)?),
                None => digest(GENESIS.as_bytes()),
            },
            last_time_ms: entries.last().map(|e| e.time_ms),
            totals: UsageTotals::default(),
            purposes: BTreeMap::new(),
        };
        for (id, entry) in entries.iter().enumerate() {
            if let Event::Reserve {
                purpose, tokens, ..
            } = &entry.event
            {
                let settled = settlements.get(&id);
                let tokens = settled.copied().unwrap_or(*tokens);
                add_total(&mut summary.totals, tokens, settled.is_some())?;
                add_total(
                    summary.purposes.entry(purpose.clone()).or_default(),
                    tokens,
                    settled.is_some(),
                )?;
            }
        }
        Ok(summary)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path.with_extension("lock"))?;
        lock.try_lock()
            .map_err(|_| Error::Invalid("ledger already open"))?;
        let entries = if path.exists() {
            read_entries(&path)?
        } else {
            vec![]
        };
        Ok(Self {
            path,
            _lock: lock,
            entries,
            failed: false,
        })
    }
    fn append(&mut self, time_ms: u64, event: Event) -> Result<usize> {
        if self.failed || self.entries.last().is_some_and(|e| e.time_ms > time_ms) {
            return Err(Error::Invalid(
                "ledger unavailable or clock moved backwards",
            ));
        }
        let previous = match self.entries.last() {
            Some(entry) => digest(&serde_json::to_vec(entry)?),
            None => digest(GENESIS.as_bytes()),
        };
        let id = self.entries.len();
        let mut entries = self.entries.clone();
        entries.push(Entry {
            previous,
            time_ms,
            event,
        });
        let bytes = serde_json::to_vec(&entries)?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(Error::Invalid("ledger full"));
        }
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // Atomic replacement, with both file and parent directory made durable.
        let persist = (|| -> Result<()> {
            let mut file = tempfile::NamedTempFile::new_in(parent)?;
            file.write_all(&bytes)?;
            file.as_file().sync_all()?;
            file.persist(&self.path).map_err(|e| Error::Io(e.error))?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if let Err(error) = persist {
            self.failed = true;
            return Err(error);
        }
        self.entries = entries;
        Ok(id)
    }
    pub fn reserve(&mut self, request: Reservation<'_>, quotas: Quotas, now: u64) -> Result<usize> {
        if quotas.member.is_none() && quotas.club.is_none() || request.club.is_empty() {
            return Err(Error::Invalid("missing quota scope"));
        }
        let settled: BTreeMap<_, _> = self
            .entries
            .iter()
            .filter_map(|e| match e.event {
                Event::Settle {
                    reservation,
                    tokens,
                } => Some((reservation, tokens)),
                _ => None,
            })
            .collect();
        let mut member_used = 0u64;
        let mut club_used = 0u64;
        for (i, entry) in self.entries.iter().enumerate() {
            if let Event::Reserve {
                member,
                club,
                tokens,
                ..
            } = &entry.event
                && entry.time_ms.saturating_add(DAY_MS) > now
            {
                let charged = settled.get(&i).copied().unwrap_or(*tokens);
                if member == request.member {
                    member_used = member_used
                        .checked_add(charged)
                        .ok_or(Error::Invalid("quota overflow"))?;
                }
                if club == request.club {
                    club_used = club_used
                        .checked_add(charged)
                        .ok_or(Error::Invalid("quota overflow"))?;
                }
            }
        }
        let exceeds = |used: u64, limit: Option<u64>| {
            limit.is_some_and(|limit| {
                used.checked_add(request.tokens)
                    .is_none_or(|total| total > limit)
            })
        };
        if request.tokens == 0
            || exceeds(member_used, quotas.member)
            || exceeds(club_used, quotas.club)
        {
            return Err(Error::Invalid("member or institution quota exhausted"));
        }
        self.append(
            now,
            Event::Reserve {
                member: request.member.into(),
                club: request.club.to_owned(),
                model: request.model.into(),
                purpose: request.purpose.into(),
                tokens: request.tokens,
            },
        )
    }
    pub fn settle(&mut self, id: usize, tokens: u64, now: u64) -> Result<()> {
        let Some(Entry {
            event: Event::Reserve { tokens: limit, .. },
            ..
        }) = self.entries.get(id)
        else {
            return Err(Error::Invalid("unknown reservation"));
        };
        if tokens > *limit
            || self
                .entries
                .iter()
                .any(|e| matches!(e.event, Event::Settle {reservation, ..} if reservation == id))
        {
            self.failed = true;
            return Err(Error::Invalid("provider exceeded token reservation"));
        }
        self.append(
            now,
            Event::Settle {
                reservation: id,
                tokens,
            },
        )?;
        Ok(())
    }
}
