//! Per-backend cache of what this backend learned from Vault about keys: the
//! key versions (export mode), or that a key does not exist (both modes).
//!
//! The cache is process-local (each PostgreSQL backend has its own) and
//! bounded by `pii_vault.cache_max_entries`. Entries expire after
//! `pii_vault.cache_ttl_sec`, absent keys sooner, and the current settings
//! apply to entries already cached. The cache is
//! * dropped entirely when the Vault endpoint changes or when the
//!   cluster-wide invalidation epoch moves (`piitext_cache_invalidate()`);
//! * cleared key by key when a backend of the cluster shreds or creates a key
//!   (see `shared`).

use crate::config;
use crate::shared::{self, Counter, Generation, KeyChanges};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub type Key = Zeroizing<[u8; 32]>;

/// How long a key known to be absent is remembered at most. Short, because
/// another cluster may create a key with the same name.
const ABSENT_TTL: Duration = Duration::from_secs(30);

/// All exportable versions of one Vault key, oldest first. Built once and
/// never resized, so key bytes are not copied around the heap; they are wiped
/// when the last reference is dropped.
pub struct KeySet {
    versions: Vec<(u32, Key)>,
}

impl KeySet {
    /// `versions` must be sorted by version number and non-empty.
    pub fn new(versions: Vec<(u32, Key)>) -> Option<Self> {
        let sorted = versions.windows(2).all(|w| w[0].0 < w[1].0);
        (!versions.is_empty() && sorted).then_some(KeySet { versions })
    }

    pub fn latest(&self) -> (u32, &[u8; 32]) {
        let (v, k) = self.versions.last().expect("KeySet is never empty");
        (*v, k)
    }

    pub fn get(&self, version: u32) -> Option<&[u8; 32]> {
        self.versions
            .iter()
            .find(|(v, _)| *v == version)
            .map(|(_, k)| &**k)
    }

    pub fn newest_first(&self) -> impl Iterator<Item = (u32, &[u8; 32])> {
        self.versions.iter().rev().map(|(v, k)| (*v, &**k))
    }
}

pub enum Lookup {
    /// The key's versions, fetched `age` ago.
    Hit {
        keys: Arc<KeySet>,
        age: Duration,
    },
    /// Vault recently reported that the key does not exist.
    Absent,
    Miss,
}

struct Entry {
    key_id: Vec<u8>,
    /// `None`: the key does not exist.
    keys: Option<Arc<KeySet>>,
    fetched_at: Instant,
}

impl Entry {
    fn live(&self, ttl: Duration, now: Instant) -> bool {
        let lifetime = if self.keys.is_some() {
            ttl
        } else {
            ttl.min(ABSENT_TTL)
        };
        now.duration_since(self.fetched_at) < lifetime
    }
}

#[derive(Default)]
struct Cache {
    scope: String,
    generation: Generation,
    /// Keyed by `shared::key_hash` of the key id; the key id itself is
    /// compared on lookup.
    entries: HashMap<u64, Entry>,
}

impl Cache {
    fn sync(&mut self, scope: &str, now: Generation) {
        if self.scope != scope || self.generation.epoch != now.epoch {
            self.entries.clear();
            self.scope.clear();
            self.scope.push_str(scope);
        } else if self.generation.key_seq != now.key_seq {
            match shared::key_changes(self.generation.key_seq, now.key_seq) {
                KeyChanges::Keys(hashes) => {
                    for hash in hashes {
                        self.entries.remove(&hash);
                    }
                }
                KeyChanges::Unknown => self.entries.clear(),
            }
        }
        self.generation = now;
    }

    /// Make room for one more entry: drop expired entries, then the oldest
    /// ~10% so that eviction cost is amortised over many inserts.
    fn make_room(&mut self, max: usize, ttl: Duration, now: Instant) {
        let before = self.entries.len();
        self.entries.retain(|_, e| e.live(ttl, now));
        if self.entries.len() >= max {
            let keep = max.saturating_sub(max / 10 + 1);
            let excess = self.entries.len() - keep;
            let mut ages: Vec<Instant> = self.entries.values().map(|e| e.fetched_at).collect();
            let (_, cutoff, _) = ages.select_nth_unstable(excess - 1);
            let cutoff = *cutoff;
            let older = ages.iter().filter(|t| **t < cutoff).count();
            let mut equal_budget = excess - older;
            self.entries.retain(|_, e| {
                if e.fetched_at < cutoff {
                    false
                } else if e.fetched_at == cutoff && equal_budget > 0 {
                    equal_budget -= 1;
                    false
                } else {
                    true
                }
            });
        }
        shared::add(
            Counter::CacheEvictions,
            (before - self.entries.len()) as u64,
        );
    }
}

thread_local! {
    static CACHE: RefCell<Cache> = RefCell::new(Cache::default());
}

fn with_cache<R>(scope: &str, f: impl FnOnce(&mut Cache) -> R) -> R {
    let now = shared::generation();
    CACHE.with(|c| {
        let mut cache = c.borrow_mut();
        cache.sync(scope, now);
        f(&mut cache)
    })
}

fn settings() -> (Duration, usize) {
    (config::cache_ttl(), config::cache_max_entries())
}

/// What this backend knows about the key, under the current settings.
pub fn get(scope: &str, key_id: &[u8]) -> Lookup {
    let (ttl, max) = settings();
    with_cache(scope, |cache| {
        if ttl.is_zero() || max == 0 {
            // Caching is disabled: forget what was cached before.
            cache.entries.clear();
            shared::incr(Counter::CacheMisses);
            return Lookup::Miss;
        }
        let hash = shared::key_hash(key_id);
        let now = Instant::now();
        let lookup = match cache.entries.get(&hash) {
            Some(e) if e.key_id == key_id && e.live(ttl, now) => match &e.keys {
                Some(keys) => Lookup::Hit {
                    keys: keys.clone(),
                    age: now.duration_since(e.fetched_at),
                },
                None => Lookup::Absent,
            },
            Some(e) if e.key_id == key_id => {
                cache.entries.remove(&hash);
                shared::incr(Counter::CacheEvictions);
                Lookup::Miss
            }
            _ => Lookup::Miss,
        };
        shared::incr(if matches!(lookup, Lookup::Miss) {
            Counter::CacheMisses
        } else {
            Counter::CacheHits
        });
        lookup
    })
}

/// Whether the key with this hash was invalidated after `since`.
fn invalidated_since(since: Generation, now: Generation, hash: u64) -> bool {
    if since.epoch != now.epoch {
        return true;
    }
    if since.key_seq == now.key_seq {
        return false;
    }
    match shared::key_changes(since.key_seq, now.key_seq) {
        KeyChanges::Keys(hashes) => hashes.contains(&hash),
        KeyChanges::Unknown => true,
    }
}

/// Remember what Vault answered about a key (`None`: it does not exist),
/// taken at generation `since`. If the key was shredded, created or
/// invalidated after `since`, the answer may already be outdated: nothing is
/// cached and false is returned.
pub fn put(scope: &str, key_id: &[u8], keys: Option<Arc<KeySet>>, since: Generation) -> bool {
    let (ttl, max) = settings();
    with_cache(scope, |cache| {
        let hash = shared::key_hash(key_id);
        if invalidated_since(since, cache.generation, hash) {
            cache.entries.remove(&hash);
            return false;
        }
        if ttl.is_zero() || max == 0 {
            return true;
        }
        let now = Instant::now();
        if !cache.entries.contains_key(&hash) && cache.entries.len() >= max {
            cache.make_room(max, ttl, now);
        }
        cache.entries.insert(
            hash,
            Entry {
                key_id: key_id.to_vec(),
                keys,
                fetched_at: now,
            },
        );
        true
    })
}

/// Remove one key from this backend's cache. Returns whether it was cached.
pub fn evict(key_id: &[u8]) -> bool {
    let hash = shared::key_hash(key_id);
    CACHE.with(|c| {
        let mut cache = c.borrow_mut();
        match cache.entries.get(&hash) {
            Some(e) if e.key_id == key_id => cache.entries.remove(&hash).is_some(),
            _ => false,
        }
    })
}

/// Drop every cached key of this backend. Returns how many were removed.
pub fn flush() -> usize {
    CACHE.with(|c| {
        let mut cache = c.borrow_mut();
        let n = cache.entries.len();
        cache.entries.clear();
        n
    })
}

pub fn len() -> usize {
    CACHE.with(|c| c.borrow().entries.len())
}
