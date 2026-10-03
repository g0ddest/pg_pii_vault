//! Cluster-wide state kept in PostgreSQL shared memory.
//!
//! Available only when the library is listed in `shared_preload_libraries`.
//! It holds
//! * an invalidation epoch, bumped by `piitext_cache_invalidate()`: every
//!   backend drops its whole key cache when it sees a new epoch;
//! * a ring of key changes, published when a key is shredded or created:
//!   every backend drops its cached entry for that key only;
//! * monitoring counters.
//!
//! Without preloading the extension still works, but invalidation is
//! per-backend and bounded by the cache TTL.

use pgrx::prelude::*;
use pgrx::{pg_shmem_init, PGRXSharedMemory, PgAtomic};
use std::sync::atomic::{fence, AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Copy, Debug)]
pub enum Counter {
    CacheHits,
    CacheMisses,
    CacheEvictions,
    /// HTTP requests sent to Vault (every attempt).
    VaultRequests,
    /// Attempts that failed in transport or with HTTP 412/429/5xx.
    VaultErrors,
    /// Statements that failed because Vault refused the token or its policy.
    VaultDenied,
    KeysCreated,
    KeysShredded,
    /// Values returned as '****' because their key is gone.
    DecryptMasked,
}

impl Counter {
    pub const ALL: [Counter; 9] = [
        Counter::CacheHits,
        Counter::CacheMisses,
        Counter::CacheEvictions,
        Counter::VaultRequests,
        Counter::VaultErrors,
        Counter::VaultDenied,
        Counter::KeysCreated,
        Counter::KeysShredded,
        Counter::DecryptMasked,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Counter::CacheHits => "cache_hits",
            Counter::CacheMisses => "cache_misses",
            Counter::CacheEvictions => "cache_evictions",
            Counter::VaultRequests => "vault_requests",
            Counter::VaultErrors => "vault_errors",
            Counter::VaultDenied => "vault_denied",
            Counter::KeysCreated => "keys_created",
            Counter::KeysShredded => "keys_shredded",
            Counter::DecryptMasked => "decrypt_masked",
        }
    }
}

const N_COUNTERS: usize = Counter::ALL.len();

/// Slots of the key change ring. A backend that falls further behind than
/// this drops its whole cache instead of single keys.
const KEY_RING_SLOTS: usize = 2048;

/// One published key change. Written and read like a seqlock: `stamp` is the
/// sequence number + 1 of the change the slot holds, and 0 while it is being
/// overwritten.
struct KeySlot {
    stamp: AtomicU64,
    hash: AtomicU64,
}

pub struct SharedState {
    epoch: AtomicU64,
    counters: [AtomicU64; N_COUNTERS],
    /// Number of key changes published so far.
    key_seq: AtomicU64,
    key_ring: [KeySlot; KEY_RING_SLOTS],
}

impl Default for SharedState {
    fn default() -> Self {
        SharedState {
            epoch: AtomicU64::new(0),
            counters: [const { AtomicU64::new(0) }; N_COUNTERS],
            key_seq: AtomicU64::new(0),
            key_ring: [const {
                KeySlot {
                    stamp: AtomicU64::new(0),
                    hash: AtomicU64::new(0),
                }
            }; KEY_RING_SLOTS],
        }
    }
}

// SAFETY: only atomics, no pointers; valid when mapped at any address.
unsafe impl PGRXSharedMemory for SharedState {}

static SHARED: PgAtomic<SharedState> = unsafe { PgAtomic::new(c"pg_pii_vault_shared_state") };
static SHMEM_ENABLED: AtomicBool = AtomicBool::new(false);
static LOCAL: [AtomicU64; N_COUNTERS] = [const { AtomicU64::new(0) }; N_COUNTERS];

/// Request the shared memory segment. Must be called from `_PG_init` while
/// `shared_preload_libraries` is being processed.
pub fn init() {
    pg_shmem_init!(SHARED);
    SHMEM_ENABLED.store(true, Ordering::Release);
}

pub fn available() -> bool {
    SHMEM_ENABLED.load(Ordering::Acquire)
}

fn state() -> Option<&'static SharedState> {
    available().then(|| SHARED.get())
}

/// Hash identifying a key id in the key change ring and in the key cache
/// (FNV-1a). Collisions only cause an unnecessary cache eviction.
pub fn key_hash(key_id: &[u8]) -> u64 {
    key_id.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Position in the stream of invalidations. Key material fetched from Vault
/// is cached only if nothing invalidated it after the generation taken
/// before the request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Generation {
    pub epoch: u64,
    pub key_seq: u64,
}

/// The current generation (always the default without shared memory).
pub fn generation() -> Generation {
    match state() {
        Some(s) => Generation {
            epoch: s.epoch.load(Ordering::Acquire),
            key_seq: s.key_seq.load(Ordering::Acquire),
        },
        None => Generation::default(),
    }
}

/// Make every backend drop its key cache. Returns false when the library is
/// not preloaded (only the local cache can be flushed then).
pub fn bump_epoch() -> bool {
    match state() {
        Some(s) => {
            s.epoch.fetch_add(1, Ordering::AcqRel);
            true
        }
        None => false,
    }
}

/// Announce that a key was shredded or created: every backend drops what it
/// cached about it. Returns false when the library is not preloaded.
pub fn publish_key_change(key_id: &[u8]) -> bool {
    let Some(s) = state() else {
        return false;
    };
    let seq = s.key_seq.fetch_add(1, Ordering::AcqRel);
    let slot = &s.key_ring[(seq % KEY_RING_SLOTS as u64) as usize];
    slot.stamp.store(0, Ordering::Relaxed);
    fence(Ordering::Release);
    slot.hash.store(key_hash(key_id), Ordering::Relaxed);
    slot.stamp.store(seq + 1, Ordering::Release);
    true
}

pub enum KeyChanges {
    /// Hashes of the keys that changed.
    Keys(Vec<u64>),
    /// Too many changes, or a slot is being rewritten: drop everything.
    Unknown,
}

/// The key changes published in `[from, to)`.
pub fn key_changes(from: u64, to: u64) -> KeyChanges {
    let Some(s) = state() else {
        return KeyChanges::Keys(Vec::new());
    };
    if to < from || to - from > KEY_RING_SLOTS as u64 {
        return KeyChanges::Unknown;
    }
    let mut hashes = Vec::with_capacity((to - from) as usize);
    for seq in from..to {
        let slot = &s.key_ring[(seq % KEY_RING_SLOTS as u64) as usize];
        let before = slot.stamp.load(Ordering::Acquire);
        let hash = slot.hash.load(Ordering::Relaxed);
        fence(Ordering::Acquire);
        let after = slot.stamp.load(Ordering::Relaxed);
        if before != seq + 1 || after != seq + 1 {
            return KeyChanges::Unknown;
        }
        hashes.push(hash);
    }
    KeyChanges::Keys(hashes)
}

pub fn incr(counter: Counter) {
    add(counter, 1);
}

pub fn add(counter: Counter, n: u64) {
    if n == 0 {
        return;
    }
    LOCAL[counter as usize].fetch_add(n, Ordering::Relaxed);
    if let Some(s) = state() {
        s.counters[counter as usize].fetch_add(n, Ordering::Relaxed);
    }
}

pub fn local_value(counter: Counter) -> u64 {
    LOCAL[counter as usize].load(Ordering::Relaxed)
}

pub fn cluster_value(counter: Counter) -> Option<u64> {
    state().map(|s| s.counters[counter as usize].load(Ordering::Relaxed))
}
