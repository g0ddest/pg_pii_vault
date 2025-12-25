use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

struct CacheEntry {
    key: [u8; 32],
    expires_at: Instant,
}

static KEY_CACHE: Lazy<RwLock<HashMap<Vec<u8>, CacheEntry>>> = Lazy::new(|| {
    RwLock::new(HashMap::new())
});

pub fn get_cached_key(key_id: &[u8]) -> Option<[u8; 32]> {
    let cache = KEY_CACHE.read().ok()?;
    if let Some(entry) = cache.get(key_id) {
        if entry.expires_at > Instant::now() {
            return Some(entry.key);
        }
    }
    None
}

pub fn insert_into_cache(key_id: Vec<u8>, key: [u8; 32], ttl_secs: u64) {
    if let Ok(mut cache) = KEY_CACHE.write() {
        cache.insert(key_id, CacheEntry {
            key,
            expires_at: Instant::now() + Duration::from_secs(ttl_secs),
        });
    }
}
