//! Key resolution (cache, then Vault) and the encrypt / decrypt / shred
//! operations built on it.

use crate::cache::{self, KeySet, Lookup};
use crate::config::{self, Endpoint, KeyMode};
use crate::contents::{PiiSealedData, FORMAT_V3};
use crate::crypto;
use crate::error::PiiError;
use crate::http;
use crate::shared::{self, Counter};
use crate::vault;
use crate::MAX_TRANSIT_PLAINTEXT_BYTES;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

pub enum Opened {
    Plaintext(Zeroizing<String>),
    /// The key (or the key version) no longer exists: the value was
    /// crypto-shredded and cannot be recovered.
    Shredded,
}

/// How often a key is fetched again when it changes while being fetched.
const FETCH_ATTEMPTS: usize = 3;

/// `piitext_reencrypt()` uses a cached key set only if it is younger than this.
const FRESH: Duration = Duration::from_secs(2);

/// Test builds only: a deterministic, per-key-id key so tests notice when
/// the wrong key is used. Release builds never reach this.
pub(crate) fn mock_keyset(key_id: &[u8]) -> Arc<KeySet> {
    let mut key = Zeroizing::new([0x5au8; 32]);
    for (i, b) in key_id.iter().enumerate() {
        key[i % 32] ^= b.rotate_left((i / 32) as u32 % 8).wrapping_add(i as u8);
    }
    key[31] ^= key_id.len() as u8;
    Arc::new(KeySet::new(vec![(1, key)]).expect("one version"))
}

/// The configured endpoint, once its mount is known to be a Transit engine.
fn endpoint() -> Result<Endpoint, PiiError> {
    let ep = config::endpoint()?;
    vault::verify_mount(&ep)?;
    Ok(ep)
}

fn masked() -> Opened {
    shared::incr(Counter::DecryptMasked);
    Opened::Shredded
}

fn kept_changing(key_id: &[u8]) -> PiiError {
    PiiError::Unavailable(format!(
        "key {} changed repeatedly while it was being fetched from Vault",
        vault::key_name(key_id)
    ))
}

/// The key versions to encrypt with, creating the key in Vault if needed
/// (and allowed).
fn keys_for_encryption(key_id: &[u8]) -> Result<Arc<KeySet>, PiiError> {
    if config::is_mock() {
        return Ok(mock_keyset(key_id));
    }
    let ep = endpoint()?;
    let scope = ep.scope();
    for _ in 0..FETCH_ATTEMPTS {
        // A key remembered as absent is created below, so only hits count.
        if let Lookup::Hit { keys, .. } = cache::get(&scope, key_id) {
            return Ok(keys);
        }
        let mut since = shared::generation();
        let keys = match vault::export_keys(&ep, key_id) {
            Ok(keys) => keys,
            Err(PiiError::KeyNotFound(name)) => {
                if !config::auto_create_keys() {
                    return Err(PiiError::KeyNotFound(format!(
                        "{name} (and pii_vault.auto_create_keys is off)"
                    )));
                }
                match vault::create_key(&ep, key_id, true) {
                    Ok(()) => {
                        // Other backends may remember the key as absent.
                        shared::publish_key_change(key_id);
                        since = shared::generation();
                        export_after_create(&ep, key_id)?
                    }
                    // The policy may not allow creating keys (keys provisioned
                    // by another process); the key may still have appeared.
                    Err(PiiError::PermissionDenied(msg)) => match vault::export_keys(&ep, key_id) {
                        Ok(keys) => keys,
                        Err(_) => return Err(PiiError::PermissionDenied(msg)),
                    },
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        };
        let keys = Arc::new(keys);
        if cache::put(&scope, key_id, Some(keys.clone()), since) {
            return Ok(keys);
        }
        // The key was shredded or created again while it was being fetched:
        // these versions may already be deleted, so fetch again.
    }
    Err(kept_changing(key_id))
}

/// A performance standby can briefly lag behind the node that created the key.
fn export_after_create(ep: &Endpoint, key_id: &[u8]) -> Result<KeySet, PiiError> {
    let mut delay = Duration::from_millis(50);
    for _ in 0..3 {
        match vault::export_keys(ep, key_id) {
            Err(PiiError::KeyNotFound(_)) => {
                http::interruptible_sleep(delay);
                delay *= 2;
            }
            other => return other,
        }
    }
    vault::export_keys(ep, key_id)
}

/// Encrypt with the latest version of the key named by `key_id`, creating the
/// key in Vault if needed (and allowed), in the configured key mode.
pub fn seal(plaintext: &str, key_id: &[u8]) -> Result<PiiSealedData, PiiError> {
    vault::validate_key_id(key_id)?;
    match config::key_mode() {
        KeyMode::Export => {
            let keys = keys_for_encryption(key_id)?;
            let (version, key) = keys.latest();
            crypto::seal(plaintext.as_bytes(), key_id, version, key)
        }
        KeyMode::Transit => seal_transit(plaintext, key_id, true),
    }
}

/// Encrypt again under the latest version of the value's own key, for
/// `piitext_reencrypt()`. Unlike `seal`, it does not rely on a cached key set
/// that may predate a rotation, and it never creates the key: a key that is
/// gone means that the value was shredded while it was being re-encrypted.
pub fn reseal(plaintext: &str, key_id: &[u8]) -> Result<PiiSealedData, PiiError> {
    vault::validate_key_id(key_id)?;
    let shredded = |name: String| {
        PiiError::KeyNotFound(format!(
            "{name} (the value was crypto-shredded and cannot be re-encrypted)"
        ))
    };
    if config::key_mode() == KeyMode::Transit {
        return match seal_transit(plaintext, key_id, false) {
            Err(PiiError::KeyNotFound(name)) => Err(shredded(name)),
            other => other,
        };
    }
    if config::is_mock() {
        let keys = mock_keyset(key_id);
        let (version, key) = keys.latest();
        return crypto::seal(plaintext.as_bytes(), key_id, version, key);
    }
    let ep = endpoint()?;
    let scope = ep.scope();
    if let Lookup::Hit { keys, age } = cache::get(&scope, key_id) {
        if age < FRESH {
            let (version, key) = keys.latest();
            return crypto::seal(plaintext.as_bytes(), key_id, version, key);
        }
    }
    for _ in 0..FETCH_ATTEMPTS {
        let since = shared::generation();
        let keys = match vault::export_keys(&ep, key_id) {
            Ok(keys) => Arc::new(keys),
            Err(PiiError::KeyNotFound(name)) => return Err(shredded(name)),
            Err(e) => return Err(e),
        };
        if cache::put(&scope, key_id, Some(keys.clone()), since) {
            let (version, key) = keys.latest();
            return crypto::seal(plaintext.as_bytes(), key_id, version, key);
        }
    }
    Err(kept_changing(key_id))
}

fn seal_transit(
    plaintext: &str,
    key_id: &[u8],
    may_create: bool,
) -> Result<PiiSealedData, PiiError> {
    if plaintext.len() > MAX_TRANSIT_PLAINTEXT_BYTES {
        return Err(PiiError::InvalidArgument(format!(
            "value is {} bytes long; with pii_vault.key_mode = transit values are limited to \
             {MAX_TRANSIT_PLAINTEXT_BYTES} bytes",
            plaintext.len()
        )));
    }
    if config::is_mock() {
        return Err(PiiError::Config(
            "pii_vault.key_mode = transit needs a real Vault server (mock:// is active)".into(),
        ));
    }
    let ep = endpoint()?;
    let aad = crypto::transit_aad(key_id);
    let attempt = || vault::transit_encrypt(&ep, key_id, plaintext.as_bytes(), aad.as_bytes());
    let (version, ciphertext) = match attempt() {
        Ok(done) => done,
        // Encrypting under a missing key is refused with 403 unless the
        // policy grants "create" on transit/encrypt (upsert), which the
        // recommended policy does not; create the key explicitly instead.
        Err(first @ (PiiError::KeyNotFound(_) | PiiError::PermissionDenied(_))) => {
            if !may_create || !config::auto_create_keys() {
                return Err(first);
            }
            match vault::create_key(&ep, key_id, false) {
                // Other backends may remember the key as absent.
                Ok(()) => {
                    shared::publish_key_change(key_id);
                }
                Err(PiiError::PermissionDenied(_)) => return Err(first),
                Err(e) => return Err(e),
            }
            let mut delay = Duration::from_millis(50);
            let mut result = attempt();
            for _ in 0..3 {
                match result {
                    Err(PiiError::KeyNotFound(_)) | Err(PiiError::PermissionDenied(_)) => {
                        http::interruptible_sleep(delay);
                        delay *= 2;
                        result = attempt();
                    }
                    _ => break,
                }
            }
            result?
        }
        Err(e) => return Err(e),
    };
    Ok(PiiSealedData {
        version: FORMAT_V3,
        key_id: key_id.to_vec(),
        key_version: Some(version),
        iv: Vec::new(),
        tag: Vec::new(),
        ciphertext: ciphertext.into_bytes(),
    })
}

fn open_transit(sealed: &PiiSealedData) -> Result<Opened, PiiError> {
    if config::is_mock() {
        return Err(PiiError::Config(
            "format 3 values need a real Vault server (mock:// is active)".into(),
        ));
    }
    let ep = endpoint()?;
    let scope = ep.scope();
    // Transit mode caches nothing but the absence of keys.
    if let Lookup::Absent = cache::get(&scope, &sealed.key_id) {
        return Ok(masked());
    }
    let ciphertext = std::str::from_utf8(&sealed.ciphertext)
        .map_err(|_| PiiError::Corrupted("format 3 ciphertext is not UTF-8".into()))?;
    let aad = crypto::transit_aad(&sealed.key_id);
    let since = shared::generation();
    match vault::transit_decrypt(&ep, &sealed.key_id, ciphertext, aad.as_bytes())? {
        vault::TransitOpened::Plaintext(mut bytes) => {
            let bytes = std::mem::take(&mut *bytes);
            match String::from_utf8(bytes) {
                Ok(text) => Ok(Opened::Plaintext(Zeroizing::new(text))),
                Err(e) => {
                    let _ = Zeroizing::new(e.into_bytes());
                    Err(PiiError::Corrupted(
                        "decrypted value is not valid UTF-8".into(),
                    ))
                }
            }
        }
        vault::TransitOpened::KeyMissing => {
            cache::put(&scope, &sealed.key_id, None, since);
            Ok(masked())
        }
        vault::TransitOpened::Unreadable => Ok(masked()),
    }
}

fn try_open(sealed: &PiiSealedData, keys: &KeySet) -> Result<Option<Zeroizing<String>>, PiiError> {
    let mut candidates: Vec<(u32, &[u8; 32])> = Vec::new();
    match sealed.key_version {
        Some(v) => candidates.extend(keys.get(v).map(|k| (v, k))),
        None => {
            // Format 1 does not record the version; 0.0.x always used
            // version 1 unless the key had been rotated.
            candidates.extend(keys.get(1).map(|k| (1, k)));
            candidates.extend(keys.newest_first().filter(|(v, _)| *v != 1));
        }
    }
    for (version, key) in candidates {
        if let Some(mut bytes) = crypto::open(sealed, version, key) {
            let bytes = std::mem::take(&mut *bytes);
            return match String::from_utf8(bytes) {
                Ok(text) => Ok(Some(Zeroizing::new(text))),
                Err(e) => {
                    let _ = Zeroizing::new(e.into_bytes());
                    Err(PiiError::Corrupted(
                        "decrypted value is not valid UTF-8".into(),
                    ))
                }
            };
        }
    }
    Ok(None)
}

/// Decrypt a sealed value. Only a key that is really gone (the Transit
/// engine reports it missing, or no key version authenticates the value)
/// yields `Shredded`; every other failure is an error, so a Vault outage or
/// a misconfiguration never silently looks like erased data.
pub fn open(sealed: &PiiSealedData) -> Result<Opened, PiiError> {
    if sealed.version == FORMAT_V3 {
        return open_transit(sealed);
    }
    if config::is_mock() {
        return Ok(match try_open(sealed, &mock_keyset(&sealed.key_id))? {
            Some(text) => Opened::Plaintext(text),
            None => Opened::Shredded,
        });
    }
    let ep = endpoint()?;
    let scope = ep.scope();
    match cache::get(&scope, &sealed.key_id) {
        Lookup::Hit { keys, .. } => {
            if let Some(text) = try_open(sealed, &keys)? {
                return Ok(Opened::Plaintext(text));
            }
            // The cached key set can be stale (key rotated or re-created
            // since it was cached): ask Vault before declaring the value
            // shredded.
        }
        Lookup::Absent => return Ok(masked()),
        Lookup::Miss => {}
    }
    let since = shared::generation();
    match vault::export_keys(&ep, &sealed.key_id) {
        Ok(keys) => {
            let keys = Arc::new(keys);
            cache::put(&scope, &sealed.key_id, Some(keys.clone()), since);
            match try_open(sealed, &keys)? {
                Some(text) => Ok(Opened::Plaintext(text)),
                None => Ok(masked()),
            }
        }
        Err(PiiError::KeyNotFound(_)) => {
            cache::put(&scope, &sealed.key_id, None, since);
            Ok(masked())
        }
        Err(e) => Err(e),
    }
}

/// Drops the cached copies of a key when it goes out of scope: this
/// backend's at once, the other backends' through shared memory.
struct ForgetKey<'a>(&'a [u8]);

impl Drop for ForgetKey<'_> {
    fn drop(&mut self) {
        cache::evict(self.0);
        shared::publish_key_change(self.0);
    }
}

/// Crypto-shred the key named by `key_id` and invalidate cached copies in
/// every backend of this cluster (when preloaded).
pub fn shred(key_id: &[u8]) -> Result<bool, PiiError> {
    vault::validate_key_id(key_id)?;
    if config::is_mock() {
        return Err(PiiError::Config(
            "piitext_shred() needs a real Vault server (mock:// is active)".into(),
        ));
    }
    let ep = endpoint()?;
    // Once the deletion is requested, the key may be gone even if no answer
    // arrives (error, timeout, cancellation): invalidate whatever happens.
    let _forget = ForgetKey(key_id);
    vault::delete_key(&ep, key_id)
}
