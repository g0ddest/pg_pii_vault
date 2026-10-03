//! HashiCorp Vault Transit API calls used by the extension.
//!
//! Keys are Transit keys of type `aes256-gcm96` named after the hex encoding
//! of the key id. With `key_mode = export` they are created exportable, the
//! raw key material is exported and AES-256-GCM runs locally; with
//! `key_mode = transit` they are not exportable and Vault encrypts and
//! decrypts.
//!
//! A value is reported as crypto-shredded only when the Transit engine itself
//! says that the key does not exist, in exactly the words Vault uses. Before
//! such an answer is trusted, `verify_mount` makes sure that the mount is a
//! Transit engine: other engines answer requests for missing keys the same
//! way. A proxy's error page, a redirect or any other failure is an error: an
//! outage or a misconfiguration must never look like erased data.

use crate::cache::KeySet;
use crate::config::{self, Endpoint};
use crate::contents::transit_ciphertext_version;
use crate::error::PiiError;
use crate::http::{self, Method, Request, Response, TransportError};
use crate::shared::{self, Counter};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use pgrx::prelude::*;
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Longest accepted key id, in bytes (the Vault key name is twice as long).
pub const MAX_KEY_ID_LEN: usize = 128;

pub fn validate_key_id(key_id: &[u8]) -> Result<(), PiiError> {
    if key_id.is_empty() {
        return Err(PiiError::InvalidArgument("key id must not be empty".into()));
    }
    if key_id.len() > MAX_KEY_ID_LEN {
        return Err(PiiError::InvalidArgument(format!(
            "key id is {} bytes long; the maximum is {MAX_KEY_ID_LEN}",
            key_id.len()
        )));
    }
    Ok(())
}

pub fn key_name(key_id: &[u8]) -> String {
    hex::encode(key_id)
}

fn backoff(attempt: u32) -> Duration {
    let base = 100u64.saturating_mul(1 << attempt.saturating_sub(1).min(4));
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()) % 50)
        .unwrap_or(0);
    Duration::from_millis(base.min(2_000) + jitter)
}

/// Send one authenticated request, retrying transient failures (connection
/// errors, HTTP 412, 429 and 5xx) up to `pii_vault.max_retries` times.
/// Timeouts are not retried: the wait is already bounded by
/// `pii_vault.timeout_ms` and a retry would multiply it. Returns the response
/// and the number of attempts it took.
fn send_counted(
    ep: &Endpoint,
    method: Method,
    path: &str,
    body: Option<&[u8]>,
) -> Result<(Response, u32), PiiError> {
    let token = config::vault_token()?;
    let url = format!("{}/v1/{}", ep.base_url, path);
    let retries = config::max_retries();
    let mut attempt = 0;
    loop {
        shared::incr(Counter::VaultRequests);
        let started = Instant::now();
        let outcome = http::execute(Request {
            method,
            url: url.clone(),
            token: Some(token.clone()),
            namespace: ep.namespace.clone(),
            json_body: body.map(|b| Zeroizing::new(b.to_vec())),
        })?;
        let elapsed = started.elapsed();
        let (failed, transient) = match &outcome {
            Ok(resp) => {
                debug1!(
                    "pg_pii_vault: {} /v1/{} -> HTTP {} in {} ms",
                    method.as_str(),
                    path,
                    resp.status,
                    elapsed.as_millis()
                );
                // 412: a performance standby has not caught up yet.
                let server_error = matches!(resp.status, 412 | 429 | 500..=599);
                (server_error, server_error)
            }
            Err(e) => {
                debug1!(
                    "pg_pii_vault: {} /v1/{} failed after {} ms: {}",
                    method.as_str(),
                    path,
                    elapsed.as_millis(),
                    e
                );
                (true, matches!(e, TransportError::Connect(_)))
            }
        };
        if failed {
            shared::incr(Counter::VaultErrors);
        }
        if transient && attempt < retries {
            attempt += 1;
            http::interruptible_sleep(backoff(attempt));
            continue;
        }
        let attempts = attempt + 1;
        return match outcome {
            Ok(resp) => Ok((resp, attempts)),
            Err(TransportError::Timeout) => Err(PiiError::Unavailable(format!(
                "{} {} timed out after {} ms (pii_vault.timeout_ms)",
                method.as_str(),
                url,
                config::transport().timeout.as_millis()
            ))),
            Err(e) => Err(PiiError::Unavailable(format!(
                "{} {}: {e}",
                method.as_str(),
                url
            ))),
        };
    }
}

fn send(
    ep: &Endpoint,
    method: Method,
    path: &str,
    body: Option<&[u8]>,
) -> Result<Response, PiiError> {
    send_counted(ep, method, path, body).map(|(resp, _)| resp)
}

/// Messages of the Transit engine that the extension acts on.
const MSG_KEY_NOT_FOUND: &str = "encryption key not found";
const MSG_AUTH_FAILED: &str = "cipher: message authentication failed";
const MSG_VERSION_TOO_OLD: &str =
    "ciphertext or signature version is disallowed by policy (too old)";
const MSG_VERSION_TOO_NEW: &str = "invalid ciphertext: version is too new";
const MSG_NOT_EXPORTABLE: &str = "private key material is not exportable";

fn msg_no_such_key(name: &str) -> String {
    format!("no existing key named {name} could be found")
}

fn msg_delete_not_found(name: &str) -> String {
    format!("error deleting policy {name}: could not delete key; not found")
}

/// The messages of a Vault error response: a JSON object holding an `errors`
/// list of strings and nothing else. `None` for any other body (a proxy's
/// error page, another service), which is never read as an answer of the
/// Transit engine.
fn vault_errors(resp: &Response) -> Option<Vec<String>> {
    let value: serde_json::Value = serde_json::from_slice(&resp.body).ok()?;
    let object = value.as_object()?;
    if object.len() != 1 {
        return None;
    }
    object
        .get("errors")?
        .as_array()?
        .iter()
        .map(|e| e.as_str().map(str::to_owned))
        .collect()
}

/// Whether the response is Vault's error response with exactly `message`.
fn vault_says(resp: &Response, status: u16, message: &str) -> bool {
    resp.status == status
        && vault_errors(resp).is_some_and(|errors| errors.len() == 1 && errors[0] == message)
}

/// Vault's answer to a read of something that does not exist: HTTP 404 with
/// an empty error list. Trusted only once the mount is known to be a Transit
/// engine (`verify_mount`): other engines answer the same way.
fn is_absent(resp: &Response) -> bool {
    resp.status == 404 && vault_errors(resp).is_some_and(|errors| errors.is_empty())
}

/// Longest Vault error text copied into an error message.
const MAX_ERROR_TEXT_CHARS: usize = 300;

/// The error text of a response on one line and without control characters,
/// for error messages and the server log.
fn error_text(resp: &Response) -> String {
    let raw = match vault_errors(resp) {
        Some(errors) if !errors.is_empty() => errors.join("; "),
        _ => String::from_utf8_lossy(&resp.body).into_owned(),
    };
    let printable: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let line = printable.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.is_empty() {
        "(empty response)".into()
    } else {
        line.chars().take(MAX_ERROR_TEXT_CHARS).collect()
    }
}

fn unexpected(method: Method, path: &str, resp: &Response) -> PiiError {
    let what = format!("{} /v1/{}", method.as_str(), path);
    let detail = error_text(resp);
    match resp.status {
        401 | 403 => PiiError::PermissionDenied(format!(
            "{what} returned HTTP {}: {detail}",
            resp.status
        )),
        404 if detail.contains("no handler for route") => PiiError::Config(format!(
            "Vault has no secrets engine at the path of {what}; check pii_vault.mount and pii_vault.namespace"
        )),
        404 => PiiError::Vault(format!(
            "{what} returned HTTP 404 that does not come from the Transit secrets engine ({detail}); check pii_vault.url and pii_vault.mount"
        )),
        412 | 429 | 500..=599 => {
            PiiError::Unavailable(format!("{what} returned HTTP {}: {detail}", resp.status))
        }
        300..=399 => PiiError::Vault(format!(
            "{what} returned a redirect (HTTP {}); redirects are not followed, point pii_vault.url at the active Vault node or a load balancer",
            resp.status
        )),
        s => PiiError::Vault(format!("{what} returned HTTP {s}: {detail}")),
    }
}

/// The secrets engine at `pii_vault.mount`, as Vault describes it.
pub struct MountInfo {
    pub engine: String,
    pub path: String,
    pub accessor: String,
}

#[derive(Deserialize)]
struct MountResponse {
    data: MountData,
}

#[derive(Deserialize)]
struct MountData {
    #[serde(rename = "type")]
    engine: String,
    path: String,
    #[serde(default)]
    accessor: String,
}

/// Ask Vault which secrets engine serves `pii_vault.mount`. The endpoint
/// answers any token that may use some path of that mount.
pub fn mount_info(ep: &Endpoint) -> Result<MountInfo, PiiError> {
    let path = format!("sys/internal/ui/mounts/{}", ep.mount);
    let resp = send(ep, Method::Get, &path, None)?;
    if resp.status == 403 {
        return Err(PiiError::PermissionDenied(format!(
            "the token may not use pii_vault.mount \"{}\": no secrets engine is mounted there, or the token's policy does not cover it ({})",
            ep.mount,
            error_text(&resp)
        )));
    }
    if resp.status != 200 {
        return Err(unexpected(Method::Get, &path, &resp));
    }
    let parsed: MountResponse = serde_json::from_slice(&resp.body).map_err(|e| {
        PiiError::Vault(format!(
            "cannot parse Vault's description of the mount \"{}\": {e}",
            ep.mount
        ))
    })?;
    Ok(MountInfo {
        engine: parsed.data.engine,
        path: parsed.data.path,
        accessor: parsed.data.accessor,
    })
}

/// Check that `pii_vault.mount` is the mount point of a Transit engine, and
/// the expected one if `pii_vault.mount_accessor` is set.
pub fn check_mount(ep: &Endpoint, info: &MountInfo) -> Result<(), PiiError> {
    let mounted_at = info.path.trim_matches('/');
    // A namespace may be given as a path prefix ("ns1/transit").
    if ep.mount != mounted_at && !ep.mount.ends_with(&format!("/{mounted_at}")) {
        return Err(PiiError::Config(format!(
            "pii_vault.mount \"{}\" is not the mount point of a secrets engine: it lies inside the {} engine mounted at \"{}\"",
            ep.mount, info.engine, info.path
        )));
    }
    if info.engine != "transit" {
        return Err(PiiError::Config(format!(
            "pii_vault.mount \"{}\" is a {} secrets engine, not Transit",
            ep.mount, info.engine
        )));
    }
    if let Some(expected) = &ep.accessor {
        if info.accessor != *expected {
            return Err(PiiError::Config(format!(
                "the Transit mount \"{}\" has accessor {}, but pii_vault.mount_accessor is {expected}: this is not the expected key space",
                ep.mount, info.accessor
            )));
        }
    }
    Ok(())
}

/// How long a backend trusts an earlier mount check.
const MOUNT_RECHECK: Duration = Duration::from_secs(300);

thread_local! {
    /// The endpoint whose mount was last verified, and when.
    static VERIFIED_MOUNT: RefCell<Option<(Endpoint, Instant)>> = const { RefCell::new(None) };
}

/// Make sure that `pii_vault.mount` is a Transit engine before any of its
/// answers is trusted or any key is created or deleted there. Checked once
/// per backend and endpoint, and again every five minutes.
pub fn verify_mount(ep: &Endpoint) -> Result<(), PiiError> {
    let verified = VERIFIED_MOUNT.with(|v| {
        matches!(&*v.borrow(), Some((checked, at)) if checked == ep && at.elapsed() < MOUNT_RECHECK)
    });
    if verified {
        return Ok(());
    }
    let info = mount_info(ep)?;
    check_mount(ep, &info)?;
    VERIFIED_MOUNT.with(|v| *v.borrow_mut() = Some((ep.clone(), Instant::now())));
    Ok(())
}

#[derive(Deserialize)]
struct ExportResponse {
    data: ExportData,
}

#[derive(Deserialize)]
struct ExportData {
    keys: HashMap<String, String>,
    #[serde(default, rename = "type")]
    key_type: Option<String>,
}

const KEY_TYPE: &str = "aes256-gcm96";

fn parse_export(body: &[u8]) -> Result<KeySet, PiiError> {
    let mut parsed: ExportResponse = serde_json::from_slice(body)
        .map_err(|e| PiiError::Vault(format!("cannot parse key export response: {e}")))?;
    if let Some(key_type) = parsed.data.key_type.as_deref().filter(|t| *t != KEY_TYPE) {
        let message = format!("the key has type {key_type}; pg_pii_vault needs {KEY_TYPE} keys");
        for encoded in parsed.data.keys.values_mut() {
            encoded.zeroize();
        }
        return Err(PiiError::Vault(message));
    }
    let mut encoded: Vec<(u32, String)> = Vec::with_capacity(parsed.data.keys.len());
    for (version, b64) in parsed.data.keys {
        match version.parse::<u32>() {
            Ok(v) => encoded.push((v, b64)),
            Err(_) => {
                let mut b64 = b64;
                b64.zeroize();
                for (_, s) in encoded.iter_mut() {
                    s.zeroize();
                }
                return Err(PiiError::Vault(format!(
                    "key export response has a non-numeric version \"{version}\""
                )));
            }
        }
    }
    encoded.sort_by_key(|(v, _)| *v);

    // Push zeroed slots first and decode into them in place, so key bytes are
    // never moved (and left behind) on the way into the KeySet.
    let mut versions = Vec::with_capacity(encoded.len());
    let mut failure = None;
    for (version, b64) in encoded.iter_mut() {
        if failure.is_none() {
            match STANDARD.decode(b64.as_bytes()) {
                Ok(raw) => {
                    let raw = Zeroizing::new(raw);
                    if raw.len() == 32 {
                        versions.push((*version, Zeroizing::new([0u8; 32])));
                        if let Some((_, slot)) = versions.last_mut() {
                            slot.copy_from_slice(&raw);
                        }
                    } else {
                        failure = Some(PiiError::Vault(format!(
                            "key version {version} is {} bytes long; expected a 32-byte aes256-gcm96 key",
                            raw.len()
                        )));
                    }
                }
                Err(e) => {
                    failure = Some(PiiError::Vault(format!(
                        "key version {version} is not valid base64: {e}"
                    )))
                }
            }
        }
        b64.zeroize();
    }
    if let Some(e) = failure {
        return Err(e);
    }
    KeySet::new(versions)
        .ok_or_else(|| PiiError::Vault("key export response contains no key versions".into()))
}

/// Export every version of the key that Vault still allows to decrypt with.
/// A missing key (never created, or deleted by crypto-shredding) is
/// `PiiError::KeyNotFound`.
pub fn export_keys(ep: &Endpoint, key_id: &[u8]) -> Result<KeySet, PiiError> {
    let name = key_name(key_id);
    let path = format!("{}/export/encryption-key/{}", ep.mount, name);
    let resp = send(ep, Method::Get, &path, None)?;
    match resp.status {
        200 => parse_export(&resp.body),
        404 if is_absent(&resp) => Err(PiiError::KeyNotFound(name)),
        _ if vault_says(&resp, 400, MSG_NOT_EXPORTABLE) => Err(PiiError::Vault(format!(
            "key {name} exists but is not exportable (created with pii_vault.key_mode = transit, \
             or outside pg_pii_vault); use key_mode = transit for it or set exportable=true on the key in Vault"
        ))),
        _ => Err(unexpected(Method::Get, &path, &resp)),
    }
}

/// Create an `aes256-gcm96` key (exportable for `key_mode = export`, not
/// exportable for `transit`). Vault treats creating an existing key as a
/// no-op, so concurrent creation by several backends is harmless.
pub fn create_key(ep: &Endpoint, key_id: &[u8], exportable: bool) -> Result<(), PiiError> {
    let path = format!("{}/keys/{}", ep.mount, key_name(key_id));
    let body: &[u8] = if exportable {
        br#"{"type":"aes256-gcm96","exportable":true}"#
    } else {
        br#"{"type":"aes256-gcm96"}"#
    };
    let resp = send(ep, Method::Post, &path, Some(body))?;
    match resp.status {
        200 | 204 => {
            shared::incr(Counter::KeysCreated);
            Ok(())
        }
        _ => Err(unexpected(Method::Post, &path, &resp)),
    }
}

#[derive(Deserialize)]
struct EncryptResponse {
    data: EncryptData,
}

#[derive(Deserialize)]
struct EncryptData {
    ciphertext: String,
    #[serde(default)]
    key_version: Option<u32>,
}

#[derive(Deserialize)]
struct DecryptResponse {
    data: DecryptData,
}

#[derive(Deserialize)]
struct DecryptData {
    plaintext: String,
}

/// `key_mode = transit`: Vault encrypts `plaintext` with the latest version
/// of the key. Returns the key version and the Transit ciphertext.
/// A key that does not exist yields `KeyNotFound`, or `PermissionDenied`
/// when the policy cannot see missing keys (encrypt only creates keys with
/// the "create" capability, which the recommended policy does not grant).
pub fn transit_encrypt(
    ep: &Endpoint,
    key_id: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(u32, String), PiiError> {
    let name = key_name(key_id);
    let path = format!("{}/encrypt/{}", ep.mount, name);
    // Built by hand into wiped memory: base64 needs no JSON escaping.
    let mut body = Zeroizing::new(String::with_capacity(plaintext.len() * 4 / 3 + 64));
    body.push_str(r#"{"plaintext":""#);
    STANDARD.encode_string(plaintext, &mut body);
    body.push_str(r#"","associated_data":""#);
    STANDARD.encode_string(aad, &mut body);
    body.push_str(r#""}"#);
    let resp = send(ep, Method::Post, &path, Some(body.as_bytes()))?;
    match resp.status {
        200 => {
            let parsed: EncryptResponse = serde_json::from_slice(&resp.body)
                .map_err(|e| PiiError::Vault(format!("cannot parse encrypt response: {e}")))?;
            let version = transit_ciphertext_version(&parsed.data.ciphertext).ok_or_else(|| {
                PiiError::Vault("encrypt response does not contain a Transit ciphertext".into())
            })?;
            if parsed.data.key_version.is_some_and(|v| v != version) {
                return Err(PiiError::Vault(format!(
                    "encrypt response reports key version {} for a ciphertext of version {version}",
                    parsed.data.key_version.unwrap_or(0)
                )));
            }
            Ok((version, parsed.data.ciphertext))
        }
        _ if vault_says(&resp, 400, MSG_KEY_NOT_FOUND) => Err(PiiError::KeyNotFound(name)),
        _ => Err(unexpected(Method::Post, &path, &resp)),
    }
}

pub enum TransitOpened {
    Plaintext(Zeroizing<Vec<u8>>),
    /// The key does not exist: the value was crypto-shredded.
    KeyMissing,
    /// The key exists but cannot decrypt the value: the value's key version
    /// was retired, the key was created again after a shred, or the value was
    /// not made for this key and context.
    Unreadable,
}

/// `key_mode = transit`: Vault decrypts a format 3 value.
pub fn transit_decrypt(
    ep: &Endpoint,
    key_id: &[u8],
    ciphertext: &str,
    aad: &[u8],
) -> Result<TransitOpened, PiiError> {
    let path = format!("{}/decrypt/{}", ep.mount, key_name(key_id));
    let body = serde_json::to_vec(&serde_json::json!({
        "ciphertext": ciphertext,
        "associated_data": STANDARD.encode(aad),
    }))
    .map_err(|e| PiiError::Vault(format!("cannot build the decrypt request: {e}")))?;
    let resp = send(ep, Method::Post, &path, Some(&body))?;
    if resp.status == 200 {
        let parsed: DecryptResponse = serde_json::from_slice(&resp.body)
            .map_err(|e| PiiError::Vault(format!("cannot parse decrypt response: {e}")))?;
        let mut encoded = parsed.data.plaintext;
        let decoded = STANDARD.decode(encoded.as_bytes());
        encoded.zeroize();
        return decoded
            .map(|bytes| TransitOpened::Plaintext(Zeroizing::new(bytes)))
            .map_err(|e| PiiError::Vault(format!("decrypt response is not valid base64: {e}")));
    }
    if vault_says(&resp, 400, MSG_KEY_NOT_FOUND) {
        return Ok(TransitOpened::KeyMissing);
    }
    if [MSG_AUTH_FAILED, MSG_VERSION_TOO_OLD, MSG_VERSION_TOO_NEW]
        .iter()
        .any(|message| vault_says(&resp, 400, message))
    {
        return Ok(TransitOpened::Unreadable);
    }
    if resp.status == 400
        && vault_errors(&resp)
            .is_some_and(|errors| errors.len() == 1 && errors[0].starts_with("invalid ciphertext"))
    {
        return Err(PiiError::Corrupted(format!(
            "Vault rejected the ciphertext: {}",
            error_text(&resp)
        )));
    }
    Err(unexpected(Method::Post, &path, &resp))
}

/// Crypto-shred: allow deletion of the key and delete it. Returns false when
/// the key did not exist. This is not transactional: once it returns true
/// the key is gone even if the calling transaction rolls back.
pub fn delete_key(ep: &Endpoint, key_id: &[u8]) -> Result<bool, PiiError> {
    let name = key_name(key_id);
    let config_path = format!("{}/keys/{}/config", ep.mount, name);
    let resp = send(
        ep,
        Method::Post,
        &config_path,
        Some(br#"{"deletion_allowed":true}"#),
    )?;
    match resp.status {
        200 | 204 => {}
        _ if vault_says(&resp, 400, &msg_no_such_key(&name)) => return Ok(false),
        _ => return Err(unexpected(Method::Post, &config_path, &resp)),
    }
    let key_path = format!("{}/keys/{}", ep.mount, name);
    let (resp, attempts) = send_counted(ep, Method::Delete, &key_path, None)?;
    match resp.status {
        200 | 204 => {
            shared::incr(Counter::KeysShredded);
            Ok(true)
        }
        // Gone since the first request: deleted by someone else, or by an
        // earlier attempt of this DELETE whose answer was lost.
        _ if vault_says(&resp, 400, &msg_delete_not_found(&name)) => {
            if attempts > 1 {
                shared::incr(Counter::KeysShredded);
            }
            Ok(attempts > 1)
        }
        _ => Err(unexpected(Method::Delete, &key_path, &resp)),
    }
}

/// One line of `piitext_vault_check()`.
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    /// False for advisory lines: optional capabilities and hardening hints.
    pub required: bool,
    pub detail: String,
}

impl Check {
    fn required(name: &'static str, ok: bool, detail: String) -> Check {
        Check {
            name,
            ok,
            required: true,
            detail,
        }
    }

    fn advisory(name: &'static str, ok: bool, detail: String) -> Check {
        Check {
            name,
            ok,
            required: false,
            detail,
        }
    }
}

#[derive(Deserialize)]
struct HealthBody {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    sealed: Option<bool>,
    #[serde(default)]
    standby: Option<bool>,
}

#[derive(Deserialize)]
struct LookupSelf {
    data: LookupSelfData,
}

#[derive(Deserialize)]
struct LookupSelfData {
    #[serde(default)]
    ttl: Option<i64>,
    #[serde(default)]
    renewable: Option<bool>,
    #[serde(default)]
    policies: Vec<String>,
}

#[derive(Deserialize)]
struct CapabilitiesSelf {
    #[serde(flatten)]
    paths: HashMap<String, serde_json::Value>,
}

/// Key name used by the diagnostic probes. Real key names are hex strings,
/// so it can never name a key the extension uses.
const PROBE_KEY: &str = "pg-pii-vault-probe";

/// Exercise the request the extension depends on most (key export, or
/// decryption in transit mode) for a key that does not exist. Succeeds only
/// if the token is accepted and its policy allows the request; needs none of
/// the optional policy rules.
fn probe_key_access(ep: &Endpoint, transit: bool) -> Check {
    let (method, path, body): (Method, String, Option<&[u8]>) = if transit {
        (
            Method::Post,
            format!("{}/decrypt/{PROBE_KEY}", ep.mount),
            Some(br#"{"ciphertext":"vault:v1:AAAA"}"#),
        )
    } else {
        (
            Method::Get,
            format!("{}/export/encryption-key/{PROBE_KEY}", ep.mount),
            None,
        )
    };
    let what = if transit { "decryption" } else { "key export" };
    match send(ep, method, &path, body) {
        // The probe key does not exist: exactly the answer a working setup gives.
        Ok(resp) if is_absent(&resp) || vault_says(&resp, 400, MSG_KEY_NOT_FOUND) => {
            Check::required(
                "key_access",
                true,
                format!(
                    "the Transit engine at {}/ accepts {what} requests",
                    ep.mount
                ),
            )
        }
        Ok(resp) if resp.status == 200 || (resp.status == 400 && vault_errors(&resp).is_some()) => {
            Check::required(
                "key_access",
                true,
                format!(
                    "the Transit engine at {}/ accepts {what} requests (a key named {PROBE_KEY} exists)",
                    ep.mount
                ),
            )
        }
        Ok(resp) => Check::required(
            "key_access",
            false,
            unexpected(method, &path, &resp).to_string(),
        ),
        Err(e) => Check::required("key_access", false, e.to_string()),
    }
}

/// Diagnose connectivity, the mount, token validity and policy capabilities
/// without touching any real key.
pub fn check(ep: &Endpoint) -> Vec<Check> {
    let mut out = Vec::new();
    let health_path = "sys/health?standbyok=true&perfstandbyok=true";
    match http::execute(Request {
        method: Method::Get,
        url: format!("{}/v1/{}", ep.base_url, health_path),
        token: None,
        namespace: None,
        json_body: None,
    }) {
        Ok(Ok(resp)) => {
            let health: Option<HealthBody> = serde_json::from_slice(&resp.body).ok();
            let sealed = health.as_ref().and_then(|h| h.sealed).unwrap_or(false);
            out.push(Check::required(
                "vault_reachable",
                resp.status == 200 && !sealed,
                format!(
                    "HTTP {}; version {}; sealed={}; standby={}",
                    resp.status,
                    health
                        .as_ref()
                        .and_then(|h| h.version.clone())
                        .unwrap_or_else(|| "?".into()),
                    sealed,
                    health.as_ref().and_then(|h| h.standby).unwrap_or(false)
                ),
            ));
        }
        Ok(Err(e)) => {
            out.push(Check::required("vault_reachable", false, e.to_string()));
            return out;
        }
        Err(e) => {
            out.push(Check::required("vault_reachable", false, e.to_string()));
            return out;
        }
    }

    let transit = config::key_mode() == config::KeyMode::Transit;
    match mount_info(ep).and_then(|info| check_mount(ep, &info).map(|()| info)) {
        Ok(info) => {
            out.push(Check::required(
                "transit_mount",
                true,
                format!(
                    "{}/ is a Transit secrets engine (accessor {})",
                    ep.mount, info.accessor
                ),
            ));
            out.push(probe_key_access(ep, transit));
        }
        Err(e) => {
            out.push(Check::required("transit_mount", false, e.to_string()));
            out.push(Check::required(
                "key_access",
                false,
                "not checked: pii_vault.mount is not a usable Transit engine".into(),
            ));
        }
    }

    match send(ep, Method::Get, "auth/token/lookup-self", None) {
        Ok(resp) if resp.status == 200 => {
            let info: Option<LookupSelf> = serde_json::from_slice(&resp.body).ok();
            let (ttl, renewable, policies) = info
                .map(|i| (i.data.ttl, i.data.renewable, i.data.policies))
                .unwrap_or((None, None, Vec::new()));
            let ttl_text = match ttl {
                Some(0) => "never expires".to_string(),
                Some(t) => format!("expires in {t} s unless renewed"),
                None => "ttl unknown".to_string(),
            };
            out.push(Check::required(
                "token_valid",
                true,
                format!(
                    "{ttl_text}; renewable={}; policies={}",
                    renewable.unwrap_or(false),
                    policies.join(",")
                ),
            ));
        }
        // A valid token whose policy lacks the optional lookup-self rule.
        Ok(resp) if resp.status == 403 && !error_text(&resp).contains("invalid token") => {
            out.push(Check::advisory(
                "token_valid",
                false,
                format!(
                    "cannot inspect the token (HTTP 403: {}); optional: allow read on auth/token/lookup-self",
                    error_text(&resp)
                ),
            ))
        }
        Ok(resp) => out.push(Check::required(
            "token_valid",
            false,
            unexpected(Method::Get, "auth/token/lookup-self", &resp).to_string(),
        )),
        Err(e) => out.push(Check::required("token_valid", false, e.to_string())),
    }

    // Capabilities the configured key mode needs, asked for a dummy key name.
    let export_path = format!("{}/export/encryption-key/{PROBE_KEY}", ep.mount);
    let key_path = format!("{}/keys/{PROBE_KEY}", ep.mount);
    let config_path = format!("{}/keys/{PROBE_KEY}/config", ep.mount);
    let mut needed: Vec<(&'static str, String, &'static str)> = Vec::new();
    if transit {
        needed.push((
            "policy_encrypt",
            format!("{}/encrypt/{PROBE_KEY}", ep.mount),
            "update",
        ));
        needed.push((
            "policy_decrypt",
            format!("{}/decrypt/{PROBE_KEY}", ep.mount),
            "update",
        ));
    } else {
        needed.push(("policy_export", export_path.clone(), "read"));
    }

    let mut paths: Vec<String> = needed.iter().map(|r| r.1.clone()).collect();
    paths.extend([export_path.clone(), key_path.clone(), config_path.clone()]);
    paths.sort();
    paths.dedup();
    let body = serde_json::to_vec(&serde_json::json!({ "paths": paths })).unwrap_or_default();
    let caps: HashMap<String, serde_json::Value> = match send(
        ep,
        Method::Post,
        "sys/capabilities-self",
        Some(&body),
    ) {
        Ok(resp) if resp.status == 200 => serde_json::from_slice::<CapabilitiesSelf>(&resp.body)
            .map(|c| c.paths)
            .unwrap_or_default(),
        Ok(resp) => {
            out.push(Check::advisory(
                    "policy",
                    false,
                    format!(
                        "cannot inspect the token's capabilities (HTTP {}: {}); optional: allow update on sys/capabilities-self",
                        resp.status,
                        error_text(&resp)
                    ),
                ));
            return out;
        }
        Err(e) => {
            out.push(Check::advisory("policy", false, e.to_string()));
            return out;
        }
    };
    let granted = |path: &str| -> Vec<String> {
        caps.get(path)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let has =
        |path: &str, capability: &str| granted(path).iter().any(|g| g == capability || g == "root");
    for (name, path, capability) in &needed {
        let ok = has(path, capability);
        let mut detail = format!("{path}: [{}]", granted(path).join(","));
        if !ok {
            detail.push_str(&format!("; missing: {capability}"));
        }
        out.push(Check::required(name, ok, detail));
    }

    // Creating a Transit key is an "update": the path has no existence
    // check, so a "create" grant alone is not enough.
    let can_create = has(&key_path, "update");
    let create_detail = format!("{key_path}: [{}]", granted(&key_path).join(","));
    out.push(if config::auto_create_keys() {
        Check::required(
            "policy_create_keys",
            can_create,
            if can_create {
                create_detail
            } else {
                format!("{create_detail}; missing: update (or set pii_vault.auto_create_keys = off and provision keys yourself)")
            },
        )
    } else {
        Check::advisory(
            "policy_create_keys",
            can_create,
            format!("{create_detail}; not needed: pii_vault.auto_create_keys is off"),
        )
    });

    let can_shred = has(&config_path, "update") && has(&key_path, "delete");
    out.push(Check::advisory(
        "policy_shred",
        can_shred,
        format!(
            "{config_path}: [{}]; {key_path}: [{}]{}",
            granted(&config_path).join(","),
            granted(&key_path).join(","),
            if can_shred {
                ""
            } else {
                "; piitext_shred() will be refused (only needed if keys are shredded from the database)"
            }
        ),
    ));
    if transit {
        let can_export = has(&export_path, "read");
        out.push(Check::advisory(
            "policy_no_export",
            !can_export,
            if can_export {
                format!(
                    "{export_path}: [{}]; the token can export key material although key_mode = transit",
                    granted(&export_path).join(",")
                )
            } else {
                "the token cannot export key material".into()
            },
        ));
    }
    out
}
