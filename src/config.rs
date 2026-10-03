//! Configuration parameters (GUCs).
//!
//! Every parameter that influences where keys come from is `SUSET`: only a
//! superuser (or `ALTER ROLE/DATABASE ... SET` issued by one) can change it.
//! Otherwise any role could point `pii_vault.url` at its own server and
//! receive the Vault token, or make the extension encrypt with keys it chose.

use crate::error::PiiError;
use pgrx::guc::{GucContext, GucFlags, GucRegistry, GucSetting};
use pgrx::prelude::*;
use std::ffi::{c_char, c_void, CStr, CString};
use std::time::Duration;
use zeroize::Zeroizing;

pub static URL: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static TOKEN: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static TOKEN_FILE: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static MOUNT: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(Some(c"transit"));
pub static NAMESPACE: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static MOUNT_ACCESSOR: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static CA_FILE: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static CLIENT_CERT_FILE: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static CLIENT_KEY_FILE: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
pub static TIMEOUT_MS: GucSetting<i32> = GucSetting::<i32>::new(5_000);
pub static MAX_RETRIES: GucSetting<i32> = GucSetting::<i32>::new(2);
pub static CACHE_TTL_SEC: GucSetting<i32> = GucSetting::<i32>::new(300);
pub static CACHE_MAX_ENTRIES: GucSetting<i32> = GucSetting::<i32>::new(10_000);
pub static AUTO_CREATE_KEYS: GucSetting<bool> = GucSetting::<bool>::new(true);
pub static ALLOW_STAGING: GucSetting<bool> = GucSetting::<bool>::new(true);
pub static ALLOW_INSECURE_HTTP: GucSetting<bool> = GucSetting::<bool>::new(false);
pub static KEY_MODE: GucSetting<KeyMode> = GucSetting::<KeyMode>::new(KeyMode::Export);

/// How new values are encrypted. Existing values are always readable,
/// whatever the current mode: the stored format records how they were made.
#[derive(PostgresGucEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyMode {
    /// Export the key from Vault and encrypt locally (format 2); keys are
    /// cached per backend.
    #[name = c"export"]
    Export,
    /// Let Vault encrypt and decrypt (format 3); keys never leave Vault and
    /// every decryption is a Vault request.
    #[name = c"transit"]
    Transit,
}

pub fn register() {
    // SAFETY: the check hook is a #[pg_guard] function that only reads its input.
    unsafe {
        GucRegistry::define_string_guc_with_hooks(
            c"pii_vault.url",
            c"Base URL of the HashiCorp Vault server, e.g. https://vault.example.com:8200.",
            c"Only superusers can change it.",
            &URL,
            GucContext::Suset,
            GucFlags::default(),
            Some(check_url),
            None,
            None,
        );
    }
    GucRegistry::define_string_guc(
        c"pii_vault.token",
        c"Vault token used to fetch and create keys.",
        c"Visible only to superusers. Prefer pii_vault.token_file so the token never appears in configuration catalogs or logs.",
        &TOKEN,
        GucContext::Suset,
        GucFlags::SUPERUSER_ONLY,
    );
    GucRegistry::define_string_guc(
        c"pii_vault.token_file",
        c"File containing the Vault token (e.g. a Vault Agent token sink).",
        c"Read on every Vault request, so token rotation needs no reload. Used when pii_vault.token is empty.",
        &TOKEN_FILE,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_string_guc(
        c"pii_vault.mount",
        c"Mount path of the Vault Transit secrets engine.",
        c"",
        &MOUNT,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_string_guc(
        c"pii_vault.mount_accessor",
        c"Expected accessor of the Transit mount (for example transit_4a1b2c3d).",
        c"When set, the extension refuses to use a mount with another accessor, so that pointing it at another Vault, namespace or mount raises an error instead of reading every value as '****'.",
        &MOUNT_ACCESSOR,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_string_guc(
        c"pii_vault.namespace",
        c"Vault Enterprise / HCP Vault namespace (sent as X-Vault-Namespace).",
        c"",
        &NAMESPACE,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_string_guc(
        c"pii_vault.ca_file",
        c"PEM file with the CA certificates trusted for the Vault TLS connection.",
        c"When empty the operating system trust store is used.",
        &CA_FILE,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_string_guc(
        c"pii_vault.client_cert_file",
        c"PEM client certificate (chain) for mutual TLS with Vault.",
        c"Requires pii_vault.client_key_file.",
        &CLIENT_CERT_FILE,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_string_guc(
        c"pii_vault.client_key_file",
        c"PEM private key for pii_vault.client_cert_file.",
        c"",
        &CLIENT_KEY_FILE,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        c"pii_vault.timeout_ms",
        c"Timeout for one Vault HTTP request, in milliseconds.",
        c"",
        &TIMEOUT_MS,
        100,
        600_000,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        c"pii_vault.max_retries",
        c"Retries for transient Vault failures (connection errors, HTTP 429/5xx).",
        c"",
        &MAX_RETRIES,
        0,
        10,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        c"pii_vault.cache_ttl_sec",
        c"How long a backend keeps a key fetched from Vault, in seconds. 0 disables caching.",
        c"Bounds how long a backend of another cluster (or of this one, if the library is not preloaded) can still decrypt after the key was shredded.",
        &CACHE_TTL_SEC,
        0,
        86_400,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        c"pii_vault.cache_max_entries",
        c"Maximum number of keys cached per backend. 0 disables caching.",
        c"",
        &CACHE_MAX_ENTRIES,
        0,
        10_000_000,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_bool_guc(
        c"pii_vault.auto_create_keys",
        c"Create a missing Vault key when encrypting for a new key id.",
        c"Decryption never creates keys.",
        &AUTO_CREATE_KEYS,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_bool_guc(
        c"pii_vault.allow_staging",
        c"Allow plaintext (unencrypted) staging values in piitext columns.",
        c"When off, piitext_in_text() and plaintext payloads given to the type's input and receive functions are refused, so every new value is encrypted.",
        &ALLOW_STAGING,
        GucContext::Suset,
        GucFlags::default(),
    );

    GucRegistry::define_enum_guc(
        c"pii_vault.key_mode",
        c"How new values are encrypted: export (local AES with exported keys) or transit (Vault encrypts; keys never leave Vault).",
        c"Values written in either mode stay readable after switching.",
        &KEY_MODE,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_bool_guc(
        c"pii_vault.allow_insecure_http",
        c"Allow a plain http:// Vault URL that is not a loopback address.",
        c"The token and exported key material would cross the network unencrypted. Loopback URLs (e.g. a local Vault Agent) are always allowed.",
        &ALLOW_INSECURE_HTTP,
        GucContext::Suset,
        GucFlags::default(),
    );

    // Reject typos such as "pii_vault.tokn" instead of silently keeping them.
    #[cfg(not(feature = "pg14"))]
    unsafe {
        pg_sys::MarkGUCPrefixReserved(c"pii_vault".as_ptr());
    }
    #[cfg(feature = "pg14")]
    unsafe {
        pg_sys::EmitWarningsOnPlaceholders(c"pii_vault".as_ptr());
    }
}

#[pg_guard]
unsafe extern "C-unwind" fn check_url(
    newval: *mut *mut c_char,
    _extra: *mut *mut c_void,
    _source: pg_sys::GucSource::Type,
) -> bool {
    // SAFETY: PostgreSQL passes a valid pointer to a (possibly NULL) C string.
    let raw = unsafe { *newval };
    if raw.is_null() {
        return true;
    }
    let value = unsafe { CStr::from_ptr(raw) }.to_string_lossy();
    match validate_url(&value) {
        Ok(()) => true,
        Err(detail) => {
            let detail = CString::new(detail).unwrap_or_default();
            // SAFETY: PostgreSQL reads (and frees) this palloc'd string right after we return.
            unsafe { pg_sys::GUC_check_errdetail_string = pg_sys::pstrdup(detail.as_ptr()) };
            false
        }
    }
}

pub(crate) fn validate_url(value: &str) -> Result<(), String> {
    let v = value.trim();
    if v.is_empty() {
        return Ok(());
    }
    #[cfg(any(test, feature = "pg_test"))]
    if v.starts_with("mock://") {
        return Ok(());
    }
    let rest = v
        .strip_prefix("https://")
        .or_else(|| v.strip_prefix("http://"))
        .ok_or_else(|| "The URL must start with https:// or http://.".to_string())?;
    if rest.is_empty() || rest.starts_with('/') {
        return Err("The URL has no host.".into());
    }
    if rest.contains(char::is_whitespace) || rest.contains(['?', '#']) {
        return Err("The URL must not contain whitespace, a query string or a fragment.".into());
    }
    if rest
        .split('/')
        .next()
        .is_some_and(|authority| authority.contains('@'))
    {
        // ureq would send them as HTTP basic authentication, and the URL is
        // readable by every role and appears in error messages.
        return Err("The URL must not contain credentials (user:password@).".into());
    }
    Ok(())
}

fn read_string(setting: &GucSetting<Option<CString>>) -> Option<String> {
    setting
        .get()
        .map(|c| c.to_string_lossy().trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Where keys live: the Vault server, the namespace and the Transit mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub base_url: String,
    pub mount: String,
    pub namespace: Option<String>,
    /// `pii_vault.mount_accessor`: the accessor the mount must have.
    pub accessor: Option<String>,
}

impl Endpoint {
    /// Identity of the key space, used to scope the key cache.
    pub fn scope(&self) -> String {
        format!(
            "{}\n{}\n{}",
            self.base_url,
            self.namespace.as_deref().unwrap_or(""),
            self.mount
        )
    }
}

fn valid_path(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
        && s.split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Host part of an http(s) URL, without userinfo, port or brackets.
pub(crate) fn url_host(url: &str) -> &str {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or("");
    if let Some(bracketed) = host_port.strip_prefix('[') {
        return bracketed.split(']').next().unwrap_or("");
    }
    host_port.split(':').next().unwrap_or("")
}

pub(crate) fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub fn endpoint() -> Result<Endpoint, PiiError> {
    let url =
        read_string(&URL).ok_or_else(|| PiiError::Config("pii_vault.url is not set".into()))?;
    validate_url(&url).map_err(|m| PiiError::Config(format!("invalid pii_vault.url: {m}")))?;
    if url.starts_with("http://") && !is_loopback(url_host(&url)) && !ALLOW_INSECURE_HTTP.get() {
        return Err(PiiError::Config(format!(
            "pii_vault.url \"{url}\" uses plain http to a non-loopback host; use https:// \
             (or set pii_vault.allow_insecure_http = on for development only)"
        )));
    }
    let mount = read_string(&MOUNT)
        .map(|m| m.trim_matches('/').to_owned())
        .unwrap_or_else(|| "transit".into());
    if !valid_path(&mount) {
        return Err(PiiError::Config(format!(
            "invalid pii_vault.mount \"{mount}\""
        )));
    }
    let namespace = read_string(&NAMESPACE)
        .map(|n| n.trim_matches('/').to_owned())
        .filter(|n| !n.is_empty());
    if let Some(ns) = &namespace {
        if !valid_path(ns) {
            return Err(PiiError::Config(format!(
                "invalid pii_vault.namespace \"{ns}\""
            )));
        }
    }
    Ok(Endpoint {
        base_url: url.trim_end_matches('/').to_owned(),
        mount,
        namespace,
        accessor: read_string(&MOUNT_ACCESSOR),
    })
}

/// The Vault token: `pii_vault.token` if set, otherwise the content of
/// `pii_vault.token_file` (re-read every time, so rotation needs no reload).
pub fn vault_token() -> Result<Zeroizing<String>, PiiError> {
    if let Some(raw) = TOKEN.get() {
        let token = Zeroizing::new(raw.to_string_lossy().trim().to_owned());
        if !token.is_empty() {
            return Ok(token);
        }
    }
    if let Some(path) = read_string(&TOKEN_FILE) {
        let content = Zeroizing::new(std::fs::read(&path).map_err(|e| {
            PiiError::Config(format!("cannot read pii_vault.token_file \"{path}\": {e}"))
        })?);
        let token = std::str::from_utf8(&content)
            .map_err(|_| {
                PiiError::Config(format!(
                    "pii_vault.token_file \"{path}\" is not valid UTF-8"
                ))
            })?
            .trim();
        if token.is_empty() {
            return Err(PiiError::Config(format!(
                "pii_vault.token_file \"{path}\" is empty"
            )));
        }
        return Ok(Zeroizing::new(token.to_owned()));
    }
    Err(PiiError::Config(
        "neither pii_vault.token nor pii_vault.token_file is set".into(),
    ))
}

/// Human-readable description of where the token comes from (never the token).
pub fn token_source() -> String {
    if TOKEN
        .get()
        .is_some_and(|t| !t.to_bytes().trim_ascii().is_empty())
    {
        "pii_vault.token".into()
    } else if let Some(path) = read_string(&TOKEN_FILE) {
        format!("pii_vault.token_file ({path})")
    } else {
        "not configured".into()
    }
}

/// Settings that shape the HTTP client; a change rebuilds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportSettings {
    pub timeout: Duration,
    pub ca_file: Option<String>,
    pub client_cert_file: Option<String>,
    pub client_key_file: Option<String>,
}

pub fn transport() -> TransportSettings {
    TransportSettings {
        timeout: Duration::from_millis(TIMEOUT_MS.get().max(1) as u64),
        ca_file: read_string(&CA_FILE),
        client_cert_file: read_string(&CLIENT_CERT_FILE),
        client_key_file: read_string(&CLIENT_KEY_FILE),
    }
}

pub fn max_retries() -> u32 {
    MAX_RETRIES.get().max(0) as u32
}

pub fn cache_ttl() -> Duration {
    Duration::from_secs(CACHE_TTL_SEC.get().max(0) as u64)
}

pub fn cache_max_entries() -> usize {
    CACHE_MAX_ENTRIES.get().max(0) as usize
}

pub fn auto_create_keys() -> bool {
    AUTO_CREATE_KEYS.get()
}

pub fn allow_staging() -> bool {
    ALLOW_STAGING.get()
}

pub fn key_mode() -> KeyMode {
    KEY_MODE.get()
}

/// Test builds only: `mock://` URLs switch to deterministic in-process keys.
/// Release builds reject such URLs in the check hook, so the zero-knowledge
/// "mock" keys can never protect real data.
#[cfg(any(test, feature = "pg_test"))]
pub fn is_mock() -> bool {
    read_string(&URL).is_some_and(|u| u.starts_with("mock://"))
}

#[cfg(not(any(test, feature = "pg_test")))]
pub fn is_mock() -> bool {
    false
}
