use pgrx::callconv::{Arg, ArgAbi, BoxRet, FcInfo};
use pgrx::datum::{Datum, FromDatum, IntoDatum, UnboxDatum};
use pgrx::prelude::*;
use pgrx::{InOutFuncs, StringInfo};
use serde::Deserialize;
use std::ffi::CStr;
use zeroize::Zeroizing;

mod cache;
mod config;
mod contents;
mod crypto;
mod error;
mod http;
mod keyring;
mod shared;
mod vault;

#[cfg(any(test, feature = "pg_test"))]
mod tests;

use contents::{PiiSealedData, PiiTextContents};
use error::{OrRaise, PiiError};
use keyring::Opened;
use shared::Counter;

::pgrx::pg_module_magic!(name, version);

/// Returned instead of the plaintext when the value's key was crypto-shredded.
const SHREDDED_MASK: &str = "****";

/// Largest plaintext accepted for a new value. PII fields are small; the cap
/// keeps memory use (several copies per value) and dump size bounded.
pub const MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;

/// Largest plaintext accepted with `pii_vault.key_mode = transit`. Vault
/// refuses JSON strings longer than 1 MiB by default, and the value travels
/// base64-encoded inside one.
pub const MAX_TRANSIT_PLAINTEXT_BYTES: usize = 512 * 1024;

#[pg_guard]
pub unsafe extern "C-unwind" fn _PG_init() {
    config::register();
    // SAFETY: plain read of a PostgreSQL global while the library is loaded.
    if unsafe { pg_sys::process_shared_preload_libraries_in_progress } {
        shared::init();
    } else if config::TOKEN.get().is_some() {
        warning!(
            "pg_pii_vault is not loaded via shared_preload_libraries: a pii_vault.token set in the \
             server configuration is visible to every role until the library is loaded, and \
             piitext_shred() only invalidates the key cache of the current backend"
        );
    }
}

extension_sql!(
    r#"
DO $$
BEGIN
    IF pg_catalog.getdatabaseencoding() <> 'UTF8' THEN
        RAISE EXCEPTION 'pg_pii_vault requires a UTF8 database; this database uses %',
            pg_catalog.getdatabaseencoding()
            USING HINT = 'Create the database with ENCODING ''UTF8''.';
    END IF;
END
$$;
"#,
    name = "require_utf8",
    bootstrap
);

/// Column type holding either an encrypted (sealed) value or, during a
/// migration, a plaintext staging value.
///
/// Stored as a plain varlena of the value bytes (see `contents`). Values
/// written by pg_pii_vault 0.0.x were wrapped by pgrx in a CBOR map
/// `{"inner": ...}`; they are still read transparently.
#[derive(Debug, Clone, PostgresType)]
#[inoutfuncs]
#[bikeshed_postgres_type_manually_impl_from_into_datum]
pub struct PiiText {
    inner: Vec<u8>,
}

/// CBOR prefix of the pgrx 0.0.x storage wrapper: map(1), text(5) "inner".
/// Current values start with a CBOR map of four or more entries or with
/// UTF-8, never with 0xA1, so the two layouts cannot be confused.
const LEGACY_WRAPPER_PREFIX: [u8; 7] = [0xA1, 0x65, b'i', b'n', b'n', b'e', b'r'];

#[derive(Deserialize)]
struct LegacyWrapper {
    #[serde(with = "serde_bytes")]
    inner: Vec<u8>,
}

impl PiiText {
    fn from_stored(stored: &[u8]) -> PiiText {
        if stored.starts_with(&LEGACY_WRAPPER_PREFIX) {
            match serde_cbor::from_slice::<LegacyWrapper>(stored) {
                Ok(legacy) => PiiText {
                    inner: legacy.inner,
                },
                Err(e) => {
                    PiiError::Corrupted(format!("cannot decode 0.0.x storage wrapper: {e}")).raise()
                }
            }
        } else {
            PiiText {
                inner: stored.to_vec(),
            }
        }
    }

    fn contents(&self) -> PiiTextContents<'_> {
        PiiTextContents::parse(&self.inner).or_raise()
    }

    fn sealed(data: PiiSealedData) -> PiiText {
        PiiText {
            inner: PiiTextContents::Sealed(data).to_bytes(),
        }
    }
}

impl IntoDatum for PiiText {
    fn into_datum(self) -> Option<pg_sys::Datum> {
        Some(
            pgrx::varlena::rust_byte_slice_to_bytea(&self.inner)
                .into_pg()
                .into(),
        )
    }

    fn type_oid() -> pg_sys::Oid {
        pgrx::wrappers::rust_regtypein::<Self>()
    }
}

impl FromDatum for PiiText {
    unsafe fn from_polymorphic_datum(
        datum: pg_sys::Datum,
        is_null: bool,
        _typoid: pg_sys::Oid,
    ) -> Option<Self> {
        if is_null {
            return None;
        }
        // SAFETY: a non-null piitext datum is a (possibly toasted) varlena.
        let stored = unsafe {
            let varlena = pg_sys::pg_detoast_datum_packed(datum.cast_mut_ptr());
            pgrx::varlena::varlena_to_byte_slice(varlena)
        };
        Some(PiiText::from_stored(stored))
    }
}

unsafe impl BoxRet for PiiText {
    unsafe fn box_into<'fcx>(self, fcinfo: &mut FcInfo<'fcx>) -> Datum<'fcx> {
        match self.into_datum() {
            None => fcinfo.return_null(),
            Some(datum) => unsafe { fcinfo.return_raw_datum(datum) },
        }
    }
}

unsafe impl UnboxDatum for PiiText {
    type As<'dat>
        = Self
    where
        Self: 'dat;

    unsafe fn unbox<'dat>(datum: Datum<'dat>) -> Self::As<'dat>
    where
        Self: 'dat,
    {
        // SAFETY: Datum<'dat> is a transparent wrapper around pg_sys::Datum.
        unsafe {
            <Self as FromDatum>::from_datum(
                std::mem::transmute::<Datum<'dat>, pg_sys::Datum>(datum),
                false,
            )
            .expect("piitext datum must not be NULL")
        }
    }
}

unsafe impl<'fcx> ArgAbi<'fcx> for PiiText
where
    Self: 'fcx,
{
    unsafe fn unbox_arg_unchecked(arg: Arg<'_, 'fcx>) -> Self {
        let index = arg.index();
        unsafe {
            arg.unbox_arg_using_from_datum()
                .unwrap_or_else(|| panic!("argument {index} must not be null"))
        }
    }
}

impl InOutFuncs for PiiText {
    fn input(input: &CStr) -> Self {
        let text = input
            .to_str()
            .map_err(|_| PiiError::InvalidText("input is not valid UTF-8".into()))
            .or_raise();
        let (inner, staging) = contents::decode_text(text).or_raise();
        if staging {
            check_staging(inner.len());
        }
        PiiText { inner }
    }

    fn output(&self, buffer: &mut StringInfo) {
        buffer.push_str(&contents::encode_text(&self.inner));
    }
}

/// Binary input (COPY BINARY, binary protocol, binary logical replication).
/// STABLE like the text input function: both refuse plaintext staging values
/// when pii_vault.allow_staging is off.
#[pg_extern(stable, strict, parallel_safe)]
fn piitext_recv(mut internal: pgrx::Internal) -> PiiText {
    // SAFETY: PostgreSQL passes a StringInfo positioned at this value.
    let buf = unsafe { internal.get_mut::<pg_sys::StringInfoData>() }
        .expect("piitext_recv called without a buffer");
    let remaining = (buf.len - buf.cursor).max(0) as usize;
    if remaining > contents::MAX_STORED_BYTES {
        PiiError::InvalidArgument(format!(
            "value is {remaining} bytes long; piitext values are limited to {MAX_PLAINTEXT_BYTES} bytes"
        ))
        .raise();
    }
    // SAFETY: data[cursor..len] is initialised memory owned by the StringInfo.
    let bytes = unsafe {
        std::slice::from_raw_parts(buf.data.add(buf.cursor as usize).cast::<u8>(), remaining)
    }
    .to_vec();
    buf.cursor = buf.len;
    if let PiiTextContents::Staging(_) = PiiTextContents::parse_input(&bytes).or_raise() {
        check_staging(bytes.len());
    }
    PiiText { inner: bytes }
}

/// Binary output: the stored value bytes.
#[pg_extern(immutable, strict, parallel_safe)]
fn piitext_send(input: PiiText) -> Vec<u8> {
    input.inner
}

extension_sql!(
    r#"
ALTER TYPE piitext SET (RECEIVE = piitext_recv, SEND = piitext_send);
-- The input function depends on pii_vault.allow_staging.
ALTER FUNCTION piitext_in(cstring) STABLE;
"#,
    name = "piitext_binary_io",
    requires = [piitext_recv, piitext_send]
);

fn check_size(len: usize) {
    if len > MAX_PLAINTEXT_BYTES {
        PiiError::InvalidArgument(format!(
            "value is {len} bytes long; piitext values are limited to {MAX_PLAINTEXT_BYTES} bytes"
        ))
        .raise();
    }
}

/// Gate for plaintext staging values, whichever way they enter the database
/// (piitext_in_text(), the type's input function or its receive function).
fn check_staging(len: usize) {
    if !config::allow_staging() {
        PiiError::StagingDisabled.raise();
    }
    check_size(len);
}

/// Build a plaintext staging value (NOT encrypted), e.g. while migrating an
/// existing column. Refused when pii_vault.allow_staging is off.
/// STABLE because it depends on that setting.
#[pg_extern(stable, strict, parallel_safe, name = "piitext_in_text")]
fn piitext_input(input: &str) -> PiiText {
    check_staging(input.len());
    PiiText {
        inner: input.as_bytes().to_vec(),
    }
}

/// Decrypt: the plaintext of a piitext value (also used by `value::text`).
/// Returns '****' only when the key was crypto-shredded; any other failure
/// (Vault unreachable, permission denied, misconfiguration) raises an error.
///
/// STABLE, not IMMUTABLE: the result depends on configuration and on Vault,
/// and must never end up in an index, a generated column or a constant-folded
/// plan (that would persist plaintext and defeat crypto-shredding).
#[pg_extern(stable, strict, parallel_safe, cost = 100, name = "piitext_out_text")]
fn piitext_output(input: PiiText) -> String {
    match input.contents() {
        PiiTextContents::Staging(s) => s.into_owned(),
        PiiTextContents::Sealed(sealed) => match keyring::open(&sealed).or_raise() {
            Opened::Plaintext(mut text) => std::mem::take(&mut *text),
            Opened::Shredded => SHREDDED_MASK.to_string(),
        },
    }
}

extension_sql!(
    r#"
-- Decryption is always explicit: value::text (or piitext_out_text(value)).
-- There is deliberately no cast from text to piitext: writing text into a
-- piitext column must fail instead of silently storing unencrypted PII.
CREATE CAST (piitext AS text) WITH FUNCTION piitext_out_text(piitext);
CREATE CAST (piitext AS varchar) WITH FUNCTION piitext_out_text(piitext);
"#,
    name = "piitext_casts",
    requires = [piitext_output]
);

fn required_key_id(key_id: Option<Vec<u8>>) -> Vec<u8> {
    key_id.unwrap_or_else(|| PiiError::InvalidArgument("key id must not be NULL".into()).raise())
}

/// Encrypt `plaintext` with the latest version of the Vault key named by
/// `key_id_bytes`; the key is created on first use unless
/// pii_vault.auto_create_keys is off. NULL plaintext gives NULL; a NULL key
/// id is an error (it would otherwise silently turn the value into NULL).
#[pg_extern(volatile, cost = 100)]
fn piitext_encrypt(plaintext: Option<&str>, key_id_bytes: Option<Vec<u8>>) -> Option<PiiText> {
    let plaintext = plaintext?;
    let key_id = required_key_id(key_id_bytes);
    check_size(plaintext.len());
    Some(PiiText::sealed(
        keyring::seal(plaintext, &key_id).or_raise(),
    ))
}

fn plaintext_of(input: &PiiText) -> Zeroizing<String> {
    match input.contents() {
        PiiTextContents::Staging(s) => Zeroizing::new(s.into_owned()),
        PiiTextContents::Sealed(sealed) => match keyring::open(&sealed).or_raise() {
            Opened::Plaintext(text) => text,
            Opened::Shredded => PiiError::KeyNotFound(format!(
                "{} (the value was crypto-shredded and cannot be re-encrypted)",
                vault::key_name(&sealed.key_id)
            ))
            .raise(),
        },
    }
}

/// Encrypt a staging value, or re-encrypt a sealed value under another key id.
#[pg_extern(volatile, cost = 100, name = "piitext_encrypt_piitext")]
fn piitext_encrypt_from_piitext(
    input: Option<PiiText>,
    key_id_bytes: Option<Vec<u8>>,
) -> Option<PiiText> {
    let input = input?;
    let key_id = required_key_id(key_id_bytes);
    let plaintext = plaintext_of(&input);
    check_size(plaintext.len());
    Some(PiiText::sealed(
        keyring::seal(&plaintext, &key_id).or_raise(),
    ))
}

/// Re-encrypt a sealed value with the latest version of its own key (after a
/// key rotation, or to upgrade values written by pg_pii_vault 0.0.x).
#[pg_extern(volatile, strict, cost = 100)]
fn piitext_reencrypt(input: PiiText) -> PiiText {
    let key_id = match input.contents() {
        PiiTextContents::Sealed(sealed) => sealed.key_id,
        PiiTextContents::Staging(_) => PiiError::InvalidArgument(
            "value is not encrypted; use piitext_encrypt_piitext(value, key_id)".into(),
        )
        .raise(),
    };
    let plaintext = plaintext_of(&input);
    check_size(plaintext.len());
    PiiText::sealed(keyring::reseal(&plaintext, &key_id).or_raise())
}

#[pg_extern(immutable, strict, parallel_safe)]
fn piitext_is_encrypted(input: PiiText) -> bool {
    matches!(input.contents(), PiiTextContents::Sealed(_))
}

/// Key id of a sealed value (NULL for staging values).
#[pg_extern(immutable, strict, parallel_safe)]
fn piitext_key_id(input: PiiText) -> Option<Vec<u8>> {
    match input.contents() {
        PiiTextContents::Sealed(sealed) => Some(sealed.key_id),
        PiiTextContents::Staging(_) => None,
    }
}

/// Vault key version of a sealed value (NULL for staging values and for
/// values written by pg_pii_vault 0.0.x, which did not record it).
#[pg_extern(immutable, strict, parallel_safe)]
fn piitext_key_version(input: PiiText) -> Option<i64> {
    match input.contents() {
        PiiTextContents::Sealed(sealed) => sealed.key_version.map(i64::from),
        PiiTextContents::Staging(_) => None,
    }
}

/// Human-readable description of a value. Never reveals the plaintext.
#[pg_extern(immutable, strict, parallel_safe)]
fn piitext_debug(input: PiiText) -> String {
    match input.contents() {
        PiiTextContents::Staging(s) => format!("Staging(plaintext_bytes={})", s.len()),
        PiiTextContents::Sealed(sealed) => format!(
            "Sealed(format={}, key_id=\\x{}, key_version={}, ciphertext_bytes={})",
            sealed.version,
            hex::encode(&sealed.key_id),
            sealed
                .key_version
                .map_or_else(|| "unrecorded".to_string(), |v| v.to_string()),
            sealed.ciphertext.len()
        ),
    }
}

/// The value bytes (CBOR for sealed values, UTF-8 for staging values).
#[pg_extern(immutable, strict, parallel_safe)]
fn piitext_raw(input: PiiText) -> Vec<u8> {
    input.inner
}

/// Crypto-shred: delete the Vault key named by `key_id_bytes`, making every
/// value encrypted with it permanently unreadable. Returns false when no such
/// key existed. Takes effect immediately and is NOT undone if the transaction
/// rolls back.
#[pg_extern(volatile)]
fn piitext_shred(key_id_bytes: Option<Vec<u8>>) -> bool {
    keyring::shred(&required_key_id(key_id_bytes)).or_raise()
}

/// Evict one key from this backend's key cache.
#[pg_extern(volatile, strict)]
fn piitext_cache_evict(key_id_bytes: Vec<u8>) -> bool {
    cache::evict(&key_id_bytes)
}

/// Drop every key cached by this backend; returns the number removed.
#[pg_extern(volatile)]
fn piitext_cache_flush() -> i64 {
    cache::flush() as i64
}

/// Make every backend of the cluster drop its key cache (for example after
/// deleting or rotating keys directly in Vault). Returns false when the
/// library is not preloaded, in which case only this backend was flushed.
#[pg_extern(volatile)]
fn piitext_cache_invalidate() -> bool {
    cache::flush();
    shared::bump_epoch()
}

/// Monitoring counters for this backend and, when preloaded, the cluster.
#[pg_extern(volatile)]
fn piitext_stats() -> TableIterator<
    'static,
    (
        name!(metric, String),
        name!(backend, i64),
        name!(cluster, Option<i64>),
    ),
> {
    let mut rows = vec![("cache_entries".to_string(), cache::len() as i64, None)];
    for counter in Counter::ALL {
        rows.push((
            counter.name().to_string(),
            shared::local_value(counter) as i64,
            shared::cluster_value(counter).map(|v| v as i64),
        ));
    }
    TableIterator::new(rows)
}

/// Check the deployment: preloading, configuration, Vault reachability, token
/// validity and the policy capabilities the extension needs. A deployment is
/// healthy when every `required` check is `ok`; the other rows are advisory
/// (optional capabilities and hardening hints).
#[pg_extern(volatile)]
fn piitext_vault_check() -> TableIterator<
    'static,
    (
        name!(check_name, String),
        name!(ok, bool),
        name!(required, bool),
        name!(detail, String),
    ),
> {
    let mut rows: Vec<(String, bool, bool, String)> = Vec::new();
    rows.push((
        "shared_preload_libraries".into(),
        shared::available(),
        true,
        if shared::available() {
            "preloaded; cluster-wide cache invalidation and statistics enabled".into()
        } else {
            "not preloaded: add pg_pii_vault to shared_preload_libraries".into()
        },
    ));
    let token = config::vault_token();
    rows.push((
        "token".into(),
        token.is_ok(),
        true,
        match &token {
            Ok(_) => format!("from {}", config::token_source()),
            Err(e) => e.to_string(),
        },
    ));
    match config::endpoint() {
        Ok(ep) => {
            rows.push((
                "endpoint".into(),
                true,
                true,
                format!(
                    "url={} mount={} namespace={} key_mode={}",
                    ep.base_url,
                    ep.mount,
                    ep.namespace.as_deref().unwrap_or("(none)"),
                    match config::key_mode() {
                        config::KeyMode::Export => "export",
                        config::KeyMode::Transit => "transit",
                    }
                ),
            ));
            let https = ep.base_url.starts_with("https://");
            let loopback = config::is_loopback(config::url_host(&ep.base_url));
            // Plain http to another host is only reachable with
            // pii_vault.allow_insecure_http = on: a deliberate override.
            rows.push((
                "tls".into(),
                https || loopback,
                false,
                if https {
                    "https".into()
                } else if loopback {
                    "plain http to a loopback address (e.g. a local Vault Agent); traffic stays on this host".into()
                } else {
                    "plain http (pii_vault.allow_insecure_http = on): the token and key material cross the network unencrypted".into()
                },
            ));
            if token.is_ok() {
                for c in vault::check(&ep) {
                    rows.push((c.name.to_string(), c.ok, c.required, c.detail));
                }
            }
        }
        Err(e) => rows.push(("endpoint".into(), false, true, e.to_string())),
    }
    TableIterator::new(rows)
}

extension_sql!(
    r#"
-- Least privilege by default: reading a piitext column (SELECT) yields only
-- ciphertext. Decrypting, encrypting and administrative functions must be
-- granted explicitly, e.g.
--   GRANT EXECUTE ON FUNCTION piitext_out_text(piitext),
--       piitext_encrypt(text, bytea) TO app_role;
REVOKE ALL ON FUNCTION piitext_out_text(piitext) FROM PUBLIC;
REVOKE ALL ON FUNCTION piitext_encrypt(text, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION piitext_encrypt_piitext(piitext, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION piitext_reencrypt(piitext) FROM PUBLIC;
REVOKE ALL ON FUNCTION piitext_shred(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION piitext_cache_invalidate() FROM PUBLIC;
REVOKE ALL ON FUNCTION piitext_vault_check() FROM PUBLIC;
"#,
    name = "piitext_privileges",
    requires = [
        piitext_output,
        piitext_encrypt,
        piitext_encrypt_from_piitext,
        piitext_reencrypt,
        piitext_shred,
        piitext_cache_invalidate,
        piitext_vault_check,
        "piitext_casts"
    ]
);

#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {}

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        vec![
            "shared_preload_libraries = 'pg_pii_vault'",
            "pii_vault.url = 'mock://localhost'",
        ]
    }
}
