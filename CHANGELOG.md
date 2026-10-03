# Changelog

All notable changes to pg_pii_vault are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-10-03

A maintenance release with updated dependencies. It changes neither the SQL interface nor the stored
values: after installing the new files and restarting, `ALTER EXTENSION pg_pii_vault UPDATE` only
records the new version.

### Fixed

- The extension builds again with warnings denied after the update to `aes-gcm` 0.11, which deprecated
  `Nonce::from_slice`.

### Changed

- Dependencies: `aes-gcm` 0.11.1, `base64` 0.23.1, `libc` 0.2.190; test and build dependencies
  `cc` 1.6.0, `tokio` 1.53.2, `uuid` 1.27.0. The `dtolnay/rust-toolchain` action is pinned to a newer
  commit.
- The upgrade test in CI also upgrades from 0.1.0.

## [0.1.0] - 2026-10-03

0.1.0 is a security release. It changes behaviour that applications rely on and cannot be downgraded.
Follow [UPGRADING.md](UPGRADING.md) to upgrade from 0.0.0.

### Security

- **Decryption must be granted.** `EXECUTE` on `piitext_out_text`, `piitext_encrypt`,
  `piitext_encrypt_piitext`, `piitext_reencrypt`, `piitext_shred`, `piitext_cache_invalidate` and
  `piitext_vault_check` is revoked from `PUBLIC`. In 0.0.0 every role that could `SELECT` a `piitext`
  column could decrypt it, including backup and reporting roles and members of `pg_read_all_data`.
- **Settings are superuser-only.** Every `pii_vault.*` parameter needs a superuser to change it. In
  0.0.0 any role could point `pii_vault.url` at its own server and receive the Vault token, or read the
  token with `SHOW pii_vault.token`. The token parameter is now hidden from other roles, and the
  `pii_vault` prefix is reserved, so misspelled parameter names are errors (PostgreSQL 15 and later).
- **No implicit casts.** The implicit cast from `text` to `piitext` is removed: in 0.0.0, writing text
  into a `piitext` column silently stored it unencrypted. The cast from `piitext` to `text` (and the new
  one to `varchar`) is explicit, so decryption never happens unnoticed.
- **Correct function volatility.** Decryption is `STABLE` and encryption is `VOLATILE`. In 0.0.0 both
  were `IMMUTABLE`, so decrypted values could be stored in indexes and generated columns, and an
  encryption with constant arguments could be evaluated once at plan time and reuse one IV for many
  rows.
- **Vault failures are errors, not masks.** A value reads as `****` only when the Transit engine itself
  reports, in Vault's exact words, that its key or key version does not exist, or when no existing key
  version authenticates the value. Vault being unreachable, sealed or slow, HTTP 401/403, a 404 or
  redirect answered by a proxy, and configuration errors now raise errors with distinct SQLSTATEs. In
  0.0.0 all of them returned `****`, and an application that wrote the value back lost the data.
- **The mount is verified.** Before it trusts an answer, or creates or deletes a key, each backend
  checks that `pii_vault.mount` is the mount point of a Transit engine. Other engines (KV, cubbyhole)
  answer requests for missing keys like Transit and accept the requests that would create or delete
  keys. The new `pii_vault.mount_accessor` setting pins the expected mount, so that pointing the
  extension at another Vault, namespace or mount raises an error instead of masking every value.
- **No stale keys after a shred.** A key that was being fetched while it was shredded is not cached,
  and a shred that fails or is cancelled after the deletion was requested still makes every backend of
  the cluster drop the key. Encryption never uses a key the cluster knows to be deleted.
- **Decryption never creates keys.** In 0.0.0, reading a value whose key had been deleted created a new
  key with the same name.
- **A NULL key id is an error.** In 0.0.0 `piitext_encrypt(value, NULL)` returned NULL and silently
  dropped the value.
- **Transport security.** `pii_vault.url` must use `https://`; plain `http://` is accepted only for
  loopback addresses unless `pii_vault.allow_insecure_http` is on. The URL must not contain credentials.
  Redirects are never followed, so the token cannot be forwarded to another host, and proxy environment
  variables are ignored. TLS is provided by rustls with the operating system trust store or
  `pii_vault.ca_file`; mutual TLS is supported. The URL, mount and namespace are validated, so settings
  cannot be used to reach other Vault paths.
- **Hardened value format.** Encrypted values and plaintext staging values can no longer be confused:
  a sealed value is a CBOR map, whose first byte can never start UTF-8 text. The format version, the
  fields, key id, IV, tag and ciphertext lengths are validated, a format 3 ciphertext must have exactly
  Vault's shape, and input must be in the encoding the extension writes, so no other data can travel
  inside a sealed value or alter a request to Vault. Oversized input is refused before it is decoded. A
  corrupted value raises SQLSTATE `XX001`; in 0.0.0 it could be returned as garbage or abort the query
  with a Rust panic.
- **Stronger associated data.** New values (format 2) bind the format version, the key id and the key
  version into the AES-GCM associated data.
- **Key versions.** Each value records the Vault key version it was encrypted with, and encryption uses
  the latest version. In 0.0.0 the version used after a rotation was arbitrary.
- **Staging can be switched off.** With `pii_vault.allow_staging = off`, plaintext staging values are
  refused on every way in: `piitext_in_text()`, the type's text input and its binary input.
- **Least-privilege Vault policies** are shipped in `vault/policies/` and verified against Vault. They
  do not allow rotating, reconfiguring or trimming keys.
- **Memory hygiene.** Key material, the token and buffers that hold plaintext are zeroed when released
  (best effort). The key cache is bounded.
- `mock://` URLs, which used a fixed all-zero key, exist only in test builds.

### Added

- **Transit key mode** (`pii_vault.key_mode = 'transit'`): Vault encrypts and decrypts, keys are created
  non-exportable and never leave Vault. Values of both modes stay readable after a switch.
- **Crypto-shredding from SQL**: `piitext_shred(key_id)`.
- **Re-encryption**: `piitext_reencrypt(value)` rewrites a value with the latest version of its key, in
  the current key mode.
- **Metadata functions**: `piitext_is_encrypted()`, `piitext_key_id()`, `piitext_key_version()`.
- **Cache control**: `piitext_cache_evict()`, `piitext_cache_flush()` and `piitext_cache_invalidate()`.
  With the library in `shared_preload_libraries`, `piitext_shred()` and the creation of a key make every
  backend of the cluster drop that key, and `piitext_cache_invalidate()` makes every backend drop its
  whole cache. Keys known to be absent are remembered for up to 30 seconds, so reading values of erased
  subjects does not cost a Vault request each time.
- **Monitoring**: `piitext_stats()` (per-backend and cluster-wide counters, including `vault_denied`)
  and `piitext_vault_check()` (configuration, connectivity, the Transit mount, token and policy checks;
  its `required` column makes it usable as a readiness probe).
- **Binary I/O** (`piitext_send`, `piitext_recv`): `COPY ... (FORMAT binary)`, the binary protocol and
  binary logical replication work.
- **Settings**: `pii_vault.token_file`, `pii_vault.namespace`, `pii_vault.mount_accessor`, `pii_vault.key_mode`,
  `pii_vault.ca_file`, `pii_vault.client_cert_file`, `pii_vault.client_key_file`,
  `pii_vault.timeout_ms`, `pii_vault.max_retries`, `pii_vault.cache_max_entries`,
  `pii_vault.auto_create_keys`, `pii_vault.allow_staging`, `pii_vault.allow_insecure_http`.
- **Resilience**: a timeout for every Vault request; retries with backoff for connection errors and
  HTTP 412/429/5xx; queries waiting for Vault can be cancelled; a session keeps at most four abandoned
  requests to Vault running, so a stalled Vault cannot pile up threads and connections.
- **SQLSTATEs** for every error class (`55000`, `22023`, `22P02`, `XX001`, `42501`, `58000`, `38000`,
  `42704`), with hints.
- **Upgrade script** `pg_pii_vault--0.0.0--0.1.0.sql`. It warns about indexes, generated columns,
  materialized views and extended statistics that hold decrypted values, and about indexes and
  generated columns on the other formerly IMMUTABLE functions, whose dumps can no longer be restored.
- **Size limits**: 16 MiB of plaintext per value (512 KiB in transit mode); key ids of 1 to 128 bytes.
- **Packaging**: release archives for PostgreSQL 14 to 18 on amd64 and arm64 with checksums and build
  provenance; a multi-architecture container image with SBOM and provenance; a container entry point
  that maps `PII_VAULT_*` environment variables to settings and keeps the token out of command lines.
- **CI**: tests on PostgreSQL 14 to 18 against a fake Vault and a real Vault with least-privilege
  tokens, an upgrade test, a container smoke test, clippy, rustfmt and `cargo deny`.
- **Documentation**: [USAGE.md](USAGE.md), [UPGRADING.md](UPGRADING.md),
  [docs/OPERATIONS.md](docs/OPERATIONS.md), [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md),
  [CONTRIBUTING.md](CONTRIBUTING.md).

### Changed

- **Text representation.** The text form of a value is `piitext:` followed by base64, which is safe for
  `COPY` and `pg_dump`. The 0.0.x form (`{"inner":[...]}`) is still accepted on input, so old dumps can
  be restored.
- **Storage.** Values are stored as plain byte strings instead of a serialized Rust structure, which
  takes about a third of the space for short values. Values written by 0.0.x are read without
  migration.
- **Key cache.** The cache is per backend, bounded by `pii_vault.cache_max_entries`, scoped to the
  Vault endpoint, follows changed settings at once, and is refreshed when a cached key cannot decrypt a
  value (after a rotation or when a key was re-created).
- **`piitext_reencrypt()`** asks Vault for the latest key version instead of trusting a cached one, and
  never creates a key: re-encrypting a value whose key was shredded meanwhile fails instead of storing
  the plaintext under a new key.
- **HTTP client.** `ureq` with rustls replaces `reqwest`. Requests run on a short-lived thread with
  signals blocked, so PostgreSQL's signal handling is not disturbed, and no OpenSSL is linked into the
  server.
- **Database encoding.** `CREATE EXTENSION` requires a UTF8 database.
- **`piitext_debug()`** reports the format, key id, key version and ciphertext size, and never shows
  plaintext.
- **Docker.** The image is built against the same PostgreSQL image it runs on, preloads the library and
  the demo uses a least-privilege token delivered through a file.
- Dependencies are updated and `Cargo.lock` is committed.

### Removed

- The implicit casts between `text` and `piitext`.
- `EXECUTE` for `PUBLIC` on the functions listed under Security.
- Support for PostgreSQL 13, which is end-of-life.
- `mock://` URLs in release builds.

## [0.0.0] - 2025-12-26

Proof of concept.

- `piitext` type with AES-256-GCM encryption under per-record keys exported from HashiCorp Vault
  Transit.
- `piitext_encrypt()`, `piitext_encrypt_piitext()`, `piitext_in_text()`, `piitext_out_text()`,
  `piitext_debug()`, `piitext_raw()`.
- Settings `pii_vault.url`, `pii_vault.token`, `pii_vault.mount`, `pii_vault.cache_ttl_sec`.
- PostgreSQL 13 to 18.

[0.1.1]: https://github.com/g0ddest/pg_pii_vault/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/g0ddest/pg_pii_vault/compare/v0.0.0-poc...v0.1.0
[0.0.0]: https://github.com/g0ddest/pg_pii_vault/releases/tag/v0.0.0-poc
