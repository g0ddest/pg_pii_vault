# pg_pii_vault

[![PR Validation](https://github.com/g0ddest/pg_pii_vault/actions/workflows/pr-validation.yml/badge.svg)](https://github.com/g0ddest/pg_pii_vault/actions/workflows/pr-validation.yml)

pg_pii_vault is a PostgreSQL extension for column-level encryption of personal data (PII). It adds the
column type `piitext`. Every value is encrypted with AES-256-GCM under a per-record key, in practice one
key per data subject, and that key is held in the HashiCorp Vault Transit secrets engine. To erase a
person, you delete their key in Vault (crypto-shredding). Every value encrypted with that key then becomes
permanently unreadable, including the copies in replicas, dumps and base backups, so a GDPR erasure
request does not require rewriting backups. Decryption is always explicit and must be granted separately.
A role that can only `SELECT` the table sees ciphertext.

## Status

Version 0.1.0. Before using it in production, make sure that:

- `pg_pii_vault` is listed in `shared_preload_libraries`. Preloading is required for cluster-wide cache
  invalidation after shredding and for cluster-wide statistics. Without it, a `pii_vault.token` set in
  the server configuration is visible to every role until the library is loaded.
- Vault is reached over TLS (`https://`), or over plain HTTP only through a Vault Agent (or Vault Proxy)
  on the same host (loopback address).
- The extension uses a least-privilege Vault token, supplied through `pii_vault.token_file`, for example
  from a Vault Agent file sink.
- Vault is backed up, for example with Raft snapshots. Without the keys, the encrypted data is lost.

## Features

- **Two key modes.** In `export` mode (the default), the key is exported from Vault, AES-256-GCM runs
  in the PostgreSQL backend and keys are cached per backend. In `transit` mode, Vault encrypts and
  decrypts, keys are created non-exportable and they never leave Vault. Values written in either mode stay
  readable after a switch, as long as the token keeps the Vault capability that their format needs.
- **Crypto-shredding.** `piitext_shred(key_id)` deletes the key in Vault. From then on, every value
  encrypted with that key reads as `****`.
- **Key rotation with recorded key versions.** Each value records the Vault key version it was encrypted
  with (`piitext_key_version()`). Values under older versions stay readable, and `piitext_reencrypt()`
  rewrites a value with the latest version.
- **Least privilege by default.**
  - `SELECT` returns ciphertext.
  - Decryption, encryption and administrative functions are not executable by `PUBLIC`.
  - Decryption requires an explicit cast (`value::text`). There is no cast from `text` to `piitext`, so
    writing plain text into a `piitext` column fails.
  - All settings are superuser-only. `pii_vault.token` is hidden from every role except superusers and
    members of `pg_read_all_settings`.
  - The shipped Vault policies do not allow rotating, reconfiguring or trimming keys.
- **Predictable failure handling.**
  - Vault failures raise errors with distinct SQLSTATEs. They are never reported as `****`. A value
    reads as `****` only when the Transit engine itself reports, in Vault's exact words, that its key or
    key version is gone. Before trusting such an answer, the extension checks that `pii_vault.mount` is a
    Transit engine, and optionally that it is the expected one (`pii_vault.mount_accessor`). A wrong
    mount, a 404 or redirect from a proxy, or an unexpected answer is an error.
  - Each HTTP request has a timeout. Connection errors and HTTP 412/429/5xx responses are retried with
    backoff.
  - A query that is waiting for Vault can still be cancelled (`statement_timeout`,
    `pg_cancel_backend()`).
  - Redirects are never followed, and proxy environment variables are ignored.
- **Cluster-wide cache invalidation.** When the library is preloaded, `piitext_shred()` makes every
  backend of the cluster drop its cached copy of that key, also when the shred fails or is cancelled
  after the deletion was requested, and `piitext_cache_invalidate()` makes every backend drop its whole
  cache. A key fetched while it is being shredded is never cached.
- **Binary I/O.** `COPY ... (FORMAT binary)`, the binary protocol and binary logical replication are
  supported. The text form (`piitext:` followed by base64) is safe for `COPY` and `pg_dump`.
- **Monitoring.** `piitext_stats()` reports cache and Vault counters per backend and per cluster.
  `piitext_vault_check()` checks the configuration, connectivity, token and Vault policy, and marks which
  checks are required, so it can serve as a readiness probe.
- **Upgrade path.** You can upgrade from 0.0.0 with `ALTER EXTENSION pg_pii_vault UPDATE TO '0.1.0'`.
  Values written by 0.0.x are read without migration. See [UPGRADING.md](UPGRADING.md).

## Quick start

To try the extension locally with PostgreSQL and a Vault dev server, see [DOCKER.md](DOCKER.md).
The rest of this README assumes that the extension is installed and that Vault has the Transit secrets
engine enabled at `transit/`.

## Installation

The extension is built for one PostgreSQL major version at a time. Install the build that matches your
server's major version (14 to 18).

### Release archives

Each GitHub release has one Linux archive per PostgreSQL major version and CPU architecture
(`pg_pii_vault-<version>-pg<major>-linux-<amd64|arm64>.tar.gz`, with a `.sha256` file and a build
provenance attestation; see [DOCKER.md](DOCKER.md#verifying-a-release) for verification). The archive
holds:

- the shared library `pg_pii_vault.so`;
- `pg_pii_vault.control`;
- the `pg_pii_vault--*.sql` install and upgrade scripts.

The files are laid out as in the PGDG Debian and Ubuntu packages (`usr/lib/postgresql/<major>/lib`,
`usr/share/postgresql/<major>/extension`). On other layouts, copy the shared library to
`$(pg_config --pkglibdir)` and the control file and SQL scripts to `$(pg_config --sharedir)/extension`,
using the `pg_config` of the target server.

The archives are built on Ubuntu 22.04 and need glibc 2.35 or later (Debian 12, Ubuntu 22.04 and newer).
They have no other runtime dependency; in particular they do not use OpenSSL. On other platforms, build
from source.

### Docker image

A PostgreSQL image with the extension installed is described in [DOCKER.md](DOCKER.md).

### From source

You need a Rust toolchain, libclang, and the PostgreSQL server development files for the target major
version. The build uses the committed `Cargo.lock`.

```sh
cargo install cargo-pgrx --version 0.16.1 --locked
PG_CONFIG=/usr/lib/postgresql/18/bin/pg_config          # pg_config of the target server
cargo pgrx init --pg18 "$PG_CONFIG"                     # --pg14 ... --pg17 for other versions
cargo pgrx install --release --pg-config "$PG_CONFIG"   # add --sudo if the target directories need root
```

`cargo pgrx install` installs the shared library, the control file and the install and upgrade scripts.

After installation, configure the server as described in the next section and restart it. Then create
the extension in each database that needs it, as shown in
[Checking the deployment](#checking-the-deployment).

## Production configuration

### postgresql.conf

```ini
shared_preload_libraries = 'pg_pii_vault'        # changing this requires a restart

pii_vault.url        = 'https://vault.example.internal:8200'
#pii_vault.url       = 'http://127.0.0.1:8100'            # alternative: Vault Agent listener on this host
pii_vault.token_file = '/run/vault-agent/pg-pii-vault.token'
#pii_vault.ca_file   = '/etc/pg_pii_vault/vault-ca.pem'   # when the Vault CA is not in the OS trust store
#pii_vault.key_mode  = 'transit'                          # default 'export'; see "Choosing a key mode"
pii_vault.mount_accessor = 'transit_4a1b2c3d'             # the accessor of your Transit mount
```

Find the accessor with `vault secrets list` (column `Accessor`) or in the `transit_mount` row of
`piitext_vault_check()`. With it set, pointing the extension at another Vault server, namespace or mount
raises an error instead of reading every value as `****`.

The operating system user that runs PostgreSQL must be able to read the token file. The file is read on
every Vault request, so Vault Agent can renew or replace the token without a reload. Every setting except
`shared_preload_libraries` takes effect on reload (`SELECT pg_reload_conf();`). Once no migration needs
plaintext staging values, consider also setting `pii_vault.allow_staging = off`. All settings are listed
in the [configuration reference](#configuration-reference).

### Vault policies

The repository ships the least-privilege policies in `vault/policies/`:

| File | Grants |
|---|---|
| [`pg-pii-vault.hcl`](vault/policies/pg-pii-vault.hcl) | `export` mode: export key material and create exportable `aes256-gcm96` keys. |
| [`pg-pii-vault-transit.hcl`](vault/policies/pg-pii-vault-transit.hcl) | `transit` mode: encrypt and decrypt through Vault, and create non-exportable keys. Keys cannot be exported. |
| [`pg-pii-vault-shred.hcl`](vault/policies/pg-pii-vault-shred.hcl) | Optional: allow and perform key deletion. Needed only if `piitext_shred()` is called from the database. |

The last three blocks of `pg-pii-vault.hcl` and `pg-pii-vault-transit.hcl` concern the token itself.
`auth/token/renew-self` lets Vault Agent renew the periodic token (Vault's `default` policy grants the
same). `auth/token/lookup-self` and `sys/capabilities-self` are optional: they only let
`piitext_vault_check()` inspect the token and its capabilities.

```sh
vault policy write pg-pii-vault         vault/policies/pg-pii-vault.hcl           # export mode
vault policy write pg-pii-vault-transit vault/policies/pg-pii-vault-transit.hcl   # transit mode
vault policy write pg-pii-vault-shred   vault/policies/pg-pii-vault-shred.hcl     # optional
```

The paths in the policy files assume that the Transit engine is mounted at `transit/`. Adjust them if
`pii_vault.mount` is different. Keep these details when you adapt the policies:

- A `create` capability alone does not allow creating Transit keys. The extension needs `update`.
- `allowed_parameters` values are type-sensitive. `"exportable" = [true]` must be a boolean, not the
  string `"true"`.
- Do not widen `transit/keys/+` to `transit/keys/*`. That would also allow rotating, reconfiguring and
  trimming every key.

If another process provisions the keys, set `pii_vault.auto_create_keys = off` and remove the
`transit/keys/+` block from `pg-pii-vault.hcl` or `pg-pii-vault-transit.hcl`.

For the token, use a periodic token that Vault Agent obtains (auto-auth, for example AppRole or
Kubernetes) and writes to a file sink. See [docs/OPERATIONS.md](docs/OPERATIONS.md).

### Checking the deployment

```sql
CREATE EXTENSION pg_pii_vault;         -- as a superuser, in each database; the database must be UTF8
SELECT * FROM piitext_vault_check();
```

Every row with `required = true` must report `ok = true`. The checks cover preloading, the token, the
endpoint, Vault reachability, that `pii_vault.mount` is a Transit engine (`transit_mount`), a real key
request against it (`key_access`), token validity and the capabilities that the configured key mode
needs. As a readiness probe:

```sql
SELECT bool_and(ok) FROM piitext_vault_check() WHERE required;
```

Rows with `required = false` are advisory:

- `tls` is false only for plain HTTP to another host, which requires `pii_vault.allow_insecure_http = on`.
- `policy_shred` is false if the token cannot delete keys, which is fine when keys are shredded outside
  the database.
- `policy_no_export` (transit mode) is false while the token can still export keys, for example during a
  migration from export mode.
- `policy_create_keys` is advisory when `pii_vault.auto_create_keys = off`.
- `token_valid` and `policy` are advisory when the token's policy lacks the optional rules that let the
  extension inspect the token and its capabilities.

## Usage

### Table and privileges

```sql
CREATE TABLE customer (
    id        integer PRIMARY KEY,
    full_name piitext NOT NULL,
    email     piitext
);

GRANT SELECT, INSERT, UPDATE, DELETE ON customer TO app;
GRANT EXECUTE ON FUNCTION
    piitext_encrypt(text, bytea),
    piitext_out_text(piitext),
    piitext_encrypt_piitext(piitext, bytea),
    piitext_reencrypt(piitext)
TO app;
```

Roles without `EXECUTE` on `piitext_out_text(piitext)` get only ciphertext. This includes reporting
roles, backup roles and members of `pg_read_all_data`. Grant `piitext_shred(bytea)` only to the role
that performs erasure.

### Writing and reading

To encrypt, pass the plaintext and a key id that identifies the data subject. Send plaintext as bind
parameters. A statement that fails is written to the server log, and SQL literals in it would include
the plaintext.

```sql
-- $1 = 42, $2 = 'Jane Doe', $3 = 'jane@example.com'
INSERT INTO customer (id, full_name, email)
VALUES ($1, piitext_encrypt($2, int4send($1)), piitext_encrypt($3, int4send($1)));
```

To decrypt, use an explicit cast. Without the cast, a `piitext` column is returned as ciphertext in its
text form (`piitext:` followed by base64).

```sql
SELECT id, full_name::text AS full_name, email::text AS email
FROM customer
WHERE id = 42;
```

```
 id | full_name |      email
----+-----------+------------------
 42 | Jane Doe  | jane@example.com
```

### Inspecting values

These functions do not contact Vault, and `PUBLIC` can execute them.

```sql
SELECT piitext_is_encrypted(email) AS encrypted,
       piitext_key_id(email)       AS key_id,
       piitext_key_version(email)  AS key_version,
       piitext_debug(email)        AS debug
FROM customer
WHERE id = 42;
```

```
 encrypted |   key_id   | key_version |                                  debug
-----------+------------+-------------+-------------------------------------------------------------------------
 t         | \x0000002a |           1 | Sealed(format=2, key_id=\x0000002a, key_version=1, ciphertext_bytes=16)
```

### Key rotation

Rotating a key is a task for the Vault administrator. The shipped policies do not allow it.

```sh
vault write -f transit/keys/0000002a/rotate
```

```sql
-- Export mode: without this, backends keep encrypting with their cached key version
-- until pii_vault.cache_ttl_sec expires.
SELECT piitext_cache_invalidate();

-- Rewrite existing values with the latest key version.
UPDATE customer
SET full_name = piitext_reencrypt(full_name),
    email     = piitext_reencrypt(email)
WHERE id = 42;

SELECT piitext_key_version(email) FROM customer WHERE id = 42;   -- 2
```

Each value keeps the key version it was written with. It stays readable as long as Vault keeps that
version. Do not raise `min_decryption_version` or trim the key in Vault before the values have been
re-encrypted. Values under a version that is no longer available read as `****`.

### Crypto-shredding (erasure)

```sql
SELECT piitext_shred(int4send(42));               -- true: the key was deleted in Vault
SELECT email::text FROM customer WHERE id = 42;   -- ****
DELETE FROM customer WHERE id = 42;               -- copies in backups and replicas stay unreadable
```

- `piitext_shred()` requires `EXECUTE` on the function and the `pg-pii-vault-shred.hcl` policy on the
  token. It returns `false` if the key did not exist.
- The deletion is immediate and not transactional. `ROLLBACK` does not bring the key back.
- When the library is preloaded, the deletion takes effect at once in every backend of this cluster.
- In export mode, backends of other clusters and standbys stop decrypting within
  `pii_vault.cache_ttl_sec`. To make that immediate, run `SELECT piitext_cache_invalidate();` there.
- Shredding does not block the key id. A later `piitext_encrypt()` with the same key id creates a new key.

For more examples, see [USAGE.md](USAGE.md).

## Designing key ids

The key id is a `bytea` value of 1 to 128 bytes. The Vault key name is its lowercase hex encoding.

- **Identify the data subject, not the row.** All PII of one person, in every table, should use the same
  key id. One `piitext_shred()` call then erases all of it.
- **Separate entity types that share an id space.** Customer 42 and employee 42 must not share a key.
  Prefix a type byte, or use separate Vault mounts.
- **Never use PII as the key id.** Do not use an e-mail address or a national id number, for example. The
  key id appears in Vault paths, Vault audit logs and error messages.
- **Use one key space per mount and environment.** Test and production databases, or independent
  databases whose ids overlap, must not use the same Transit mount. Separate them with `pii_vault.mount`
  (or `pii_vault.namespace`).

```sql
SELECT encode(int4send(42), 'hex');                     -- 0000002a            integer id
SELECT encode(int8send(42), 'hex');                     -- 000000000000002a    bigint id
SELECT encode('\x01'::bytea || int8send(42), 'hex');    -- 01000000000000002a  customer 42
SELECT encode('\x02'::bytea || int8send(42), 'hex');    -- 02000000000000002a  employee 42
SELECT encode(uuid_send('6f1c1a8e-3b8e-4a53-9b53-0c1f0c3b2a10'), 'hex');
                                                        -- 6f1c1a8e3b8e4a539b530c1f0c3b2a10
SELECT encode(convert_to('C-42', 'UTF8'), 'hex');       -- 432d3432            text id
```

## Choosing a key mode

`pii_vault.key_mode` only affects new encryptions. The stored format records how each value was
encrypted.

| | `export` (default) | `transit` |
|---|---|---|
| Who encrypts | The PostgreSQL backend, with key material exported from Vault | Vault (`transit/encrypt`, `transit/decrypt`) |
| Key material outside Vault | Yes: in backend memory, cached for up to `pii_vault.cache_ttl_sec`, zeroed when dropped | Never: keys are created non-exportable |
| Vault requests | One per distinct key per backend per `cache_ttl_sec`; three for a new key | One per value encrypted or decrypted; nothing is cached |
| Vault audit log records | Key exports | Every encryption and decryption |
| Shredding reaches other clusters and standbys | Within `cache_ttl_sec` | On the next request |
| A leaked token allows | Decryption, and export of keys whose copies shredding cannot revoke | Decryption through Vault while the token is valid; no key export |
| Stored format | 2 | 3 |
| Vault policy | `pg-pii-vault.hcl` | `pg-pii-vault-transit.hcl` |

Use `transit` if key material must never leave Vault and Vault can handle one request per value. Use
`export` if read volume makes one Vault request per value impractical.

To move an existing deployment from `export` to `transit`:

1. Attach `pg-pii-vault-transit.hcl` to the token. Keep `pg-pii-vault.hcl` for now, because reading
   format 2 values needs the export capability.
2. Set `pii_vault.key_mode = 'transit'` and reload.
3. Re-encrypt every value, for example
   `UPDATE customer SET full_name = piitext_reencrypt(full_name), email = piitext_reencrypt(email);`
   On large tables, do this in batches.
4. Detach `pg-pii-vault.hcl`.

Keep two limitations in mind:

- Keys created in `export` mode stay exportable in Vault, because Transit cannot revoke exportability.
  For the guarantee that keys never leave Vault, use `transit` mode from the start, on a mount whose keys
  were all created in `transit` mode.
- Switching back to `export` fails for keys created in `transit` mode, because they cannot be exported
  (SQLSTATE `38000`).

## SQL API reference

The "Default EXECUTE" column shows who can call each function after `CREATE EXTENSION`. "Superuser" means
that `EXECUTE` is revoked from `PUBLIC`: grant it explicitly to the roles that need it.

| Function | Description | Default EXECUTE |
|---|---|---|
| `piitext_encrypt(plaintext text, key_id bytea) → piitext` | Encrypts with the latest version of the Vault key named `hex(key_id)`. Creates the key if it is missing (`pii_vault.auto_create_keys`). NULL plaintext returns NULL. A NULL key id with non-NULL plaintext is an error. Plaintext is limited to 16 MiB (512 KiB in transit mode). | superuser |
| `piitext_out_text(piitext) → text` | Decrypts; also backs the explicit casts `::text` and `::varchar`. Returns `****` only if the key that encrypted the value, or that key version, no longer exists in Vault. Any other failure is an error. Never creates keys. Returns staging values as they are. | superuser |
| `piitext_encrypt_piitext(value piitext, key_id bytea) → piitext` | Encrypts a staging value, or re-encrypts a value under another key id. Fails for shredded values. | superuser |
| `piitext_reencrypt(piitext) → piitext` | Re-encrypts with the latest version of the value's own key, in the current key mode. Asks Vault for the latest version unless the key was fetched in the last two seconds, and never creates the key: if it was shredded meanwhile, the call fails. Use it after a rotation, for 0.0.x values or to change the key mode. | superuser |
| `piitext_shred(key_id bytea) → boolean` | Crypto-shreds: deletes the Vault key. Returns `true` if the key was deleted and `false` if it did not exist. Immediate, and not undone by `ROLLBACK`. | superuser |
| `piitext_cache_invalidate() → boolean` | Makes every backend of the cluster drop its cached keys. Returns `false` if the library is not preloaded; then only this backend is flushed. | superuser |
| `piitext_vault_check() → TABLE(check_name text, ok boolean, required boolean, detail text)` | Checks the deployment: preloading, token, endpoint, TLS, Vault reachability, that the mount is a Transit engine (and the expected one), access to it, token validity, and the policy capabilities for the key mode. The deployment is healthy when every `required` row is `ok`. Touches no real key. | superuser |
| `piitext_in_text(text) → piitext` | Builds a plaintext staging value, which is not encrypted, for migrations. Refused when `pii_vault.allow_staging = off`. Limited to 16 MiB. | `PUBLIC` |
| `piitext_is_encrypted(piitext) → boolean` | Returns `true` for encrypted values and `false` for staging values. | `PUBLIC` |
| `piitext_key_id(piitext) → bytea` | Returns the key id, or NULL for staging values. | `PUBLIC` |
| `piitext_key_version(piitext) → bigint` | Returns the Vault key version used, or NULL for staging values and values written by 0.0.x. | `PUBLIC` |
| `piitext_debug(piitext) → text` | Describes a value (format, key id, key version, ciphertext size). Never shows the plaintext. | `PUBLIC` |
| `piitext_raw(piitext) → bytea` | Returns the stored bytes: CBOR for encrypted values, UTF-8 for staging values. | `PUBLIC` |
| `piitext_cache_evict(key_id bytea) → boolean` | Removes one key from this backend's cache. | `PUBLIC` |
| `piitext_cache_flush() → bigint` | Empties this backend's cache and returns the number of keys removed. | `PUBLIC` |
| `piitext_stats() → TABLE(metric text, backend bigint, cluster bigint)` | Returns `cache_entries`, `cache_hits`, `cache_misses`, `cache_evictions`, `vault_requests`, `vault_errors`, `vault_denied`, `keys_created`, `keys_shredded` and `decrypt_masked`. `cluster` is NULL if the library is not preloaded. | `PUBLIC` |
| `piitext_send(piitext) → bytea`, `piitext_recv(internal) → piitext` | Binary I/O functions of the type. Like the text input function, `piitext_recv` refuses staging values when `pii_vault.allow_staging = off`. | `PUBLIC` |

Errors are raised with these SQLSTATEs:

| SQLSTATE | Meaning |
|---|---|
| `55000` | Configuration error: URL or token missing, token file unreadable, plain HTTP to a non-loopback host, `pii_vault.mount` not a Transit engine, or a mount accessor other than `pii_vault.mount_accessor`. Also raised when staging values are disabled. |
| `22023` | Invalid argument: empty or NULL key id, key id longer than 128 bytes, value larger than 16 MiB (512 KiB in transit mode), or `piitext_reencrypt()` on a staging value. |
| `22P02` | Invalid `piitext` text input. |
| `XX001` | Corrupted value: undecodable, beyond the limits of its format, or, on input, not in the encoding pg_pii_vault writes. |
| `42501` | Vault answered 401 or 403: the token is invalid, expired or revoked, its policy does not allow the operation, or no secrets engine is mounted at `pii_vault.mount`. |
| `58000` | Vault unavailable: network error, timeout, TLS failure, HTTP 412/429/5xx after retries, or too many earlier requests of the session still running after a cancellation. Safe to retry. |
| `38000` | Unexpected Vault response, for example a redirect, a 404 that does not come from the Transit engine, or a key that is not exportable or not of type `aes256-gcm96`. |
| `42704` | Key not found: encrypting with `pii_vault.auto_create_keys = off`, or re-encrypting a shredded value. |

## Configuration reference

All settings are superuser-only. Set them in `postgresql.conf`, or with `ALTER DATABASE` / `ALTER ROLE
... SET` issued by a superuser. Never put the token itself in SQL: `SET` statements can be logged, and
`ALTER ROLE/DATABASE ... SET` values are stored in `pg_db_role_setting`, which every role can read. Unknown
`pii_vault.*` names are rejected.

| Setting | Default | Meaning |
|---|---|---|
| `pii_vault.url` | `''` | Vault base URL. Requires `https://`. Plain `http://` is accepted only for a loopback address (a local Vault Agent) or when `allow_insecure_http` is on. |
| `pii_vault.token_file` | `''` | File that contains the Vault token. Read on every Vault request, so token rotation needs no reload. Used when `pii_vault.token` is empty. |
| `pii_vault.token` | `''` | The Vault token. Only superusers and members of `pg_read_all_settings` (which includes `pg_monitor`) can read it. Prefer `token_file`. |
| `pii_vault.mount` | `'transit'` | Mount path of the Transit secrets engine. It must be the mount point of a Transit engine. |
| `pii_vault.mount_accessor` | `''` | Expected accessor of that mount (for example `transit_4a1b2c3d`). When set, a mount with another accessor is refused, so a wrong server, namespace or mount raises an error instead of masking every value. Recommended in production. |
| `pii_vault.namespace` | `''` | Vault Enterprise or HCP Vault namespace, sent as `X-Vault-Namespace`. |
| `pii_vault.key_mode` | `'export'` | `export` or `transit`; see [Choosing a key mode](#choosing-a-key-mode). |
| `pii_vault.ca_file` | `''` | PEM bundle of the CAs trusted for Vault's TLS certificate. Replaces the OS trust store. Empty means the OS trust store is used. |
| `pii_vault.client_cert_file`, `pii_vault.client_key_file` | `''` | PEM client certificate and private key for mutual TLS. Set both. |
| `pii_vault.timeout_ms` | `5000` | Timeout for one Vault HTTP request, from 100 to 600000 ms. Waiting queries can still be cancelled. |
| `pii_vault.max_retries` | `2` | Retries, from 0 to 10, for connection errors and HTTP 412/429/5xx, with backoff. |
| `pii_vault.cache_ttl_sec` | `300` | Export mode: how long a backend keeps a key, from 0 to 86400 s; 0 disables caching. Also bounds how long backends that do not see the shred can still decrypt after shredding: backends of other clusters and standbys, or of this cluster if the library is not preloaded. |
| `pii_vault.cache_max_entries` | `10000` | Export mode: the maximum number of keys cached per backend; 0 disables caching. |
| `pii_vault.auto_create_keys` | `on` | Encryption creates missing keys. Decryption never creates keys. |
| `pii_vault.allow_staging` | `on` | `off` refuses plaintext staging values on every way in: `piitext_in_text()`, the type's text input (literals, `COPY`, `pg_restore`) and binary input. It does not stop a staging value that already exists from being copied (`INSERT ... SELECT`, a column default or prepared statement created earlier); a `CHECK (piitext_is_encrypted(col))` constraint does. |
| `pii_vault.allow_insecure_http` | `off` | Allows `http://` to non-loopback hosts. For development only. |

## Security model

- **What is protected.** Encrypted values are protected in table files, WAL, replicas, dumps and backups
  against anyone who lacks decryption rights. `SELECT` alone returns ciphertext. Crypto-shredding makes
  the values of one data subject permanently unreadable.
- **Who can still decrypt.** Superusers, the operating system user of the database server, and anyone
  who holds the Vault token can decrypt every value the token can reach. In `export` mode, key material is
  also present in backend memory. There it is zeroed when dropped and cached for at most
  `pii_vault.cache_ttl_sec`. A token holder can also export keys, and shredding cannot revoke copies made
  that way. In `transit` mode, keys stay in Vault, and Vault audits every decryption.
- **What authenticated data binds.** It binds the format version, key id and key version. Transit mode
  uses associated data specific to this extension, so values that other applications encrypted with the
  same Transit keys cannot be decrypted through the database. It does not bind a value to a row: an
  encrypted value copied into another row still decrypts there.
- **What shredding does not cover.**
  - Staging values.
  - Plaintext that existed before encryption: old row versions, WAL and backups made before encryption,
    and application logs.
  - Vault snapshots taken before the key was deleted. How long you keep snapshots bounds how long erased
    data can still be recovered.

The full threat model is in [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

## Limitations

- **No operators on `piitext`.** There are no equality or ordering operators, so `=`, `DISTINCT`,
  `GROUP BY`, `ORDER BY`, `UNION` (without `ALL`), indexes and unique constraints on `piitext` columns
  do not work. Compare decrypted text instead, for example `email::text = $1`, which decrypts every row
  it examines. Decrypted values cannot be indexed or stored in generated columns.
- **UTF8 databases only.** `CREATE EXTENSION` refuses databases with other encodings.
- **Vault round trips.** In export mode, each distinct key costs one Vault round trip per backend and
  cache period, and a new key costs three. In transit mode, each value costs one round trip. Reading N
  rows that use N distinct keys means N Vault requests. Plan bulk jobs and Vault capacity accordingly.
- **Staging values are plaintext.** Values created with `piitext_in_text()` appear in base64 to anyone
  who can `SELECT` them, and shredding does not cover them. Plaintext written before encryption remains in
  WAL, backups, replicas and dead tuples until they expire or are vacuumed.
- **No automatic encryption.** The extension has no triggers. The application, or a trigger that you
  write, calls `piitext_encrypt()`.
- **Changing the key space makes values unreadable.** `pii_vault.url`, `pii_vault.mount` and
  `pii_vault.namespace` select the key space. Pointed at another Transit engine (another Vault server,
  namespace or mount), the extension reads existing values as `****`, because their keys really are
  absent there, unless `pii_vault.mount_accessor` is set: then it raises an error. A path that is not a
  Transit engine, or that the token may not use, always raises an error. Either way the values are
  readable again once the setting is restored.
- **Shredded values still cost Vault requests.** A backend remembers that a key is absent for at most 30
  seconds, so reads of shredded values cost one Vault request per key and backend every 30 seconds.
  Delete shredded rows, or set their `piitext` columns to NULL, if they are read often.
- **Size limits.** Plaintext is limited to 16 MiB per value, and to 512 KiB in transit mode (Vault
  limits the size of JSON strings). Key ids are 1 to 128 bytes.

## Compatibility

- PostgreSQL 14, 15, 16, 17 and 18, with `UTF8` databases.
- HashiCorp Vault with the Transit secrets engine, including Vault Enterprise and HCP namespaces. Tested
  with Vault 2.1.1. The shipped policies need Vault 1.1 or later (`+` path segments), and transit mode
  needs Vault 1.13 or later (`associated_data`).
- Linux, on x86-64 and arm64. macOS works for development. Windows is not supported.
- Built with pgrx 0.16.1. Building requires cargo-pgrx 0.16.1 exactly.

## Testing

```sh
cargo pgrx test pg18        # or pg14, pg15, pg16, pg17
```

The tests start a temporary PostgreSQL cluster with the library preloaded. They exercise the Vault code
paths against a fake Vault server that runs inside the test process. `mock://` URLs exist only in test
builds.

To also run the end-to-end tests against a real Vault dev server, enable Transit at `transit/` and set
`PII_VAULT_TEST_URL`:

```sh
vault server -dev -dev-root-token-id=root &
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root vault secrets enable transit
PII_VAULT_TEST_URL=http://127.0.0.1:8200 PII_VAULT_TEST_TOKEN=root cargo pgrx test pg18
```

| Variable | Purpose | Default |
|---|---|---|
| `PII_VAULT_TEST_URL` | Vault address. Setting it enables the real-Vault tests. | unset (tests skipped) |
| `PII_VAULT_TEST_TOKEN` | Token for export mode, ideally with `pg-pii-vault.hcl` and `pg-pii-vault-shred.hcl` | `root` |
| `PII_VAULT_TEST_TRANSIT_TOKEN` | Token for transit mode, ideally with `pg-pii-vault-transit.hcl` and `pg-pii-vault-shred.hcl` | `PII_VAULT_TEST_TOKEN` |
| `PII_VAULT_TEST_ADMIN_TOKEN` | Token that rotates keys during the tests | `PII_VAULT_TEST_TOKEN` |

## Documentation

- [USAGE.md](USAGE.md): usage guide with more examples.
- [docs/OPERATIONS.md](docs/OPERATIONS.md): operations guide for production deployments.
- [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md): security model and threat analysis.
- [UPGRADING.md](UPGRADING.md): upgrading from 0.0.x.
- [CHANGELOG.md](CHANGELOG.md): changes in each release.
- [DOCKER.md](DOCKER.md): Docker image and local demo.
- [SECURITY.md](SECURITY.md): how to report a vulnerability.

## License

MIT, see [LICENSE](LICENSE).

## Author

Vitalii Velicodnii
