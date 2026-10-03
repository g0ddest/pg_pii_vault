# Security model

This document describes what pg_pii_vault 0.1 protects, against whom, and what it relies on. It is
written for the operators and developers who deploy the extension. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

The examples and messages below come from PostgreSQL 18.1 with the library preloaded, Vault 2.1.1 and
the policy files in [`vault/policies/`](../vault/policies/). PostgreSQL's own error texts differ
slightly between versions.

Contents:

1. [Overview](#1-overview)
2. [Assets](#2-assets)
3. [Trust boundaries](#3-trust-boundaries)
4. [What the extension protects against](#4-what-the-extension-protects-against)
5. [What it does not protect against](#5-what-it-does-not-protect-against)
6. [Cryptography](#6-cryptography)
7. [Key modes: export and transit](#7-key-modes-export-and-transit)
8. [Privilege model](#8-privilege-model)
9. [Network](#9-network)
10. [Vault policies](#10-vault-policies)
11. [Logging](#11-logging)
12. [Hardening checklist](#12-hardening-checklist)

## 1. Overview

A `piitext` column stores values encrypted with AES-256-GCM. The caller chooses a key id for each value,
normally the identifier of the data subject. The key id names a HashiCorp Vault Transit key: the Vault
key name is the hex encoding of the key id. Deleting that key in Vault makes every value encrypted with it
unreadable (crypto-shredding). Such values read as `****`.

`pii_vault.key_mode` selects how new values are encrypted:

- `export` (default): the backend exports the key from Vault, caches it for up to
  `pii_vault.cache_ttl_sec` and encrypts locally.
- `transit`: Vault encrypts and decrypts. Key material never leaves Vault.

In short:

- Only roles with `EXECUTE` on `piitext_out_text(piitext)` can decrypt. The privilege is revoked from
  `PUBLIC`. Every other role, including members of `pg_read_all_data`, reads ciphertext.
- Superusers, the database host, Vault, and whoever holds the extension's Vault token are trusted.
- The extension does not bind a value to its row and does not encrypt staging values. It has no control
  over plaintext outside sealed values: before encryption, after decryption and in logs.

## 2. Assets

| Asset | Where it exists | Protection |
|---|---|---|
| PII plaintext | The application; the client connection; backend memory while a value is encrypted or decrypted; Vault request bodies in transit mode; staging values | Tables, WAL, backups and replicas hold it only as ciphertext, except staging values and plaintext written before encryption (section 5). |
| Key material | Vault Transit keys of type `aes256-gcm96`, one per key id, with every version kept for decryption | Export mode: copied into each backend that uses the key and cached for up to `pii_vault.cache_ttl_sec` (default 300 s). Transit mode: stays in Vault. Vault storage and Vault snapshots hold it, including keys deleted after the snapshot was taken. |
| Vault token | `pii_vault.token_file` (or `pii_vault.token`), backend memory, the `X-Vault-Token` header | Grants, for every key of the mount: export (export mode) or encrypt and decrypt (transit mode), key creation, and key deletion if the shred policy is attached. Key names are predictable, so the token reaches all keys of the mount, not only the keys in use. |

The following is not secret. Every role that can read a `piitext` column can see it:

- The key id and key version of each value (`piitext_key_id()`, `piitext_key_version()`). Key ids also
  appear in Vault request paths, Vault audit logs and error messages.
- The length of each value. AES-GCM does not pad: for a format 2 value, `piitext_debug()` reports
  `ciphertext_bytes` equal to the length of the plaintext in bytes.
- Which values belong to the same data subject.

Encryption is randomized: equal plaintexts give different ciphertexts, so equal values cannot be
recognized.

## 3. Trust boundaries

| Actor | What it can do | Trust |
|---|---|---|
| Roles without `EXECUTE` on `piitext_out_text`: reporting, BI and backup roles, `pg_read_all_data`, logical replication subscribers | Read ciphertext and the metadata listed in section 2 | Not trusted with plaintext |
| Roles with `EXECUTE` on `piitext_out_text`, directly or through membership, and any SQL that runs as them, including `SECURITY DEFINER` functions they own | Decrypt every value they can read, and any `piitext` value they obtain elsewhere (for example from a dump) whose key the token can reach | Trusted with plaintext |
| Roles with `EXECUTE` on `piitext_encrypt`, `piitext_encrypt_piitext` or `piitext_reencrypt` | Write authentic values under any key id; create Vault keys while `pii_vault.auto_create_keys = on` | Trusted with the key namespace |
| Roles with `EXECUTE` on `piitext_shred` | Irreversibly delete any key of the mount, if the token has the shred policy | Trusted with erasure |
| Superusers; roles with `pg_read_server_files`, `pg_write_server_files` or `pg_execute_server_program` | Read the token file, change `pii_vault.*` settings, decrypt everything, and in export mode export any key of the mount | Fully trusted |
| Roles with `pg_read_all_settings`, which includes `pg_monitor` | Read `pii_vault.token` if the token is set as a parameter | Keep the token out of parameters |
| Roles with `CREATEROLE` on PostgreSQL 14 and 15 | Grant themselves membership in any non-superuser role, including decrypting roles | Treat as trusted |
| The operating system account of PostgreSQL, and root on the database host | Read the token file and backend memory | Fully trusted (section 7 compares the impact per key mode) |
| Vault and its operators | Hold all keys | Fully trusted |
| Network between PostgreSQL and Vault | Carries the token, and key material (export mode) or plaintext (transit mode) | Untrusted: TLS required (section 9) |
| Network between clients and PostgreSQL | Carries plaintext PII in both directions | Untrusted: require TLS |

A view does not pass the decryption privilege to its readers: PostgreSQL checks `EXECUTE` on functions
used in a view against the role that queries the view. A `SECURITY DEFINER` function does pass it,
because it runs with its owner's privileges.

## 4. What the extension protects against

### 4.1 Reading PII without the decryption privilege

`SELECT`, `COPY`, `pg_dump`, `format()`, `concat()` and `to_json()` return the text form of the stored
bytes: `piitext:` followed by base64. Every path to plaintext goes through `piitext_out_text`: calling it,
the casts `::text` and `::varchar`, and the `||` operator with a text operand, which PostgreSQL
implements with a `::text` cast. For a role with `SELECT` on the table but without `EXECUTE` on
`piitext_out_text`:

```sql
SELECT email FROM customer WHERE id = 1;
--  piitext:pmF2AmFrSQEAAAAAAAAAAWJrdgFhaU...

SELECT email::text FROM customer WHERE id = 1;
-- ERROR:  permission denied for function piitext_out_text
```

The same holds for members of `pg_read_all_data` and for `pg_dump` run by such a role.

### 4.2 Copies of the storage

Table files, WAL, base backups, `pg_dump` output, and physical and logical replicas contain sealed values
only as ciphertext. Reading them requires the Vault key and a token that can use it. This covers stolen
or discarded disks, storage snapshots and backup media, with the exceptions in section 5: staging values,
plaintext written before encryption, temporary files and memory dumps.

A restored backup is readable only with the same Vault keys. Back up Vault (for example with Raft
snapshots): if Vault is lost, all encrypted data is lost.

### 4.3 Erasure (crypto-shredding)

Deleting a key in Vault makes every value encrypted with it return `****`: in every table and database
that uses the key, and in every backup and replica. `piitext_shred(key_id)` deletes the key from SQL; the
token needs the shred policy (section 10). When the deletion takes effect:

| Where | Reads return `****` |
|---|---|
| Vault | Immediately |
| Transit mode (format 3 values) | On the next read: nothing is cached |
| Export mode, the cluster that called `piitext_shred()`, library preloaded | Immediately: every backend drops its cached copy of the key, also if the call fails or is cancelled after the deletion was requested |
| Export mode, other clusters and standbys, or library not preloaded | Within `pii_vault.cache_ttl_sec`, or at once after `SELECT piitext_cache_invalidate();` in that cluster |

`piitext_shred()` is not transactional:

```sql
BEGIN;
SELECT piitext_shred('\x01'::bytea || int8send(2));   -- t
ROLLBACK;                                              -- the key stays deleted
SELECT email::text FROM customer WHERE id = 2;         -- ****
```

Erasure is complete only when no copy of the key remains. Vault snapshots taken before the deletion still
contain the key. In export mode, a key that was copied out of Vault cannot be revoked (section 5).
Raising `min_decryption_version` on a Vault key also masks values of the older versions, but it can be
undone; deleting the key and trimming versions cannot.

### 4.4 Tampering with stored values

AES-GCM authenticates the ciphertext together with the format version, key id and key version
(section 6.2). A value whose ciphertext or header was modified, or which was moved under another key id,
never decrypts to attacker-chosen plaintext. It reads as `****`, like a shredded value, and increments
the `decrypt_masked` counter of `piitext_stats()`. A value that is not structurally valid raises an error
with SQLSTATE `XX001`. An unexpected rise of `decrypt_masked` therefore indicates tampering or a key
deleted outside the normal process.

### 4.5 Accidental plaintext writes and silent failures

- There is no cast from `text` to `piitext`. Writing a `text` expression into a `piitext` column fails
  with `column "email" is of type piitext but expression is of type text`. Encryption is always an
  explicit `piitext_encrypt()` call.
- There are no operators on `piitext`: comparisons such as `email = '...'` or `email LIKE '...'` fail
  instead of decrypting. Decryption happens only through the paths listed in 4.1.
- If Vault is unreachable, denies the request or is misconfigured, decryption raises an error instead of
  returning `****`, so an `UPDATE` cannot write the mask back over real data. This includes a wrong
  `pii_vault.mount` and a 404 answered by a proxy or load balancer instead of Vault. Only a key or key
  version that the Transit engine itself reports as missing, or a value that fails authentication, reads
  as `****`, and only after the extension has checked that the mount is a Transit engine. Section 6.3
  lists the two cases in which a value reads as `****` although its key was not deleted.

### 4.6 Configuration changes by non-superusers

Every `pii_vault.*` parameter can be changed only by a superuser: in the configuration files, with `SET`,
or with `ALTER ROLE` or `ALTER DATABASE ... SET` issued by a superuser. A non-superuser cannot point the
extension at another Vault server, weaken TLS, change the key mode or re-enable staging:

```sql
SET pii_vault.url = 'https://vault.attacker.example';
-- ERROR:  permission denied to set parameter "pii_vault.url"
```

The same error applies to `set_config()`, to `SET` clauses of functions, and to `ALTER ROLE ... SET` on
one's own role. On PostgreSQL 15 and later the `pii_vault` prefix is reserved, so a misspelled parameter
name is an error instead of a silently ignored setting:

```sql
SET pii_vault.tokne = 'x';
-- ERROR:  invalid configuration parameter name "pii_vault.tokne"
-- DETAIL:  "pii_vault" is a reserved prefix.
```

On PostgreSQL 14, unknown names only produce a warning when the library is loaded.

### 4.7 Token leaks on the way to Vault

The token is sent only to `pii_vault.url`. Plain `http://` is refused unless the host is a loopback
address, redirects are not followed, and proxy environment variables are ignored (section 9). Request
paths are built from the validated mount and namespace and from the hex-encoded key id, so SQL input
cannot change where a request goes.

## 5. What it does not protect against

1. **Superusers and equivalent roles.** They can read the token, change `pii_vault.url`, or call Vault
   directly. Section 3 lists the roles that are equivalent.
2. **SQL that runs with the decryption privilege.** Compromised application credentials, SQL injection
   in the application, `SECURITY DEFINER` functions and role membership all give plaintext. The
   privilege is not limited to tables: a role with `EXECUTE` on `piitext_out_text` also decrypts a
   `piitext` value it copied from a dump, a log or another database that uses the same mount.
3. **A compromised database host.** In export mode the attacker obtains the keys cached in backend
   memory and, with the token, can export every key of the mount. Those copies stay usable after the key
   is deleted in Vault, so crypto-shredding cannot revoke them. In transit mode the attacker can decrypt
   through Vault until the token is revoked, but obtains no key material. In both modes the attacker sees
   all plaintext the database processes while the host is compromised.
4. **Moving sealed values between rows.** The associated data binds the format, key id and key version,
   not the database, table, column or row. A role that can update the column can copy a sealed value
   into another row, where it decrypts normally. A `CHECK` constraint that ties the key id to the row
   (section 12, item 9) limits this to values of the same data subject.
5. **Staging values.** A staging value is plaintext. Its text form is the base64 of the plaintext, and
   `piitext_raw()` returns the bytes, to any role with `SELECT`, without `EXECUTE` on any function.
   Staging values are accepted while `pii_vault.allow_staging` is on, which is the default. With
   `pii_vault.allow_staging = off` every way in is closed: `piitext_in_text()`, and staging payloads given
   to the type's input functions through literals, `COPY`, `pg_restore`, binary input and logical
   replication:

   ```sql
   SET pii_vault.allow_staging = off;                    -- as a superuser
   SELECT piitext_in_text('x');
   -- ERROR:  plaintext piitext values are disabled (pii_vault.allow_staging = off)
   SELECT 'piitext:eA=='::piitext;                       -- a staging value holding 'x'
   -- ERROR:  plaintext piitext values are disabled (pii_vault.allow_staging = off)
   ```

   The setting controls how values enter the database, not what is stored. Staging values that are
   already stored stay readable until they are encrypted, and they can still be copied: with
   `INSERT ... SELECT`, or through a column default or a prepared statement created while staging was
   on. Only a `CHECK (piitext_is_encrypted(column))` constraint (section 12, item 9) guarantees that a
   column holds no staging value.
6. **Plaintext written before encryption.** Staging values, plaintext columns being migrated and old row
   versions stay in WAL, WAL archives, base backups, replicas and dead tuples until retention expires and
   `VACUUM` removes them. Crypto-shredding covers sealed values only.
7. **Plaintext after decryption.** The extension has no control over decrypted text: application memory,
   logs, caches, exports and error reports; tables or materialized views filled with decrypted values;
   extended statistics on a decrypting expression (`CREATE STATISTICS ... ON (email::text)`: `ANALYZE`
   stores samples of the plaintext); temporary files written by sorts and hashes over decrypted values;
   strings built with `||`. PostgreSQL refuses indexes and stored generated columns on decrypted values,
   because decryption is not `IMMUTABLE`, but it accepts the other objects.
8. **Logs.** Statement text with literal PII, bind parameter values and details of constraint violations
   can reach the server log (section 11).
9. **Metadata.** Key ids, key versions, value lengths and which values share a data subject (section 2).
10. **Other Vault clients of the same mount.** Any Vault identity that can export a key, or use it
    through `transit/encrypt` and `transit/decrypt`, can decrypt database values it obtains. It can also
    create values that the database accepts as authentic, because the associated data is fixed and
    documented (section 6.2). Treat one Transit mount as one trust domain.
11. **Badly chosen key ids.** If two data subjects share a key id, shredding one erases the other. If one
    subject has several key ids, erasure must delete all of them (section 6.4).

## 6. Cryptography

### 6.1 Algorithms

- AES-256-GCM with a 128-bit authentication tag. The keys are Vault Transit keys of type `aes256-gcm96`.
- Export mode (format 2): the backend exports every decryptable version of the key
  (`GET <mount>/export/encryption-key/<name>`) and encrypts with the latest version, using the RustCrypto
  `aes-gcm` implementation. Each value gets a fresh random 96-bit IV from `pg_strong_random()`,
  PostgreSQL's cryptographically secure random source. Encryption fails if no random bytes are
  available.
- Transit mode (format 3): the backend sends the plaintext and the associated data to
  `POST <mount>/encrypt/<name>`. Vault encrypts with the latest key version and a nonce it generates, and
  returns `vault:v<N>:<base64>`, which is stored unchanged. Decryption sends it to
  `POST <mount>/decrypt/<name>` with the same associated data.
- With random 96-bit IVs, NIST SP 800-38D limits one key version to 2^32 encryptions. Keys per data
  subject stay far below this limit; do not use one key id for a very large number of values.

### 6.2 Stored formats and associated data

A stored value is either a staging value (raw UTF-8, not encrypted) or a sealed value (a CBOR map). A CBOR
map starts with a byte that cannot start UTF-8 text, so the two kinds cannot be confused. The text form
used by `SELECT`, `COPY` and `pg_dump` is `piitext:` followed by the base64 of the stored bytes.

| Format | Written by | Fields | Associated data (AAD) |
|---|---|---|---|
| 1 | pg_pii_vault 0.0.x | `v`, key id `k`, IV `i`, tag `t`, ciphertext `c` | `col:piitext:id:<hex key id>` |
| 2 | 0.1.0 and later, `key_mode = export` | as format 1, plus key version `kv` | `pg_pii_vault:v2:<hex key id>:<key version>` |
| 3 | 0.1.0 and later, `key_mode = transit` | `v`, `k`, `kv`, and `c` holding the Vault ciphertext `vault:v<N>:...` | `pg_pii_vault:v3:<hex key id>`, sent to Vault as `associated_data` |

A higher format number is rejected as corrupted. Values of every format stay readable whatever
`pii_vault.key_mode` is, provided that the token has the capabilities they need (section 7).
`piitext_reencrypt()` rewrites a value in the format of the current mode.

Every value is checked when it is read: unknown fields, a key id longer than the format allows (128
bytes; 1024 for format 1), a ciphertext longer than any value, or a format 3 value whose recorded key
version does not match its Vault ciphertext (`vault:v<N>:` followed by base64, nothing else) are
rejected with SQLSTATE `XX001`. Values that enter through the type's input functions must also be in
exactly the encoding the extension writes. So no other data can travel inside a sealed value, and a
format 3 ciphertext cannot alter the request sent to Vault.

`piitext_is_encrypted()` checks this format, not authenticity. A role that may write a column can store
any well-formed sealed value, whose ciphertext field holds whatever bytes it chose; it decrypts to `****`.

What the associated data binds:

- The format version. Relabelling a value as another format is rejected or fails authentication.
- The key id. Changing the key id in the header, or moving the ciphertext under another key id, fails
  authentication.
- The key version, in format 2. In format 3, Vault selects the key version from the `vault:v<N>:` prefix
  of its ciphertext; the `kv` field is informational and used by `piitext_key_version()`.
- Nothing about the database, table, column or row (section 5, item 4).

The transit-mode AAD also separates this extension's ciphertexts from those of other applications that
use the same Transit keys. A Transit ciphertext produced without this AAD reads as `****` when it is
placed in a `piitext` value. Conversely, a Vault client that uses the same AAD produces values that the
database accepts.

### 6.3 Decryption outcomes

| Situation | Result |
|---|---|
| The key and key version exist and the value authenticates | Plaintext |
| The key was deleted, the key version was trimmed or is below `min_decryption_version`, or the value does not authenticate with the keys currently in Vault | `****`, and `decrypt_masked` increases |
| The value is structurally invalid (bad CBOR, wrong IV or tag length, Vault reports `invalid ciphertext`) | Error, SQLSTATE `XX001` |
| Vault unreachable or timing out, HTTP 401 or 403, redirect, misconfiguration, no Transit engine at `pii_vault.mount`, a 404 that does not come from the Transit engine | Error, SQLSTATE `58000`, `42501`, `38000` or `55000` |

How the extension decides that a key is gone:

- First, each backend checks that `pii_vault.mount` is the mount point of a Transit engine, and that
  it has the accessor in `pii_vault.mount_accessor` if that is set. Other engines, such as KV or
  cubbyhole, answer requests for missing keys exactly like Transit does, and accept the requests that
  would create or delete keys.
- Export mode: the export request is answered with HTTP 404 and an error list that is empty and the
  only field of the body (`{"errors":[]}`). Any other 404, for example an error page from a proxy, is an
  error.
- Transit mode: the decrypt request is answered with HTTP 400 and exactly one of Vault's messages:
  `encryption key not found` (the key is gone), `cipher: message authentication failed`,
  `ciphertext or signature version is disallowed by policy (too old)` or
  `invalid ciphertext: version is too new` (the key exists but cannot decrypt this value). Any other
  answer is an error, including the same words in another body.
- In export mode, a value that fails to authenticate with a cached key is retried with keys fetched from
  Vault before it is reported as `****`.

Two situations give `****` although the key was not deleted. The extension cannot tell them apart from
erasure, so operators must prevent them:

- **The extension is pointed at another key space.** If `pii_vault.url`, `pii_vault.namespace` or
  `pii_vault.mount` names a different Transit engine that the token may use, the keys really are absent
  there and every value reads as `****`. Set `pii_vault.mount_accessor` to the accessor of the right
  mount: the extension then refuses any other mount with an error. Treat these settings as part of the
  data: change them only together with a migration of the keys.
- **A Vault standby that lags behind.** Vault Enterprise performance standbys answer reads from their
  own, eventually consistent state. A key created a moment ago may be unknown to a standby, so a value
  written with a new key can read as `****` for an instant when it is read through that standby by
  another backend. Point `pii_vault.url` at the active node, or at a load balancer that sends requests
  to it.

### 6.4 Key ids

A key id is 1 to 128 bytes of `bytea`. The Vault key name is its lowercase hex encoding:

```sql
SELECT encode('\x01'::bytea || int8send(42), 'hex');   -- 01000000000000002a
```

Key ids are not secret, but the guarantees depend on choosing them well:

- Use one key id per data subject, for all of that subject's values in all tables, so that one deletion
  erases all of them. For example `int8send(customer_id)` or `uuid_send(subject_uuid)`.
- Entity types with overlapping identifiers (customer 42 and employee 42) must not share a key. Add a type
  prefix, for example `'\x01'::bytea || int8send(id)`, or use separate mounts.
- Keep the encoding stable: `int4send(42)` and `int8send(42)` are different key ids.
- Never use PII, such as an e-mail address or a national identifier, as the key id. It is stored in clear
  in every value and appears in Vault request paths, Vault audit logs and error messages.
- Use a separate Transit mount for each application and environment: the token reaches every key of its
  mount, and key names are predictable.

### 6.5 Memory hygiene

The extension keeps key material, the Vault token, Vault request and response bodies that carry keys or
plaintext, and its intermediate plaintext buffers in memory that is overwritten when released (Rust
`zeroize`). This is best effort. The decrypted text handed to PostgreSQL is not wiped, and neither are
copies made by PostgreSQL, the TLS and HTTP libraries, the kernel, swap or core dumps. Treat backend
memory and core dumps as containing PII and, in export mode, key material.

## 7. Key modes: export and transit

| | `export` (default) | `transit` |
|---|---|---|
| Where AES-GCM runs | In the database backend | In Vault |
| Key material in the database | Every version of each key in use, cached per backend for up to `pii_vault.cache_ttl_sec` | Never |
| Keys created as | Exportable; Vault cannot make a key non-exportable again | Not exportable |
| Token capabilities (section 10) | Read `export/encryption-key/+`, update `keys/+` | Update `encrypt/+`, `decrypt/+` and `keys/+` |
| Vault round trips | One per distinct key per backend and cache period (three for a new key) | One per encrypted or decrypted value |
| Plaintext sent to Vault | No | Yes, over TLS |
| Vault audit trail | One entry per key export | One entry per encryption and decryption |
| Database host or token compromised | Attacker can export every key of the mount; the copies outlive deletion in Vault | Attacker can decrypt through Vault until the token is revoked; keys stay in Vault |
| After the token is revoked | Cached keys keep working for up to `pii_vault.cache_ttl_sec`, unless `piitext_cache_invalidate()` is run | Requests fail at once |
| Erasure takes effect | Immediately in the calling cluster when preloaded; elsewhere within `pii_vault.cache_ttl_sec` | Immediately |
| Stored format | 2 | 3 |

Switching modes:

- `pii_vault.key_mode` affects new encryptions only. Reading a format 2 value needs the export
  capability and reading a format 3 value needs the decrypt capability. With only the transit policy,
  reading a format 2 value fails:

  ```
  ERROR:  Vault denied the request: GET /v1/transit/export/encryption-key/<name> returned HTTP 403: ...
  ```

  Keep both policies attached until `UPDATE ... SET column = piitext_reencrypt(column)` has rewritten
  every value, then remove the export policy.
- Keys created in export mode stay exportable, and re-encryption keeps the key name. For the guarantee
  that key material never left Vault, use transit mode from the start, on a mount whose keys were all
  created in transit mode.
- In transit mode, `piitext_vault_check()` reports `policy_no_export`, which is `ok` only when the token
  cannot export keys.

## 8. Privilege model

### 8.1 Functions

`CREATE EXTENSION pg_pii_vault` requires a superuser: the extension is not trusted. It revokes `EXECUTE`
from `PUBLIC` on these functions:

| Function | Allows | Grant to |
|---|---|---|
| `piitext_out_text(piitext)`, and through it `::text`, `::varchar` and `\|\|` with text | Decryption | Roles that must see plaintext |
| `piitext_encrypt(text, bytea)` | Encryption; creates Vault keys while `pii_vault.auto_create_keys = on` | Writers |
| `piitext_encrypt_piitext(piitext, bytea)` | Encrypting a staging value, re-encrypting under another key id | Writers, migration jobs |
| `piitext_reencrypt(piitext)` | Re-encrypting with the latest version of the value's key | Rotation and migration jobs |
| `piitext_shred(bytea)` | Deleting Vault keys | A dedicated erasure role, if erasure runs from SQL |
| `piitext_cache_invalidate()` | Dropping the key caches of all backends | Operators |
| `piitext_vault_check()` | Reporting the token source, token TTL and policies, and the Vault endpoint | Operators |

The other functions stay executable by `PUBLIC`, and none of them decrypts: the type's input and output
functions, `piitext_send`, `piitext_recv`, `piitext_in_text` (creates staging values, subject to
`pii_vault.allow_staging`), `piitext_is_encrypted`, `piitext_key_id`, `piitext_key_version`,
`piitext_debug`, `piitext_raw`, `piitext_cache_evict` and `piitext_cache_flush` (current backend only),
and `piitext_stats`. The text form and `piitext_raw()` expose staging plaintext and the metadata of sealed
values.

Typical grants:

```sql
-- application: read and write PII
GRANT EXECUTE ON FUNCTION
    piitext_out_text(piitext),
    piitext_encrypt(text, bytea),
    piitext_encrypt_piitext(piitext, bytea),
    piitext_reencrypt(piitext)
  TO pii_app;

-- erasure: only if piitext_shred() is used and the token has the shred policy
GRANT EXECUTE ON FUNCTION piitext_shred(bytea) TO pii_erasure;

-- operations
GRANT EXECUTE ON FUNCTION piitext_vault_check(), piitext_cache_invalidate() TO pii_ops;
```

Do not make reporting, backup or monitoring roles members of these roles: members inherit `EXECUTE`.

### 8.2 Settings

- Every `pii_vault.*` parameter is superuser-only (section 4.6).
- `pii_vault.token` is also hidden: `SHOW`, `current_setting()`, `pg_settings` and `SHOW ALL` do not
  reveal it to other roles.

  ```sql
  SHOW pii_vault.token;
  -- ERROR:  permission denied to examine "pii_vault.token"
  -- DETAIL:  Only roles with privileges of the "pg_read_all_settings" role may examine this parameter.
  ```

  Members of `pg_read_all_settings` can read it, and `pg_monitor` is a member. This is one reason to
  leave `pii_vault.token` empty and use `pii_vault.token_file`.
- The library must be listed in `shared_preload_libraries`. Until the library is loaded in a backend,
  `pii_vault.*` values from the configuration files are plain placeholder settings that every role can
  read with `SHOW`, token included. Preloading defines the parameters, with their protections, before
  any session starts. A library loaded later while `pii_vault.token` is set logs a warning saying so.
  Preloading is also required for cluster-wide cache invalidation after `piitext_shred()` and for
  cluster statistics.
- The other parameters, including `pii_vault.url` and `pii_vault.token_file` (the path, not the file's
  content), are readable by every role.

### 8.3 The Vault token

Deliver the token through `pii_vault.token_file`:

- Written by Vault Agent (auto-auth with a periodic token and a file sink), or by the platform's secret
  mechanism. The file is read on every Vault request, so rotating the token needs no reload.
- Owned by the operating system account of PostgreSQL, mode `0600`, outside the data directory. Base
  backups copy the data directory, including `postgresql.auto.conf` and, in many layouts,
  `postgresql.conf`.
- Every role can see the path (`SHOW pii_vault.token_file`). Superusers can read the content, and so can
  roles with `pg_read_server_files` (`COPY ... FROM '<path>'`) or `pg_execute_server_program`.

Never put the token in SQL: not with `SET`, `ALTER SYSTEM`, `ALTER ROLE ... SET`, `ALTER DATABASE ...
SET` or a function's `SET` clause. The statement text reaches the server log and `pg_stat_statements`
(section 11), and `pg_db_role_setting` and `pg_proc.proconfig` are readable by every role. After
`ALTER ROLE ... SET pii_vault.token = '...'`, any role can read the token with:

```sql
SELECT setrole::regrole, setdatabase, setconfig FROM pg_db_role_setting;
```

If `pii_vault.token` is used at all, set it only in `postgresql.conf`, readable only by the PostgreSQL
account. The extension never writes the token into error messages or logs.

### 8.4 Auditing privileges

Roles that can execute the protected functions, directly or through inherited membership (superusers
appear with `rolsuper = t`):

```sql
SELECT r.rolname, r.rolsuper, f.fn AS function
FROM pg_roles AS r
CROSS JOIN unnest(ARRAY[
    'piitext_out_text(piitext)',
    'piitext_encrypt(text,bytea)',
    'piitext_encrypt_piitext(piitext,bytea)',
    'piitext_reencrypt(piitext)',
    'piitext_shred(bytea)',
    'piitext_cache_invalidate()',
    'piitext_vault_check()'
]) AS f(fn)
WHERE has_function_privilege(r.oid, f.fn, 'EXECUTE')
ORDER BY r.rolname, f.fn;
```

Run it in each database that has the extension, with the extension's schema on the `search_path` (or
schema-qualify the function names). Also review which roles can `SET ROLE` to the listed roles without
inheriting their privileges (`pg_auth_members`).

Non-superuser roles that can read the token outside the extension:

```sql
SELECT r.rolname,
       pg_has_role(r.oid, 'pg_read_all_settings', 'USAGE') AS reads_token_parameter,
       pg_has_role(r.oid, 'pg_read_server_files', 'USAGE')
         OR pg_has_role(r.oid, 'pg_execute_server_program', 'USAGE') AS reads_token_file
FROM pg_roles AS r
WHERE NOT r.rolsuper
  AND r.rolname NOT LIKE 'pg\_%'
  AND (pg_has_role(r.oid, 'pg_read_all_settings', 'USAGE')
       OR pg_has_role(r.oid, 'pg_read_server_files', 'USAGE')
       OR pg_has_role(r.oid, 'pg_execute_server_program', 'USAGE'));
```

## 9. Network

Between PostgreSQL and Vault:

- `pii_vault.url` must use `https://`. `http://` is accepted only for loopback hosts (`localhost`,
  `127.0.0.0/8`, `::1`), for example a Vault Agent on the same host, unless
  `pii_vault.allow_insecure_http = on`, which is for development only. The check runs on every request:

  ```sql
  SET pii_vault.url = 'http://192.0.2.10:8200';          -- as a superuser, in a test session
  SELECT piitext_encrypt('x', '\x01'::bytea || int8send(1));
  -- ERROR:  pg_pii_vault configuration error: pii_vault.url "http://192.0.2.10:8200" uses plain http to
  --         a non-loopback host; use https:// (or set pii_vault.allow_insecure_http = on for development only)
  ```

  A URL with another scheme, whitespace, a query string, a fragment or credentials (`user:password@`)
  is rejected when it is set.
- TLS is provided by rustls. The server certificate and host name are always verified; no option
  disables verification. With `pii_vault.ca_file` empty, the operating system trust store is used. A
  `pii_vault.ca_file` replaces that store, so pointing it at your internal CA bundle limits trust to
  those CAs.
- For mutual TLS, set `pii_vault.client_cert_file` and `pii_vault.client_key_file`. Setting only one of
  them is an error. The files are read again when they change. Make the key file readable only by the
  PostgreSQL account.
- Redirects are never followed. A 3xx answer is an error (SQLSTATE `38000`) and the redirect target is not
  contacted, so the token cannot be forwarded to it. Point `pii_vault.url` at the active Vault node or at a
  load balancer that forwards requests.
- `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and similar environment variables are ignored: the connection
  to Vault is always direct. There is no proxy setting.
- `pii_vault.timeout_ms` bounds each request, and waiting queries remain cancellable.
- Vault audit devices: keep the default hashing of request and response values (`log_raw` off). Export
  responses contain key material and transit-mode requests contain plaintext. Request paths, which
  contain the key names, are logged in clear.

Between clients and PostgreSQL, plaintext PII travels in both directions. Require TLS for these
connections (`hostssl` entries in `pg_hba.conf`).

## 10. Vault policies

The repository ships least-privilege policies in [`vault/policies/`](../vault/policies/). Attach to the
extension's token only the ones the deployment needs.

[`pg-pii-vault.hcl`](../vault/policies/pg-pii-vault.hcl), export mode:

```hcl
# Normal operation: export key material, create keys on first encryption.
path "transit/export/encryption-key/+" {
  capabilities = ["read"]
}
path "transit/keys/+" {
  # Creating a Transit key is an "update" (the path has no existence check).
  # "+" matches the key name only, so rotate/config/trim stay forbidden.
  capabilities = ["update"]
  allowed_parameters = {
    "type"       = ["aes256-gcm96"]
    "exportable" = [true]
  }
}
# Lets Vault Agent keep a periodic token alive. Vault's "default" policy
# grants the same; the rule matters when that policy is not attached.
path "auth/token/renew-self" {
  capabilities = ["update"]
}
# Optional: lets piitext_vault_check() inspect the token and its policy.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "sys/capabilities-self" {
  capabilities = ["update"]
}
```

[`pg-pii-vault-transit.hcl`](../vault/policies/pg-pii-vault-transit.hcl), transit mode:

```hcl
# key_mode = 'transit': Vault performs the encryption; keys never leave Vault.
path "transit/encrypt/+" {
  capabilities = ["update"]
}
path "transit/decrypt/+" {
  capabilities = ["update"]
}
path "transit/keys/+" {
  # Create non-exportable keys on first encryption ("update": no existence check).
  capabilities = ["update"]
  allowed_parameters = {
    "type" = ["aes256-gcm96"]
  }
}
# Lets Vault Agent keep a periodic token alive. Vault's "default" policy
# grants the same; the rule matters when that policy is not attached.
path "auth/token/renew-self" {
  capabilities = ["update"]
}
# Optional: lets piitext_vault_check() inspect the token and its policy.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "sys/capabilities-self" {
  capabilities = ["update"]
}
```

[`pg-pii-vault-shred.hcl`](../vault/policies/pg-pii-vault-shred.hcl), only if `piitext_shred()` is
used from the database:

```hcl
# Only if piitext_shred() is used from the database.
path "transit/keys/+/config" {
  capabilities = ["update"]
  allowed_parameters = {
    "deletion_allowed" = [true]
  }
}
path "transit/keys/+" {
  capabilities = ["delete"]
}
```

What they allow, and why:

- `update` on `transit/keys/+` only creates keys. `+` matches a single path segment, so rotating,
  reconfiguring and trimming keys stay forbidden. `transit/keys/*` would allow all of that on every key. A
  `create` capability alone does not allow creating Transit keys.
- `allowed_parameters` restricts key creation to `aes256-gcm96` and, in export mode, to
  `exportable = true`. The values are type-sensitive: `"exportable" = ["true"]`, a string, rejects the
  boolean that the extension sends. The transit policy does not allow `exportable`, so its token cannot
  create exportable keys.
- The shred policy allows only setting `deletion_allowed = true` and deleting keys. With it, the token
  can irreversibly delete every key of the mount. Without it, erase keys with a separate Vault identity:

  ```
  vault write transit/keys/<hex key id>/config deletion_allowed=true
  vault delete transit/keys/<hex key id>
  ```

  Then run `SELECT piitext_cache_invalidate();` in every cluster that uses the keys, or wait
  `pii_vault.cache_ttl_sec`.
- `auth/token/renew-self` lets Vault Agent keep the periodic token alive. Vault's `default` policy grants
  the same, so the rule only matters for tokens created without that policy. It allows a token to renew
  itself and nothing else.
- `auth/token/lookup-self` and `sys/capabilities-self` are optional. They let `piitext_vault_check()`
  report the token's TTL, policies and capabilities.
- The token can learn key metadata (versions, creation times, `min_decryption_version`) from the
  answers to key creation and, with the shred policy, to an empty configuration request, and it can tell
  whether a key exists. It cannot read key material without the export rule.
- If another process provisions the keys, set `pii_vault.auto_create_keys = off` and remove the
  `transit/keys/+` block.
- The paths assume that the Transit engine is mounted at `transit/`. Adjust them to `pii_vault.mount`.

Tokens:

- Use a periodic token that Vault Agent obtains (auto-auth, for example AppRole or Kubernetes) and writes
  to a file sink read through `pii_vault.token_file`. Restrict where the token can be used from, for
  example with `token_bound_cidrs` on the auth method's role.
- Revoking the token stops transit mode at once. In export mode, backends keep decrypting with cached
  keys for up to `pii_vault.cache_ttl_sec`. After revoking a token in an incident, run
  `SELECT piitext_cache_invalidate();` in every cluster.
- `SELECT * FROM piitext_vault_check();` checks the token and the capabilities that the configured key
  mode needs. Rows with `required = true` must be `ok`; the others are advisory.

## 11. Logging

The extension's own messages never contain the token or plaintext. They contain the Vault URL, the
request path and the key name (the hex key id). At `DEBUG1` the extension also logs the path and
duration of every Vault request. The main risk is the PostgreSQL server log:

- **Literals.** With the default `log_min_error_statement = error`, every failing statement is logged
  with its text, so a literal plaintext ends up in the log:

  ```
  ERROR:  key id must not be empty
  STATEMENT:  SELECT piitext_encrypt('ana@example.com', '\x'::bytea);
  ```

  Pass PII as bind parameters, through the extended query protocol that drivers use for prepared
  statements. The same failure then logs only the placeholder:

  ```
  ERROR:  key id must not be empty
  STATEMENT:  SELECT piitext_encrypt($1, '\x'::bytea)
  ```

- **Bind values.** Keep `log_parameter_max_length_on_error = 0`, the default. With another value, error
  reports include the parameter values (`CONTEXT:  unnamed portal with parameters: $1 = '...'`). Any
  session can change this parameter, so check driver and connection pool settings. Set
  `log_parameter_max_length = 0` if statements are logged through `log_statement`,
  `log_min_duration_statement` or statement sampling: the default, `-1`, logs bind values in full.
- **Statement logging.** Use `log_statement = 'none'` or `'ddl'` on databases with PII. `auto_explain`
  logs the query text, literals included.
- **Constraint violations** include the row in `DETAIL` (`Failing row contains (...)`): ciphertext for
  sealed values, base64 plaintext for staging values.
- **`pg_stat_statements`** replaces constants in DML statements with placeholders, but PostgreSQL 14 to
  17 store `SET` statements verbatim; PostgreSQL 18 replaces the value. `pg_stat_activity.query` shows
  the running statement, literals included, to the session's own role, superusers and members of
  `pg_read_all_stats`.
- If an application cannot avoid literals, keep statement text out of error reports for its role:

  ```sql
  ALTER ROLE pii_app SET log_min_error_statement = panic;
  ```

## 12. Hardening checklist

1. Add `pg_pii_vault` to `shared_preload_libraries` on the primary and on every standby.
2. Leave `pii_vault.token` empty. Deliver the token through `pii_vault.token_file`, written by Vault
   Agent, owned by the PostgreSQL account, mode `0600`, outside the data directory.
3. Use an `https://` URL. Set `pii_vault.ca_file` to your internal CA bundle, configure mutual TLS if
   Vault requires it, and keep `pii_vault.allow_insecure_http = off`. Set `pii_vault.mount_accessor` to
   the accessor of the Transit mount.
4. Attach only the shipped policies the deployment needs (section 10), to a periodic token, on a Transit
   mount dedicated to one application and environment. Leave out the shred policy unless erasure runs
   from SQL.
5. Choose the key mode deliberately (section 7). If key material must never leave Vault, use `transit`
   from the start and check that `policy_no_export` is `ok` in `piitext_vault_check()`.
6. Grant `EXECUTE` on the protected functions only to dedicated roles (section 8.1). Keep reporting,
   backup and monitoring roles out of them, and review with the queries in section 8.4.
7. Grant `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program` and, on
   PostgreSQL 14 and 15, `CREATEROLE` only to roles that are trusted like superusers.
8. Allow no untrusted role to create objects in the extension's schema or in any schema on the
   application's `search_path`, so that no one can place a function with a matching name and argument
   types in front of the extension's. On PostgreSQL 14 this includes
   `REVOKE CREATE ON SCHEMA public FROM PUBLIC;`.
9. Enforce encryption at rest and tie each value to its data subject, then set
   `pii_vault.allow_staging = off` once migrations are finished:

   ```sql
   ALTER TABLE customer
       ADD CONSTRAINT customer_email_sealed
           CHECK (piitext_is_encrypted(email)),
       ADD CONSTRAINT customer_email_subject
           CHECK (piitext_key_id(email) = '\x01'::bytea || int8send(id));
   ```

10. Choose key ids per data subject, with a type prefix, a stable encoding and no PII (section 6.4).
11. Pass PII to SQL as bind parameters and apply the logging settings in section 11.
12. Require TLS on client connections (`hostssl`).
13. Set `pii_vault.cache_ttl_sec` to the longest acceptable delay between erasure and unreadability on
    other clusters and standbys. After deleting or rotating keys outside `piitext_shred()`, or revoking
    a token, run `SELECT piitext_cache_invalidate();` in every cluster. Until then, backends that cached
    a rotated key keep encrypting with its previous version, and backends that cached a deleted key
    keep decrypting with it and encrypt new values with a key that no longer exists. Such new values
    are unreadable as soon as the cache entry expires, so do not reuse the key id of an erased subject
    before then.
14. Keep Vault snapshots no longer than the erasure deadline allows, and back up Vault together with the
    database: backups are unreadable without the keys.
15. After migrating plaintext into `piitext`, account for the plaintext still in WAL archives, backups
    and replicas, let it expire, and `VACUUM` the table.
16. Disable or protect core dumps of the PostgreSQL service, and encrypt swap.
17. Monitor `piitext_stats()` (`decrypt_masked`, `vault_errors`, `vault_denied`) and
    `SELECT bool_and(ok) FROM piitext_vault_check() WHERE required`, and keep a Vault audit device enabled
    with default hashing.
18. Review regularly that no object persists decrypted values: materialized views, tables filled with
    decrypted data, and extended statistics on decrypting expressions (the query in
    [UPGRADING.md, step 1.3](../UPGRADING.md#13-find-objects-that-store-decrypted-values) lists the
    objects that depend on the decryption function).

For container deployments, see [DOCKER.md](../DOCKER.md).
