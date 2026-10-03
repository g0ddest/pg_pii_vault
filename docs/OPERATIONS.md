# Operations guide

This guide is for the people who run pg_pii_vault 0.1 in production: database administrators and Vault
operators. For SQL usage see [USAGE.md](../USAGE.md), for the threat model see
[SECURITY-MODEL.md](SECURITY-MODEL.md), for container deployments see [DOCKER.md](../DOCKER.md), and for
upgrading from 0.0.0 see [UPGRADING.md](../UPGRADING.md).

The commands and outputs below were run against PostgreSQL 18 and Vault 2.1.1.

1. [Deployment checklist](#1-deployment-checklist)
2. [Vault setup](#2-vault-setup)
3. [PostgreSQL configuration](#3-postgresql-configuration)
4. [Access control](#4-access-control)
5. [Health checks and monitoring](#5-health-checks-and-monitoring)
6. [Crypto-shredding](#6-crypto-shredding)
7. [Key rotation](#7-key-rotation)
8. [Changing the key mode](#8-changing-the-key-mode)
9. [The key cache](#9-the-key-cache)
10. [Performance and capacity](#10-performance-and-capacity)
11. [Backup, restore and replication](#11-backup-restore-and-replication)
12. [When Vault is unavailable](#12-when-vault-is-unavailable)
13. [Error reference](#13-error-reference)
14. [Troubleshooting](#14-troubleshooting)

## 1. Deployment checklist

1. Vault: a Transit mount dedicated to this application and environment, the policies from
   `vault/policies/`, a periodic token delivered by Vault Agent, audit device enabled, snapshots scheduled
   ([section 2](#2-vault-setup)).
2. PostgreSQL: the extension files installed on the primary and on every standby and subscriber;
   `pg_pii_vault` in `shared_preload_libraries`; `pii_vault.url` with `https://`,
   `pii_vault.token_file` and `pii_vault.mount_accessor` set in `postgresql.conf`
   ([section 3](#3-postgresql-configuration)).
3. Databases: UTF8 encoding, `CREATE EXTENSION pg_pii_vault` as a superuser, grants for the application,
   erasure and monitoring roles ([section 4](#4-access-control)).
4. Checks: `SELECT bool_and(ok) FROM piitext_vault_check() WHERE required` returns `t` on every node, and
   it is wired into monitoring together with `piitext_stats()` ([section 5](#5-health-checks-and-monitoring)).
5. Procedures agreed and tested: erasure ([section 6](#6-crypto-shredding)), key rotation
   ([section 7](#7-key-rotation)), restore of the database together with Vault
   ([section 11](#11-backup-restore-and-replication)).
6. Hardening: the checklist in [SECURITY-MODEL.md](SECURITY-MODEL.md#12-hardening-checklist).

## 2. Vault setup

### 2.1 Transit mount

```sh
vault secrets enable -path=transit transit
```

Use one mount per application and environment. All keys of a mount form one key space: the Vault key
name is the hex encoding of the key id, so two databases that use the same mount and overlapping ids
share keys, and the extension's token reaches every key of the mount. Select the mount with
`pii_vault.mount`, and pin it with `pii_vault.mount_accessor`:

```sh
vault secrets list -format=json | jq -r '."transit/".accessor'      # transit_4a1b2c3d
```

Before it trusts any answer, and before it creates or deletes any key, each backend asks Vault which
engine serves `pii_vault.mount` (`GET sys/internal/ui/mounts/<mount>`, allowed for any token that may use
the mount) and refuses anything but the mount point of a Transit engine with the expected accessor. Other
engines, such as KV or cubbyhole, answer requests for missing keys exactly like Transit does, and some
accept the requests that create or delete keys. The check is repeated every five minutes.

The extension creates one Transit key of type `aes256-gcm96` per key id, on the first encryption for
that id. With one key per data subject, expect as many keys as data subjects
([section 10](#10-performance-and-capacity)).

### 2.2 Policies

```sh
vault policy write pg-pii-vault         vault/policies/pg-pii-vault.hcl           # export mode
vault policy write pg-pii-vault-transit vault/policies/pg-pii-vault-transit.hcl   # transit mode
vault policy write pg-pii-vault-shred   vault/policies/pg-pii-vault-shred.hcl     # only if the database shreds
```

| Rule | Purpose |
|---|---|
| `read` on `transit/export/encryption-key/+` | Export mode: fetch the key versions used to encrypt and decrypt. |
| `update` on `transit/encrypt/+` and `transit/decrypt/+` | Transit mode: Vault encrypts and decrypts. |
| `update` on `transit/keys/+`, limited by `allowed_parameters` | Create a key on the first encryption for a key id. Not needed if `pii_vault.auto_create_keys = off`. |
| `update` on `auth/token/renew-self` | Lets Vault Agent renew the periodic token. Vault's `default` policy grants the same. |
| `read` on `auth/token/lookup-self`, `update` on `sys/capabilities-self` | Optional: let `piitext_vault_check()` report the token's TTL, policies and capabilities. |
| Shred policy: `update` on `transit/keys/+/config` limited to `deletion_allowed = true`, `delete` on `transit/keys/+` | `piitext_shred()`. |

With these policies the token cannot rotate keys, change `min_decryption_version`, trim key versions,
read key configuration or list keys. In transit mode it cannot export keys, and it can only create keys
that are not exportable.

Keep these details when you adapt the policies. Each was checked against Vault:

- Creating a Transit key needs `update`. A `create` capability alone is refused.
- `allowed_parameters` values are type-sensitive. `"exportable" = [true]` must be a boolean; the string
  `"true"` rejects the request that the extension sends.
- `transit/keys/+` matches the key itself only. `transit/keys/*` would also match `…/rotate`,
  `…/config` and `…/trim` for every key.
- If the mount is not `transit/`, change the paths accordingly.
- If another process provisions keys, set `pii_vault.auto_create_keys = off` and remove the
  `transit/keys/+` block. Keys must be of type `aes256-gcm96`, and exportable for export mode.

### 2.3 The token

Use a periodic token that Vault Agent obtains and renews, written to a file that PostgreSQL reads
through `pii_vault.token_file`. The extension reads the file on every Vault request, so a new token
needs no reload.

Example with AppRole:

```sh
vault auth enable approle
vault write auth/approle/role/pg-pii-vault \
    token_policies="pg-pii-vault,pg-pii-vault-shred" \
    token_period=1h \
    token_bound_cidrs="10.0.10.0/24" \
    secret_id_bound_cidrs="10.0.10.0/24"
vault read  -field=role_id   auth/approle/role/pg-pii-vault/role-id          > /etc/vault-agent/role-id
vault write -f -field=secret_id auth/approle/role/pg-pii-vault/secret-id     > /etc/vault-agent/secret-id
```

`/etc/vault-agent/agent.hcl`:

```hcl
vault {
  address = "https://vault.example.internal:8200"
  ca_cert = "/etc/pg_pii_vault/vault-ca.pem"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path                   = "/etc/vault-agent/role-id"
      secret_id_file_path                 = "/etc/vault-agent/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "/run/vault-agent/pg-pii-vault.token"
      mode = 0640
    }
  }
}
```

```sh
vault agent -config=/etc/vault-agent/agent.hcl
```

- Run the agent as the PostgreSQL operating system user, or as a user whose group PostgreSQL belongs
  to, so that the server can read the sink file and nobody else can.
- The agent renews the token at about two thirds of its period and the file does not change. If a
  renewal fails, the agent authenticates again and writes a new token to the file.
- The token must be allowed to renew itself. The shipped policies include `auth/token/renew-self`; Vault's
  `default` policy grants it too. Without it the token expires after one period, the agent has to
  authenticate again, and until it does the file holds an expired token and every Vault request fails
  with SQLSTATE `42501`.
- Do not use a token with a fixed lifetime: it stops working when it reaches its maximum TTL (32 days by
  default).
- `piitext_vault_check()` shows the remaining lifetime in the `token_valid` row.

Kubernetes and other platforms: use the matching Vault Agent auto-auth method, or mount a secret that
your platform keeps current, and point `pii_vault.token_file` at it.

### 2.4 Network and high availability

- `pii_vault.url` must be `https://`. Set `pii_vault.ca_file` if Vault's CA is not in the operating
  system trust store; the file then replaces that store. For mutual TLS, set
  `pii_vault.client_cert_file` and `pii_vault.client_key_file`. Certificate files are re-read when they
  change.
- Plain `http://` is accepted only for a loopback address, for example a Vault Agent or Vault Proxy
  listener on the database host.
- The extension never follows redirects and ignores proxy environment variables. Point `pii_vault.url`
  at the active Vault node or at a load balancer that routes to it. A standby that answers with a
  redirect produces an error (SQLSTATE `38000`).
- Vault Enterprise performance standbys answer reads from an eventually consistent state. A key created
  an instant ago may be unknown to a standby, and a value written with that key then reads as `****`
  through it. Route the extension's requests to the active node.
- Vault namespaces (Enterprise, HCP): set `pii_vault.namespace`.
- Enable a Vault audit device. In export mode it records every key export, in transit mode every
  encryption and decryption. Keep the default hashing of request and response values.

## 3. PostgreSQL configuration

```ini
shared_preload_libraries = 'pg_pii_vault'        # restart required; append to an existing list

pii_vault.url        = 'https://vault.example.internal:8200'
pii_vault.token_file = '/run/vault-agent/pg-pii-vault.token'
#pii_vault.mount      = 'transit'
pii_vault.mount_accessor = 'transit_4a1b2c3d'    # the accessor of the mount, see section 2.1
#pii_vault.namespace  = ''
#pii_vault.key_mode   = 'export'                 # or 'transit'
#pii_vault.ca_file    = '/etc/pg_pii_vault/vault-ca.pem'
#pii_vault.timeout_ms = 5000
#pii_vault.max_retries = 2
#pii_vault.cache_ttl_sec = 300
#pii_vault.cache_max_entries = 10000
#pii_vault.auto_create_keys = on
#pii_vault.allow_staging = on                    # set to off once no migration needs staging values
```

- **Preloading is required.** Without `shared_preload_libraries`, a `pii_vault.token` in the
  configuration is readable by every role until the library is loaded in a session, `piitext_shred()`
  and `piitext_cache_invalidate()` reach only the calling backend, and `piitext_stats()` has no
  cluster-wide counters. Preload the library on standbys too.
- **Every `pii_vault.*` setting is superuser-only** and takes effect on reload
  (`SELECT pg_reload_conf();`). A superuser can also set them per database or role, for example
  `ALTER DATABASE app SET pii_vault.mount = 'transit-app';`. Unknown `pii_vault.*` names are rejected
  (PostgreSQL 15 and later).
- **Never put the token in SQL.** `SET`, `ALTER SYSTEM`, `ALTER DATABASE … SET` and `ALTER ROLE … SET`
  put it into the server log, `pg_stat_statements` or world-readable catalogs. Use
  `pii_vault.token_file`.
- **`pii_vault.url`, `pii_vault.namespace` and `pii_vault.mount` select the key space.** Changing them
  makes existing values unreadable until they are restored: an error if the new location is not a
  Transit engine, the token may not use it, or its accessor differs from `pii_vault.mount_accessor`;
  `****` if it is another Transit engine and no accessor is pinned. Change them only together with a
  migration of the keys.
- The database must be UTF8. `CREATE EXTENSION` refuses other encodings.
- All settings with their defaults are listed in the
  [configuration reference](../README.md#configuration-reference).

Installing or upgrading PostgreSQL itself: install the extension build for the new major version before
`pg_upgrade`; stored values need no conversion.

## 4. Access control

```sql
CREATE EXTENSION pg_pii_vault;      -- superuser, once per database

-- Application: reads and writes PII.
GRANT EXECUTE ON FUNCTION
    piitext_out_text(piitext),
    piitext_encrypt(text, bytea),
    piitext_encrypt_piitext(piitext, bytea),
    piitext_reencrypt(piitext)
TO app_rw;

-- Erasure job.
GRANT EXECUTE ON FUNCTION piitext_shred(bytea), piitext_cache_invalidate() TO erasure_job;

-- Monitoring.
GRANT EXECUTE ON FUNCTION piitext_vault_check() TO monitoring;
```

- A role without `EXECUTE` on `piitext_out_text(piitext)` reads only ciphertext, whatever its table
  privileges are. Give reporting, backup and replication roles no grant.
- `EXECUTE` on `piitext_out_text` decrypts any `piitext` value the role can obtain, not only rows of
  particular tables.
- Roles that are equivalent to superusers for this extension, and the queries to audit grants, are in
  [SECURITY-MODEL.md, section 8](SECURITY-MODEL.md#8-privilege-model).
- Connection poolers: the key cache belongs to the server backend, not to the client session.
  PostgreSQL checks `EXECUTE` on every call, so a client that inherits a pooled connection cannot decrypt
  without the grant, whatever the cache holds.

## 5. Health checks and monitoring

### 5.1 `piitext_vault_check()`

```sql
SELECT check_name, ok, required, detail FROM piitext_vault_check();
```

```
        check_name        | ok | required | detail
--------------------------+----+----------+---------------------------------------------------------------------
 shared_preload_libraries | t  | t        | preloaded; cluster-wide cache invalidation and statistics enabled
 token                    | t  | t        | from pii_vault.token_file (/run/vault-agent/pg-pii-vault.token)
 endpoint                 | t  | t        | url=https://vault.example.internal:8200 mount=transit namespace=(none) key_mode=export
 tls                      | t  | f        | https
 vault_reachable          | t  | t        | HTTP 200; version 2.1.1; sealed=false; standby=false
 transit_mount            | t  | t        | transit/ is a Transit secrets engine (accessor transit_4a1b2c3d)
 key_access               | t  | t        | the Transit engine at transit/ accepts key export requests
 token_valid              | t  | t        | expires in 3520 s unless renewed; renewable=true; policies=default,pg-pii-vault,pg-pii-vault-shred
 policy_export            | t  | t        | transit/export/encryption-key/pg-pii-vault-probe: [read]
 policy_create_keys       | t  | t        | transit/keys/pg-pii-vault-probe: [delete,update]
 policy_shred             | t  | f        | transit/keys/pg-pii-vault-probe/config: [update]; transit/keys/pg-pii-vault-probe: [delete,update]
```

The deployment is healthy when every `required` row is `ok`:

```sql
SELECT bool_and(ok) FROM piitext_vault_check() WHERE required;
```

- `transit_mount` checks that `pii_vault.mount` is the mount point of a Transit engine and, if
  `pii_vault.mount_accessor` is set, that it has that accessor.
- `key_access` sends the request the extension depends on most (a key export, or a decryption in
  transit mode) for a key that cannot exist, `pg-pii-vault-probe`. It proves that the token is accepted
  and that its policy allows the request. It needs none of the optional policy rules and touches no real
  key.
- Advisory rows (`required = f`): `tls` (false only for plain HTTP to another host, which needs
  `pii_vault.allow_insecure_http = on`), `policy_shred`, `policy_no_export` (transit mode: false while
  the token can still export keys), `policy_create_keys` when `pii_vault.auto_create_keys = off`, and
  `token_valid` / `policy` when the token's policy lacks the optional inspection rules.
- In transit mode the policy rows are `policy_encrypt`, `policy_decrypt` and `policy_no_export` instead
  of `policy_export`.
- The function makes five Vault requests. It is suitable as a readiness probe run every minute or so,
  not as a per-request check. Run it on every node, standbys included.

### 5.2 `piitext_stats()`

```sql
SELECT metric, backend, cluster FROM piitext_stats();
```

`backend` counts for the current connection; `cluster` counts for all backends since the server
started, and is NULL when the library is not preloaded.

| Metric | Meaning | Watch for |
|---|---|---|
| `cache_entries` | Keys cached by this backend, including keys known to be absent (`cluster` is always NULL) | |
| `cache_hits`, `cache_misses` | Key cache lookups | A low hit ratio in export mode means many short-lived connections or more distinct keys than `pii_vault.cache_max_entries`. |
| `cache_evictions` | Entries dropped because they expired or the cache was full | Constant growth: raise `pii_vault.cache_max_entries`. |
| `vault_requests` | HTTP requests sent to Vault, every attempt | Capacity planning for Vault. |
| `vault_errors` | Attempts that failed with a connection error, a timeout or HTTP 412/429/5xx | Any sustained rate: Vault is unreachable, overloaded or sealed. |
| `vault_denied` | Statements that failed because Vault refused the token or its policy (HTTP 401/403) | Any increase: the token expired or was revoked, or a policy is missing. |
| `keys_created` | Keys created by encryptions | Roughly the number of new data subjects. |
| `keys_shredded` | Keys deleted by `piitext_shred()` | Should match the erasure journal. |
| `decrypt_masked` | Values returned as `****` | An unexpected rise means reads of erased subjects, a key deleted outside the procedure, tampered values, or the extension pointed at the wrong key space. |

### 5.3 Logs

- The extension's errors carry the SQLSTATEs listed in [section 13](#13-error-reference). Alert on
  `58000` and `42501` errors whose message starts with `Vault`.
- To trace Vault requests in one session:

  ```sql
  SET client_min_messages = debug1;      -- superuser session
  SELECT piitext_encrypt('x', '\xff00'::bytea);
  -- DEBUG:  pg_pii_vault: GET /v1/transit/export/encryption-key/ff00 -> HTTP 404 in 2 ms
  -- DEBUG:  pg_pii_vault: POST /v1/transit/keys/ff00 -> HTTP 200 in 1 ms
  -- DEBUG:  pg_pii_vault: GET /v1/transit/export/encryption-key/ff00 -> HTTP 200 in 0 ms
  ```

  `log_min_messages = debug1` sends the same lines to the server log, together with PostgreSQL's own
  debug output. The lines contain the key name, never the token or plaintext.
- Keep plaintext out of the server log: see [SECURITY-MODEL.md, section 11](SECURITY-MODEL.md#11-logging).

### 5.4 Periodic reviews

- Grants on the protected functions ([SECURITY-MODEL.md, section 8.4](SECURITY-MODEL.md#84-auditing-privileges)).
- Objects that persist decrypted values. PostgreSQL refuses indexes and stored generated columns on
  decrypted values, but accepts materialized views, tables filled from decrypted data and extended
  statistics on a decrypting expression. The query in
  [UPGRADING.md, step 1.3](../UPGRADING.md#13-find-objects-that-store-decrypted-values) lists every
  object that depends on the decryption function.
- Staging values that were never encrypted:
  `SELECT count(*) FROM <table> WHERE NOT piitext_is_encrypted(<column>);`

## 6. Crypto-shredding

Deleting a data subject's key in Vault makes every value encrypted with it unreadable, in every table,
backup and replica.

### 6.1 From the database

Requirements: `EXECUTE` on `piitext_shred(bytea)` for the erasure role, and the
`pg-pii-vault-shred.hcl` policy on the token.

```sql
SELECT piitext_shred('\x01'::bytea || int8send(1003));    -- t: the key was deleted
```

- The function sets `deletion_allowed` on the key and deletes it: two Vault requests.
- It returns `f` if the key does not exist: already shredded, or nothing was ever encrypted for this
  subject. Repeating the call is safe.
- It is **not transactional**. The key is gone when the function returns, even if the transaction
  rolls back.
- Every backend of the cluster drops its cached copy of the key, also when the call fails or is
  cancelled after the deletion was requested: the request may have reached Vault although its answer
  did not arrive. Record the request in a journal table and commit before you shred, and retry from the
  journal until the call succeeds. [USAGE.md, section 12](../USAGE.md#12-crypto-shredding-for-a-gdpr-erasure-request)
  shows the full flow.
- Any error means that the key may still exist. Retry.

### 6.2 From Vault

With a Vault identity other than the database token:

```sh
vault write  transit/keys/0100000000000003eb/config deletion_allowed=true
vault delete transit/keys/0100000000000003eb
```

Then run `SELECT piitext_cache_invalidate();` in every PostgreSQL cluster that uses the mount, or wait
`pii_vault.cache_ttl_sec`.

### 6.3 When the erasure takes effect

| Where | Values read as `****` |
|---|---|
| Transit mode, everywhere | On the next read |
| Export mode, the cluster where `piitext_shred()` ran, library preloaded | Immediately: every backend drops its cached copy of the key |
| Export mode, other clusters and physical standbys; any cluster if the key was deleted from Vault directly; library not preloaded | Within `pii_vault.cache_ttl_sec`, or immediately after `SELECT piitext_cache_invalidate();` on that cluster |

A backend that still caches a deleted key also **encrypts** new values with it until the cache entry
expires. Such values are unreadable from then on. After deleting keys outside `piitext_shred()`, or
when several clusters share a mount, invalidate the caches everywhere before the key id is used again.

### 6.4 After the erasure

- Shredding does not block the key id. A later `piitext_encrypt()` with the same key id creates a new
  key, and the new data is readable. Block writes for erased subjects in the application.
- Values of the erased subject still occupy space and cost Vault requests: a backend remembers that a
  key is absent for at most 30 seconds. Delete the rows or set the columns to NULL.
- Re-encrypting a shredded value fails with SQLSTATE `42704`. Exclude erased subjects from rotation and
  migration batches.
- Shredding covers encrypted values only: not staging values, not plaintext that existed before
  encryption (old WAL, backups taken before the migration), not copies outside the database.
- **Vault snapshots taken before the erasure still contain the key.** Keep snapshot retention within
  your erasure deadline. After restoring Vault from a snapshot, replay the erasure journal.
- In export mode a key that was exported before the erasure may survive in a copy outside Vault
  (backend memory of a compromised host, for example). Transit mode avoids this.

To confirm an erasure:

```sql
SELECT piitext_out_text(email) FROM customer WHERE id = 1003;     -- ****
```

```sh
vault read transit/keys/0100000000000003eb                         # No value found
```

## 7. Key rotation

Rotation adds a new version to a key. New values use the latest version; existing values keep the
version they were written with, and stay readable while Vault keeps that version. The database token
cannot rotate keys; a Vault administrator does.

1. Rotate:

   ```sh
   vault write -f transit/keys/0100000000000003e9/rotate
   ```

   To rotate every key of the mount, loop over `vault list -format=json transit/keys`. Vault can also
   rotate a key on a schedule (`auto_rotate_period` in the key configuration).
2. Export mode only: make the backends pick up the new version for new values. Otherwise
   `piitext_encrypt()` keeps encrypting with the cached version until `pii_vault.cache_ttl_sec`
   expires. `piitext_reencrypt()` always asks Vault for the latest version.

   ```sql
   SELECT piitext_cache_invalidate();        -- on every cluster that uses the mount
   ```

3. Re-encrypt the existing values. On large tables, work in primary key ranges, one transaction per
   batch (PostgreSQL has no `UPDATE … LIMIT`):

   ```sql
   UPDATE customer
   SET    email = piitext_reencrypt(email)
   WHERE  id >= 1 AND id < 10001
     AND  piitext_is_encrypted(email)
     AND  piitext_key_version(email) IS DISTINCT FROM 2;      -- 2 = the version after the rotation
   ```

   `piitext_key_version()` reads only the stored value and needs no Vault request. It is NULL for
   values written by 0.0.x, which `IS DISTINCT FROM` includes.
4. Check that no old version is left:

   ```sql
   SELECT piitext_key_version(email) AS version, count(*)
   FROM customer WHERE piitext_is_encrypted(email) GROUP BY 1 ORDER BY 1;
   ```

5. Optional: retire the old versions in Vault by raising `min_decryption_version`, then
   `min_available_version` and `trim`. Values still encrypted with a retired version read as `****`
   from then on. Raising `min_decryption_version` can be undone; trimming cannot.

A batch fails with SQLSTATE `42704` if it contains a value whose key was shredded. Exclude erased
subjects, or see [UPGRADING.md, step 9](../UPGRADING.md#9-optional-rewrite-old-values-in-format-2) for a
row-by-row loop that skips them.

## 8. Changing the key mode

`pii_vault.key_mode` affects new encryptions only. Values of both formats stay readable, provided that
the token has the capability their format needs: export for format 2, decrypt for format 3.

### 8.1 From export to transit

1. Attach `pg-pii-vault-transit.hcl` to the token **in addition to** `pg-pii-vault.hcl`. Reading the
   existing format 2 values still needs the export capability.
2. Set `pii_vault.key_mode = 'transit'` and reload. Check with `piitext_vault_check()`; at this point
   `policy_no_export` is false, which is expected.
3. Re-encrypt every value in batches: `UPDATE … SET col = piitext_reencrypt(col) WHERE …`. Find the
   remaining ones with `piitext_debug(col) LIKE 'Sealed(format=2,%'` or
   `LIKE 'Sealed(format=1,%'`.
4. Detach `pg-pii-vault.hcl`. `policy_no_export` becomes true.

Keys created in export mode stay exportable: Vault cannot make a key non-exportable again. For the
guarantee that key material never left Vault, use transit mode from the start on a mount whose keys were
all created in transit mode.

Transit mode limits: a value may hold at most 512 KiB of plaintext, because Vault refuses JSON strings
longer than 1 MiB by default. Transit mode needs Vault 1.13 or later.

### 8.2 From transit to export

Keys created in transit mode are not exportable, so export mode cannot use them:

```
ERROR:  unexpected Vault response: key 0100000000000003e9 exists but is not exportable (created with
        pii_vault.key_mode = transit, or outside pg_pii_vault); use key_mode = transit for it or set
        exportable=true on the key in Vault
```

A Vault administrator must first make each key exportable, which cannot be undone:

```sh
vault write transit/keys/0100000000000003e9/config exportable=true
```

Then attach `pg-pii-vault.hcl`, set `pii_vault.key_mode = 'export'`, reload and re-encrypt as above.

## 9. The key cache

Each backend has its own cache; nothing is shared between backends.

- **What is cached.** In export mode, every version of each key in use, for `pii_vault.cache_ttl_sec`
  (default 300 s; 0 disables caching), up to `pii_vault.cache_max_entries` keys (default 10000) per
  backend. In both modes, the fact that a key does not exist, for at most 30 seconds, so that reading
  values of erased subjects does not cost a Vault request each time. When the cache is full, expired
  entries and then the oldest tenth are dropped. Changed settings apply at once, also to entries
  already cached.
- **Memory.** About 200 bytes per cached key plus 32 bytes per key version, so a full default cache is a
  few megabytes per backend. Key bytes are zeroed when an entry is dropped.
- **Invalidation within the cluster** (library preloaded):
  - `piitext_shred()` makes every backend drop that key, and so does the creation of a key, so that no
    backend keeps treating a key created again as absent;
  - `piitext_cache_invalidate()` makes every backend drop its whole cache;
  - a key that was being fetched while it was shredded or created is not cached.
- **Other clusters and standbys** see changes only when their entries expire, or after
  `SELECT piitext_cache_invalidate();` there.
- A cached key that cannot decrypt a value (the key was rotated, or deleted and created again) is
  fetched again before the value is reported as `****`.
- `pii_vault.cache_ttl_sec` is a trade-off. A longer TTL means fewer Vault requests. A shorter TTL
  means that clusters which do not see a shred, a rotation or a revoked token follow sooner.
- Cache functions: `piitext_cache_evict(key_id)` and `piitext_cache_flush()` act on the calling backend;
  `piitext_cache_invalidate()` acts on every backend of the cluster.

## 10. Performance and capacity

Vault requests per operation:

| Operation | Export mode | Transit mode |
|---|---|---|
| Encrypt, key cached | 0 | 1 |
| Encrypt, key not cached | 1 | 1 |
| Encrypt, first value for a new key id | 3 (export, create, export) | 3 (encrypt refused, create, encrypt) |
| Decrypt, key cached | 0 | 1 |
| Decrypt, key not cached | 1 | 1 |
| Decrypt a shredded value | 1 per key and backend every 30 s | 1 per key and backend every 30 s |
| `piitext_reencrypt()` | 1, plus 1 if the key was not fetched in the last 2 s | 2 |
| `piitext_shred()` | 2 | 2 |
| `piitext_vault_check()` | 5 | 5 |
| Mount check, per backend and endpoint | 1 at first use, then every 5 minutes | same |

- **Reads.** In export mode a backend with a cold cache that decrypts N rows of N data subjects makes N
  requests; with a warm cache it makes none. In transit mode it always makes N. Each request is one
  HTTP round trip on a kept-alive connection per backend.
- **Bulk loads.** Loading N new data subjects costs about 3N requests. Use several sessions on disjoint
  id ranges; the encryption functions are not parallel safe, so one statement encrypts serially.
- **Parallel query.** Decryption is `PARALLEL SAFE`. Each parallel worker has its own cache and makes
  its own requests.
- **Connections.** Short-lived connections start with an empty cache. Use a connection pooler so that
  backends, and their caches, live long.
- **Bound the wait.** One request waits at most `pii_vault.timeout_ms` (default 5 s). Connection
  errors and HTTP 412/429/5xx are retried `pii_vault.max_retries` times (default 2) with backoff;
  timeouts are not retried. Waiting statements can be cancelled, and `statement_timeout` applies.
- **Vault capacity.** One Transit key per data subject means millions of keys for millions of subjects.
  Size Vault's storage for them, and limit the Transit engine's in-memory key cache
  (`vault write transit/cache-config size=…`), which is unlimited by default. Measure with
  `vault_requests` from `piitext_stats()` before you choose a key mode.

## 11. Backup, restore and replication

### 11.1 The database and Vault belong together

Encrypted values are useless without their keys. Treat Vault's storage as part of the database:

- Back up Vault (Raft snapshots: `vault operator raft snapshot save …`) at least as often as the
  database's recovery point objective requires. Restoring Vault to a snapshot **loses every key created
  after the snapshot**, and with it every value encrypted for the data subjects added since then.
- A Vault snapshot also **brings back keys deleted after it was taken**. After a Vault restore, replay
  the erasure journal.
- Restoring an old database backup against the current Vault is safe: values whose keys were shredded
  in the meantime read as `****`, which is the purpose of crypto-shredding.

### 11.2 Dumps and base backups

- `pg_dump`, `COPY` and base backups contain encrypted values as ciphertext. They can be restored into
  any database that has the extension and reaches the same Vault mount.
- Staging values are plaintext in dumps and backups. Restoring a dump that contains staging values
  needs `pii_vault.allow_staging = on`.
- Dumps taken with 0.0.x use the old text form, which 0.1.0 accepts. Dumps that contain indexes or
  generated columns on decrypted values cannot be restored as they are
  ([UPGRADING.md, step 5](../UPGRADING.md#5-drop-the-objects-reported-by-the-warnings)).

### 11.3 Physical standbys

- Install the extension, preload the library and configure `pii_vault.*` on every standby, with its own
  token file. Decryption works on a hot standby; it needs Vault like the primary.
- A standby has its own key caches. `piitext_shred()` on the primary does not reach them: run
  `SELECT piitext_cache_invalidate();` on the standby (it works in a read-only session), or accept a
  delay of `pii_vault.cache_ttl_sec`.

### 11.4 Logical replication

- Values are replicated as ciphertext, in text or binary format (`binary = true` works). The subscriber
  needs the extension, and the same Vault mount if it decrypts.
- Tables with `piitext` columns need a primary key or a unique index as replica identity.
  `REPLICA IDENTITY FULL` does not work: `piitext` has no equality operator, and the apply worker stops
  with `could not identify an equality operator for type piitext`.
- A subscriber with `pii_vault.allow_staging = off` refuses staging values from the publisher, and
  replication stops with `plaintext piitext values are disabled`. Encrypt staging values on the
  publisher first, or keep the setting on until they are gone.

### 11.5 Removing the extension

To stop using `piitext`, decrypt the columns into `text` while the keys still exist, then drop the
extension. Values whose keys were shredded become the literal text `****`; clear them first.

```sql
ALTER TABLE customer ALTER COLUMN email TYPE text USING email::text;
DROP EXTENSION pg_pii_vault;
```

## 12. When Vault is unavailable

| Situation | Export mode | Transit mode |
|---|---|---|
| Vault unreachable, sealed or returning 5xx | Reads and writes that use a cached key keep working until the entry expires. Everything else fails with SQLSTATE `58000` after the retries. | Every encryption and decryption fails with `58000`. |
| Vault slow | Each request waits up to `pii_vault.timeout_ms`, then fails with `58000`. | Same. |
| Token expired or revoked, policy missing | Cached keys keep working until they expire. Everything else fails with `42501`. | Fails with `42501` at once. |
| Vault restored without recent keys | Values of the affected data subjects read as `****`. | Same. |

Nothing is masked during an outage: statements fail, and applications should retry `58000` with backoff.
No data is written unencrypted, and no key is created by a read.

A request that is abandoned (cancelled, or past `pii_vault.timeout_ms`) keeps a thread and a connection
until each phase of the request times out, at most `pii_vault.timeout_ms` per phase. A backend keeps at
most four such requests; while four are still running, new requests of that session fail at once with
SQLSTATE `58000` (`4 earlier requests of this session to Vault are still running`). Keep
`pii_vault.timeout_ms` well below `statement_timeout`.

After revoking a token in an incident, run `SELECT piitext_cache_invalidate();` on every cluster so
that export-mode backends stop using cached keys.

## 13. Error reference

| SQLSTATE | Message starts with | Cause | Action |
|---|---|---|---|
| `58000` | `Vault is unavailable:` | Connection error, timeout, TLS failure, HTTP 412/429/5xx after the retries, or four abandoned requests of the session still running | Transient: retry. Check Vault and the network if it persists. |
| `42501` | `Vault denied the request:` | HTTP 401/403: the token is invalid, expired or revoked, its policy does not allow the request, or nothing is mounted at `pii_vault.mount` | Check the token file and Vault Agent; compare the policy with `vault/policies/`; check `pii_vault.mount`; run `piitext_vault_check()`. |
| `55000` | `pg_pii_vault configuration error:` | URL or token not set, token or certificate file unreadable, plain HTTP to another host, invalid mount or namespace, `pii_vault.mount` not the mount point of a Transit engine, a mount accessor other than `pii_vault.mount_accessor` | Fix the `pii_vault.*` settings. |
| `55000` | `plaintext piitext values are disabled` | A staging value while `pii_vault.allow_staging = off` | Encrypt with `piitext_encrypt()`, or enable staging for a migration or a restore. |
| `38000` | `unexpected Vault response:` | A redirect; a 404 that does not come from the Transit engine (proxy, wrong URL path); a key that is not exportable or not `aes256-gcm96`; a malformed reply | Check `pii_vault.url`, load balancers and the key's configuration. |
| `42704` | `encryption key not found in Vault:` | Encrypting with `pii_vault.auto_create_keys = off` and no key; re-encrypting a shredded value | Provision the key, or exclude erased subjects. |
| `22023` | (varies) | NULL, empty or over-long key id; value larger than 16 MiB (512 KiB in transit mode); `piitext_reencrypt()` on a staging value | Fix the calling SQL. |
| `22P02` | `invalid input syntax for type piitext:` | Text that is not a `piitext:` value where `piitext` is expected | Use `piitext_encrypt()`. |
| `XX001` | `corrupted piitext value:` | A value cannot be decoded or exceeds the limits of its format, an input value is not in the encoding pg_pii_vault writes, or Vault rejects a ciphertext as invalid | Investigate storage corruption or tampering; restore the row from a backup. |

`****` is not an error: the value's key, or key version, does not exist in Vault any more.

## 14. Troubleshooting

**Every value reads as `****`.** The keys are absent where the extension looks. Check that
`pii_vault.url`, `pii_vault.namespace` and `pii_vault.mount` point at the Vault and mount that hold
the keys (`SELECT detail FROM piitext_vault_check() WHERE check_name = 'endpoint';`), that Vault was
not restored from an older snapshot, and that the requests do not go to a lagging standby.

**`Vault denied the request … invalid token`.** The token in `pii_vault.token_file` expired or was
revoked. Check that Vault Agent is running and can renew the token.

**`Vault denied the request … permission denied` for some operations only.** A policy rule is missing
or was adapted incorrectly. `piitext_vault_check()` names the missing capability. The usual causes are
in [section 2.2](#22-policies).

**`the token may not use pii_vault.mount …`.** Nothing is mounted at `pii_vault.mount` (or in
`pii_vault.namespace`), or the token's policy does not cover that path.

**`pii_vault.mount "…" is a kv secrets engine, not Transit`** or **`… is not the mount point of a
secrets engine`.** `pii_vault.mount` names another engine, or a path inside one. Set it to the mount
point of the Transit engine, for example `transit`.

**`… has accessor …, but pii_vault.mount_accessor is …: this is not the expected key space`.** The
extension reaches a different Transit mount than the one pinned: another Vault server, namespace or
mount, or a mount that was disabled and enabled again. Fix the setting that points elsewhere; change
`pii_vault.mount_accessor` only if the keys really moved to the new mount.

**`… earlier requests of this session to Vault are still running`.** Vault did not answer several
requests that were then cancelled. Wait for them to time out (`pii_vault.timeout_ms`) and check Vault.

**`… returned a redirect`.** `pii_vault.url` points at a Vault standby or at a server that redirects.
Use the active node or a load balancer.

**`… returned HTTP 404 that does not come from the Transit secrets engine`.** Something other than
Vault's Transit engine answered: a reverse proxy, another secrets engine at that mount, or a wrong path
in `pii_vault.url`.

**`invalid peer certificate`.** Vault's certificate is not trusted. Set `pii_vault.ca_file` to the CA
that issued it. Verification cannot be disabled.

**`uses plain http to a non-loopback host`.** Use `https://`. `pii_vault.allow_insecure_http = on` is
for development only.

**`timed out after 5000 ms`.** Vault did not answer within `pii_vault.timeout_ms`. Check the network
path and Vault's load.

**`key … exists but is not exportable`.** The key was created in transit mode or outside the
extension. See [section 8.2](#82-from-transit-to-export).

**`pg_pii_vault requires a UTF8 database`.** Create the database with `ENCODING 'UTF8'`.

**`permission denied for function piitext_out_text`.** The role lacks the grant
([section 4](#4-access-control)).

**`column … is of type piitext but expression is of type text`.** The SQL writes text into a `piitext`
column. Encrypt with `piitext_encrypt(value, key_id)`.

**WARNING `pg_pii_vault is not loaded via shared_preload_libraries` at the first use in a session.**
Add the library to `shared_preload_libraries` and restart.

**Encryption works but is slow for new data subjects.** Each new key costs three Vault requests. See
[section 10](#10-performance-and-capacity).
