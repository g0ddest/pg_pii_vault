# Upgrading pg_pii_vault

## From 0.1.0 to 0.1.1

0.1.1 updates dependencies and changes neither the SQL interface nor the stored values.

1. Install the new files (see [step 2](#2-install-the-new-files) below) on the primary, every physical
   standby and every logical replication subscriber.
2. Restart the server: the library is preloaded, so running backends keep the old one until then.
3. In every database that has the extension, as a superuser:

   ```sql
   ALTER EXTENSION pg_pii_vault UPDATE;
   SELECT extversion FROM pg_extension WHERE extname = 'pg_pii_vault';   -- 0.1.1
   ```

Nothing else changes.

## From 0.0.0 to 0.1

The rest of this guide covers the upgrade from 0.0.0. Installing 0.1.1 and running
`ALTER EXTENSION pg_pii_vault UPDATE` takes a 0.0.0 database straight to 0.1.1, through 0.1.0.

0.1.0 is a security release and changes behaviour that applications rely on. Read the whole procedure before you start, and rehearse it on a copy of the production databases. [CHANGELOG.md](CHANGELOG.md) lists every change. [USAGE.md](USAGE.md) describes how to use 0.1.0.

## What changes

| Area | 0.0.0 | 0.1.0 |
|---|---|---|
| Writing text to a `piitext` column | Silently stored plaintext (implicit `text -> piitext` cast) | Fails. Encrypt with `piitext_encrypt(text, key_id)`. |
| Decryption | Implicit cast, `IMMUTABLE` function | Explicit only (`value::text`, `piitext_out_text(value)`); `STABLE` |
| Privileges | Every function executable by `PUBLIC` | Decryption, encryption and administrative functions need `GRANT EXECUTE` |
| Configuration | Any role could `SET pii_vault.*`, and `SHOW pii_vault.token` revealed the token | All `pii_vault.*` settings are superuser-only. The token comes from `pii_vault.token_file`. The library must be in `shared_preload_libraries`. |
| Vault outage, missing permission, misconfiguration | Read as `****` | Error with a SQLSTATE. `****` now only means that the key or key version no longer exists. |
| NULL key id in `piitext_encrypt*()` | Silently returned NULL | Error 22023 |
| Objects that store decrypted values | Indexes and generated columns on decrypted values could be created | Refused. Existing indexes, generated columns, materialized views and extended statistics objects are reported by a WARNING and must be dropped. |
| Plaintext staging values | Always accepted | Refused on every way in while `pii_vault.allow_staging = off` (the default is `on`) |
| Indexes and generated columns on `piitext_encrypt()`, `piitext_encrypt_piitext()` or `piitext_in_text()` | Allowed, the functions were `IMMUTABLE` | Reported by a WARNING: they keep working, but their dumps cannot be restored |
| Limits | None | 16 MiB of plaintext per value, key ids of 1 to 128 bytes. Values written by 0.0.0 with more than 16 MiB or a key id longer than 1024 bytes cannot be read (SQLSTATE `XX001`). |
| Vault URL | Anything, including plain `http://` over the network and `mock://` | `https://`, or `http://` only to a loopback address unless `pii_vault.allow_insecure_http = on`. `mock://` exists only in test builds. |
| Database encoding | Not checked | UTF8 required |
| PostgreSQL versions | 13 to 18 | 14 to 18 |
| Stored values | Format 1, text form `{"inner":[...]}` | Values written by 0.0.0 stay readable. New values use format 2 (format 3 in transit mode) and the text form `piitext:<base64>`. |

## 1. Prepare

### 1.1 Back up

There is no downgrade path (see [Rollback](#rollback)). Before you start, take:

- a backup of every database that has the extension, either `pg_dump` or a base backup with WAL archive;
- a snapshot of Vault (for example a Raft snapshot).

### 1.2 Check the encoding

```sql
SELECT datname, pg_encoding_to_char(encoding) AS encoding
FROM pg_database
WHERE datallowconn
ORDER BY datname;
```

Any database that uses the extension must be UTF8. In other encodings, values with non-ASCII characters fail. The update script only warns about this: `pg_pii_vault requires a UTF8 database; this database uses ...`. To move the data, dump the database and restore it into a new database created with `ENCODING 'UTF8'`.

### 1.3 Find objects that store decrypted values

Run the following query in each database, before and after the update:

```sql
SELECT classid::regclass AS catalog,
       pg_describe_object(classid, objid, objsubid) AS object
FROM pg_depend
WHERE refclassid = 'pg_proc'::regclass
  AND refobjid = 'piitext_out_text(piitext)'::regprocedure
  AND deptype IN ('n', 'a')
  AND classid <> 'pg_cast'::regclass
ORDER BY 1, 2;
```

It lists every object that calls the decryption function:

- **These store plaintext and must be dropped** (see [step 5](#5-drop-the-objects-reported-by-the-warnings)):
  - indexes: `index ...`
  - stored generated columns: `default value for column ... of table ...` (on PostgreSQL 14 and 15: `column ... of table ...`)
  - materialized views: `rule _RETURN on materialized view ...`
  - extended statistics objects: `statistics object ...`
- **These only decrypt at run time:** views (`rule _RETURN on view ...`), check constraints and SQL-standard function bodies.

Tables that were filled with decrypted values, for example by `CREATE TABLE AS` or `INSERT ... SELECT value::text`, do not show up in `pg_depend`. Search the application's migrations for them.

If one of these indexes enforces a business rule such as unique emails, that guarantee disappears when the index is dropped. Plan to enforce the rule elsewhere.

### 1.4 Prepare the application code

The following changes work with both 0.0.0 and 0.1.0, so you can deploy them before the upgrade:

- **Writes.** Encrypt with `piitext_encrypt(value, key_id)`, passing the plaintext as a bind parameter. Remove any assignment of text to a `piitext` column: in 0.0.0 it stored plaintext, in 0.1.0 it fails with SQLSTATE 22P02 or 42804.
- **Reads.** Decrypt explicitly with `value::text` or `piitext_out_text(value)` wherever the plaintext is used. This includes `WHERE`, `LIKE`, `ORDER BY`, function arguments such as `lower(value::text)`, and `INSERT ... SELECT` into text columns. Without the cast, 0.1.0 fails with SQLSTATE 42883 or 42804, or returns the `piitext:` text form, for example in a plain `SELECT value`.
- **Key ids.** Never pass a NULL key id. In 0.1.0 it raises SQLSTATE 22023. Keep using the key ids your code already uses for existing subjects. The 0.0.0 documentation helpers `int_to_key_bytes(id)` and `bigint_to_key_bytes(id)` return the same bytes as `int4send(id)` and `int8send(id)`.
- **Session settings.** Remove `SET pii_vault.*` from sessions and connection setup code. In 0.1.0 it fails for non-superusers with SQLSTATE 42501.
- **Errors.** Handle errors where the application used to receive `****` during Vault problems (see [USAGE.md, section 14](USAGE.md#14-error-handling-in-applications)).
- **Tests.** Test setups that use `mock://` need a Vault dev server with the Transit engine.
- **Parsers.** Update code that parses the old text form (`{"inner":[...]}`) or the output of `piitext_debug()`.

### 1.5 Prepare Vault

- Create a least-privilege token for the database:
  - policy `vault/policies/pg-pii-vault.hcl`
  - plus `vault/policies/pg-pii-vault-shred.hcl` if `piitext_shred()` is used from the database

  Keys created by 0.0.0 are exportable `aes256-gcm96` keys and work with the default `pii_vault.key_mode = 'export'`. Keep export mode for the upgrade.
- Deliver the token as a file that only the PostgreSQL operating system user can read. Use a periodic token renewed by Vault Agent with a file sink, or a Kubernetes or Docker secret. The file is read on every Vault request, so rotating the token needs no reload.

## 2. Install the new files

Install the new files on the primary, on every physical standby, and on logical replication subscribers that have the extension:

- the shared library (`pg_pii_vault.so`, or `pg_pii_vault.dylib` on macOS)
- `pg_pii_vault.control`
- `pg_pii_vault--0.1.1.sql` (a fresh installation)
- `pg_pii_vault--0.0.0--0.1.0.sql` and `pg_pii_vault--0.1.0--0.1.1.sql` (the update path)

To build from source, follow [README.md](README.md). It requires cargo-pgrx 0.16.1. For container images, see [DOCKER.md](DOCKER.md).

Check that the new version is available:

```sql
SELECT name, default_version, installed_version
FROM pg_available_extensions
WHERE name = 'pg_pii_vault';
-- default_version 0.1.1, installed_version 0.0.0 (until step 4)
```

## 3. Configure the server and restart

### 3.1 Move the configuration into the server configuration

Put the settings into `postgresql.conf`, or into a file included from it, with restrictive file permissions:

```ini
shared_preload_libraries = 'pg_pii_vault'        # append to the existing list, if any
pii_vault.url = 'https://vault.example.internal:8200'
pii_vault.token_file = '/run/vault-agent/pg_pii_vault.token'
pii_vault.mount = 'transit'
pii_vault.mount_accessor = 'transit_4a1b2c3d'   # from: vault secrets list
#pii_vault.namespace = 'pii'                     # Vault Enterprise / HCP namespace
#pii_vault.ca_file = '/etc/pki/vault-ca.pem'     # private CA; the default is the OS trust store
```

- `pii_vault.url` must use `https://`. Plain `http://` is accepted only for a loopback address, such as a Vault Agent listener on the same host.
- Every `pii_vault.*` parameter is superuser-only. Values set by a superuser with `ALTER DATABASE ... SET` or `ALTER ROLE ... SET` are applied to that database's or role's sessions. Use this for per-database settings such as `pii_vault.mount`.
- Never store the token with `ALTER DATABASE` or `ALTER ROLE`. The `pg_db_role_setting` catalog is readable by every role.

### 3.2 Remove the old settings

Find `pii_vault.*` settings stored for databases and roles:

```sql
SELECT coalesce(d.datname, '(all databases)') AS database,
       coalesce(r.rolname, '(all roles)')     AS role,
       s.setconfig
FROM pg_db_role_setting s
LEFT JOIN pg_database d ON d.oid = s.setdatabase
LEFT JOIN pg_roles    r ON r.oid = s.setrole
WHERE array_to_string(s.setconfig, ' ') LIKE '%pii\_vault.%';
```

Remove each token, for example `ALTER DATABASE app RESET pii_vault.token;` or `ALTER ROLE app_rw RESET pii_vault.token;`. If the token was stored with `ALTER SYSTEM`, run `ALTER SYSTEM RESET pii_vault.token;` too. Re-issue the non-secret settings you still need as a superuser. Also remove the `SET pii_vault.*` statements from applications and scripts (see [1.4](#14-prepare-the-application-code)).

### 3.3 Restart

`shared_preload_libraries` only takes effect after a restart. Restart the standbys first, then the primary. Then check:

```sql
SHOW shared_preload_libraries;       -- contains pg_pii_vault
```

Until step 4 runs, each database uses the new library with the 0.0.0 catalog. That catalog still has the implicit casts, `EXECUTE` for `PUBLIC` and no binary I/O. Run step 4 immediately after the restart.

## 4. Update the extension

In every database that has the extension, as a superuser:

```sql
ALTER EXTENSION pg_pii_vault UPDATE;      -- 0.0.0 -> 0.1.0 -> 0.1.1
SELECT extversion FROM pg_extension WHERE extname = 'pg_pii_vault';   -- 0.1.1
```

The update changes only the catalog. It does not read or rewrite stored values, so it completes quickly. Afterwards the catalog is the same as that of a fresh installation. Values written by 0.0.0 stay readable, and 0.1.0 also accepts the old `{"inner":[...]}` text form in dumps.

## 5. Drop the objects reported by the WARNINGs

The update prints a WARNING for every index, stored generated column, materialized view and extended statistics object that uses the decryption function. These objects hold plaintext that crypto-shredding cannot erase. For example:

```text
WARNING:  pg_pii_vault: index people_email_plain stores or indexes decrypted plaintext; drop it (and re-create it without decrypting) to restore crypto-shredding guarantees
WARNING:  pg_pii_vault: default value for column email_plain of table people stores or indexes decrypted plaintext; drop it (and re-create it without decrypting) to restore crypto-shredding guarantees
WARNING:  pg_pii_vault: rule _RETURN on materialized view people_mv stores or indexes decrypted plaintext; drop it (and re-create it without decrypting) to restore crypto-shredding guarantees
WARNING:  pg_pii_vault: statistics object people_email_stats stores or indexes decrypted plaintext; drop it (and re-create it without decrypting) to restore crypto-shredding guarantees
```

Drop the objects. If a replacement is needed, re-create it without decrypted values. For the example above:

```sql
DROP INDEX people_email_plain;
ALTER TABLE people DROP COLUMN email_plain;       -- the stored generated column
DROP MATERIALIZED VIEW people_mv;
DROP STATISTICS people_email_stats;               -- removes the sampled plaintext from pg_statistic_ext_data
VACUUM FULL people;                               -- removes the dropped column's values from the table files
```

- `DROP COLUMN` leaves the values in the table files until the table is rewritten. `VACUUM FULL` rewrites it, and holds an `ACCESS EXCLUSIVE` lock while it runs. Dropping an index or a materialized view deletes its files.
- 0.1.0 still accepts `CREATE STATISTICS` on a decrypting expression, because PostgreSQL does not require such expressions to be immutable. Never create one: `ANALYZE` stores samples of the plaintext. Re-run the query from [1.3](#13-find-objects-that-store-decrypted-values) from time to time to catch new ones.
- Copies of the plaintext remain in WAL archives, older backups and dumps, logical replication subscribers, and disk blocks freed by the drop or rewrite. Handle them under your retention policy.

The update also warns about indexes and stored generated columns built on `piitext_encrypt()`, `piitext_encrypt_piitext()` or `piitext_in_text()`, which 0.0.0 declared `IMMUTABLE`:

```text
WARNING:  pg_pii_vault: default value for column enc of table people uses piitext_encrypt(text,bytea), which is no longer IMMUTABLE: a dump of it cannot be restored; replace it with an ordinary column filled by the application or a trigger
```

They keep working, but a dump of them fails to restore. A generated column on `piitext_in_text()` also stores plaintext. Replace them before you take the next dump.

Dump and restore: a dump of a 0.0.0 database that still contains one of these objects cannot be restored into 0.1.0 as it is.

- An index on a decrypted value fails with `functions in index expression must be marked IMMUTABLE`.
- A generated column on a decrypted value fails with `generation expression is not immutable`.
- A materialized view would be restored and refreshed with plaintext again.

Drop these objects before you take the dump, or edit the dump.

## 6. Grant privileges

After the update, a role that has only `SELECT` on a table reads ciphertext. Grant each role what it needs:

```sql
-- Applications that read and write PII
GRANT EXECUTE ON FUNCTION
    piitext_out_text(piitext),
    piitext_encrypt(text, bytea),
    piitext_encrypt_piitext(piitext, bytea),
    piitext_reencrypt(piitext)
TO app_rw;

-- Roles that only read plaintext
GRANT EXECUTE ON FUNCTION piitext_out_text(piitext) TO support_agent;

-- Erasure process and monitoring
GRANT EXECUTE ON FUNCTION piitext_shred(bytea), piitext_cache_invalidate() TO erasure_job;
GRANT EXECUTE ON FUNCTION piitext_vault_check() TO monitoring;
```

Before 0.1.0, backup, reporting and `pg_read_all_data` roles could decrypt everything. Grant them nothing unless they really need plaintext. For views and `SECURITY DEFINER` functions, see [USAGE.md, section 6.3](USAGE.md#63-views-and-functions-for-authorised-roles).

## 7. Replace the old Vault token

With 0.0.0, any database role could read the token (`SHOW pii_vault.token`), or send it to a host of its choice (`SET pii_vault.url`). Treat that token as exposed:

1. Revoke it, for example with `vault token revoke -accessor <accessor>`.
2. Review the Vault audit log for its use.
3. Keep only the least-privilege token from [1.5](#15-prepare-vault).

## 8. Encrypt plaintext stored by 0.0.0

With 0.0.0, text written to a `piitext` column was stored unencrypted, as a staging value, without any error. Count such values in each `piitext` column. This makes no Vault request:

```sql
SELECT count(*) FROM people WHERE NOT piitext_is_encrypted(note);
```

Encrypt them under the key id of the row's data subject, in primary key batches on large tables:

```sql
UPDATE people
SET    note = piitext_encrypt_piitext(note, int4send(id))    -- use your key id convention
WHERE  NOT piitext_is_encrypted(note);
```

Then run `VACUUM FULL` on the table. As in step 5, copies of the plaintext remain in WAL archives, backups and dumps taken before this step.

To make sure no plaintext is ever stored again, set `pii_vault.allow_staging = off` in the server configuration once no staging value is left and no migration needs them. The type then refuses plaintext on every way in. A `CHECK (piitext_is_encrypted(note))` constraint gives the same guarantee for one column (see [USAGE.md, section 10](USAGE.md#10-staging-values)).

With 0.0.0, a Vault problem made reads return `****`. An application that wrote such a value back stored the literal text `****`, encrypted. `WHERE note::text = '****'` finds these rows, but it also matches values whose key was deleted, and it decrypts every row it scans. Restore affected rows from backups.

## 9. Optional: rewrite old values in format 2

Values written by 0.0.0 (format 1) keep working. They do not record their key version, so after a key rotation decryption has to try the key versions one by one. Rewriting them with `piitext_reencrypt()` records the version and binds it to the ciphertext. Run it in primary key ranges:

```sql
UPDATE people
SET    email = piitext_reencrypt(email)
WHERE  id >= 1 AND id < 10001
  AND  piitext_is_encrypted(email)
  AND  piitext_key_version(email) IS NULL;     -- format 1 only
```

If a batch contains a value whose Vault key no longer exists, the batch fails with SQLSTATE 42704. Process that range one row at a time and leave the unreadable values unchanged:

```sql
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT id FROM people
             WHERE id >= 1 AND id < 10001
               AND piitext_is_encrypted(email) AND piitext_key_version(email) IS NULL
    LOOP
        BEGIN
            UPDATE people SET email = piitext_reencrypt(email) WHERE id = r.id;
        EXCEPTION WHEN undefined_object THEN
            RAISE NOTICE 'people.id = %: key no longer exists, value left unchanged', r.id;
        END;
    END LOOP;
END $$;
```

## 10. Verify

```sql
-- Extension version and preloading.
SELECT extversion FROM pg_extension WHERE extname = 'pg_pii_vault';   -- 0.1.1
SHOW shared_preload_libraries;                                        -- contains pg_pii_vault

-- Configuration, Vault connection, token and policy. Every row with required = true must
-- have ok = true; the other rows are advisory (for example policy_shred, which is false if
-- the database does not shred).
SELECT check_name, ok, required, detail FROM piitext_vault_check();
SELECT bool_and(ok) AS healthy FROM piitext_vault_check() WHERE required;

-- Casts: two explicit (castcontext 'e') casts from piitext and none to piitext.
SELECT castsource::regtype, casttarget::regtype, castcontext
FROM pg_cast
WHERE 'piitext'::regtype IN (castsource, casttarget);

-- Grants.
SELECT has_function_privilege('app_rw', 'piitext_out_text(piitext)', 'EXECUTE')   AS can_decrypt,
       has_function_privilege('app_rw', 'piitext_encrypt(text, bytea)', 'EXECUTE') AS can_encrypt;
```

`piitext_vault_check()` reports these checks:

- `shared_preload_libraries`, `token`, `endpoint`, `tls`, `vault_reachable`, `transit_mount`, `key_access`, `token_valid`
- in export mode: `policy_export`
- in transit mode: `policy_encrypt`, `policy_decrypt`, `policy_no_export`
- `policy_create_keys` and the optional `policy_shred`

Stored formats per `piitext` column, without any Vault request. `\gexec` is a psql meta-command. It runs the generated query:

```sql
SELECT string_agg(format(
           $q$SELECT %L AS column_name,
                     CASE WHEN NOT piitext_is_encrypted(%I) THEN 'staging (plaintext)'
                          ELSE 'format ' || substring(piitext_debug(%I) FROM 'format=([0-9]+)')
                     END AS kind,
                     count(*) AS n
              FROM %s WHERE %I IS NOT NULL GROUP BY 1, 2$q$,
           c.oid::regclass || '.' || a.attname, a.attname, a.attname, c.oid::regclass, a.attname),
       E'\nUNION ALL\n') || E'\nORDER BY 1, 2'
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
WHERE a.atttypid = 'piitext'::regtype
  AND a.attnum > 0
  AND NOT a.attisdropped
  AND c.relkind = 'r'
\gexec
```

In the output, `format 1` means a value written by 0.0.0. `format 2` and `format 3` mean values written by 0.1.0 in export or transit mode. `staging (plaintext)` must not appear once [step 8](#8-encrypt-plaintext-stored-by-000) is done.

Finally, run a round trip as an application role. Use a test subject whose key you may create in Vault:

```sql
SET ROLE app_rw;
SELECT piitext_encrypt('upgrade check', '\xff00'::bytea)::text;   -- upgrade check
RESET ROLE;
SELECT piitext_shred('\xff00'::bytea);                             -- remove the test key again
```

## Rollback

- There is no downgrade script. 0.0.0 cannot read values written by 0.1.0: the storage layout, the format and the text form have all changed.
- If nothing has been written since the restart in [3.3](#33-restart), you can still go back to 0.0.0 as long as `ALTER EXTENSION ... UPDATE` has not run. Reinstall the 0.0.0 files, restore the old configuration and restart.
- Otherwise, restore the backups from [1.1](#11-back-up) and reinstall the 0.0.0 files. Restore the Vault snapshot too if keys were deleted in the meantime. Changes made after the backup are lost.
