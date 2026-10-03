# pg_pii_vault developer guide

This guide covers pg_pii_vault 0.1.0 and is written for developers who write SQL and application code against `piitext` columns. Installing the extension, configuring the server and setting up Vault are operator tasks. For installation, see [README.md](README.md). For container images, see [DOCKER.md](DOCKER.md). To upgrade from 0.0.0, see [UPGRADING.md](UPGRADING.md).

1. [How it works](#1-how-it-works)
2. [Before you start](#2-before-you-start)
3. [Schema design](#3-schema-design)
4. [Privileges](#4-privileges)
5. [Writing data](#5-writing-data)
6. [Reading data](#6-reading-data)
7. [Updating data](#7-updating-data)
8. [NULL semantics](#8-null-semantics)
9. [Encrypting an existing plaintext column](#9-encrypting-an-existing-plaintext-column)
10. [Staging values](#10-staging-values)
11. [Re-encryption and key rotation](#11-re-encryption-and-key-rotation)
12. [Crypto-shredding for a GDPR erasure request](#12-crypto-shredding-for-a-gdpr-erasure-request)
13. [Metadata functions](#13-metadata-functions)
14. [Error handling in applications](#14-error-handling-in-applications)
15. [Performance](#15-performance)
16. [Function reference](#16-function-reference)

## 1. How it works

- A `piitext` column stores text encrypted with AES-256-GCM. The key is a HashiCorp Vault Transit key. Each value records the **key id** (`bytea`) it was encrypted with, and the Vault key name is the hex encoding of that id. For example, key id `\x0100000000000003e9` uses Vault key `0100000000000003e9`.
- You choose the key id when you encrypt. Use one key per **data subject** (person). Deleting that key in Vault (crypto-shredding) then makes all of that person's encrypted values permanently unreadable. This includes the copies in backups, WAL archives and replicas.
- Encryption and decryption are always explicit. Write with `piitext_encrypt(plaintext, key_id)` and read with `value::text` or `piitext_out_text(value)`. There is no cast from `text` to `piitext`.
- A value whose key no longer exists decrypts to `****`. Any other problem raises an error, for example Vault being unreachable, access denied, a wrong Transit mount or another configuration error. Nothing is masked silently.
- Operators choose the key mode with `pii_vault.key_mode`:
  - `export` (the default): PostgreSQL fetches the key from Vault, caches it per connection and runs AES itself.
  - `transit`: Vault encrypts and decrypts, and every value costs one Vault request.

  The SQL is the same in both modes. Values written in one mode stay readable after a switch.

## 2. Before you start

- Your database administrator installs the extension. Only superusers can change the `pii_vault.*` settings, so you cannot `SET` them from application code. You can read them:

  ```sql
  SELECT extversion FROM pg_extension WHERE extname = 'pg_pii_vault';   -- 0.1.0
  SELECT name, setting FROM pg_settings WHERE name LIKE 'pii\_vault.%' ORDER BY name;
  ```

- `SELECT * FROM piitext_vault_check();` checks preloading, the Vault connection, the token and the Vault policy. The deployment is healthy when every row with `required = true` has `ok = true`. By default only superusers can run it; operators can grant it to other roles.
- The database must use the UTF8 encoding. `CREATE EXTENSION` refuses other encodings.
- Your roles need `EXECUTE` grants on the encryption functions (see [section 4](#4-privileges)).
- The examples use literal values so they are easy to read. Application code must send PII as bind parameters (see [section 5.2](#52-bind-parameters)).

## 3. Schema design

### 3.1 Columns

Store each PII attribute in its own `piitext` column. Keep everything you filter, join or sort on in ordinary columns: ids, foreign keys, status and timestamps.

```sql
CREATE TABLE customer (
    id          bigint PRIMARY KEY,
    status      text NOT NULL DEFAULT 'active',     -- 'active' | 'erased'
    full_name   piitext,
    email       piitext,
    phone       piitext,
    birth_date  piitext,                            -- ISO 8601 text, e.g. '1987-04-12'
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE customer_address (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id  bigint NOT NULL REFERENCES customer (id),
    kind         text NOT NULL,                     -- 'home' | 'postal'
    address      piitext NOT NULL
);
```

- `piitext` holds text only. Convert other types to a stable text form before you encrypt them, for example `to_char(d, 'YYYY-MM-DD')`. Convert them back after decryption, for example `birth_date::text::date`.
- `piitext` has no equality or ordering operators. This rules out primary keys, unique constraints, `ORDER BY`, `DISTINCT`, `GROUP BY` and `UNION` (without `ALL`) on `piitext` columns. Compare the decrypted text instead (see [section 6.4](#64-comparisons-search-and-operators)).
- In export mode, a sealed value takes about 50 bytes more than its plaintext, plus the length of the key id. Transit-mode values are larger.
- A column can be made to accept encrypted values only (see [section 10](#10-staging-values)):

  ```sql
  ALTER TABLE customer ADD CONSTRAINT customer_email_encrypted CHECK (piitext_is_encrypted(email));
  ```

### 3.2 Key ids

Follow these rules for key ids:

1. **The key id identifies the data subject, not the row.** Every value of customer 1001 uses the same key id: in `customer`, in `customer_address` and in any other table. One shred then erases all of them.
2. Every table with `piitext` columns stores the subject's id in a plain column, for example `customer_address.customer_id`. The key id is derived from that column.
3. Subject types that share an id space must not share keys: customer 42 and employee 42 need different key ids. Prefix the id with a one-byte type tag.
4. Choose one encoding per subject type and never change it. `int4send(42)` (`\x0000002a`) and `int8send(42)` (`\x000000000000002a`) name different keys. If an id column may be widened to `bigint` later, use `int8send` from the start.
5. Never use PII (email, phone number, national id, account number) as part of a key id. Key names appear in Vault request paths, Vault audit logs and error messages.
6. A key id is 1 to 128 bytes long.
7. Different applications and environments must not share keys. Operators give each of them its own Transit mount (`pii_vault.mount`).

The standard encodings are:

| Subject id type | Key id expression | Example |
|---|---|---|
| `integer` | `int4send(id)` | `int4send(42)` = `\x0000002a` |
| `bigint` | `int8send(id)` | `int8send(42)` = `\x000000000000002a` |
| `uuid` | `uuid_send(id)` | 16 bytes |
| `text` | `convert_to(id, 'UTF8')` | `convert_to('C-000042', 'UTF8')` = `\x432d303030303432` |

Put the convention into one helper function per subject type, and use only the helpers in SQL and application code:

```sql
-- One-byte type tags: 0x01 customer, 0x02 employee, 0x03 web lead, 0x04 partner contact.
CREATE FUNCTION pii_key_customer(customer_id bigint) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN '\x01'::bytea || int8send(customer_id);

CREATE FUNCTION pii_key_employee(employee_id integer) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN '\x02'::bytea || int4send(employee_id);

CREATE FUNCTION pii_key_lead(lead_id uuid) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN '\x03'::bytea || uuid_send(lead_id);

CREATE FUNCTION pii_key_partner_contact(contact_ref text) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN '\x04'::bytea || convert_to(contact_ref, 'UTF8');

SELECT encode(pii_key_customer(1001), 'hex') AS vault_key_name;   -- 0100000000000003e9
```

Each helper is `STRICT`, so a NULL subject id gives a NULL key id. `piitext_encrypt` then raises an error; it does not silently store NULL.

### 3.3 Never persist decrypted values

Decryption is `STABLE`, so PostgreSQL refuses indexes and generated columns on decrypted values. It cannot refuse every case. Never store decrypted values in any of these:

- materialized views, for example `CREATE MATERIALIZED VIEW ... AS SELECT email::text ...`
- tables filled by `CREATE TABLE AS`, `SELECT INTO` or `INSERT ... SELECT value::text`, including temporary and unlogged tables that are kept longer than needed
- extended statistics on a decrypted expression, for example `CREATE STATISTICS ... ON (email::text) ...`. `ANALYZE` stores samples of the plaintext.

Plaintext stored in these places survives crypto-shredding. Also avoid `CHECK` constraints that decrypt. Every write would call Vault, and after an erasure the constraint would see `****`.

## 4. Privileges

The decryption, encryption and administrative functions are not executable by `PUBLIC`. A role that has only `SELECT` on a table reads ciphertext. Grant each role what it needs:

| Role | Grants |
|---|---|
| Application that reads and writes PII | `piitext_out_text(piitext)`, `piitext_encrypt(text, bytea)`; for re-encryption also `piitext_encrypt_piitext(piitext, bytea)`, `piitext_reencrypt(piitext)` |
| Consumers of plaintext that only read | `piitext_out_text(piitext)` |
| Reporting, BI, backup roles | none: they read ciphertext |
| Erasure process | `piitext_shred(bytea)`, `piitext_cache_invalidate()` |
| Monitoring | `piitext_vault_check()` (`piitext_stats()` is executable by `PUBLIC`) |

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON customer, customer_address TO app_rw;
GRANT EXECUTE ON FUNCTION
    piitext_out_text(piitext),
    piitext_encrypt(text, bytea),
    piitext_encrypt_piitext(piitext, bytea),
    piitext_reencrypt(piitext)
TO app_rw;
```

- `EXECUTE` on `piitext_out_text` lets a role decrypt any `piitext` value it can obtain, not only the rows it can `SELECT`. For example, it can decrypt a value copied from a dump. Grant it deliberately.
- The casts `::text` and `::varchar` call `piitext_out_text`, and so does the `||` operator (see [section 6.4](#64-comparisons-search-and-operators)). All of them need that grant.
- PostgreSQL checks the grants for every query, so they also hold behind connection poolers.
- Table owners that are not superusers need the same grants.
- If a non-superuser runs `SET pii_vault....`, it fails with SQLSTATE 42501. Remove such statements from connection setup code.

## 5. Writing data

### 5.1 Encrypting values

```sql
INSERT INTO customer (id, full_name, email, phone, birth_date)
VALUES (1001,
        piitext_encrypt('Ana Popescu',             pii_key_customer(1001)),
        piitext_encrypt('ana.popescu@example.com', pii_key_customer(1001)),
        piitext_encrypt('+373 60 000 001',         pii_key_customer(1001)),
        piitext_encrypt('1987-04-12',              pii_key_customer(1001)));

-- The address belongs to customer 1001, so it is encrypted under the customer's key.
INSERT INTO customer_address (customer_id, kind, address)
VALUES (1001, 'home', piitext_encrypt('str. Exemplu 1, Chisinau', pii_key_customer(1001)));
```

- `piitext_encrypt` uses the latest version of the Vault key. The first encryption under a new key id creates the key. If operators turned `pii_vault.auto_create_keys` off, it fails with SQLSTATE 42704 instead.
- Every call uses a fresh random IV, so the same plaintext never encrypts to the same bytes twice.
- Plaintext can be up to 16 MiB, or 512 KiB in transit mode. Larger values fail with SQLSTATE 22023.
- Writing text directly fails by design; nothing is stored unencrypted:

  ```sql
  INSERT INTO customer (id, email) VALUES (1002, 'ion.rusu@example.com');
  -- ERROR:  invalid input syntax for type piitext: expected a value starting with "piitext:"
  INSERT INTO customer (id, email) VALUES (1002, 'ion.rusu@example.com'::text);
  -- ERROR:  column "email" is of type piitext but expression is of type text
  ```

### 5.2 Bind parameters

A literal in the SQL text reaches the server log whenever the statement is logged or fails (`log_min_error_statement`). It also shows up in client-side traces. Send PII as bind parameters. The generic parameterised statement below works with libpq `PQexecParams`, JDBC prepared statements and most other drivers:

```sql
-- $1 customer id (bigint), $2 full name, $3 email, $4 phone, $5 birth date as 'YYYY-MM-DD'
INSERT INTO customer (id, full_name, email, phone, birth_date)
VALUES ($1,
        piitext_encrypt($2, pii_key_customer($1)),
        piitext_encrypt($3, pii_key_customer($1)),
        piitext_encrypt($4, pii_key_customer($1)),
        piitext_encrypt($5, pii_key_customer($1)));
```

psql 16 and later sends real bind parameters with `\bind`:

```sql
INSERT INTO customer (id, email)
VALUES ($1, piitext_encrypt($2, pii_key_customer($1))) \bind 1002 'ion.rusu@example.com' \g
```

psql variables are substituted by the client, so the value still reaches the server as a literal. Use them only for interactive administration; they are not a substitute for bind parameters:

```sql
\set cust_id 1003
\set email 'maria.ionescu@example.com'
INSERT INTO customer (id, email)
VALUES (:cust_id, piitext_encrypt(:'email', pii_key_customer(:cust_id)));
```

Bind parameters keep plaintext out of the statement text. PostgreSQL still writes parameter values next to every statement it logs unless `log_parameter_max_length = 0` (a superuser setting), so agree the logging settings with your operators.

### 5.3 Bulk loads

`COPY` cannot encrypt. Load the plaintext into a temporary table, encrypt it with `INSERT ... SELECT`, then drop the temporary table. Temporary tables are not written to WAL and disappear at the end of the session.

```sql
CREATE TEMP TABLE customer_import (id bigint, full_name text, email text);
\copy customer_import FROM 'customers.csv' WITH (FORMAT csv, HEADER true)
INSERT INTO customer (id, full_name, email)
SELECT id,
       piitext_encrypt(full_name, pii_key_customer(id)),
       piitext_encrypt(email,     pii_key_customer(id))
FROM customer_import;
DROP TABLE customer_import;
```

Every distinct key id costs Vault round trips the first time it is used (see [section 15](#15-performance)). `COPY ... FROM` into a `piitext` column accepts only the `piitext:` text form, such as the output of `COPY ... TO` or `pg_dump` of a `piitext` column. `COPY` in binary format works as well.

## 6. Reading data

### 6.1 Explicit decryption

```sql
SELECT id,
       full_name::text        AS full_name,
       email::text            AS email,
       birth_date::text::date AS birth_date
FROM customer
WHERE id = $1;
```

`piitext_out_text(email)` is the same as `email::text`, and `email::varchar` also decrypts. When the cast is in the select list, PostgreSQL decrypts only the rows it returns. With `ORDER BY <plain column> LIMIT n`, it decrypts only the `n` rows it returns.

### 6.2 Selecting without decryption

```sql
SELECT id, email FROM customer WHERE id = 1001;
--   id  |                    email
-- ------+----------------------------------------------
--  1001 | piitext:pmF2AmFrSQEAAAAAAAAD6WJrdgFhaU...   (shortened)
```

The `piitext:` text form is standard base64 of the stored bytes. `SELECT`, `COPY`, `pg_dump`, logical replication, `to_json()`, `concat()` and `format()` all see this form. Reading it needs no privilege beyond `SELECT` and no Vault access. You can write it back into a `piitext` column unchanged, for example in a dump and restore or a copy to another database that uses the same Vault keys.

### 6.3 Views and functions for authorised roles

A view can give a role decrypted columns without access to the table:

```sql
CREATE VIEW customer_contact AS
SELECT id, full_name::text AS full_name, email::text AS email, phone::text AS phone
FROM customer
WHERE status = 'active';

GRANT SELECT ON customer_contact TO support_agent;
GRANT EXECUTE ON FUNCTION piitext_out_text(piitext) TO support_agent;
```

Functions called by a view run with the privileges of the role that queries the view. `support_agent` therefore needs `EXECUTE` on `piitext_out_text` in addition to `SELECT` on the view. It does not need `SELECT` on `customer`.

To hand out one value at a time without granting `piitext_out_text`, use a `SECURITY DEFINER` function. It must be owned by a role that has `SELECT` on the table and `EXECUTE` on `piitext_out_text`. Such a function is also a natural place for business checks and audit logging.

```sql
CREATE FUNCTION customer_email(p_customer_id bigint) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    RETURN (SELECT email::text FROM public.customer WHERE id = p_customer_id);

REVOKE ALL ON FUNCTION customer_email(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION customer_email(bigint) TO support_agent;
```

### 6.4 Comparisons, search and operators

```sql
SELECT id FROM customer WHERE email = 'ana.popescu@example.com';
-- ERROR:  operator does not exist: piitext = unknown
SELECT DISTINCT email FROM customer;
-- ERROR:  could not identify an equality operator for type piitext

-- Works, but decrypts every row of the table. Avoid this on large tables (see section 15).
SELECT id FROM customer WHERE email::text = $1;
```

- For `ORDER BY`, `DISTINCT`, `GROUP BY` and `UNION`, use the decrypted expression, for example `ORDER BY email::text`.
- Functions that expect `text` need the cast, for example `lower(email::text)` or `length(email::text)`.
- `||` decrypts. PostgreSQL's built-in `anynonarray || text` operator casts its non-text operand with `::text`, so `email || ''` returns plaintext and needs `EXECUTE` on `piitext_out_text`. `concat()`, `format()` and `to_json()` use the `piitext:` text form and return ciphertext. Write the cast explicitly in every case.

## 7. Updating data

```sql
-- $1 customer id, $2 new email
UPDATE customer
SET    email = piitext_encrypt($2, pii_key_customer(id))
WHERE  id = $1;
```

Derive the key id from the row being written, as in `pii_key_customer(id)` or `pii_key_customer(customer_id)`. Never derive it from a request parameter that could name another subject.

Changing a value means decrypting it, changing it and encrypting it again:

```sql
UPDATE customer
SET    email = piitext_encrypt(lower(email::text), pii_key_customer(id))
WHERE  id = 1001;
```

A sealed value is bound to its key id, not to its row. If you copy it into another subject's row, it stays encrypted under the first subject's key. It then survives the erasure of its new owner and becomes unreadable when the first subject is erased. Re-encrypt it when you copy it:

```sql
-- Copy the home address of customer 1001 to customer 1002 (same household).
INSERT INTO customer_address (customer_id, kind, address)
SELECT 1002, kind, piitext_encrypt_piitext(address, pii_key_customer(1002))
FROM customer_address
WHERE customer_id = 1001 AND kind = 'home';
```

Never write back a value that you read as `****`. That encrypts the literal text `****` under a newly created key for the erased subject. Check the subject's status instead (see [section 12](#12-crypto-shredding-for-a-gdpr-erasure-request)).

## 8. NULL semantics

| Expression | Result |
|---|---|
| `piitext_encrypt(NULL, key_id)` | `NULL` |
| `piitext_encrypt('x', NULL)` | ERROR 22023 `key id must not be NULL` |
| `piitext_encrypt(NULL, NULL)` | `NULL` |
| `piitext_encrypt('', key_id)` | an encrypted empty string (decrypts to `''`, not `NULL`) |
| `NULL::piitext::text`, `piitext_out_text(NULL)` | `NULL` |
| `piitext_encrypt_piitext(NULL, key_id)` | `NULL` |
| `piitext_encrypt_piitext(value, NULL)` | ERROR 22023 `key id must not be NULL` |
| `piitext_reencrypt(NULL)` | `NULL` |
| `piitext_is_encrypted`, `piitext_key_id`, `piitext_key_version`, `piitext_debug` of `NULL` | `NULL` |
| `piitext_key_id(staging value)` | `NULL` |
| `piitext_key_version(staging value or value written by 0.0.x)` | `NULL` |
| `piitext_shred(NULL)` | ERROR 22023 `key id must not be NULL` |
| decrypting a value whose key was deleted | `'****'`, not `NULL` |

In 0.0.0 a NULL key id silently turned the value into NULL. In 0.1.0 it is an error, so a missing subject id can no longer erase data unnoticed.

## 9. Encrypting an existing plaintext column

Suppose `customer` still has a plaintext column `tax_id text` from before pg_pii_vault was introduced. The procedure below encrypts it with no downtime beyond short locks. It uses the same key id expression as the application, `pii_key_customer(id)`, which is `'\x01'::bytea || int8send(id)`.

**Step 1.** Add the encrypted column:

```sql
ALTER TABLE customer ADD COLUMN tax_id_enc piitext;
```

**Step 2.** Keep new writes in sync while the backfill runs. The application keeps writing `tax_id` until the switch in step 5. The roles that write to `customer` need `EXECUTE` on `piitext_encrypt` while this trigger exists.

```sql
CREATE FUNCTION customer_tax_id_sync() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    NEW.tax_id_enc := piitext_encrypt(NEW.tax_id, pii_key_customer(NEW.id));
    RETURN NEW;
END $$;

CREATE TRIGGER customer_tax_id_sync
    BEFORE INSERT OR UPDATE OF tax_id ON customer
    FOR EACH ROW EXECUTE FUNCTION customer_tax_id_sync();
```

**Step 3.** Backfill in primary key ranges, one transaction per batch. PostgreSQL has no `UPDATE ... LIMIT`; a range on the primary key keeps every batch an index range scan.

```sql
UPDATE customer
SET    tax_id_enc = piitext_encrypt(tax_id, pii_key_customer(id))
WHERE  id >= 1 AND id < 10001
  AND  tax_id IS NOT NULL
  AND  tax_id_enc IS NULL;
```

Repeat for the next ranges. Alternatively, use a procedure that commits after each batch. Run `CALL` outside an explicit transaction block.

```sql
CREATE PROCEDURE customer_tax_id_backfill(batch_size bigint DEFAULT 10000)
    LANGUAGE plpgsql AS $$
DECLARE
    lo bigint;
    hi bigint;
BEGIN
    SELECT min(id), max(id) INTO lo, hi FROM customer;
    WHILE lo <= hi LOOP
        UPDATE customer
        SET    tax_id_enc = piitext_encrypt(tax_id, pii_key_customer(id))
        WHERE  id >= lo AND id < lo + batch_size
          AND  tax_id IS NOT NULL
          AND  tax_id_enc IS NULL;
        COMMIT;
        lo := lo + batch_size;
    END LOOP;
END $$;

CALL customer_tax_id_backfill();
```

**Step 4.** Verify. All three queries must return 0.

```sql
-- Every plaintext value has an encrypted counterpart (no Vault access).
SELECT count(*) AS missing
FROM customer WHERE tax_id IS NOT NULL AND tax_id_enc IS NULL;

-- Every value is sealed under the right key id (no Vault access).
SELECT count(*) AS wrong_key
FROM customer
WHERE tax_id_enc IS NOT NULL
  AND (NOT piitext_is_encrypted(tax_id_enc) OR piitext_key_id(tax_id_enc) <> pii_key_customer(id));

-- Every value decrypts to the original. This decrypts every row:
-- one Vault request per subject key in export mode, one per row in transit mode.
SELECT count(*) AS mismatched
FROM customer WHERE tax_id_enc::text IS DISTINCT FROM tax_id;
```

**Step 5.** Switch over in one transaction, and deploy the application version that writes with `piitext_encrypt` and reads with `::text` at the same time. After the rename, old code that writes text into `tax_id` fails with SQLSTATE 42804 and stores nothing.

```sql
BEGIN;
UPDATE customer
SET    tax_id_enc = piitext_encrypt(tax_id, pii_key_customer(id))
WHERE  tax_id IS NOT NULL AND tax_id_enc IS NULL;      -- rows missed so far, if any
DROP TRIGGER customer_tax_id_sync ON customer;
DROP FUNCTION customer_tax_id_sync();
ALTER TABLE customer DROP COLUMN tax_id;
ALTER TABLE customer RENAME COLUMN tax_id_enc TO tax_id;
COMMIT;
```

**Step 6.** Remove the plaintext left behind. `DROP COLUMN` only hides the column: its values stay in the table's data files. Every backfill `UPDATE` also left behind a dead row version that contains the plaintext. `VACUUM FULL` rewrites the table and its TOAST table without either of them. It holds an `ACCESS EXCLUSIVE` lock on the table while it runs.

```sql
VACUUM FULL customer;
```

Crypto-shredding cannot reach plaintext outside the table. Handle these copies under your retention policy:

- WAL segments and WAL archives
- base backups and dumps taken before the migration
- logical replication subscribers and CDC consumers
- disk blocks freed by the rewrite (the old files are deleted, not overwritten)

Physical standbys replay the rewrite.

## 10. Staging values

`piitext_in_text(text)` builds a **staging value**: plaintext stored in a `piitext` column without encryption. It exists for migrations, for example to convert a small table in place during a maintenance window:

```sql
CREATE TABLE lead (id uuid PRIMARY KEY, email text);    -- an existing table

-- Converts in place. Rewrites the table under an ACCESS EXCLUSIVE lock.
ALTER TABLE lead ALTER COLUMN email TYPE piitext USING piitext_in_text(email);

-- Encrypt the staging values. On a large table, run this in batches (see section 9).
UPDATE lead
SET    email = piitext_encrypt_piitext(email, pii_key_lead(id))
WHERE  NOT piitext_is_encrypted(email);

SELECT count(*) FROM lead WHERE NOT piitext_is_encrypted(email);   -- 0
```

For large or busy tables, prefer the procedure in [section 9](#9-encrypting-an-existing-plaintext-column), which never exposes the whole column as staging values.

Staging values are **not protected**:

- Any role with `SELECT` can read them. No grant or Vault access is needed, because the `piitext:` text form is base64 of the plaintext:

  ```sql
  SELECT convert_from(decode(substr(concat(email), 9), 'base64'), 'UTF8') FROM lead
  WHERE NOT piitext_is_encrypted(email);
  ```

- `piitext_raw()`, `pg_dump`, `COPY`, logical replication and error messages that print row values also expose the plaintext.
- Crypto-shredding does not cover them. After they are encrypted, their plaintext stays in WAL, backups and dead row versions (see section 9, step 6).

Settings and checks:

- With `pii_vault.allow_staging = off` (a superuser setting), no new staging value can be created. `piitext_in_text()` fails with SQLSTATE 55000, and so does every other way in: a `piitext:` literal whose payload is plaintext, `COPY` in text or binary format, `pg_restore` and logical replication of such a value. Encrypted values are accepted as before. Existing staging values stay readable and can still be encrypted with `piitext_encrypt_piitext()`.
- The setting controls how values enter the database, not what is stored. A staging value that already exists can still be copied, for example with `INSERT ... SELECT`, through a column default or a prepared statement created while staging was on.
- Because of that, a dump that contains staging values can only be restored while `allow_staging` is on. Encrypt staging values before you turn it off.
- To guarantee that one column holds only encrypted values whatever the setting is, add a check constraint:

  ```sql
  ALTER TABLE lead ADD CONSTRAINT lead_email_encrypted CHECK (piitext_is_encrypted(email));
  ```

- `piitext_reencrypt()` refuses staging values with SQLSTATE 22023. Use `piitext_encrypt_piitext(value, key_id)` to encrypt them.

## 11. Re-encryption and key rotation

Two functions re-encrypt existing values:

- `piitext_reencrypt(value)` decrypts the value and encrypts it again under the **same key id** with the latest key version, in the current key mode. Use it after a key rotation, to upgrade values written by 0.0.x (format 1) to format 2, or to move values to transit mode after operators switch `pii_vault.key_mode`. It asks Vault for the latest key version unless the key was fetched in the last two seconds, so a cached key never makes it a silent no-op, and it never creates a key.
- `piitext_encrypt_piitext(value, key_id)` decrypts the value and encrypts it under **another key id**. It also encrypts staging values.

Both need a Vault token that can decrypt the old value and encrypt the new one. For a move from export to transit mode, the token needs both policies. Both fail with SQLSTATE 42704 for a value whose key was deleted, because such a value cannot be decrypted.

### Rotation

Operators rotate keys in Vault; the database token cannot. Rotation is written in Vault CLI syntax:

```sh
vault write -f transit/keys/0100000000000003e9/rotate
```

After a rotation:

- Existing values stay readable as long as Vault keeps their key version, that is, as long as `min_decryption_version` is not raised.
- `piitext_encrypt()` in each backend keeps using the key versions it has cached until its cache entry expires (`pii_vault.cache_ttl_sec`, 300 seconds by default). `piitext_reencrypt()` is not affected. To apply the new version at once in every backend of the cluster, a role with the grant runs:

  ```sql
  SELECT piitext_cache_invalidate();     -- false means the library is not preloaded: only this backend was flushed
  ```

- To re-encrypt the subject's values with the new version, run the following. `piitext_reencrypt` is `STRICT`, so NULL columns stay NULL.

  ```sql
  UPDATE customer
  SET    full_name  = piitext_reencrypt(full_name),
         email      = piitext_reencrypt(email),
         phone      = piitext_reencrypt(phone),
         birth_date = piitext_reencrypt(birth_date)
  WHERE  id = 1001;

  UPDATE customer_address SET address = piitext_reencrypt(address) WHERE customer_id = 1001;

  SELECT piitext_key_version(email) FROM customer WHERE id = 1001;    -- 2
  ```

- Once no value uses an old version any more, operators may raise `min_decryption_version`. Values still encrypted with a retired version then read as `****`: they are effectively shredded.

For bulk re-encryption, use primary key ranges as in [section 9](#9-encrypting-an-existing-plaintext-column), and restrict each batch to the values that need it. For example, `piitext_key_version(email) IS NULL` selects values written by 0.0.x, and `piitext_key_version(email) < 2` selects values that predate a known rotation. A value whose key was deleted makes the whole batch fail with SQLSTATE 42704. Exclude erased subjects (`WHERE status <> 'erased'`), or clear their values during the erasure.

### Changing the key mode

Operators change `pii_vault.key_mode`. From then on, new values use the new mode: format 2 for export mode, format 3 for transit mode. Existing values of both formats stay readable. `piitext_reencrypt()` moves old values to the current mode. A key that was created in export mode stays exportable in Vault. The guarantee that keys never leave Vault only holds for keys created in transit mode.

## 12. Crypto-shredding for a GDPR erasure request

The flow below erases customer 1003. It uses a journal table so that the erasure can be retried and replayed:

```sql
CREATE TABLE erasure_log (
    key_id        bytea PRIMARY KEY,
    requested_at  timestamptz NOT NULL DEFAULT now(),
    shredded_at   timestamptz
);
```

**Step 1.** Record the request and stop processing the subject in an ordinary transaction. Clearing or deleting the current copies is optional. Shredding is still needed afterwards, because backups, WAL archives, replicas and dumps keep the ciphertext.

```sql
BEGIN;
UPDATE customer SET status = 'erased' WHERE id = 1003;
INSERT INTO erasure_log (key_id) VALUES (pii_key_customer(1003));
-- Optional:
UPDATE customer SET full_name = NULL, email = NULL, phone = NULL, birth_date = NULL WHERE id = 1003;
DELETE FROM customer_address WHERE customer_id = 1003;
COMMIT;
```

**Step 2.** Shred the key. The erasure role needs `EXECUTE` on `piitext_shred`.

```sql
SELECT piitext_shred(pii_key_customer(1003));   -- true: the Vault key was deleted
```

`false` means that no such key exists: it was already shredded, or nothing was ever encrypted for this subject. Both mean the erasure is done, so the step is safe to repeat.

**Step 3.** Close the request:

```sql
UPDATE erasure_log SET shredded_at = now() WHERE key_id = pii_key_customer(1003);
```

Values that were not cleared in step 1 now decrypt to `****`.

**The shred is independent of the transaction.** `piitext_shred()` deletes the Vault key the moment it runs, and `ROLLBACK` does not bring it back:

```sql
BEGIN;
SELECT piitext_shred(pii_key_customer(1002));   -- true
ROLLBACK;
SELECT email::text FROM customer WHERE id = 1002;   -- ****  (the key is gone anyway)
```

So commit the bookkeeping first (step 1), shred in a separate step, and keep the job idempotent: retry step 2 from `erasure_log` until it succeeds. Never call `piitext_shred()` in a transaction that can still fail afterwards, for example in a trigger.

Scope and caveats:

- When the library is preloaded, the shred takes effect at once in this cluster: every backend drops its cached copy of the key, even if the call fails or is cancelled after the deletion was requested. Other PostgreSQL clusters that use the same Vault keys can keep decrypting for up to `pii_vault.cache_ttl_sec`; this includes physical standbys. Run `SELECT piitext_cache_invalidate();` there, or wait. Transit mode caches nothing.
- After a shred, `piitext_encrypt()` with the same key id creates a new key. New data for the subject would be readable again. Block writes for erased subjects in the application, for example with the `status` check from step 1.
- Re-encrypting a value whose key was shredded fails with SQLSTATE 42704. Exclude erased subjects from re-encryption batches.
- Shredding covers encrypted values only. Staging values, plaintext columns, logs, exports and other systems need their own erasure.
- A Vault snapshot taken before the erasure still contains the key, and restoring it brings the key back. Keep `erasure_log`, re-run the shreds after any Vault restore, and keep Vault backup retention within your erasure deadlines.

Operators can also shred with the Vault CLI:

```sh
vault write transit/keys/0100000000000003eb/config deletion_allowed=true
vault delete transit/keys/0100000000000003eb
```

Then they run `SELECT piitext_cache_invalidate();` in each cluster, or wait `pii_vault.cache_ttl_sec`.

## 13. Metadata functions

These functions read only the stored value. They make no Vault request, never decrypt and are executable by `PUBLIC`. The output below shows customer 1001 after the rotation in [section 11](#11-re-encryption-and-key-rotation).

```sql
SELECT id,
       piitext_is_encrypted(email)           AS encrypted,
       encode(piitext_key_id(email), 'hex')  AS vault_key_name,
       piitext_key_version(email)            AS key_version,
       piitext_debug(email)                  AS debug
FROM customer
WHERE id = 1001;
--   id  | encrypted |   vault_key_name   | key_version |                                       debug
-- ------+-----------+--------------------+-------------+-----------------------------------------------------------------------------------
--  1001 | t         | 0100000000000003e9 |           2 | Sealed(format=2, key_id=\x0100000000000003e9, key_version=2, ciphertext_bytes=23)
```

- `piitext_debug()` returns one of two shapes:
  - `Sealed(format=N, key_id=..., key_version=..., ciphertext_bytes=...)`, where format 1 was written by 0.0.x (`key_version=unrecorded`), format 2 by export mode and format 3 by transit mode
  - `Staging(plaintext_bytes=N)`

  It never shows plaintext.
- `piitext_raw()` returns the stored bytes: CBOR for sealed values and the plaintext itself for staging values.
- The following query checks that values are sealed under the key of the row's subject. It finds copy mistakes like the one described in [section 7](#7-updating-data):

  ```sql
  SELECT id FROM customer_address
  WHERE piitext_key_id(address) IS DISTINCT FROM pii_key_customer(customer_id);
  ```

- `piitext_key_id()` is `IMMUTABLE` and contains no plaintext, so it can be indexed, for example `CREATE INDEX ON customer_address (piitext_key_id(address));`.

Statistics and cache:

```sql
SELECT metric, backend, cluster FROM piitext_stats();
```

`backend` counts for the current connection. `cluster` counts for all backends since the server started, and is NULL when the library is not preloaded. The metrics are:

- `cache_entries` (keys cached by this backend, including keys known to be absent), `cache_hits`, `cache_misses`, `cache_evictions`
- `vault_requests`: HTTP requests sent to Vault, counting every attempt
- `vault_errors`: attempts that failed with a connection error, a timeout or HTTP 412/429/5xx
- `vault_denied`: statements that failed because Vault refused the token or its policy (HTTP 401/403)
- `keys_created`, `keys_shredded`
- `decrypt_masked`: the number of `****` results

The cache functions are:

- `piitext_cache_evict(key_id)` and `piitext_cache_flush()` act on the current backend only.
- `piitext_cache_invalidate()` makes every backend of the cluster drop its cache. It requires a grant.

## 14. Error handling in applications

Every error raised by the extension has a SQLSTATE and usually a hint. The messages never contain the Vault token. They can contain the Vault key name (the hex key id), which is one more reason to keep PII out of key ids.

| SQLSTATE | Meaning | Retry? |
|---|---|---|
| `58000` system_error | Vault unavailable: connection error, timeout (`pii_vault.timeout_ms`), TLS failure, HTTP 412/429/5xx after the extension's own retries (`pii_vault.max_retries`), or too many earlier requests of the session still running after cancellations | Yes, with backoff. Alert if it persists. |
| `57014` query_canceled | `statement_timeout` or a cancel request while waiting for Vault (standard PostgreSQL) | Per your usual policy |
| `42501` insufficient_privilege | Vault refused the request (HTTP 401/403: the token is invalid, expired or revoked, its policy does not allow it, or no engine is mounted at `pii_vault.mount`), the role lacks `EXECUTE` on a piitext function, or a non-superuser tried to `SET pii_vault.*` | No. Fix the token, policy or grants. |
| `55000` object_not_in_prerequisite_state | Configuration error (URL, token or token file missing or unreadable, `pii_vault.mount` not a Transit engine or not the one `pii_vault.mount_accessor` names), plain `http://` to a Vault host that is not local, or staging values disabled | No. Configuration problem. |
| `38000` external_routine_exception | Unexpected Vault response: a redirect, a 404 that does not come from the Transit engine (for example from a proxy), a key that is not exportable in export mode or not of type `aes256-gcm96`, or a malformed reply | No. Operators. |
| `42704` undefined_object | Key not found: `pii_vault.auto_create_keys` is off and the key does not exist, or a shredded value was re-encrypted | No. Business handling. |
| `22023` invalid_parameter_value | NULL, empty or over-long key id, plaintext over 16 MiB (512 KiB in transit mode), or `piitext_reencrypt` on a staging value | No. Application bug. |
| `22P02` invalid_text_representation | Text that is not a `piitext:` form was given where `piitext` is expected | No. Use `piitext_encrypt`. |
| `XX001` data_corrupted | A value cannot be decoded or exceeds the limits of its format, a value given as input is not in the encoding pg_pii_vault writes, or Vault rejected a ciphertext as invalid | No. Investigate. |

Code that still relies on implicit casts fails with `42804` (text assigned to a `piitext` column) or `42883` (operator or function on `piitext`). Both are application bugs.

- Retry the whole transaction, not just the failed statement.
- A single Vault request waits at most `pii_vault.timeout_ms` (default 5000 ms). The extension retries connection errors and HTTP 412, 429 and 5xx up to `pii_vault.max_retries` times (default 2) with backoff. It does not retry timeouts. A new key id takes up to three requests. Use `statement_timeout` to bound the total wait.
- `****` is not an error. It means the key was deleted, usually because the subject was erased. Make your own data authoritative (`status = 'erased'`), and never write `****` back.
- Before 0.1.0, a Vault outage also produced `****`. An application that wrote such values back lost data. In 0.1.0 an outage is always an error.

## 15. Performance

How much Vault work a query costs depends on the key mode:

- **Export mode.** A backend fetches a key from Vault on first use and caches it for `pii_vault.cache_ttl_sec` (300 seconds by default), up to `pii_vault.cache_max_entries` keys (10000 by default). The first encryption under a new key id takes three round trips: export (404), create, export. A cold backend that decrypts N rows of N different subjects makes N round trips. The AES work itself is cheap.
- **Transit mode.** Nothing is cached. Every encryption and every decryption is one Vault request.
- **Caches are per backend.** Short-lived connections pay the round trips again. Pooled, long-lived connections keep their caches warm. Parallel workers have their own caches.
- **Erased values still cost requests.** A backend remembers that a key is gone for at most 30 seconds, so reading values of erased subjects costs one Vault request per key and backend every 30 seconds. Clear or delete the values of erased subjects (step 1 in [section 12](#12-crypto-shredding-for-a-gdpr-erasure-request)) so that scans do not pay for them.

Tips:

1. **Decrypt in the select list and filter on plain columns**, for example `SELECT email::text FROM customer WHERE id = $1`.
2. **Avoid decrypting in `WHERE`, `JOIN`, `ORDER BY` or `GROUP BY` on large tables.** Every candidate row is decrypted. If you must search by value, narrow the rows first with plain columns. PostgreSQL evaluates cheaper conditions first, and decryption is declared with `COST 100`:

   ```sql
   SELECT id FROM customer_address
   WHERE customer_id = $1              -- evaluated first
     AND address::text ILIKE $2;       -- decrypts only this customer's rows
   ```

3. **Filter by key id first.** One subject's values are found through the plain subject column (`WHERE customer_id = $1`) or through `piitext_key_id(col) = pii_key_customer($1)`. Neither touches Vault, and both can use an index.
4. **Parallel query.** Decryption is `PARALLEL SAFE`, so large read-only scans that decrypt can use parallel workers. Each worker makes its own Vault requests. The encryption functions are `VOLATILE` and not parallel safe, so statements that encrypt run serially. To speed up a large backfill, run several sessions on disjoint key ranges.
5. **`ORDER BY email::text LIMIT 10` decrypts all candidate rows** before it sorts. `ORDER BY created_at LIMIT 10` decrypts ten.
6. **Keep write transactions short** and batch large updates (see [section 9](#9-encrypting-an-existing-plaintext-column)).
7. **Measure** with `piitext_stats()`. Compare the `backend` value of `vault_requests` before and after a query.

## 16. Function reference

"Grant" means that `EXECUTE` is revoked from `PUBLIC` and must be granted explicitly.

| Function | Markings | EXECUTE | Vault | Purpose |
|---|---|---|---|---|
| `piitext_encrypt(plaintext text, key_id bytea) → piitext` | VOLATILE | grant | yes | Encrypt with the latest version of the key; creates the key if missing (`pii_vault.auto_create_keys`) |
| `piitext_out_text(piitext) → text`, casts `::text` and `::varchar` | STABLE, STRICT, PARALLEL SAFE | grant | yes (not for staging values) | Decrypt; `****` when the key or key version no longer exists |
| `piitext_encrypt_piitext(value piitext, key_id bytea) → piitext` | VOLATILE | grant | yes | Encrypt a staging value, or re-encrypt under another key id |
| `piitext_reencrypt(piitext) → piitext` | VOLATILE, STRICT | grant | yes | Re-encrypt under the same key id with the latest version, in the current key mode; never creates the key |
| `piitext_in_text(text) → piitext` | STABLE, STRICT, PARALLEL SAFE | PUBLIC | no | Build a staging value (not encrypted); refused when `pii_vault.allow_staging = off` |
| `piitext_is_encrypted(piitext) → boolean` | IMMUTABLE | PUBLIC | no | Sealed or staging |
| `piitext_key_id(piitext) → bytea` | IMMUTABLE | PUBLIC | no | Key id; NULL for staging values |
| `piitext_key_version(piitext) → bigint` | IMMUTABLE | PUBLIC | no | Vault key version; NULL for staging values and values written by 0.0.x |
| `piitext_debug(piitext) → text` | IMMUTABLE | PUBLIC | no | Description without plaintext |
| `piitext_raw(piitext) → bytea` | IMMUTABLE | PUBLIC | no | Stored bytes |
| `piitext_shred(key_id bytea) → boolean` | VOLATILE | grant | yes | Delete the Vault key; not transactional |
| `piitext_cache_evict(key_id bytea) → boolean` | VOLATILE | PUBLIC | no | Evict one key from this backend's cache |
| `piitext_cache_flush() → bigint` | VOLATILE | PUBLIC | no | Empty this backend's cache |
| `piitext_cache_invalidate() → boolean` | VOLATILE | grant | no | Every backend of the cluster drops its cache; `false` when not preloaded |
| `piitext_stats() → table (metric, backend, cluster)` | VOLATILE | PUBLIC | no | Counters |
| `piitext_vault_check() → table (check_name, ok, required, detail)` | VOLATILE | grant | yes | Configuration and Vault policy diagnostics; healthy when every `required` row is `ok` |

`piitext_send` and `piitext_recv` implement the binary format, which `COPY ... (FORMAT binary)`, drivers that use the binary protocol and binary logical replication rely on. The type's input functions are `STABLE`: they refuse plaintext staging values while `pii_vault.allow_staging` is off.
