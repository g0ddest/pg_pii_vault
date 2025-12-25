# pg_pii_vault - Usage Guide

## Basic Functionality

### 1. Create a Table

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT,
    secret_data piitext  -- Type for encrypted data
);
```

### 2. Configuration (Production with Vault)

```sql
SET pii_vault.url = 'http://vault:8200';
SET pii_vault.token = 'your-vault-token';
SET pii_vault.mount = 'transit';  -- optional, default: transit
SET pii_vault.cache_ttl_sec = 300; -- optional, default: 300
```

For testing, you can use mock mode:
```sql
SET pii_vault.url = 'mock://localhost';
```

### 3. Inserting Encrypted Data

Use the `piitext_encrypt(plaintext, key_id_bytes)` function where key_id_bytes is the byte representation of your ID:

```sql
-- With INTEGER ID
INSERT INTO users VALUES (
    123,
    'user@example.com',
    piitext_encrypt('secret password', decode('0000007b', 'hex'))  -- 123 in hex
);

-- With UUID ID
INSERT INTO users VALUES (
    456,
    'admin@example.com',
    piitext_encrypt('admin secret', uuid_send(gen_random_uuid()))
);

-- Or using existing ID from table
INSERT INTO users (id, email, secret_data)
SELECT
    789,
    'test@example.com',
    piitext_encrypt('test secret', decode(lpad(to_hex(789), 8, '0'), 'hex'));
```

### 4. Reading Data

**Readable format (decrypted text):**
```sql
SELECT id, email, piitext_out_text(secret_data) as secret
FROM users;

-- Result:
-- id  | email              | secret
-- 123 | user@example.com   | secret password
-- 456 | admin@example.com  | admin secret
```

**Debug format (to verify encryption):**
```sql
SELECT piitext_debug(secret_data) FROM users WHERE id = 123;

-- Result:
-- Sealed(PiiSealedData { version: 1, key_id: [0, 0, 0, 123], iv: [...], tag: [...], ciphertext: [...] })
```

### 5. Working with Different ID Types

#### INTEGER
```sql
-- Helper function to convert integer to bytea (big-endian)
CREATE FUNCTION int_to_key_bytes(id INTEGER) RETURNS BYTEA AS $$
    SELECT decode(lpad(to_hex(id), 8, '0'), 'hex')
$$ LANGUAGE SQL IMMUTABLE;

INSERT INTO users VALUES (100, 'test@test.com', piitext_encrypt('data', int_to_key_bytes(100)));
```

#### BIGINT
```sql
CREATE FUNCTION bigint_to_key_bytes(id BIGINT) RETURNS BYTEA AS $$
    SELECT decode(lpad(to_hex(id), 16, '0'), 'hex')
$$ LANGUAGE SQL IMMUTABLE;
```

#### UUID
```sql
-- UUID already has the uuid_send() function
INSERT INTO users VALUES (200, 'uuid@test.com', piitext_encrypt('data', uuid_send('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'::uuid)));
```

#### TEXT/VARCHAR
```sql
-- For text IDs, simply use convert_to
INSERT INTO users VALUES (300, 'text@test.com', piitext_encrypt('data', convert_to('user-id-12345', 'UTF8')));
```

## Re-encryption Workflow

You can start with unencrypted data and encrypt it later, or re-encrypt with a different key:

```sql
-- Step 1: Insert plain text (staging mode)
INSERT INTO users VALUES (999, 'alice@example.com', piitext_in_text('sensitive data'));

-- Step 2: Data is readable
SELECT piitext_out_text(secret_data) FROM users WHERE id = 999;
-- Result: sensitive data

-- Step 3: Encrypt in place with specific key_id
UPDATE users
SET secret_data = piitext_encrypt_piitext(secret_data, decode('000003e7', 'hex'))
WHERE id = 999;

-- Step 4: Still readable (automatic decryption)
SELECT piitext_out_text(secret_data) FROM users WHERE id = 999;
-- Result: sensitive data

-- Step 5: Re-encrypt with different key if needed
UPDATE users
SET secret_data = piitext_encrypt_piitext(secret_data, decode('000003e8', 'hex'))
WHERE id = 999;
```

## Security

### AAD (Additional Authenticated Data)

The extension automatically uses AAD in the format:
```
col:piitext:id:<hex_key_id>
```

This protects against:
- Moving encrypted data between records
- Substituting key_id in encrypted data

### Crypto Shredding

To delete data without possibility of recovery:
1. Delete the key in Vault for a specific key_id
2. Data becomes impossible to decrypt (returns `****`)

```sql
-- After deleting key in Vault:
SELECT piitext_out_text(secret_data) FROM users WHERE id = 123;
-- Result: ****
```

## Data Format on Disk

Data is stored in CBOR format:
```rust
{
    "v": 1,           // version
    "k": [0,0,0,123], // key_id bytes
    "i": [...],       // 12 bytes IV
    "t": [...],       // 16 bytes auth tag
    "c": [...]        // encrypted data
}
```

AES-256-GCM is used for encryption.

## pg_dump / Backup

When creating a PostgreSQL dump, the binary format (CBOR) is automatically used for the piitext type. This means:
- The dump contains encrypted data
- Access to the same keys in Vault is required for restoration
- Safe to store dumps since data is encrypted

## Performance

### Key Caching
- Keys are cached in memory for the duration of `pii_vault.cache_ttl_sec`
- Default is 300 seconds (5 minutes)
- Reduces load on Vault
- Cache is shared between all PostgreSQL sessions

### Recommendations
- Use INTEGER/BIGINT IDs for better performance
- Configure cache_ttl based on your security requirements
- In production, use indexes on ID columns

## Current Version Limitations

1. **No automatic encryption via triggers** - need to explicitly call `piitext_encrypt()`
2. **No `piitext(id_column)` syntax** - use helper functions for ID conversion
3. **SELECT returns CBOR JSON** - use `piitext_out_text()` for readable output

## Usage Examples

### Creating a View for Convenience
```sql
CREATE VIEW users_decrypted AS
SELECT
    id,
    email,
    piitext_out_text(secret_data) as secret_data
FROM users;

-- Now you can read as usual:
SELECT * FROM users_decrypted;
```

### Bulk Insert
```sql
INSERT INTO users (id, email, secret_data)
SELECT
    id,
    email,
    piitext_encrypt(secret_text, int_to_key_bytes(id))
FROM staging_table;
```

### Gradual Migration from Plain Text
```sql
-- Step 1: Add new piitext column
ALTER TABLE users ADD COLUMN secret_data_encrypted piitext;

-- Step 2: Migrate data gradually
UPDATE users
SET secret_data_encrypted = piitext_encrypt(secret_data, int_to_key_bytes(id))
WHERE secret_data_encrypted IS NULL
LIMIT 1000;

-- Step 3: Once complete, drop old column and rename
ALTER TABLE users DROP COLUMN secret_data;
ALTER TABLE users RENAME COLUMN secret_data_encrypted TO secret_data;
```

## Core Functions Reference

| Function | Description |
|----------|-------------|
| `piitext_encrypt(text, bytea)` | Encrypts text with specified key_id |
| `piitext_encrypt_piitext(piitext, bytea)` | Re-encrypts piitext with new key_id |
| `piitext_out_text(piitext)` | Decrypts and returns text |
| `piitext_in_text(text)` | Creates piitext from text (unencrypted) |
| `piitext_debug(piitext)` | Returns debug information |
| `piitext_raw(piitext)` | Returns raw CBOR bytes |
