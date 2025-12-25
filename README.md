# pg_pii_vault

PostgreSQL extension for GDPR-compliant column-level encryption using HashiCorp Vault Transit Engine.

## Notice

⚠️ This project is in the early stages of development and not ready for production use.

## Features

✅ **Column-level encryption** - Transparent encryption at the column level

✅ **Per-record keys** - Separate encryption key for each record

✅ **Vault integration** - Seamless integration with HashiCorp Vault Transit Engine

✅ **Crypto shredding** - GDPR-compliant data deletion by removing keys

✅ **AAD protection** - Prevents encrypted data from being moved between records

✅ **Key caching** - In-memory key caching for performance optimization

## Quick Start

### Installation

```bash
# Prerequisites: Rust, pgrx
cargo install cargo-pgrx
cargo pgrx init

# Build and install
cd pg_pii_vault
cargo pgrx install --pg-config $(which pg_config)
```

### Create Extension

```sql
CREATE EXTENSION pg_pii_vault;
```

### Configuration

```sql
-- Production (with Vault)
SET pii_vault.url = 'http://vault:8200';
SET pii_vault.token = 'your-vault-token';
SET pii_vault.mount = 'transit';

-- Testing (mock mode, keys are not persisted)
SET pii_vault.url = 'mock://localhost';
```

### Usage

```sql
-- 1. Create a table
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT,
    secret piitext
);

-- 2. Insert encrypted data
INSERT INTO users VALUES (
    123,
    'user@example.com',
    piitext_encrypt('my secret data', decode('0000007b', 'hex'))
);

-- 3. Read data (automatically decrypted)
SELECT id, email, piitext_out_text(secret) FROM users;
-- Result: 123 | user@example.com | my secret data

-- 4. Debug view (show encrypted structure)
SELECT piitext_debug(secret) FROM users WHERE id = 123;
-- Result: Sealed(PiiSealedData { version: 1, key_id: [0, 0, 0, 123], ... })
```

### Crypto Shredding Workflow

```sql
-- Start with unencrypted data
INSERT INTO users VALUES (456, 'alice@example.com', piitext_in_text('sensitive data'));

-- Data is readable
SELECT piitext_out_text(secret) FROM users WHERE id = 456;
-- Result: sensitive data

-- Encrypt in-place when ready
UPDATE users SET secret = piitext_encrypt(
    piitext_out_text(secret),
    decode('000001c8', 'hex')
) WHERE id = 456;

-- Still readable (decryption happens automatically)
SELECT piitext_out_text(secret) FROM users WHERE id = 456;
-- Result: sensitive data

-- Delete key in Vault for GDPR compliance
-- (key_id 000001c8)

-- Data becomes unrecoverable
SELECT piitext_out_text(secret) FROM users WHERE id = 456;
-- Result: ****
```

## Core Functions

| Function | Description |
|----------|-------------|
| `piitext_encrypt(text, bytea)` | Encrypts text with specified key_id |
| `piitext_out_text(piitext)` | Decrypts and returns text |
| `piitext_in_text(text)` | Creates piitext from text (unencrypted) |
| `piitext_debug(piitext)` | Returns debug information |
| `piitext_raw(piitext)` | Returns raw CBOR bytes |

### Data Format (CBOR)

```json
{
  "v": 1,              // version
  "k": [0,0,0,123],    // key_id (bytes)
  "i": [...],          // IV (12 bytes)
  "t": [...],          // Auth tag (16 bytes)
  "c": [...]           // Ciphertext
}
```

- **Algorithm**: AES-256-GCM
- **IV**: 12 bytes, generated via `pg_strong_random()`
- **AAD**: `col:piitext:id:<hex_key_id>` for protection against attacks

## Testing

```bash
# Run all tests
cargo pgrx test pg16

# Expected output:
# test tests::pg_test_piitext_basic ... ok
# test tests::pg_test_encryption_with_uuid ... ok
# test tests::pg_test_encryption_with_int ... ok
# test tests::pg_test_debug_output ... ok
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `pii_vault.url` | Vault server URL | - |
| `pii_vault.token` | Authorization token | - |
| `pii_vault.mount` | Transit engine mount path | `transit` |
| `pii_vault.cache_ttl_sec` | Key cache TTL (seconds) | `300` |

## Security

### AAD (Additional Authenticated Data)
Each encryption uses AAD in the format `col:piitext:id:<hex_key_id>`. This protects against:
- Copying encrypted data between records
- Key ID substitution attacks

### Crypto Shredding
For GDPR "right to be forgotten":
1. Delete the key in Vault for a specific user
2. Data becomes permanently unrecoverable (returns `****`)

### Key Management
- Keys are automatically created in Vault on first use
- Uses `aes256-gcm96` key type
- Keys are marked as `exportable` for Transit engine compatibility

## Performance

- **Key caching**: Keys are cached in shared memory
- **TTL**: Configurable cache lifetime
- **Minimal overhead**: One Vault request per TTL period

## Limitations

1. No automatic encryption via `piitext(id_column)` syntax - use `piitext_encrypt()` explicitly
2. SELECT without `piitext_out_text()` returns CBOR JSON
3. Triggers not implemented due to pgrx limitations

## Roadmap

- [ ] Automatic encryption triggers
- [ ] Syntax `CREATE TABLE t (secret piitext REFERENCES id)`
- [ ] Key rotation support
- [ ] Background worker for cache cleanup
- [ ] Metrics and monitoring
- [ ] Integration tests with testcontainers

## Author

Vitalii Velicodnii
