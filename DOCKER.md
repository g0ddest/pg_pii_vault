# Docker Setup for pg_pii_vault

This guide explains how to run PostgreSQL 18 with pg_pii_vault extension and HashiCorp Vault using Docker.

## Quick Start

### 1. Build and Start Services

```bash
# Build PostgreSQL image with extension and start all services
docker-compose up --build -d

# Check logs
docker-compose logs -f
```

### 2. Connect to PostgreSQL

```bash
# Connect using psql
docker exec -it postgres_pii_vault psql -U postgres -d testdb

# Or from host (if psql is installed)
psql -h localhost -U postgres -d testdb
# Password: postgres
```

### 3. Test the Extension

```sql
-- View demo data (decrypted)
SELECT * FROM users_demo_decrypted;

-- View encryption details
SELECT id, email, piitext_debug(secret_data) FROM users_demo;

-- Insert new encrypted data
INSERT INTO users_demo VALUES (
    100,
    'test@example.com',
    piitext_encrypt('my secret', int_to_key_bytes(100))
);

-- Query the new data
SELECT * FROM users_demo_decrypted WHERE id = 100;
```

### 4. Test Crypto Shredding

```sql
-- Step 1: Create test data
INSERT INTO users_demo VALUES (
    999,
    'shredtest@example.com',
    piitext_encrypt('data to be shredded', int_to_key_bytes(999))
);

-- Step 2: Verify data is readable
SELECT piitext_out_text(secret_data) FROM users_demo WHERE id = 999;
-- Result: data to be shredded

-- Step 3: Delete key in Vault (from host terminal)
docker exec -it vault sh -c "
    export VAULT_ADDR=http://localhost:8200 && \
    export VAULT_TOKEN=dev-token-12345 && \
    vault delete transit/keys/000003e7
"

-- Step 4: Try to read data again (back in psql)
SELECT piitext_out_text(secret_data) FROM users_demo WHERE id = 999;
-- Result: ****
```

### 5. Test Re-encryption

```sql
-- Insert plain text
INSERT INTO users_demo VALUES (
    200,
    'reencrypt@example.com',
    piitext_in_text('plain text data')
);

-- Verify it's in staging mode
SELECT piitext_debug(secret_data) FROM users_demo WHERE id = 200;
-- Result: Staging("plain text data")

-- Encrypt in place
UPDATE users_demo
SET secret_data = piitext_encrypt_piitext(secret_data, int_to_key_bytes(200))
WHERE id = 200;

-- Verify it's now encrypted
SELECT piitext_debug(secret_data) FROM users_demo WHERE id = 200;
-- Result: Sealed(PiiSealedData { ... })

-- But still readable
SELECT piitext_out_text(secret_data) FROM users_demo WHERE id = 200;
-- Result: plain text data
```

## Architecture

```
┌─────────────────┐         ┌─────────────────┐
│   PostgreSQL    │◄───────►│   Vault         │
│   + extension   │  HTTP   │   (Transit)     │
│   port: 5432    │         │   port: 8200    │
└─────────────────┘         └─────────────────┘
```

## Services

### PostgreSQL
- **Image**: Built from Dockerfile (PostgreSQL 18 + pg_pii_vault)
- **Port**: 5432
- **Credentials**: postgres/postgres
- **Database**: testdb
- **Extension**: Automatically created and configured

### Vault
- **Image**: hashicorp/vault:1.15
- **Port**: 8200
- **Mode**: Development (not for production!)
- **Token**: dev-token-12345
- **Transit Engine**: Automatically enabled

### Vault Init
- Helper service that initializes Vault
- Enables Transit engine
- Exits after initialization

## Environment Variables

You can customize the setup by editing `docker-compose.yml`:

```yaml
environment:
  # PostgreSQL
  POSTGRES_USER: postgres
  POSTGRES_PASSWORD: postgres
  POSTGRES_DB: testdb

  # Vault connection
  PII_VAULT_URL: "http://vault:8200"
  PII_VAULT_TOKEN: "dev-token-12345"
  PII_VAULT_MOUNT: "transit"
  PII_VAULT_CACHE_TTL: "300"
```

## Vault UI

Access Vault UI at: http://localhost:8200/ui
- Token: `dev-token-12345`

You can view:
- Transit keys created by the extension
- Key versions and metadata
- Audit logs (if enabled)

## Cleanup

```bash
# Stop services
docker-compose down

# Stop and remove volumes (deletes all data)
docker-compose down -v

# Remove built image
docker rmi pg_pii_vault_postgres
```

## Troubleshooting

### Extension not found
```bash
# Rebuild the image
docker-compose up --build -d
```

### Vault connection error
```bash
# Check Vault is running
docker-compose logs vault

# Verify network connectivity
docker exec postgres_pii_vault ping -c 3 vault
```

### Check extension status
```sql
-- In psql
SELECT * FROM pg_extension WHERE extname = 'pg_pii_vault';

-- Check current settings
SHOW pii_vault.url;
SHOW pii_vault.token;
SHOW pii_vault.mount;
```

### View PostgreSQL logs
```bash
docker-compose logs -f postgres
```

### Recreate from scratch
```bash
docker-compose down -v
docker system prune -f
docker-compose up --build -d
```

## Production Notes

⚠️ **This setup is for development/testing only!**

For production:
1. Use proper Vault setup (not dev mode)
2. Use TLS for Vault connection
3. Use secure token management (not hardcoded)
4. Use proper PostgreSQL authentication
5. Configure backup strategies
6. Use secrets management (Docker secrets, Kubernetes secrets, etc.)
7. Configure resource limits
8. Enable audit logging
9. Use private Docker registry
10. Implement proper monitoring and alerting

## Building for Different PostgreSQL Versions

To build for PostgreSQL 16 or 17, modify the `Dockerfile`:

```dockerfile
# Change these lines:
RUN wget https://ftp.postgresql.org/pub/source/v16.4/postgresql-16.4.tar.gz
# And the base image:
FROM postgres:16.4
```

Then rebuild:
```bash
docker-compose build --no-cache postgres
docker-compose up -d
```
