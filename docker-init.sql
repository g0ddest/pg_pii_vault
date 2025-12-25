-- Initialization script for pg_pii_vault extension
-- This runs automatically when PostgreSQL container starts

-- Create the extension
CREATE EXTENSION IF NOT EXISTS pg_pii_vault;

-- Configure Vault connection using environment variables
-- These will be set from docker-compose environment
ALTER SYSTEM SET pii_vault.url = 'http://vault:8200';
ALTER SYSTEM SET pii_vault.token = 'dev-token-12345';
ALTER SYSTEM SET pii_vault.mount = 'transit';
ALTER SYSTEM SET pii_vault.cache_ttl_sec = 300;

-- Reload configuration
SELECT pg_reload_conf();

-- Create helper function for integer to bytea conversion
CREATE OR REPLACE FUNCTION int_to_key_bytes(id INTEGER) RETURNS BYTEA AS $$
    SELECT decode(lpad(to_hex(id), 8, '0'), 'hex')
$$ LANGUAGE SQL IMMUTABLE;

-- Create helper function for bigint to bytea conversion
CREATE OR REPLACE FUNCTION bigint_to_key_bytes(id BIGINT) RETURNS BYTEA AS $$
    SELECT decode(lpad(to_hex(id), 16, '0'), 'hex')
$$ LANGUAGE SQL IMMUTABLE;

-- Create demo table
CREATE TABLE IF NOT EXISTS users_demo (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL,
    secret_data piitext
);

-- Insert demo data (encrypted)
INSERT INTO users_demo VALUES
    (1, 'alice@example.com', piitext_encrypt('Alice secret password', int_to_key_bytes(1))),
    (2, 'bob@example.com', piitext_encrypt('Bob confidential data', int_to_key_bytes(2))),
    (3, 'charlie@example.com', piitext_encrypt('Charlie personal info', int_to_key_bytes(3)));

-- Insert demo data (staging - unencrypted)
INSERT INTO users_demo VALUES
    (4, 'diana@example.com', piitext_in_text('Diana unencrypted data'));

-- Create view for convenient querying
CREATE OR REPLACE VIEW users_demo_decrypted AS
SELECT
    id,
    email,
    piitext_out_text(secret_data) as secret_data
FROM users_demo;

-- Print success message
DO $$
BEGIN
    RAISE NOTICE 'pg_pii_vault extension initialized successfully!';
    RAISE NOTICE 'Demo table "users_demo" created with sample data.';
    RAISE NOTICE 'Use "SELECT * FROM users_demo_decrypted;" to view decrypted data.';
    RAISE NOTICE 'Use "SELECT piitext_debug(secret_data) FROM users_demo;" to see encryption details.';
END $$;
