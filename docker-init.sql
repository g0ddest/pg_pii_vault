-- pg_pii_vault demo objects. Included in the image only when it is built with
-- INCLUDE_DEMO_INIT=true (docker-compose.yml does that); runs once, when the
-- data directory is initialised. The Vault settings come from the PII_VAULT_*
-- environment variables (see docker/docker-entrypoint.sh).

\set ON_ERROR_STOP on

CREATE EXTENSION IF NOT EXISTS pg_pii_vault;

-- An application role that may encrypt and decrypt, and an analyst role that
-- may read the table but only ever sees ciphertext.
CREATE ROLE demo_app LOGIN PASSWORD 'demo_app';
CREATE ROLE demo_analyst LOGIN PASSWORD 'demo_analyst';
GRANT EXECUTE ON FUNCTION
    piitext_out_text(piitext),
    piitext_encrypt(text, bytea),
    piitext_encrypt_piitext(piitext, bytea),
    piitext_reencrypt(piitext)
TO demo_app;

-- The key id identifies the data subject: all PII of customer 42 is encrypted
-- with the Vault key named after int4send(42) = 0000002a.
CREATE TABLE customers (
    id    integer PRIMARY KEY,
    name  text NOT NULL,
    email piitext,
    phone piitext
);
GRANT SELECT, INSERT, UPDATE, DELETE ON customers TO demo_app;
GRANT SELECT ON customers TO demo_analyst;

INSERT INTO customers (id, name, email, phone) VALUES
    (1, 'Alice', piitext_encrypt('alice@example.com', int4send(1)), piitext_encrypt('+373 22 000 001', int4send(1))),
    (2, 'Bob',   piitext_encrypt('bob@example.com',   int4send(2)), piitext_encrypt('+373 22 000 002', int4send(2))),
    (3, 'Carol', piitext_encrypt('carol@example.com', int4send(3)), NULL);

-- A plaintext "staging" value, as during a migration of an existing column.
INSERT INTO customers (id, name, email) VALUES (4, 'Dave', piitext_in_text('dave@example.com'));

-- Decryption is explicit (::text) and needs EXECUTE on piitext_out_text.
CREATE VIEW customers_decrypted AS
SELECT id, name, email::text AS email, phone::text AS phone
FROM customers;
GRANT SELECT ON customers_decrypted TO demo_app;

DO $$
BEGIN
    RAISE NOTICE 'pg_pii_vault demo ready: table customers, view customers_decrypted, roles demo_app / demo_analyst';
END
$$;
