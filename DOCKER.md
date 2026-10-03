# Docker

The image is the official `postgres` image (Debian trixie) with pg_pii_vault
installed and preloaded. It is published for every release as
`ghcr.io/g0ddest/pg_pii_vault:<version>` (PostgreSQL 18, `linux/amd64` and
`linux/arm64`), with SBOM and build-provenance attestations.

- [Demo with Docker Compose](#demo-with-docker-compose)
- [Running the image](#running-the-image)
- [Environment variables](#environment-variables)
- [The Vault token](#the-vault-token)
- [Building the image](#building-the-image)
- [Verifying a release](#verifying-a-release)
- [Troubleshooting](#troubleshooting)

## Demo with Docker Compose

`docker-compose.yml` starts PostgreSQL 18 with the extension and a HashiCorp
Vault **dev** server:

```bash
docker compose up -d --build --wait
docker compose exec postgres psql -U postgres -d demo
```

What the stack sets up:

- `vault` — Vault 2.1 in dev mode (in-memory, no TLS, root token
  `demo-root-token`), published on `127.0.0.1:8200` (`VAULT_PORT` to change).
- `vault-init` — mounts Transit, installs the least-privilege policies from
  `vault/policies/` and writes a periodic token restricted to
  `pg-pii-vault` + `pg-pii-vault-shred` into a shared volume.
- `postgres` — the image built with `INCLUDE_DEMO_INIT=true`, published on
  `127.0.0.1:5432` (`PG_PORT` to change). It reads the token from that volume
  (`PII_VAULT_TOKEN_FILE`) and, on first start, creates the demo objects from
  `docker-init.sql`: table `customers`, view `customers_decrypted`, role
  `demo_app` (may decrypt) and role `demo_analyst` (may only read ciphertext).

Try it:

```sql
-- decrypted through the view (needs EXECUTE on piitext_out_text)
SELECT * FROM customers_decrypted;

-- the stored form: ciphertext, readable by anyone with SELECT
SELECT id, format('%s', email) AS stored, piitext_debug(email) FROM customers;

-- every required check passes; "tls" is false because the dev Vault speaks plain http
SELECT * FROM piitext_vault_check();
SELECT bool_and(ok) AS healthy FROM piitext_vault_check() WHERE required;

-- the analyst can read the table but not decrypt it
SET ROLE demo_analyst;
SELECT format('%s', email) FROM customers WHERE id = 1;   -- piitext:...
SELECT email::text FROM customers WHERE id = 1;           -- ERROR: permission denied
RESET ROLE;

-- crypto-shredding: erase customer 2 (all of their values, in every table)
SELECT piitext_shred(int4send(2));
SELECT * FROM customers_decrypted WHERE id = 2;           -- email and phone are '****'
```

Clean up (this also drops the database volume):

```bash
docker compose down -v
```

The dev Vault keeps its keys in memory: restarting the `vault` container
destroys them, and every value encrypted before becomes `****`. Run
`docker compose down -v` and start again after such a restart. The demo sets
`PII_VAULT_ALLOW_INSECURE_HTTP=on` only because the dev server has no TLS.

## Running the image

```bash
docker run -d --name postgres \
  -e POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password \
  -e PII_VAULT_URL=https://vault.example.com:8200 \
  -e PII_VAULT_CA_FILE=/run/secrets/vault_ca.pem \
  -e PII_VAULT_TOKEN_FILE=/run/secrets/vault_token \
  -v /srv/pgdata:/var/lib/postgresql \
  -v /srv/secrets:/run/secrets:ro \
  -p 5432:5432 \
  ghcr.io/g0ddest/pg_pii_vault:0.1.1
```

Then, as a superuser, create the extension and grant the application role the
functions it needs:

```sql
CREATE EXTENSION pg_pii_vault;
GRANT EXECUTE ON FUNCTION
    piitext_out_text(piitext), piitext_encrypt(text, bytea),
    piitext_encrypt_piitext(piitext, bytea), piitext_reencrypt(piitext)
TO app;
SELECT bool_and(ok) AS healthy FROM piitext_vault_check() WHERE required;
```

Notes:

- The image adds `shared_preload_libraries = 'pg_pii_vault'` to the
  configuration template used by `initdb`. If you start from an existing data
  directory or mount your own `postgresql.conf`, add `pg_pii_vault` to
  `shared_preload_libraries` yourself (keep any libraries already listed).
  Preloading is required: without it the token setting is visible to every role
  until the library is loaded, and `piitext_shred()` only invalidates the key
  cache of the current session.
- Settings passed through environment variables are applied as `postgres -c`
  options on every start. They take precedence over `postgresql.conf` and
  `ALTER SYSTEM`.
- The container health check uses `pg_isready` over TCP, so it only reports
  healthy after the initialisation scripts have run.

## Environment variables

The entry point (`docker/docker-entrypoint.sh`) turns these variables into
pg_pii_vault settings. Unset or empty variables are ignored. See the
configuration reference in [README.md](README.md) for the meaning of each
setting. The usual `POSTGRES_*` variables of the official image work as
documented upstream.

| Variable | Setting |
|---|---|
| `PII_VAULT_URL` | `pii_vault.url` |
| `PII_VAULT_MOUNT` | `pii_vault.mount` |
| `PII_VAULT_MOUNT_ACCESSOR` | `pii_vault.mount_accessor` |
| `PII_VAULT_NAMESPACE` | `pii_vault.namespace` |
| `PII_VAULT_KEY_MODE` | `pii_vault.key_mode` (`export` or `transit`) |
| `PII_VAULT_CA_FILE` | `pii_vault.ca_file` |
| `PII_VAULT_CLIENT_CERT_FILE` | `pii_vault.client_cert_file` |
| `PII_VAULT_CLIENT_KEY_FILE` | `pii_vault.client_key_file` |
| `PII_VAULT_TIMEOUT_MS` | `pii_vault.timeout_ms` |
| `PII_VAULT_MAX_RETRIES` | `pii_vault.max_retries` |
| `PII_VAULT_CACHE_TTL` | `pii_vault.cache_ttl_sec` |
| `PII_VAULT_CACHE_MAX_ENTRIES` | `pii_vault.cache_max_entries` |
| `PII_VAULT_AUTO_CREATE_KEYS` | `pii_vault.auto_create_keys` |
| `PII_VAULT_ALLOW_STAGING` | `pii_vault.allow_staging` |
| `PII_VAULT_ALLOW_INSECURE_HTTP` | `pii_vault.allow_insecure_http` (development only) |
| `PII_VAULT_TOKEN_FILE` | `pii_vault.token_file` |
| `PII_VAULT_TOKEN` | written to a private file, passed as `pii_vault.token_file` |
| `PII_VAULT_TOKEN_DIR` | directory for that file (default `/var/run/postgresql`) |

Values must be single lines; the container refuses to start otherwise, and also
when both `PII_VAULT_TOKEN` and `PII_VAULT_TOKEN_FILE` are set.

## The Vault token

Prefer `PII_VAULT_TOKEN_FILE` pointing at a file maintained outside the
container:

- a Docker or Kubernetes secret mounted read-only, or
- the file sink of a Vault Agent (sidecar or host agent) that authenticates
  with AppRole, Kubernetes auth, etc. and keeps a periodic token renewed. The
  extension re-reads the file on every Vault request, so token rotation needs no
  restart.

`PII_VAULT_TOKEN` is a convenience: the entry point writes the value to
`$PII_VAULT_TOKEN_DIR/pii_vault_token` (mode `0600`, owned by `postgres`),
passes only the file name to the server and removes the variable from the
server's environment, so the token appears neither in process command lines nor
in the environment of PostgreSQL processes. It does remain in the container
configuration (`docker inspect`, orchestrator metadata), which is why a secret
file is the better choice in production.

The token needs the policies in `vault/policies/` (see
[docs/OPERATIONS.md](docs/OPERATIONS.md)): `pg-pii-vault.hcl` (or
`pg-pii-vault-transit.hcl` with `PII_VAULT_KEY_MODE=transit`), plus
`pg-pii-vault-shred.hcl` if `piitext_shred()` is used from the database.

## Building the image

```bash
docker build -t pg_pii_vault:local .
docker build -t pg_pii_vault:demo --build-arg INCLUDE_DEMO_INIT=true .
```

The builder stage uses the same `postgres` base image as the runtime stage, so
the extension is compiled against the exact server headers it runs with.

| Build argument | Default | Meaning |
|---|---|---|
| `PG_MAJOR` | `18` | PostgreSQL major version (14–18) |
| `PG_IMAGE_TAG` | `18.6-trixie` | `postgres` image tag; must match `PG_MAJOR` |
| `RUST_VERSION` | `1.98.1` | Rust toolchain used to compile |
| `CARGO_PGRX_VERSION` | `0.16.1` | must equal the `pgrx` version in `Cargo.toml` |
| `VERSION` | `0.1.1` | value of the `org.opencontainers.image.version` label |
| `INCLUDE_DEMO_INIT` | `false` | install `docker-init.sql` as an init script |

For another major version, pick a matching Debian trixie tag, for example:

```bash
docker build -t pg_pii_vault:pg17 --build-arg PG_MAJOR=17 --build-arg PG_IMAGE_TAG=17-trixie .
```

## Verifying a release

Release images and extension tarballs carry GitHub build-provenance
attestations:

```bash
gh attestation verify oci://ghcr.io/g0ddest/pg_pii_vault:0.1.1 --owner g0ddest
gh attestation verify pg_pii_vault-0.1.1-pg18-linux-amd64.tar.gz --owner g0ddest
sha256sum -c pg_pii_vault-0.1.1-pg18-linux-amd64.tar.gz.sha256
```

The image also includes an SBOM (`docker buildx imagetools inspect
ghcr.io/g0ddest/pg_pii_vault:0.1.1 --format '{{json .SBOM}}'`).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `pg_pii_vault configuration error: pii_vault.url is not set` | `PII_VAULT_URL` missing |
| `... uses plain http to a non-loopback host` | use `https://`; `PII_VAULT_ALLOW_INSECURE_HTTP=on` is for development only |
| `cannot read pii_vault.token_file` | the file is not mounted or not readable by the `postgres` user (UID 999) |
| `Vault denied the request ... HTTP 403` | the token expired or lacks a policy from `vault/policies/`; check `SELECT * FROM piitext_vault_check()` |
| `invalid peer certificate` | set `PII_VAULT_CA_FILE` to the CA that issued the Vault certificate |
| container exits during first start with the demo image | the demo init script encrypts data and needs a reachable Vault |
| every value reads `****` after restarting the demo | the dev Vault lost its in-memory keys; `docker compose down -v` |
