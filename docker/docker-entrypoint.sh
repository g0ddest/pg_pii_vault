#!/usr/bin/env bash
#
# Entry point of the pg_pii_vault image.
#
# Translates PII_VAULT_* environment variables into pg_pii_vault server
# settings (postgres -c options), then hands over to the official postgres
# entry point. The Vault token never appears on a command line: PII_VAULT_TOKEN
# is written to a private file and passed as pii_vault.token_file.
set -Eeuo pipefail

die() {
	echo "pg-pii-vault-entrypoint: $*" >&2
	exit 1
}

# Environment variable -> server setting.
settings=(
	PII_VAULT_URL=pii_vault.url
	PII_VAULT_MOUNT=pii_vault.mount
	PII_VAULT_MOUNT_ACCESSOR=pii_vault.mount_accessor
	PII_VAULT_NAMESPACE=pii_vault.namespace
	PII_VAULT_KEY_MODE=pii_vault.key_mode
	PII_VAULT_CA_FILE=pii_vault.ca_file
	PII_VAULT_CLIENT_CERT_FILE=pii_vault.client_cert_file
	PII_VAULT_CLIENT_KEY_FILE=pii_vault.client_key_file
	PII_VAULT_TIMEOUT_MS=pii_vault.timeout_ms
	PII_VAULT_MAX_RETRIES=pii_vault.max_retries
	PII_VAULT_CACHE_TTL=pii_vault.cache_ttl_sec
	PII_VAULT_CACHE_MAX_ENTRIES=pii_vault.cache_max_entries
	PII_VAULT_AUTO_CREATE_KEYS=pii_vault.auto_create_keys
	PII_VAULT_ALLOW_STAGING=pii_vault.allow_staging
	PII_VAULT_ALLOW_INSECURE_HTTP=pii_vault.allow_insecure_http
	PII_VAULT_TOKEN_FILE=pii_vault.token_file
)

options=()
for mapping in "${settings[@]}"; do
	var="${mapping%%=*}"
	guc="${mapping#*=}"
	value="${!var:-}"
	[[ -n "$value" ]] || continue
	[[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "$var must be a single line"
	options+=(-c "$guc=$value")
done

if [[ -n "${PII_VAULT_TOKEN:-}" ]]; then
	[[ -z "${PII_VAULT_TOKEN_FILE:-}" ]] || die "set either PII_VAULT_TOKEN or PII_VAULT_TOKEN_FILE, not both"
	[[ "$PII_VAULT_TOKEN" != *$'\n'* && "$PII_VAULT_TOKEN" != *$'\r'* ]] || die "PII_VAULT_TOKEN must be a single line"
	token_dir="${PII_VAULT_TOKEN_DIR:-/var/run/postgresql}"
	token_file="$token_dir/pii_vault_token"
	mkdir -p "$token_dir"
	(umask 077 && printf '%s\n' "$PII_VAULT_TOKEN" > "$token_file")
	if [[ "$(id -u)" == 0 ]]; then
		chown postgres:postgres "$token_file"
	fi
	options+=(-c "pii_vault.token_file=$token_file")
fi
# Keep the token out of the server's environment.
unset PII_VAULT_TOKEN

# Only add settings when the container starts the server (the official entry
# point treats a first argument starting with "-" as postgres options).
if [[ "${1:-}" == postgres || "${1:-}" == -* ]]; then
	set -- "$@" "${options[@]}"
fi

exec docker-entrypoint.sh "$@"
