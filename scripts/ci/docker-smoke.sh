#!/usr/bin/env bash
#
# Smoke test of the Docker image with the demo stack from docker-compose.yml.
#
# env: COMPOSE_PROJECT (default pg-pii-vault-smoke), PG_PORT, VAULT_PORT,
#      SKIP_BUILD=1 to reuse an already built pg_pii_vault:demo image.
set -Eeuo pipefail

cd "$(dirname "$0")/../.."
project="${COMPOSE_PROJECT:-pg-pii-vault-smoke}"
export PG_PORT="${PG_PORT:-55432}" VAULT_PORT="${VAULT_PORT:-58200}"

compose() {
	docker compose -p "${project}" "$@"
}
fail() {
	echo "docker smoke test FAILED: $*" >&2
	exit 1
}
cleanup() {
	compose logs --no-color > "${RUNNER_TEMP:-/tmp}/pg-pii-vault-compose.log" 2>&1 || true
	compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "${SKIP_BUILD:-}" == 1 ]]; then
	compose up -d --wait
else
	compose up -d --build --wait
fi

sql() {
	local role="$1"
	shift
	compose exec -T postgres psql -U "${role}" -d demo -X -At -v ON_ERROR_STOP=1 "$@"
}

[[ "$(sql postgres -c "SELECT email FROM customers_decrypted WHERE id = 1")" == "alice@example.com" ]] ||
	fail "demo data does not decrypt"

failed=$(sql postgres -c "SELECT coalesce(string_agg(check_name || ': ' || detail, '; '), '') FROM piitext_vault_check() WHERE required AND NOT ok")
[[ -z "${failed}" ]] || fail "piitext_vault_check(): ${failed}"

ciphertext=$(sql demo_analyst -c "SELECT format('%s', email) FROM customers WHERE id = 1")
[[ "${ciphertext}" == piitext:* ]] || fail "analyst saw '${ciphertext}' instead of ciphertext"
if sql demo_analyst -c "SELECT email::text FROM customers WHERE id = 1" >/dev/null 2>&1; then
	fail "analyst could decrypt without EXECUTE on piitext_out_text"
fi

[[ "$(sql demo_app -c "SELECT phone FROM customers_decrypted WHERE id = 2")" == "+373 22 000 002" ]] ||
	fail "application role cannot decrypt"
sql demo_app -c "INSERT INTO customers (id, name, email) VALUES (10, 'Eve', piitext_encrypt('eve@example.com', int4send(10)))" >/dev/null

[[ "$(sql postgres -c "SELECT piitext_shred(int4send(2))")" == "t" ]] || fail "piitext_shred() did not delete the key"
[[ "$(sql postgres -c "SELECT email FROM customers_decrypted WHERE id = 2")" == "****" ]] || fail "shredded value still readable"
[[ "$(sql postgres -c "SELECT email FROM customers_decrypted WHERE id = 1")" == "alice@example.com" ]] ||
	fail "shredding one subject affected another"

# The token must not appear in any server process command line or environment.
# Read /proc as the postgres user: without CAP_SYS_PTRACE even root in the
# container cannot read the environment of another user's processes.
token=$(compose exec -T postgres cat /vault-token/token)
# shellcheck disable=SC2016 # the script is expanded inside the container
proc_dump=$(compose exec -T -u postgres postgres sh -c '
	readable=0
	for p in /proc/[0-9]*; do
		{ tr "\0" " " < "$p/cmdline"; echo; } 2>/dev/null
		if env=$(tr "\0" "\n" < "$p/environ" 2>/dev/null); then
			readable=$((readable + 1))
			printf "%s\n" "$env"
		fi
	done
	echo "readable-environments=$readable"')
grep -q "readable-environments=[1-9]" <<<"${proc_dump}" || fail "could not inspect any process environment"
grep -q "pii_vault.token_file" <<<"${proc_dump}" || fail "pii_vault.token_file not passed to the server"
if grep -qF "${token}" <<<"${proc_dump}"; then
	fail "the Vault token is visible in a process command line or environment"
fi

echo "docker smoke test passed"
