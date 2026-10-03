#!/usr/bin/env bash
#
# Prepare a Vault dev server for the test suite: mount Transit, install the
# policies shipped in vault/policies and create least-privilege tokens for the
# real-Vault tests (exported to $GITHUB_ENV, or printed).
#
# env: VAULT_ADDR (default http://127.0.0.1:8200), VAULT_ROOT_TOKEN (default root)
set -Eeuo pipefail

addr="${VAULT_ADDR:-http://127.0.0.1:8200}"
root="${VAULT_ROOT_TOKEN:-root}"
cd "$(dirname "$0")/../.."

api() {
	curl -fsS -H "X-Vault-Token: ${root}" "$@"
}

for _ in $(seq 1 60); do
	curl -fsS "${addr}/v1/sys/health" >/dev/null 2>&1 && break
	sleep 1
done
curl -fsS "${addr}/v1/sys/health" >/dev/null

if ! api "${addr}/v1/sys/mounts" | jq -e '.data["transit/"]' >/dev/null; then
	api -X POST "${addr}/v1/sys/mounts/transit" -d '{"type":"transit"}'
fi

for policy in pg-pii-vault pg-pii-vault-shred pg-pii-vault-transit; do
	jq -n --rawfile policy "vault/policies/${policy}.hcl" '{policy: $policy}' |
		api -X PUT "${addr}/v1/sys/policies/acl/${policy}" -d @-
done

token() {
	jq -n --argjson policies "$1" '{policies: $policies, period: "24h", no_default_policy: true}' |
		api -X POST "${addr}/v1/auth/token/create" -d @- |
		jq -r .auth.client_token
}

export_token=$(token '["pg-pii-vault","pg-pii-vault-shred"]')
transit_token=$(token '["pg-pii-vault-transit","pg-pii-vault-shred"]')

if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
	echo "::add-mask::${export_token}"
	echo "::add-mask::${transit_token}"
fi

{
	echo "PII_VAULT_TEST_URL=${addr}"
	echo "PII_VAULT_TEST_TOKEN=${export_token}"
	echo "PII_VAULT_TEST_TRANSIT_TOKEN=${transit_token}"
	echo "PII_VAULT_TEST_ADMIN_TOKEN=${root}"
} >> "${GITHUB_ENV:-/dev/stdout}"
