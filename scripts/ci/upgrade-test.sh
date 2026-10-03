#!/usr/bin/env bash
#
# Upgrade test: install the previous release, write data with it, install the
# current tree, run ALTER EXTENSION ... UPDATE and check that
#   * the old values still decrypt,
#   * the objects that persist decrypted values, or can no longer be
#     restored from a dump, are reported,
#   * the catalog equals a fresh installation of the new version.
#
# usage: scripts/ci/upgrade-test.sh <pg-major>
# env:   PG_CONFIG           pg_config of the server (default: PGDG path for <pg-major>)
#        PREV_REF            git revision of the previous release (default: 0.0.0 = 3425662)
#        NEW_VERSION         version installed by the current tree (default: from Cargo.toml)
#        UPGRADE_WORK_DIR    scratch directory; keep it short (unix socket path limit)
#        UPGRADE_PORT        port of the temporary cluster (default 5499)
#        PII_VAULT_TEST_URL, PII_VAULT_TEST_ADMIN_TOKEN  Vault with Transit at transit/
set -Eeuo pipefail

major="${1:?usage: upgrade-test.sh <pg-major>}"
pg_config="${PG_CONFIG:-/usr/lib/postgresql/${major}/bin/pg_config}"
prev_ref="${PREV_REF:-3425662}"
root_dir="$(cd "$(dirname "$0")/../.." && pwd)"
new_version="${NEW_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "${root_dir}/Cargo.toml" | head -1)}"
work="${UPGRADE_WORK_DIR:-${RUNNER_TEMP:-/tmp}/pii-upgrade}"
port="${UPGRADE_PORT:-5499}"
vault_url="${PII_VAULT_TEST_URL:-http://127.0.0.1:8200}"
vault_token="${PII_VAULT_TEST_ADMIN_TOKEN:-root}"
bindir="$("$pg_config" --bindir)"

cleanup() {
	"${bindir}/pg_ctl" -D "${work}/data" -m immediate stop >/dev/null 2>&1 || true
	git -C "${root_dir}" worktree remove --force "${work}/prev" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -rf "${work}"
mkdir -p "${work}"

psql() {
	"${bindir}/psql" -h localhost -p "${port}" -U postgres -X -q -v ON_ERROR_STOP=1 "$@"
}
fail() {
	echo "upgrade test FAILED: $*" >&2
	exit 1
}

echo "--- installing the previous release (${prev_ref})"
git -C "${root_dir}" worktree add --detach "${work}/prev" "${prev_ref}" >/dev/null
(cd "${work}/prev" && cargo pgrx install --pg-config "${pg_config}" --no-default-features --features "pg${major}")

echo "--- starting a temporary cluster"
"${bindir}/initdb" -D "${work}/data" -U postgres -A trust --encoding=UTF8 --locale=C >/dev/null
cat >> "${work}/data/postgresql.conf" <<EOF
port = ${port}
listen_addresses = 'localhost'
unix_socket_directories = '${work}'
shared_preload_libraries = 'pg_pii_vault'
EOF
"${bindir}/pg_ctl" -D "${work}/data" -l "${work}/server.log" -w start >/dev/null

echo "--- writing data with the previous release"
psql -d postgres -c "CREATE DATABASE upg"
psql -d upg <<SQL
CREATE EXTENSION pg_pii_vault;
SET pii_vault.url = '${vault_url}';
SET pii_vault.token = '${vault_token}';
CREATE TABLE people (id int PRIMARY KEY, email piitext, note piitext);
INSERT INTO people VALUES
    (1, piitext_encrypt('alice@example.com', int4send(1)), piitext_in_text('staged note')),
    (2, piitext_encrypt('Žluťoučký kůň', int4send(2)), NULL);
-- Objects that persist decrypted values; 0.0.0 allowed them.
CREATE INDEX people_email_plain ON people ((email::text));
CREATE STATISTICS people_email_stats ON (email::text) FROM people;
ALTER TABLE people ADD COLUMN email_plain text GENERATED ALWAYS AS (email::text) STORED;
-- A generated column on a formerly IMMUTABLE function: its dump cannot be
-- restored into 0.1.0.
CREATE TABLE generated_enc (id int, plain text,
    enc piitext GENERATED ALWAYS AS (piitext_encrypt(plain, int4send(id))) STORED);
SQL

echo "--- installing the current tree (${new_version})"
(cd "${root_dir}" && cargo pgrx install --pg-config "${pg_config}" --no-default-features --features "pg${major}")
"${bindir}/pg_ctl" -D "${work}/data" -w restart >/dev/null

update_log=$(psql -d upg -c "ALTER EXTENSION pg_pii_vault UPDATE TO '${new_version}'" 2>&1)
echo "${update_log}"
# A generated column appears as "default value for column ..." on
# PostgreSQL 16 and later and as "column ..." before.
for object in "index people_email_plain" "statistics object people_email_stats" \
	"column email_plain of table people"; do
	grep -q "${object} stores or indexes decrypted plaintext" <<<"${update_log}" ||
		fail "${object} was not reported"
done
grep -q "column enc of table generated_enc uses piitext_encrypt(text,bytea), which is no longer IMMUTABLE" <<<"${update_log}" ||
	fail "the generated column on piitext_encrypt was not reported"
psql -d upg -c "DROP INDEX people_email_plain" -c "DROP STATISTICS people_email_stats" \
	-c "ALTER TABLE people DROP COLUMN email_plain" -c "DROP TABLE generated_enc"

session="SET pii_vault.url = '${vault_url}'; SET pii_vault.token = '${vault_token}';"

got=$(psql -d upg -At <<SQL
${session}
SELECT string_agg(id || ':' || email::text || ':' || coalesce(note::text, '-'), ',' ORDER BY id) FROM people;
SQL
)
[[ "${got}" == "1:alice@example.com:staged note,2:Žluťoučký kůň:-" ]] || fail "old values read back as '${got}'"

got=$(psql -d upg -At <<SQL
${session}
UPDATE people SET email = piitext_reencrypt(email);
INSERT INTO people (id, email) VALUES (3, piitext_encrypt('carol@example.com', int4send(3)));
SELECT string_agg(id || ':' || email::text || ':' || piitext_key_version(email), ',' ORDER BY id) FROM people;
SQL
)
[[ "${got}" == "1:alice@example.com:1,2:Žluťoučký kůň:1,3:carol@example.com:1" ]] ||
	fail "re-encryption / new writes returned '${got}'"

echo "--- comparing the catalog with a fresh installation"
psql -d postgres -c "CREATE DATABASE fresh"
psql -d fresh -c "CREATE EXTENSION pg_pii_vault"
catalog_query="
SELECT 'function', p.proname::text, pg_get_function_identity_arguments(p.oid),
       p.provolatile::text || p.proparallel::text || p.proisstrict::text, p.procost::text,
       pg_get_function_result(p.oid), p.prosrc, coalesce(p.proacl::text, '')
FROM pg_proc p
JOIN pg_depend d ON d.objid = p.oid AND d.classid = 'pg_proc'::regclass AND d.deptype = 'e'
JOIN pg_extension x ON x.oid = d.refobjid AND x.extname = 'pg_pii_vault'
UNION ALL
SELECT 'cast', castsource::regtype::text, casttarget::regtype::text, castfunc::regprocedure::text,
       castcontext::text, castmethod::text, '', ''
FROM pg_cast WHERE castsource = 'piitext'::regtype OR casttarget = 'piitext'::regtype
UNION ALL
SELECT 'type', typname::text, typinput::text || '/' || typoutput::text, typreceive::text || '/' || typsend::text,
       typstorage::text, typlen::text, typalign::text, typcategory::text
FROM pg_type WHERE typname = 'piitext'
ORDER BY 1, 2, 3"
psql -d upg -At -c "${catalog_query}" > "${work}/catalog-upgraded.txt"
psql -d fresh -At -c "${catalog_query}" > "${work}/catalog-fresh.txt"
diff -u "${work}/catalog-fresh.txt" "${work}/catalog-upgraded.txt" || fail "catalog differs from a fresh installation"

echo "upgrade test passed ($(wc -l < "${work}/catalog-fresh.txt" | tr -d ' ') catalog objects compared)"
