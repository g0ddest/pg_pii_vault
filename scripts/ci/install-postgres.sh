#!/usr/bin/env bash
#
# Install PostgreSQL <major> (server and headers) from apt.postgresql.org on an
# Ubuntu runner and prepare it for cargo-pgrx, which copies the extension into
# the server's library and extension directories.
#
# usage: scripts/ci/install-postgres.sh <major>
set -Eeuo pipefail

major="${1:?usage: install-postgres.sh <major>}"

# Never stop for a configuration question (tzdata on minimal images).
apt_get() {
	sudo env DEBIAN_FRONTEND=noninteractive apt-get "$@"
}

apt_get update -qq
apt_get install -y -qq ca-certificates curl lsb-release
sudo install -d /usr/share/postgresql-common/pgdg
sudo curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
	https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" |
	sudo tee /etc/apt/sources.list.d/pgdg.list >/dev/null

# Do not create and start a default cluster; the tests run their own.
sudo install -d /etc/postgresql-common/createcluster.d
echo "create_main_cluster = false" | sudo tee /etc/postgresql-common/createcluster.d/no-main-cluster.conf >/dev/null

apt_get update -qq
apt_get install -y -qq \
	"postgresql-${major}" "postgresql-server-dev-${major}" \
	build-essential clang libclang-dev pkg-config

pg_config="/usr/lib/postgresql/${major}/bin/pg_config"
sudo chmod a+rwx "$("$pg_config" --pkglibdir)" "$("$pg_config" --sharedir)/extension"

if [[ -n "${GITHUB_ENV:-}" ]]; then
	echo "PG_CONFIG=${pg_config}" >> "$GITHUB_ENV"
fi
"$pg_config" --version
