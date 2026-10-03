# syntax=docker/dockerfile:1.7
#
# PostgreSQL with the pg_pii_vault extension.
#
# The extension is compiled in a builder stage based on the very same
# PostgreSQL image as the runtime stage, so it is built against exactly the
# headers (and ABI) of the server that loads it.

ARG PG_MAJOR=18
ARG PG_IMAGE_TAG=18.6-trixie

FROM postgres:${PG_IMAGE_TAG} AS builder

ARG PG_MAJOR
ARG RUST_VERSION=1.98.1
ARG CARGO_PGRX_VERSION=0.16.1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        curl \
        libclang-dev \
        pkg-config \
        "postgresql-server-dev-${PG_MAJOR}"; \
    rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN set -eux; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}"; \
    cargo install cargo-pgrx --version "${CARGO_PGRX_VERSION}" --locked; \
    cargo pgrx init "--pg${PG_MAJOR}=/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config"

WORKDIR /build
COPY Cargo.toml Cargo.lock pg_pii_vault.control ./
COPY src ./src
COPY sql ./sql

# The package is assembled under target/release/pg_pii_vault-pgNN/<paths of
# pg_config>; copy the files out of the cache mount into /out. The package
# directory is emptied first, so files of earlier builds left in the cache
# mount are not shipped.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    set -eux; \
    rm -rf "target/release/pg_pii_vault-pg${PG_MAJOR}"; \
    cargo pgrx package \
        --pg-config "/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config" \
        --no-default-features --features "pg${PG_MAJOR}"; \
    pkg="target/release/pg_pii_vault-pg${PG_MAJOR}"; \
    mkdir -p /out/lib /out/extension; \
    cp "${pkg}/usr/lib/postgresql/${PG_MAJOR}/lib/pg_pii_vault.so" /out/lib/; \
    cp "${pkg}/usr/share/postgresql/${PG_MAJOR}/extension/"pg_pii_vault* /out/extension/; \
    ls -l /out/lib /out/extension

FROM postgres:${PG_IMAGE_TAG}

ARG PG_MAJOR
ARG VERSION=0.1.1
# Build with INCLUDE_DEMO_INIT=true to create demo objects on first start.
ARG INCLUDE_DEMO_INIT=false

LABEL org.opencontainers.image.title="pg_pii_vault" \
      org.opencontainers.image.description="PostgreSQL ${PG_MAJOR} with pg_pii_vault: column-level PII encryption with per-record keys in HashiCorp Vault" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/g0ddest/pg_pii_vault" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /out/lib/ /usr/lib/postgresql/${PG_MAJOR}/lib/
COPY --from=builder /out/extension/ /usr/share/postgresql/${PG_MAJOR}/extension/
COPY --chmod=0755 docker/docker-entrypoint.sh /usr/local/bin/pg-pii-vault-entrypoint.sh
COPY docker-init.sql /usr/local/share/pg_pii_vault/demo-init.sql

# New clusters (initdb) preload the extension: required for token secrecy and
# cluster-wide cache invalidation. With your own postgresql.conf, add
# pg_pii_vault to shared_preload_libraries yourself.
RUN set -eux; \
    echo "shared_preload_libraries = 'pg_pii_vault'" >> /usr/share/postgresql/postgresql.conf.sample; \
    if [ "${INCLUDE_DEMO_INIT}" = "true" ]; then \
        cp /usr/local/share/pg_pii_vault/demo-init.sql /docker-entrypoint-initdb.d/50-pg_pii_vault-demo.sql; \
    fi

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
    CMD pg_isready -h 127.0.0.1 -U "${POSTGRES_USER:-postgres}" || exit 1

ENTRYPOINT ["pg-pii-vault-entrypoint.sh"]
CMD ["postgres"]
