# Multi-stage build for PostgreSQL 18 with pg_pii_vault extension

FROM rust:1.92 AS builder

# Install PostgreSQL 18 development packages
RUN apt-get update && apt-get install -y \
    build-essential \
    libreadline-dev \
    zlib1g-dev \
    flex \
    bison \
    libxml2-dev \
    libxslt-dev \
    libssl-dev \
    libxml2-utils \
    xsltproc \
    ccache \
    pkg-config \
    wget \
    ca-certificates \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Install PostgreSQL 18 from source
WORKDIR /tmp
RUN wget https://ftp.postgresql.org/pub/source/v18.1/postgresql-18.1.tar.gz && \
    tar -xzf postgresql-18.1.tar.gz && \
    cd postgresql-18.1 && \
    ./configure --prefix=/usr/local/pgsql && \
    make -j$(nproc) && \
    make install && \
    cd contrib && \
    make -j$(nproc) && \
    make install

ENV PATH="/usr/local/pgsql/bin:${PATH}"
ENV PG_CONFIG=/usr/local/pgsql/bin/pg_config

# Install cargo-pgrx
RUN cargo install cargo-pgrx --version 0.16.1 --locked

# Initialize pgrx
RUN cargo pgrx init --pg18=/usr/local/pgsql/bin/pg_config

# Copy extension source
WORKDIR /build
COPY Cargo.toml ./
COPY pg_pii_vault.control ./
COPY src ./src/

# Build the extension
RUN cargo pgrx package --pg-config /usr/local/pgsql/bin/pg_config --features pg18

# Runtime stage
FROM postgres:18.1

# Build argument to include demo init script
ARG INCLUDE_DEMO_INIT=false

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy built extension from builder
COPY --from=builder /build/target/release/pg_pii_vault-pg18/usr/local/pgsql/share/extension/* /usr/share/postgresql/18/extension/
COPY --from=builder /build/target/release/pg_pii_vault-pg18/usr/local/pgsql/lib/* /usr/lib/postgresql/18/lib/

# Conditionally copy initialization script for demo purposes only
RUN if [ "$INCLUDE_DEMO_INIT" = "true" ]; then mkdir -p /docker-entrypoint-initdb.d/; fi
COPY --chmod=0755 docker-init.sql /tmp/docker-init.sql
RUN if [ "$INCLUDE_DEMO_INIT" = "true" ]; then \
        mv /tmp/docker-init.sql /docker-entrypoint-initdb.d/; \
    else \
        rm /tmp/docker-init.sql; \
    fi

# Environment variables for Vault connection
ENV PII_VAULT_URL=""
ENV PII_VAULT_TOKEN=""
ENV PII_VAULT_MOUNT="transit"
ENV PII_VAULT_CACHE_TTL="300"

# Configure PostgreSQL to use extension settings
RUN echo "shared_preload_libraries = 'pg_pii_vault'" >> /usr/share/postgresql/postgresql.conf.sample

# Expose PostgreSQL port
EXPOSE 5432

# Use default postgres entrypoint
CMD ["postgres"]
