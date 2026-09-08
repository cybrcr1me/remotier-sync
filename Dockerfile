FROM rust:1.90-bookworm AS build
WORKDIR /src


ARG BUILD_JOBS=""

# Manifests first, so editing source does not re-download and rebuild the whole registry.
# The stub sources exist only to give cargo something to compile the dependencies against.
COPY Cargo.toml Cargo.lock ./
COPY crates/remotier-sync-proto/Cargo.toml crates/remotier-sync-proto/
COPY server/Cargo.toml server/
RUN mkdir -p crates/remotier-sync-proto/src server/src \
 && echo 'fn main() {}' > server/src/main.rs \
 && touch crates/remotier-sync-proto/src/lib.rs \
 && cargo build --release ${BUILD_JOBS:+--jobs $BUILD_JOBS} \
      --bin remotier-sync-server

# Deliberately not `|| true`. Swallowing a failure here does not skip a cache layer, it
# hides a real build error and surfaces it later as something unrelated.

COPY crates crates
COPY server server
# The stub build left fingerprints saying these are already compiled; without this the
# real code is never built and the binary stays a `fn main() {}`.
RUN touch crates/remotier-sync-proto/src/lib.rs server/src/main.rs \
 && cargo build --release ${BUILD_JOBS:+--jobs $BUILD_JOBS} \
      --bin remotier-sync-server

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Runs unprivileged. /data is the only path it needs to write.
RUN useradd --system --uid 10001 --home /data remotier \
 && mkdir -p /data && chown remotier:remotier /data
USER remotier
WORKDIR /data
VOLUME /data

COPY --from=build /src/target/release/remotier-sync-server /usr/local/bin/

ENV REMOTIER_BIND=0.0.0.0:8787 \
    DATABASE_URL=sqlite:///data/remotier-sync.db?mode=rwc
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["remotier-sync-server", "--health-check"]

ENTRYPOINT ["remotier-sync-server"]
