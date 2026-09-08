# remotier-sync

Sync server for [Remotier](https://github.com/cybrcr1me/remotier). Stores encrypted
configuration and routes it between a user's devices, and between the members of a shared
group. It cannot read any of it.

Two crates:

- `crates/remotier-sync-proto` — the wire format and the envelope crypto. **The Remotier
  client compiles this same crate.** One definition of what travels between them, because
  an end-to-end format that drifts between two hand-written implementations fails as
  "decryption failed", which tells you nothing about which side is wrong.
- `server` — axum over SQLite or Postgres.

## Run one

Images are published to `ghcr.io/cybrcr1me/remotier-sync` for `linux/amd64` and
`linux/arm64` — a lot of self-hosting happens on a Pi or an Ampere box, and easy
self-hosting is the point.

```bash
docker compose up -d          # SQLite, one container, one volume
```

Registration is **closed by default**. Open it, make your account, close it again:

```bash
REMOTIER_REGISTRATION_OPEN=true docker compose up -d
# … sign in from Remotier …
docker compose up -d          # back to closed
```

For an instance with more than a handful of people on it:

```bash
POSTGRES_PASSWORD=… docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d
```

The schema is created on start; there is no separate migration step.

### Configuration

| Variable | Default | |
|---|---|---|
| `REMOTIER_BIND` | `0.0.0.0:8787` | |
| `DATABASE_URL` | `sqlite://remotier-sync.db?mode=rwc` | the scheme picks the backend |
| `REMOTIER_INSTANCE_NAME` | `Remotier Sync` | shown on the sign-in screen |
| `REMOTIER_REGISTRATION_OPEN` | `false` | |

Put it behind TLS. The server speaks plain HTTP and expects a reverse proxy; the payloads
are encrypted either way, but the bearer tokens are not.

## What the server can and cannot see

The format is deliberately *hybrid* rather than fully opaque. Each record is a plaintext
routing header — id, kind, group, sort order, clock, tombstone — wrapped around an
encrypted payload. The header is what lets the server hand a shared group to the right
people without being able to read it.

**It learns:** how many records an account has, the shape of the group tree, who a group is
shared with, and when edits happen.

**It never learns:** a hostname, username, label, tag, port, placeholder, or note.

**It never holds:** a password, a key passphrase, or an SSH private key. Those do not sync
at all — not by filtering, but because no payload struct has anywhere to put one, and a
test fails if a field named like one appears. A shared group therefore hands a colleague
addresses and usernames, never a working credential.

### Keys

```
password + email
  └─ Argon2id ─────────────────────────────► masterKey   (never leaves the device)
       ├─ HKDF "remotier.auth.v1" ─────────► authKey     (sent here; stored Argon2id'd again)
       └─ HKDF "remotier.wrap.v1" ─────────► wrapKey
            ├─ wraps accountSecret (X25519) ─┐ stored here as ciphertext, so a new
            └─ wraps personalKey  (32 bytes) ┘ device can bootstrap from the password
```

A breached database yields `authKey` hashes and nothing that opens a record. Changing a
password re-wraps two small blobs and re-encrypts no records at all, because the account
keys themselves never change — there is a test that asserts exactly that.

A **recovery code** is issued once at registration and wraps the same two blobs a second
time. It is the only way into an account whose password is forgotten. The server holds no
key and cannot help.

Sharing a group generates a content key wrapped to each member's X25519 public key with an
anonymous sealed box, so wrapping the same key for two people produces unrelated blobs.
Revoking a share removes the row; the client rotates the group key afterwards, because a
removed member already saw the old one and no server-side deletion unsees it.

## Conflicts

Per-record last-write-wins with tombstones. The comparison lives in the `WHERE` of the
upsert rather than in Rust, so it happens under the same lock as the write — read-then-
write would let two devices pushing at once interleave into a lost update. Exact ties break
on the higher device id, deterministically, so two devices never sit swapping versions.

A clock more than 24 hours ahead is refused per record, not per batch: one device with a
wrong clock must not block everything else in the same push.

The change-log sequence is **per instance, not per account**. A pull can return records
owned by someone else (a shared group), and a cursor over per-account sequences would skip
or repeat records forever. The cost is that a cursor tells its holder roughly how many
writes the instance has taken.

## Develop

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
cargo tree | grep -i aws-lc      # must be empty
```

That last one is not decoration, and CI runs it too. `aws-lc-rs` needs CMake and NASM,
which breaks the Remotier client's cross-platform build; rustls is pinned to the `ring`
backend on both sides for that reason.

### The container build

`docker build .` and the `container` workflow both go through the same Dockerfile. Three
things in it are load-bearing:

- **The base image version is pinned above 1.85.** Dependencies here are edition 2024, and
  an older Cargo fails while *parsing a transitive manifest* — which reads as a broken
  dependency rather than a stale toolchain.
- **`.dockerignore` excludes `target/`.** The build context is sent to the daemon whole; a
  local `target/` is gigabytes, and copying it into the build stage filled the disk and
  failed the build in a way that pointed at the wrong step entirely.
- **The dependency-caching stub build is not `|| true`.** Swallowing a failure there does
  not skip a cache layer, it hides a real error and surfaces it later as something
  unrelated.

**Building on a small Docker VM.** Cargo runs one rustc per CPU and a release build of
this graph wants well over a gigabyte each, so a builder with many cores and little memory
dies with `cannot allocate memory` - which names neither cargo nor the memory limit as the
thing to change. Docker Desktop on macOS is the usual culprit: check with

```bash
docker info --format 'CPUs: {{.NCPU}}  Memory: {{.MemTotal}}'
```

and either raise the allocation in Settings → Resources, or cap the parallelism:

```bash
docker build --build-arg CARGO_BUILD_JOBS=1 -t remotier-sync .
```

The same VM has its own disk, separate from the host's. `docker system df` and
`docker buildx prune` are the things to reach for when a build reports no space left on a
machine with plenty free.

`HEALTHCHECK` runs `remotier-sync-server --health-check`, which dials loopback and insists
on a 200 from `/v1/instance`. The image ships no curl or wget on purpose, so the binary
checks itself; it is hand-rolled over `TcpStream` rather than through an HTTP client,
because the server needs no outbound HTTP otherwise and a probe is not worth a TLS stack.

CI builds the image on every pull request and throws it away — a fork has no package write
access, and pushing an image built from unreviewed code would be worse if it did. Pushes
to `main` and `v*` tags publish, with a provenance attestation so a puller can verify the
image came from this repo.

`server/tests/store.rs` exercises the `Store` trait, so pointing its `fresh()` at a
`PostgresStore` runs the same suite against the other backend unchanged. That is what the
trait is for.
