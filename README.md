# remotier-sync

Sync server for [Remotier](https://github.com/cybrcr1me/remotier). Stores encrypted
configuration and routes it between a user's devices, and between the members of a shared
group. It cannot read any of it.

Two crates:

- `crates/remotier-sync-proto` — the wire format and the envelope crypto. **The Remotier
  client compiles this same crate.** One definition of what travels between them.
- `server` — axum over SQLite or Postgres.

## Run one

Images are published to `ghcr.io/cybrcr1me/remotier-sync` for `linux/amd64` and
`linux/arm64`

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

The server speaks plain HTTP and expects a reverse proxy; the payloads
are encrypted either way.

## What the server can and cannot see

The format is deliberately *hybrid* rather than fully opaque. Each record is a plaintext
routing header — id, kind, group, sort order, clock
The header is what lets the server hand a shared group to the right
people without being able to read it.

**It knows:** how many records an account has, the shape of the group tree, who a group is
shared with, and when edits happen.

**It never knows:** a hostname, username, label, tag, port, placeholder, or note.

**It never holds:** a password, a key passphrase, or an SSH private key. Those do not sync
at all. A shared group therefore hands a colleague
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

A **recovery code** is issued once at registration and wraps the same two blobs a second
time. It is the only way into an account whose password is forgotten. The server holds no
key and cannot help.

Sharing a group generates a content key wrapped to each member's X25519 public key with an
anonymous sealed box, so wrapping the same key for two people produces unrelated blobs.
Revoking a share removes the row; the client rotates the group key afterwards, because a
removed member already saw the old one and no server-side deletion unsees it.

## Develop

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
cargo tree | grep -i aws-lc      # must be empty
```

`aws-lc-rs` needs CMake and NASM,
which breaks the Remotier client's cross-platform build; rustls is pinned to the `ring`
backend on both sides for that reason.

