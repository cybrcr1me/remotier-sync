-- The server's whole view of a user's data. Note what is not here: no hostname, no
-- username, no label. `ciphertext` is the only place a record's content exists, and
-- nothing on this side holds a key that opens it.

CREATE TABLE IF NOT EXISTS accounts (
    id                      TEXT PRIMARY KEY,
    -- NOCASE so Ada@example.com and ada@example.com cannot become two accounts. The
    -- client lowercases before deriving keys from it, for the same reason.
    email                   TEXT NOT NULL UNIQUE COLLATE NOCASE,
    -- Argon2id over the auth_key the client derived. Hashed again here so a stolen
    -- database is not a list of usable credentials.
    auth_hash               TEXT NOT NULL,
    recovery_auth_hash      TEXT NOT NULL,
    -- X25519 public key, plaintext by design: other users need it to share with you.
    account_public          TEXT NOT NULL,
    wrapped_account_secret  TEXT NOT NULL,
    wrapped_personal_key    TEXT NOT NULL,
    recovery_account_secret TEXT NOT NULL,
    recovery_personal_key   TEXT NOT NULL,
    created_at              INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    -- SHA-256 of the bearer token. The token itself is never stored, so a database dump
    -- does not hand over live sessions.
    hash       TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_account ON tokens(account_id);

CREATE TABLE IF NOT EXISTS records (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    id         TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    group_id   TEXT,
    parent_id  TEXT,
    sort       INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    device_id  TEXT NOT NULL,
    deleted_at INTEGER,
    key_ref    TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    PRIMARY KEY (account_id, kind, id)
);
CREATE INDEX IF NOT EXISTS idx_records_seq ON records(seq);
CREATE INDEX IF NOT EXISTS idx_records_group ON records(group_id);

-- One counter for the whole instance, not one per account.
--
-- A pull can return records owned by other people (a shared group), so the cursor has to
-- order records across owners. Per-account sequences cannot do that: two owners' seq 5
-- are unrelated numbers, and a cursor over them would skip records or repeat them
-- forever. The cost is that a cursor value tells its holder roughly how many writes the
-- whole instance has taken, which is not worth the machinery of a per-viewer change log.
CREATE TABLE IF NOT EXISTS sequence (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    next INTEGER NOT NULL
);
INSERT OR IGNORE INTO sequence (id, next) VALUES (1, 0);

CREATE TABLE IF NOT EXISTS shares (
    group_id          TEXT NOT NULL,
    owner_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    user_id           TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- The group's content key sealed to user_id's account_public. Opaque here.
    wrapped_group_key TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(user_id);

CREATE TABLE IF NOT EXISTS devices (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL,
    name       TEXT NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (account_id, device_id)
);
