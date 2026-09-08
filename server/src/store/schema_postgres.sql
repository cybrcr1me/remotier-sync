-- The hosted instance's schema. Mirrors schema_sqlite.sql column for column; the two are
-- kept in step by the shared test suite in `tests/store.rs`, which runs against whichever
-- backends are configured.

CREATE TABLE IF NOT EXISTS accounts (
    id                      TEXT PRIMARY KEY,
    -- CITEXT would need an extension; lowercasing on the way in does the same job and
    -- the client lowercases before deriving keys from the address anyway.
    email                   TEXT NOT NULL UNIQUE,
    auth_hash               TEXT NOT NULL,
    recovery_auth_hash      TEXT NOT NULL,
    account_public          TEXT NOT NULL,
    wrapped_account_secret  TEXT NOT NULL,
    wrapped_personal_key    TEXT NOT NULL,
    recovery_account_secret TEXT NOT NULL,
    recovery_personal_key   TEXT NOT NULL,
    created_at              BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    hash       TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_account ON tokens(account_id);

CREATE TABLE IF NOT EXISTS records (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    id         TEXT NOT NULL,
    seq        BIGINT NOT NULL,
    group_id   TEXT,
    parent_id  TEXT,
    sort       BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    device_id  TEXT NOT NULL,
    deleted_at BIGINT,
    key_ref    TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    PRIMARY KEY (account_id, kind, id)
);
CREATE INDEX IF NOT EXISTS idx_records_seq ON records(seq);
CREATE INDEX IF NOT EXISTS idx_records_group ON records(group_id);

-- One counter for the whole instance. See schema_sqlite.sql for why it is not per
-- account. A real sequence rather than a counter row: nextval does not take a row lock,
-- so concurrent pushes do not serialise behind each other the way SQLite's do.
CREATE SEQUENCE IF NOT EXISTS record_seq AS BIGINT START 1;

CREATE TABLE IF NOT EXISTS shares (
    group_id          TEXT NOT NULL,
    owner_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    user_id           TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    wrapped_group_key TEXT NOT NULL,
    created_at        BIGINT NOT NULL,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(user_id);

CREATE TABLE IF NOT EXISTS devices (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL,
    name       TEXT NOT NULL,
    last_seen  BIGINT NOT NULL,
    PRIMARY KEY (account_id, device_id)
);
