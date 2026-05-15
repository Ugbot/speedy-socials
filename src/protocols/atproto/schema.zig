//! AT Protocol PDS schema migrations.
//!
//! Migration ids follow the `atproto = 2xxx` namespace convention.
//! Each migration is idempotent (`CREATE TABLE IF NOT EXISTS`) so
//! re-running on an already-migrated DB is a no-op.

const core = @import("core");
const Migration = core.storage.Migration;

pub const repos_migration: Migration = .{
    .id = 2001,
    .name = "atproto:repos",
    .up =
    \\CREATE TABLE IF NOT EXISTS atp_repos (
    \\    did          TEXT PRIMARY KEY,
    \\    signing_key  TEXT NOT NULL,
    \\    rotation_key TEXT,
    \\    head_cid     TEXT,
    \\    head_rev     TEXT,
    \\    created_at   INTEGER NOT NULL
    \\) STRICT;
    ,
    .down = "DROP TABLE atp_repos;",
};

pub const commits_migration: Migration = .{
    .id = 2002,
    .name = "atproto:commits",
    .up =
    \\CREATE TABLE IF NOT EXISTS atp_commits (
    \\    cid          TEXT PRIMARY KEY,
    \\    did          TEXT NOT NULL,
    \\    rev          TEXT NOT NULL,
    \\    prev_cid     TEXT,
    \\    data_cid     TEXT NOT NULL,
    \\    signature    BLOB NOT NULL,
    \\    committed_at INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS atp_commits_did_rev_idx
    \\    ON atp_commits (did, rev);
    ,
    .down = "DROP TABLE atp_commits;",
};

pub const records_migration: Migration = .{
    .id = 2003,
    .name = "atproto:records",
    .up =
    \\CREATE TABLE IF NOT EXISTS atp_records (
    \\    uri        TEXT PRIMARY KEY,
    \\    did        TEXT NOT NULL,
    \\    collection TEXT NOT NULL,
    \\    rkey       TEXT NOT NULL,
    \\    cid        TEXT NOT NULL,
    \\    value      BLOB NOT NULL,
    \\    indexed_at INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS atp_records_lookup_idx
    \\    ON atp_records (did, collection, rkey);
    ,
    .down = "DROP TABLE atp_records;",
};

pub const blobs_migration: Migration = .{
    .id = 2004,
    .name = "atproto:blobs",
    .up =
    \\CREATE TABLE IF NOT EXISTS atp_blobs (
    \\    cid        TEXT PRIMARY KEY,
    \\    did        TEXT NOT NULL,
    \\    mime       TEXT,
    \\    size       INTEGER NOT NULL,
    \\    ref_count  INTEGER NOT NULL DEFAULT 0,
    \\    data       BLOB NOT NULL,
    \\    created_at INTEGER NOT NULL
    \\) STRICT;
    ,
    .down = "DROP TABLE atp_blobs;",
};

pub const mst_blocks_migration: Migration = .{
    .id = 2005,
    .name = "atproto:mst_blocks",
    .up =
    \\CREATE TABLE IF NOT EXISTS atp_mst_blocks (
    \\    cid  TEXT PRIMARY KEY,
    \\    did  TEXT NOT NULL,
    \\    data BLOB NOT NULL
    \\) STRICT;
    ,
    .down = "DROP TABLE atp_mst_blocks;",
};

pub const firehose_cursor_migration: Migration = .{
    .id = 2006,
    .name = "atproto:firehose_cursor",
    .up =
    \\CREATE TABLE IF NOT EXISTS atp_firehose_cursor (
    \\    id  INTEGER PRIMARY KEY DEFAULT 1,
    \\    seq INTEGER NOT NULL DEFAULT 0,
    \\    CHECK (id = 1)
    \\) STRICT;
    \\INSERT OR IGNORE INTO atp_firehose_cursor (id, seq) VALUES (1, 0);
    ,
    .down = "DROP TABLE atp_firehose_cursor;",
};

pub const firehose_events_migration: Migration = .{
    .id = 2007,
    .name = "atproto:firehose_events",
    .up =
    \\CREATE TABLE IF NOT EXISTS atp_firehose_events (
    \\    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    did        TEXT NOT NULL,
    \\    commit_cid TEXT NOT NULL,
    \\    body       BLOB NOT NULL,
    \\    ts         INTEGER NOT NULL
    \\) STRICT;
    ,
    .down = "DROP TABLE atp_firehose_events;",
};

pub const sessions_migration: Migration = .{
    .id = 2008,
    .name = "atproto:sessions",
    .up =
    \\CREATE TABLE IF NOT EXISTS atp_sessions (
    \\    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    did         TEXT NOT NULL,
    \\    access_jti  TEXT UNIQUE,
    \\    refresh_jti TEXT UNIQUE,
    \\    created_at  INTEGER NOT NULL,
    \\    expires_at  INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS atp_sessions_did_idx ON atp_sessions (did);
    ,
    .down = "DROP TABLE atp_sessions;",
};

/// Per-DID Argon2id password hashes for the legacy `createSession`
/// path. Migrating from the stub-accept-any policy: empty table means
/// nobody can log in via password, which is the correct default until
/// admins provision identities.
pub const user_passwords_migration: Migration = .{
    .id = 2009,
    .name = "atproto:user_passwords",
    .up =
    \\CREATE TABLE IF NOT EXISTS atp_user_passwords (
    \\    did           TEXT PRIMARY KEY,
    \\    password_hash BLOB NOT NULL,
    \\    created_at    INTEGER NOT NULL
    \\) STRICT;
    ,
    .down = "DROP TABLE atp_user_passwords;",
};

pub const all_migrations = [_]Migration{
    repos_migration,
    commits_migration,
    records_migration,
    blobs_migration,
    mst_blocks_migration,
    firehose_cursor_migration,
    firehose_events_migration,
    sessions_migration,
    user_passwords_migration,
};
