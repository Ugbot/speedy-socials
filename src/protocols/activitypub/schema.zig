//! ActivityPub plugin schema migrations.
//!
//! Migration ids follow the `ap = 1xxx` namespace convention declared
//! in `core/storage/schema.zig`. Each migration is idempotent so re-
//! running on an already-migrated DB is a no-op.
//!
//! Tables created here:
//!
//!   * `ap_users`              — minimal local AP user (more fields later)
//!   * `ap_actor_keys`         — local actor key material (PEM + private)
//!   * `ap_remote_actors`      — cached remote actor profiles
//!   * `ap_federation_outbox`  — durable, bounded-queue delivery state
//!   * `ap_federation_dead`    — terminal failures
//!   * `ap_activities`         — every inbound/outbound activity, by id
//!   * `ap_follows`            — follower / following relationships
//!   * `ap_tombstones`         — deleted object URIs (for 410 Gone responses)

const std = @import("std");
const core = @import("core");
const Migration = core.storage.Migration;
const c = @import("sqlite").c;

pub const users_migration: Migration = .{
    .id = 1001,
    .name = "activitypub:users",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_users (
    \\    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    username      TEXT NOT NULL UNIQUE,
    \\    display_name  TEXT,
    \\    bio           TEXT,
    \\    is_locked     INTEGER NOT NULL DEFAULT 0,
    \\    discoverable  INTEGER NOT NULL DEFAULT 1,
    \\    indexable     INTEGER NOT NULL DEFAULT 1,
    \\    created_at    INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS ap_users_username_idx ON ap_users (username);
    ,
    .down = "DROP TABLE ap_users;",
};

pub const actor_keys_migration: Migration = .{
    .id = 1002,
    .name = "activitypub:actor_keys",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_actor_keys (
    \\    actor_id    INTEGER PRIMARY KEY REFERENCES ap_users(id) ON DELETE CASCADE,
    \\    key_type    TEXT NOT NULL,
    \\    public_pem  TEXT NOT NULL,
    \\    private_pem BLOB NOT NULL,
    \\    created_at  INTEGER NOT NULL
    \\) STRICT;
    ,
    .down = "DROP TABLE ap_actor_keys;",
};

pub const remote_actors_migration: Migration = .{
    .id = 1003,
    .name = "activitypub:remote_actors",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_remote_actors (
    \\    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    actor_url        TEXT NOT NULL UNIQUE,
    \\    inbox_url        TEXT NOT NULL,
    \\    shared_inbox_url TEXT,
    \\    public_key_pem   TEXT,
    \\    key_id           TEXT NOT NULL UNIQUE,
    \\    updated_at       INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS ap_remote_actors_key_idx ON ap_remote_actors (key_id);
    ,
    .down = "DROP TABLE ap_remote_actors;",
};

pub const federation_outbox_migration: Migration = .{
    .id = 1004,
    .name = "activitypub:federation_outbox",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_federation_outbox (
    \\    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    target_inbox    TEXT NOT NULL,
    \\    shared_inbox    TEXT,
    \\    payload         BLOB NOT NULL,
    \\    key_id          TEXT NOT NULL,
    \\    attempts        INTEGER NOT NULL DEFAULT 0,
    \\    next_attempt_at INTEGER NOT NULL,
    \\    state           TEXT NOT NULL CHECK (state IN ('pending','in_flight','done','dead')),
    \\    inserted_at     INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS ap_federation_outbox_pending_idx
    \\    ON ap_federation_outbox (state, next_attempt_at);
    ,
    .down = "DROP TABLE ap_federation_outbox;",
};

pub const federation_dead_migration: Migration = .{
    .id = 1005,
    .name = "activitypub:federation_dead",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_federation_dead_letter (
    \\    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    target_inbox  TEXT NOT NULL,
    \\    payload       BLOB NOT NULL,
    \\    last_error    TEXT,
    \\    attempts      INTEGER NOT NULL,
    \\    dropped_at    INTEGER NOT NULL
    \\) STRICT;
    ,
    .down = "DROP TABLE ap_federation_dead_letter;",
};

pub const activities_migration: Migration = .{
    .id = 1006,
    .name = "activitypub:activities",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_activities (
    \\    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    ap_id      TEXT NOT NULL UNIQUE,
    \\    actor_id   INTEGER NOT NULL,
    \\    type       TEXT NOT NULL,
    \\    object_id  TEXT,
    \\    published  INTEGER NOT NULL,
    \\    raw        BLOB NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS ap_activities_actor_idx ON ap_activities (actor_id, published DESC);
    ,
    .down = "DROP TABLE ap_activities;",
};

pub const follows_migration: Migration = .{
    .id = 1007,
    .name = "activitypub:follows",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_follows (
    \\    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    follower    TEXT NOT NULL,
    \\    followee    TEXT NOT NULL,
    \\    state       TEXT NOT NULL CHECK (state IN ('pending','accepted','rejected')),
    \\    accepted_at INTEGER,
    \\    UNIQUE (follower, followee)
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS ap_follows_followee_idx ON ap_follows (followee);
    ,
    .down = "DROP TABLE ap_follows;",
};

pub const tombstones_migration: Migration = .{
    .id = 1008,
    .name = "activitypub:tombstones",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_tombstones (
    \\    uri        TEXT PRIMARY KEY,
    \\    deleted_at INTEGER NOT NULL
    \\) STRICT;
    ,
    .down = "DROP TABLE ap_tombstones;",
};

pub const all_migrations = [_]Migration{
    users_migration,
    actor_keys_migration,
    remote_actors_migration,
    federation_outbox_migration,
    federation_dead_migration,
    activities_migration,
    follows_migration,
    tombstones_migration,
};

/// Plugin entrypoint: push every migration onto the shared schema.
pub fn register(schema: *core.storage.Schema) !void {
    for (all_migrations) |m| try schema.register(m);
}

// ──────────────────────────────────────────────────────────────────────
// Test helper: apply migrations directly to an in-memory DB. The full
// `Schema.applyAll` path requires the writer thread up; for plugin-level
// tests we just exec the SQL.
// ──────────────────────────────────────────────────────────────────────

pub fn applyAllForTests(db: *c.sqlite3) !void {
    // Need the bookkeeping table; harmless if it already exists.
    var errmsg: [*c]u8 = null;
    _ = c.sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS migrations (id INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;",
        null,
        null,
        &errmsg,
    );
    if (errmsg != null) c.sqlite3_free(errmsg);

    for (all_migrations) |m| {
        const sql_z = try std.testing.allocator.dupeZ(u8, m.up);
        defer std.testing.allocator.free(sql_z);
        var em: [*c]u8 = null;
        const rc = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
        if (rc != c.SQLITE_OK) return error.MigrationFailed;
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "schema registers without duplicate ids" {
    var s = core.storage.Schema.init();
    try s.register(core.storage.bootstrap_migration);
    try register(&s);
    try testing.expect(s.count == all_migrations.len + 1);
}

test "all migrations apply cleanly to a fresh DB" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyAllForTests(db);
    // Sanity-check one table is queryable.
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT COUNT(*) FROM ap_federation_outbox";
    try testing.expect(c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) == c.SQLITE_OK);
    defer _ = c.sqlite3_finalize(stmt);
    try testing.expect(c.sqlite3_step(stmt) == c.SQLITE_ROW);
}

test "applying twice is idempotent" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyAllForTests(db);
    try applyAllForTests(db); // would error if CREATE TABLE wasn't IF NOT EXISTS
}

test "outbox state CHECK constraint rejects garbage" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyAllForTests(db);

    const sql = "INSERT INTO ap_federation_outbox(target_inbox, payload, key_id, next_attempt_at, state, inserted_at) VALUES ('https://x','{}','k1',0,'bogus',0)";
    var em: [*c]u8 = null;
    const rc = c.sqlite3_exec(db, sql, null, null, &em);
    if (em != null) c.sqlite3_free(em);
    try testing.expect(rc != c.SQLITE_OK);
}

test "follows UNIQUE (follower, followee) prevents duplicates" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyAllForTests(db);

    const sql1 = "INSERT INTO ap_follows(follower,followee,state) VALUES ('a','b','pending')";
    var em: [*c]u8 = null;
    try testing.expect(c.sqlite3_exec(db, sql1, null, null, &em) == c.SQLITE_OK);
    if (em != null) c.sqlite3_free(em);
    em = null;
    const rc = c.sqlite3_exec(db, sql1, null, null, &em);
    if (em != null) c.sqlite3_free(em);
    try testing.expect(rc != c.SQLITE_OK);
}
