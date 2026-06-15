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

// AP-6: track the IRI of the original Follow activity on `ap_follows`
// so an inbound `Undo{Follow}` referencing that IRI can locate and
// delete the right row. New column, indexed.
pub const follows_iri_migration: Migration = .{
    .id = 1009,
    .name = "activitypub:follows-iri",
    .up =
    \\ALTER TABLE ap_follows ADD COLUMN follow_iri TEXT;
    \\CREATE INDEX IF NOT EXISTS ap_follows_iri_idx ON ap_follows (follow_iri);
    ,
    .down = "DROP INDEX IF EXISTS ap_follows_iri_idx;",
};

// AP-12: record the deleted object's former AS2 type alongside the
// tombstone URI so a 410 Gone GET can echo the right `formerType`.
pub const tombstones_former_type_migration: Migration = .{
    .id = 1010,
    .name = "activitypub:tombstones-former-type",
    .up = "ALTER TABLE ap_tombstones ADD COLUMN former_type TEXT;",
    .down = "",
};

// AP-17: hashtag + mention indexes captured from `tag[]`.
pub const tags_migration: Migration = .{
    .id = 1012,
    .name = "activitypub:tags",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_tags (
    \\    activity_iri TEXT NOT NULL,
    \\    kind         TEXT NOT NULL,
    \\    name         TEXT NOT NULL,
    \\    href         TEXT,
    \\    PRIMARY KEY (activity_iri, kind, name)
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS ap_tags_kind_name_idx ON ap_tags (kind, name);
    ,
    .down = "DROP TABLE ap_tags;",
};

// AP-25: block enforcement. Block activities are stored here keyed on
// (actor, target); subsequent inbound activities from a blocked
// remote actor are 403'd.
pub const blocks_migration: Migration = .{
    .id = 1013,
    .name = "activitypub:blocks",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_blocks (
    \\    actor       TEXT NOT NULL,
    \\    target      TEXT NOT NULL,
    \\    activity_id TEXT,
    \\    created_at  INTEGER NOT NULL,
    \\    PRIMARY KEY (actor, target)
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS ap_blocks_target_idx ON ap_blocks (target);
    ,
    .down = "DROP TABLE ap_blocks;",
};

// AP-26: actor move (FEP-fb2a). We record the old→new actor pair so
// downstream lookups can chase the `alsoKnownAs` chain.
pub const moves_migration: Migration = .{
    .id = 1014,
    .name = "activitypub:moves",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_actor_moves (
    \\    old_actor  TEXT PRIMARY KEY,
    \\    new_actor  TEXT NOT NULL,
    \\    moved_at   INTEGER NOT NULL
    \\) STRICT;
    ,
    .down = "DROP TABLE ap_actor_moves;",
};

// AP-15: per-actor multi-key advertisement (FEP-d36d). The original
// `ap_actor_keys` row stores the primary key; additional keys land
// in this side table keyed on (username, key_id).
pub const multikey_migration: Migration = .{
    .id = 1015,
    .name = "activitypub:multikey",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_actor_extra_keys (
    \\    username    TEXT NOT NULL,
    \\    key_id      TEXT NOT NULL,
    \\    key_type    TEXT NOT NULL,
    \\    public_pem  TEXT NOT NULL,
    \\    created_at  INTEGER NOT NULL,
    \\    PRIMARY KEY (username, key_id)
    \\) STRICT;
    ,
    .down = "DROP TABLE ap_actor_extra_keys;",
};

// AP-8: track collection membership for Add/Remove activities.
// `collection` is the target collection IRI (e.g.
// `https://host/users/alice/collections/featured`); `object_iri` is
// the AP object pinned to it.
pub const collection_items_migration: Migration = .{
    .id = 1011,
    .name = "activitypub:collection-items",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_collection_items (
    \\    collection TEXT NOT NULL,
    \\    object_iri TEXT NOT NULL,
    \\    actor      TEXT NOT NULL,
    \\    added_at   INTEGER NOT NULL,
    \\    PRIMARY KEY (collection, object_iri)
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS ap_collection_items_collection_idx ON ap_collection_items (collection);
    ,
    .down = "DROP TABLE ap_collection_items;",
};

// AP-10: per-user actor type (Person / Service / Organization / Group).
pub const actor_type_migration: Migration = .{
    .id = 1016,
    .name = "activitypub:actor-type",
    .up = "ALTER TABLE ap_users ADD COLUMN actor_type TEXT NOT NULL DEFAULT 'Person';",
    .down = null,
};

// AP-16: poll votes — a Create{Note} with `name` (the option) +
// `inReplyTo` (the Question IRI) is recorded as a vote.
pub const poll_votes_migration: Migration = .{
    .id = 1017,
    .name = "activitypub:poll-votes",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_poll_votes (
    \\    activity_iri TEXT NOT NULL,
    \\    question_iri TEXT NOT NULL,
    \\    actor        TEXT NOT NULL,
    \\    option_name  TEXT NOT NULL,
    \\    created_at   INTEGER NOT NULL,
    \\    PRIMARY KEY (question_iri, actor, option_name)
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS ap_poll_votes_q_idx ON ap_poll_votes (question_iri);
    ,
    .down = "DROP TABLE ap_poll_votes;",
};

// AP-23: media attachments captured from inbound objects.
pub const attachments_migration: Migration = .{
    .id = 1018,
    .name = "activitypub:attachments",
    .up =
    \\CREATE TABLE IF NOT EXISTS ap_attachments (
    \\    object_iri TEXT NOT NULL,
    \\    url        TEXT NOT NULL,
    \\    media_type TEXT NOT NULL DEFAULT '',
    \\    name       TEXT NOT NULL DEFAULT '',
    \\    PRIMARY KEY (object_iri, url)
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS ap_attachments_obj_idx ON ap_attachments (object_iri);
    ,
    .down = "DROP TABLE ap_attachments;",
};

pub const all_migrations = [_]Migration{
    users_migration,
    actor_type_migration,
    poll_votes_migration,
    attachments_migration,
    actor_keys_migration,
    remote_actors_migration,
    federation_outbox_migration,
    federation_dead_migration,
    activities_migration,
    follows_migration,
    tombstones_migration,
    follows_iri_migration,
    tombstones_former_type_migration,
    collection_items_migration,
    tags_migration,
    blocks_migration,
    moves_migration,
    multikey_migration,
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
        // Skip if already applied — mirrors the production migration
        // runner. Without this, ALTER TABLE migrations (which have no
        // IF NOT EXISTS form in SQLite) fail on the second run.
        var chk: ?*c.sqlite3_stmt = null;
        _ = c.sqlite3_prepare_v2(db, "SELECT 1 FROM migrations WHERE id = ?", -1, &chk, null);
        _ = c.sqlite3_bind_int64(chk, 1, @intCast(m.id));
        const seen = c.sqlite3_step(chk.?) == c.SQLITE_ROW;
        _ = c.sqlite3_finalize(chk);
        if (seen) continue;

        const sql_z = try std.testing.allocator.dupeZ(u8, m.up);
        defer std.testing.allocator.free(sql_z);
        var em: [*c]u8 = null;
        const rc = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
        if (rc != c.SQLITE_OK) return error.MigrationFailed;

        // Mark applied so a re-run of `applyAllForTests` (some tests
        // do this to verify idempotency) doesn't re-execute ALTERs.
        var ins: ?*c.sqlite3_stmt = null;
        _ = c.sqlite3_prepare_v2(db, "INSERT INTO migrations(id, name, applied_at) VALUES (?, ?, 0)", -1, &ins, null);
        _ = c.sqlite3_bind_int64(ins, 1, @intCast(m.id));
        _ = c.sqlite3_bind_text(ins, 2, m.name.ptr, @intCast(m.name.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_step(ins.?);
        _ = c.sqlite3_finalize(ins);
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
