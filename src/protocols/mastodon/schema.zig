//! Mastodon plugin schema migrations.
//!
//! Migration ids in the `mastodon = 4xxx` namespace (the `3xxx` block
//! is owned by the relay plugin; `1xxx` is AP, `2xxx` is AT).
//!
//! Tables created here:
//!   * `mastodon_apps`          — OAuth2 client registrations
//!   * `mastodon_tokens`        — issued bearer tokens (jti-indexed)
//!   * `mastodon_notifications` — per-user notification feed
//!   * `mastodon_favourites`    — likes (status_id, user_id)
//!   * `mastodon_reblogs`       — boosts (status_id, user_id)
//!
//! Counts of favourites/reblogs are derived from the dedicated tables
//! rather than denormalized on `ap_activities` so the AP plugin owns
//! its schema unchanged.

const std = @import("std");
const core = @import("core");
const Migration = core.storage.Migration;
const c = @import("sqlite").c;

pub const apps_migration: Migration = .{
    .id = 4001,
    .name = "mastodon:apps",
    .up =
    \\CREATE TABLE IF NOT EXISTS mastodon_apps (
    \\    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    client_id     TEXT NOT NULL UNIQUE,
    \\    client_secret TEXT NOT NULL,
    \\    name          TEXT NOT NULL,
    \\    redirect_uri  TEXT NOT NULL,
    \\    scopes        TEXT NOT NULL,
    \\    website       TEXT,
    \\    vapid_key     TEXT,
    \\    created_at    INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS mastodon_apps_client_idx ON mastodon_apps (client_id);
    ,
    .down = "DROP TABLE mastodon_apps;",
};

pub const tokens_migration: Migration = .{
    .id = 4002,
    .name = "mastodon:tokens",
    .up =
    \\CREATE TABLE IF NOT EXISTS mastodon_tokens (
    \\    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    jti         TEXT NOT NULL UNIQUE,
    \\    app_id      INTEGER NOT NULL,
    \\    user_id     INTEGER,
    \\    scopes      TEXT NOT NULL,
    \\    expires_at  INTEGER NOT NULL,
    \\    revoked     INTEGER NOT NULL DEFAULT 0,
    \\    created_at  INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS mastodon_tokens_jti_idx ON mastodon_tokens (jti);
    ,
    .down = "DROP TABLE mastodon_tokens;",
};

pub const notifications_migration: Migration = .{
    .id = 4003,
    .name = "mastodon:notifications",
    .up =
    \\CREATE TABLE IF NOT EXISTS mastodon_notifications (
    \\    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    user_id       INTEGER NOT NULL,
    \\    type          TEXT NOT NULL CHECK (type IN ('mention','reblog','favourite','follow','poll','status')),
    \\    from_account  TEXT NOT NULL,
    \\    status_id     INTEGER,
    \\    created_at    INTEGER NOT NULL,
    \\    read          INTEGER NOT NULL DEFAULT 0
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS mastodon_notifications_user_idx ON mastodon_notifications (user_id, read, created_at DESC);
    ,
    .down = "DROP TABLE mastodon_notifications;",
};

pub const favourites_migration: Migration = .{
    .id = 4004,
    .name = "mastodon:favourites",
    .up =
    \\CREATE TABLE IF NOT EXISTS mastodon_favourites (
    \\    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    status_id   INTEGER NOT NULL,
    \\    user_id     INTEGER NOT NULL,
    \\    created_at  INTEGER NOT NULL,
    \\    UNIQUE (status_id, user_id)
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS mastodon_favourites_status_idx ON mastodon_favourites (status_id);
    ,
    .down = "DROP TABLE mastodon_favourites;",
};

pub const reblogs_migration: Migration = .{
    .id = 4005,
    .name = "mastodon:reblogs",
    .up =
    \\CREATE TABLE IF NOT EXISTS mastodon_reblogs (
    \\    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    status_id   INTEGER NOT NULL,
    \\    user_id     INTEGER NOT NULL,
    \\    created_at  INTEGER NOT NULL,
    \\    UNIQUE (status_id, user_id)
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS mastodon_reblogs_status_idx ON mastodon_reblogs (status_id);
    ,
    .down = "DROP TABLE mastodon_reblogs;",
};

pub const all_migrations = [_]Migration{
    apps_migration,
    tokens_migration,
    notifications_migration,
    favourites_migration,
    reblogs_migration,
};

pub fn register(schema: *core.storage.Schema) !void {
    for (all_migrations) |m| try schema.register(m);
}

/// Test helper: apply migrations directly to an in-memory DB. Mirrors
/// the AP plugin's helper. Also pre-creates the AP-owned tables we
/// reference (`ap_users`, `ap_activities`, `ap_follows`, `ap_actor_keys`)
/// since the Mastodon plugin reads from them.
pub fn applyAllForTests(db: *c.sqlite3) !void {
    var errmsg: [*c]u8 = null;
    _ = c.sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS migrations (id INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;",
        null, null, &errmsg);
    if (errmsg != null) c.sqlite3_free(errmsg);

    // AP tables we share. Keep schema in lock-step with
    // `src/protocols/activitypub/schema.zig`.
    const ap_sql_pieces = [_][]const u8{
        \\CREATE TABLE IF NOT EXISTS ap_users (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    username TEXT NOT NULL UNIQUE,
        \\    display_name TEXT,
        \\    bio TEXT,
        \\    is_locked INTEGER NOT NULL DEFAULT 0,
        \\    discoverable INTEGER NOT NULL DEFAULT 1,
        \\    indexable INTEGER NOT NULL DEFAULT 1,
        \\    created_at INTEGER NOT NULL
        \\) STRICT;
        ,
        \\CREATE TABLE IF NOT EXISTS ap_actor_keys (
        \\    actor_id INTEGER PRIMARY KEY,
        \\    key_type TEXT NOT NULL,
        \\    public_pem TEXT NOT NULL,
        \\    private_pem BLOB NOT NULL,
        \\    created_at INTEGER NOT NULL
        \\) STRICT;
        ,
        \\CREATE TABLE IF NOT EXISTS ap_activities (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    ap_id TEXT NOT NULL UNIQUE,
        \\    actor_id INTEGER NOT NULL,
        \\    type TEXT NOT NULL,
        \\    object_id TEXT,
        \\    published INTEGER NOT NULL,
        \\    raw BLOB NOT NULL
        \\) STRICT;
        ,
        \\CREATE TABLE IF NOT EXISTS ap_follows (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    follower TEXT NOT NULL,
        \\    followee TEXT NOT NULL,
        \\    state TEXT NOT NULL,
        \\    accepted_at INTEGER,
        \\    UNIQUE (follower, followee)
        \\) STRICT;
        ,
    };
    for (ap_sql_pieces) |sql| {
        const z = try std.testing.allocator.dupeZ(u8, sql);
        defer std.testing.allocator.free(z);
        var em: [*c]u8 = null;
        const rc = c.sqlite3_exec(db, z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
        if (rc != c.SQLITE_OK) return error.MigrationFailed;
    }

    for (all_migrations) |m| {
        const z = try std.testing.allocator.dupeZ(u8, m.up);
        defer std.testing.allocator.free(z);
        var em: [*c]u8 = null;
        const rc = c.sqlite3_exec(db, z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
        if (rc != c.SQLITE_OK) return error.MigrationFailed;
    }
}

const testing = std.testing;

test "schema registers all migrations" {
    var s = core.storage.Schema.init();
    try s.register(core.storage.bootstrap_migration);
    try register(&s);
    try testing.expect(s.count == all_migrations.len + 1);
}

test "applyAllForTests is idempotent" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyAllForTests(db);
    try applyAllForTests(db);
}

test "notification type CHECK constraint rejects garbage" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyAllForTests(db);
    const sql = "INSERT INTO mastodon_notifications(user_id,type,from_account,created_at) VALUES (1,'bogus','x',0)";
    var em: [*c]u8 = null;
    const rc = c.sqlite3_exec(db, sql, null, null, &em);
    if (em != null) c.sqlite3_free(em);
    try testing.expect(rc != c.SQLITE_OK);
}
