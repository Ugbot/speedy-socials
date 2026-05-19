//! B1: per-synthetic-actor follower storage.
//!
//! When an AP peer sends `Follow` targeting one of our synthetic
//! actors (a bridge actor we minted for an AT DID), we record the
//! follower's inbox URL here. The AT→AP firehose consumer reads
//! this table when fanning out a translated activity — one outbox
//! row per follower.
//!
//! Tiger Style: every operation bounded, no allocation on the hot
//! path, errors surface as the typed `RelayError` set.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;

const Clock = core.clock.Clock;
const RelayError = core.errors.RelayError;

pub const max_actor_url_bytes: usize = 512;
pub const max_inbox_url_bytes: usize = 512;
pub const max_follow_iri_bytes: usize = 512;

/// One follower row materialised into stack-bounded buffers.
pub const Follower = struct {
    inbox_buf: [max_inbox_url_bytes]u8 = undefined,
    inbox_len: u16 = 0,
    shared_buf: [max_inbox_url_bytes]u8 = undefined,
    shared_len: u16 = 0,

    pub fn inbox(self: *const Follower) []const u8 {
        return self.inbox_buf[0..self.inbox_len];
    }
    pub fn sharedInbox(self: *const Follower) []const u8 {
        return self.shared_buf[0..self.shared_len];
    }
};

/// Insert (or no-op if already present) a follower row.
pub fn add(
    db: *c.sqlite3,
    clock: Clock,
    actor_url: []const u8,
    follower_inbox: []const u8,
    shared_inbox: []const u8,
    follow_iri: []const u8,
) RelayError!void {
    if (actor_url.len == 0 or actor_url.len > max_actor_url_bytes) return error.IdentityMapFailed;
    if (follower_inbox.len == 0 or follower_inbox.len > max_inbox_url_bytes) return error.IdentityMapFailed;
    if (follow_iri.len == 0 or follow_iri.len > max_follow_iri_bytes) return error.IdentityMapFailed;
    if (shared_inbox.len > max_inbox_url_bytes) return error.IdentityMapFailed;

    const sql =
        "INSERT INTO relay_followers (actor_url, follower_inbox, shared_inbox, follow_iri, created_at) " ++
        "VALUES (?,?,?,?,?) ON CONFLICT(actor_url, follower_inbox) DO NOTHING";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.IdentityMapFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, actor_url.ptr, @intCast(actor_url.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, follower_inbox.ptr, @intCast(follower_inbox.len), c.sqliteTransientAsDestructor());
    if (shared_inbox.len > 0) {
        _ = c.sqlite3_bind_text(stmt, 3, shared_inbox.ptr, @intCast(shared_inbox.len), c.sqliteTransientAsDestructor());
    } else {
        _ = c.sqlite3_bind_null(stmt, 3);
    }
    _ = c.sqlite3_bind_text(stmt, 4, follow_iri.ptr, @intCast(follow_iri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 5, clock.wallUnix());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.IdentityMapFailed;
}

/// Remove a follower row by the original Follow activity IRI. AP
/// `Undo{Follow}` carries the inner `Follow` activity's `id`, which
/// is what we keyed on. Returns true when a row was actually
/// removed (so callers can audit-log no-ops vs hits).
pub fn removeByFollowIri(
    db: *c.sqlite3,
    follow_iri: []const u8,
) RelayError!bool {
    if (follow_iri.len == 0 or follow_iri.len > max_follow_iri_bytes) return error.IdentityMapFailed;
    const sql = "DELETE FROM relay_followers WHERE follow_iri = ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.IdentityMapFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, follow_iri.ptr, @intCast(follow_iri.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.IdentityMapFailed;
    return c.sqlite3_changes(db) > 0;
}

/// Remove all followers of an actor (e.g. when a synthetic actor
/// is retired). Currently unused but defined symmetric to `add`.
pub fn removeAll(db: *c.sqlite3, actor_url: []const u8) RelayError!u32 {
    const sql = "DELETE FROM relay_followers WHERE actor_url = ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.IdentityMapFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, actor_url.ptr, @intCast(actor_url.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.IdentityMapFailed;
    return @intCast(c.sqlite3_changes(db));
}

/// List followers of `actor_url` into the caller's `out` slice.
/// Bounded by `out.len`; returns the number of rows written.
pub fn list(
    db: *c.sqlite3,
    actor_url: []const u8,
    out: []Follower,
) RelayError!u32 {
    const sql = "SELECT follower_inbox, shared_inbox FROM relay_followers WHERE actor_url = ? ORDER BY created_at ASC LIMIT ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.IdentityMapFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, actor_url.ptr, @intCast(actor_url.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 2, @intCast(out.len));

    var n: u32 = 0;
    while (n < out.len) {
        const step_rc = c.sqlite3_step(stmt.?);
        if (step_rc == c.SQLITE_DONE) break;
        if (step_rc != c.SQLITE_ROW) return error.IdentityMapFailed;
        var f: Follower = .{};
        const ip = c.sqlite3_column_text(stmt, 0);
        const il: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        if (ip != null and il > 0) {
            const cap = @min(il, f.inbox_buf.len);
            @memcpy(f.inbox_buf[0..cap], ip[0..cap]);
            f.inbox_len = @intCast(cap);
        }
        if (c.sqlite3_column_type(stmt, 1) == c.SQLITE_TEXT) {
            const sp = c.sqlite3_column_text(stmt, 1);
            const sl: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
            if (sp != null and sl > 0) {
                const cap = @min(sl, f.shared_buf.len);
                @memcpy(f.shared_buf[0..cap], sp[0..cap]);
                f.shared_len = @intCast(cap);
            }
        }
        out[n] = f;
        n += 1;
    }
    return n;
}

// ── Tests ─────────────────────────────────────────────────────────

const testing = std.testing;
const schema = @import("schema.zig");

fn setupDb() !*c.sqlite3 {
    const db = try core.storage.sqlite.openWriter(":memory:");
    for (schema.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    return db;
}

test "B1: add then list returns the inbox" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(100);
    try add(db, sc.clock(), "https://relay/ap/users/at:plc:a", "https://m.example/users/eve/inbox", "https://m.example/inbox", "https://m.example/follow/1");
    var out: [4]Follower = undefined;
    const n = try list(db, "https://relay/ap/users/at:plc:a", &out);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqualStrings("https://m.example/users/eve/inbox", out[0].inbox());
    try testing.expectEqualStrings("https://m.example/inbox", out[0].sharedInbox());
}

test "B1: add is idempotent on (actor_url, follower_inbox)" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1);
    try add(db, sc.clock(), "https://relay/ap/users/x", "https://m/inbox/a", "", "https://m/follow/1");
    try add(db, sc.clock(), "https://relay/ap/users/x", "https://m/inbox/a", "", "https://m/follow/2");
    var out: [4]Follower = undefined;
    const n = try list(db, "https://relay/ap/users/x", &out);
    try testing.expectEqual(@as(u32, 1), n);
}

test "B4: removeByFollowIri deletes one row + returns true" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1);
    try add(db, sc.clock(), "https://relay/ap/users/y", "https://m/inbox/a", "", "https://m/follow/A");
    try add(db, sc.clock(), "https://relay/ap/users/y", "https://m/inbox/b", "", "https://m/follow/B");
    const removed = try removeByFollowIri(db, "https://m/follow/A");
    try testing.expect(removed);
    var out: [4]Follower = undefined;
    const n = try list(db, "https://relay/ap/users/y", &out);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqualStrings("https://m/inbox/b", out[0].inbox());
}

test "B4: removeByFollowIri on a non-existent IRI is a no-op" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    const removed = try removeByFollowIri(db, "https://m/follow/never");
    try testing.expect(!removed);
}
