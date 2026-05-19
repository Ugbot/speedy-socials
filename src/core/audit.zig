//! G2 — append-only audit log.
//!
//! Sensitive operations (admin route invocations, key rotations,
//! cert reloads, follower seeds, exports) write a row here. The
//! schema is intentionally minimal — operators that need richer
//! per-event metadata stash JSON in `detail_json`.
//!
//! Tiger Style: all writes are single-row INSERTs through the same
//! single-writer connection callers already hold. No allocator on
//! the audit path.

const std = @import("std");
const c = @import("sqlite").c;
const errors = @import("errors.zig");
const Clock = @import("clock.zig").Clock;

pub const Error = errors.StorageError;

pub const Migration = @import("storage/schema.zig").Migration;

pub const audit_migration: Migration = .{
    .id = 9,
    .name = "core:audit_log",
    .up =
    \\CREATE TABLE IF NOT EXISTS core_audit_log (
    \\    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    ts           INTEGER NOT NULL,
    \\    actor        TEXT NOT NULL,
    \\    action       TEXT NOT NULL,
    \\    target       TEXT,
    \\    detail_json  TEXT,
    \\    success      INTEGER NOT NULL DEFAULT 1
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS core_audit_log_ts_idx
    \\    ON core_audit_log (ts DESC);
    \\CREATE INDEX IF NOT EXISTS core_audit_log_actor_idx
    \\    ON core_audit_log (actor, ts DESC);
    ,
    .down = "DROP TABLE core_audit_log;",
};

/// Append one audit-log entry. All slice parameters are bounded by
/// the caller; we never copy out — the SQLite bindings own the
/// transient copy for the duration of `sqlite3_step`.
pub fn append(
    db: *c.sqlite3,
    clock: Clock,
    actor: []const u8,
    action: []const u8,
    target: []const u8,
    detail_json: []const u8,
    success: bool,
) Error!void {
    const sql =
        "INSERT INTO core_audit_log (ts, actor, action, target, detail_json, success) " ++
        "VALUES (?,?,?,?,?,?)";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, clock.wallUnix());
    _ = c.sqlite3_bind_text(stmt, 2, actor.ptr, @intCast(actor.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, action.ptr, @intCast(action.len), c.sqliteTransientAsDestructor());
    if (target.len > 0) {
        _ = c.sqlite3_bind_text(stmt, 4, target.ptr, @intCast(target.len), c.sqliteTransientAsDestructor());
    } else {
        _ = c.sqlite3_bind_null(stmt, 4);
    }
    if (detail_json.len > 0) {
        _ = c.sqlite3_bind_text(stmt, 5, detail_json.ptr, @intCast(detail_json.len), c.sqliteTransientAsDestructor());
    } else {
        _ = c.sqlite3_bind_null(stmt, 5);
    }
    _ = c.sqlite3_bind_int(stmt, 6, if (success) 1 else 0);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.StepFailed;
}

/// Count rows. Used by tests.
pub fn count(db: *c.sqlite3) i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT count(*) FROM core_audit_log", -1, &stmt, null) != c.SQLITE_OK) return -1;
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return -1;
    return c.sqlite3_column_int64(stmt, 0);
}

// ── Tests ─────────────────────────────────────────────────────────

const testing = std.testing;
const sqlite_mod = @import("storage/sqlite.zig");
const SimClock = @import("clock.zig").SimClock;

test "audit.append + count round-trip" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);

    var errmsg: [*c]u8 = null;
    const sql_z = try testing.allocator.dupeZ(u8, audit_migration.up);
    defer testing.allocator.free(sql_z);
    _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
    if (errmsg != null) c.sqlite3_free(errmsg);

    var sc = SimClock.init(100);
    try append(db, sc.clock(), "admin", "follower.seed", "https://relay/ap/users/at:plc:x", "{\"inbox\":\"https://m/inbox\"}", true);
    try append(db, sc.clock(), "admin", "tls.reload", "", "", true);
    try testing.expectEqual(@as(i64, 2), count(db));
}

test "audit.append accepts null target + null detail" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    var errmsg: [*c]u8 = null;
    const sql_z = try testing.allocator.dupeZ(u8, audit_migration.up);
    defer testing.allocator.free(sql_z);
    _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
    if (errmsg != null) c.sqlite3_free(errmsg);
    var sc = SimClock.init(1);
    try append(db, sc.clock(), "process", "shutdown", "", "", true);
    try testing.expectEqual(@as(i64, 1), count(db));
}
