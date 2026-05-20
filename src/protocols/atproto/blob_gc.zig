//! AT-24: blob garbage collection.
//!
//! Periodically sweeps `atp_blobs` rows whose `ref_count` has reached
//! zero AND whose `created_at` is older than `gc_min_age_seconds`
//! (default 24 h, so a freshly-uploaded blob has time to be
//! referenced by a record).
//!
//! Two surfaces:
//!   * `sweepOnce(db, now, min_age) -> SweepResult` — pure function
//!     called from tests + the admin endpoint.
//!   * (future) periodic worker thread launched from `plugin.init`
//!     when an env var enables it.
//!
//! Inline blobs (column `data` non-null) are deleted by row-removal.
//! External blobs (data IS NULL) reference the pluggable
//! `core.blob.Store`; on GC we also call `store.delete(cid)` for
//! each evicted row.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

pub const SweepResult = struct {
    /// Number of rows examined.
    inspected: u32 = 0,
    /// Number of rows whose ref_count <= 0 and were old enough to delete.
    deleted: u32 = 0,
    /// Errors encountered (non-fatal — sweep continues).
    errors: u32 = 0,
};

pub const default_min_age_seconds: i64 = 24 * 60 * 60;

pub fn sweepOnce(db: *c.sqlite3, now_unix: i64, min_age_seconds: i64) SweepResult {
    var result: SweepResult = .{};
    var stmt: ?*c.sqlite3_stmt = null;
    const sel_sql = "SELECT cid, data IS NOT NULL FROM atp_blobs WHERE ref_count <= 0 AND created_at <= ?";
    if (c.sqlite3_prepare_v2(db, sel_sql, -1, &stmt, null) != c.SQLITE_OK) {
        result.errors += 1;
        return result;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, now_unix - min_age_seconds);

    // Collect candidate CIDs (bounded — we cap per sweep to keep this
    // O(batch) and re-runnable).
    const max_per_sweep: u32 = 512;
    var cids_buf: [max_per_sweep][80]u8 = undefined;
    var cid_lens: [max_per_sweep]u8 = undefined;
    var inline_flags: [max_per_sweep]bool = undefined;
    var n: u32 = 0;

    while (n < max_per_sweep) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) {
            result.errors += 1;
            break;
        }
        result.inspected += 1;
        const cid_ptr = c.sqlite3_column_text(stmt, 0);
        const cid_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        const cap = @min(cid_len, cids_buf[n].len);
        if (cap == 0) continue;
        @memcpy(cids_buf[n][0..cap], cid_ptr[0..cap]);
        cid_lens[n] = @intCast(cap);
        inline_flags[n] = c.sqlite3_column_int(stmt, 1) != 0;
        n += 1;
    }

    // Delete each. External blobs go through the pluggable store too.
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const cid = cids_buf[i][0..cid_lens[i]];
        var del: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, "DELETE FROM atp_blobs WHERE cid = ?", -1, &del, null) != c.SQLITE_OK) {
            result.errors += 1;
            continue;
        }
        _ = c.sqlite3_bind_text(del, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(del.?) != c.SQLITE_DONE) {
            result.errors += 1;
            _ = c.sqlite3_finalize(del);
            continue;
        }
        _ = c.sqlite3_finalize(del);

        // External blob — also drop from the store.
        if (!inline_flags[i]) {
            if (core.blob.global()) |store| {
                store.delete(cid) catch {
                    result.errors += 1;
                };
            }
        }
        result.deleted += 1;
    }
    return result;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;
const schema_mod = @import("schema.zig");

fn setupDb() !*c.sqlite3 {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    for (schema_mod.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var em: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
    }
    return db;
}

fn insertBlob(db: *c.sqlite3, cid: []const u8, ref_count: i64, created_at: i64) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "INSERT INTO atp_blobs (cid, did, mime, size, ref_count, data, created_at) VALUES (?,?,?,?,?,?,?)";
    _ = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, "did:plc:owner", 13, c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, "image/png", 9, c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 4, 0);
    _ = c.sqlite3_bind_int64(stmt, 5, ref_count);
    _ = c.sqlite3_bind_blob(stmt, 6, "x", 1, c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 7, created_at);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.InsertFailed;
}

test "AT-24: sweepOnce drops zero-refcount old rows" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    try insertBlob(db, "bafkrei-old-orphan", 0, 100);
    // Recent orphan has created_at within the min-age cutoff.
    try insertBlob(db, "bafkrei-recent-orphan", 0, 9_500);
    try insertBlob(db, "bafkrei-referenced", 3, 100);

    // now=10_000, min_age=1_000 → cutoff=9_000. Only the row at
    // created_at=100 is older than the cutoff.
    const result = sweepOnce(db, 10_000, 1_000);
    try testing.expectEqual(@as(u32, 1), result.deleted);

    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM atp_blobs", -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_step(stmt);
    try testing.expectEqual(@as(i64, 2), c.sqlite3_column_int64(stmt, 0));
}

test "AT-24: sweepOnce never touches referenced rows" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    try insertBlob(db, "bafkrei-pinned", 1, 0);
    const result = sweepOnce(db, 100_000, 0);
    try testing.expectEqual(@as(u32, 0), result.deleted);
}

test "AT-24: sweepOnce is bounded" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var i: usize = 0;
    while (i < 600) : (i += 1) {
        var buf: [32]u8 = undefined;
        const cid = try std.fmt.bufPrint(&buf, "cid-{d:0>4}", .{i});
        try insertBlob(db, cid, 0, 0);
    }
    const result = sweepOnce(db, 1_000_000, 0);
    try testing.expect(result.deleted <= 512);
    try testing.expect(result.deleted >= 512);
}
