//! Firehose event emission + storage.
//!
//! Persistent table (`atp_firehose_events`) is append-only and NEVER drops.
//! Subscribers replay from a `cursor` (sequence number) then live-tail via
//! the per-shard event ring in `core/ws/registry.zig`. The live ring may
//! drop oldest events under burst — subscribers detect the gap (their
//! cursor < oldest available seq), reconnect, and resume from the
//! persistent table.
//!
//! The seq column on `atp_firehose_events` is a SQLite AUTOINCREMENT
//! INTEGER PRIMARY KEY, which gives us a monotonic counter without an
//! explicit cursor table read on every append. The `atp_firehose_cursor`
//! row is used by tests and external consumers wanting a "last emitted"
//! snapshot.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");
const StorageError = core.errors.StorageError;

/// Append a firehose event row. Returns the assigned sequence number.
pub fn append(
    db: *c.sqlite3,
    did: []const u8,
    commit_cid: []const u8,
    body: []const u8,
    ts: i64,
) StorageError!i64 {
    const sql = "INSERT INTO atp_firehose_events (did, commit_cid, body, ts) VALUES (?,?,?,?)";
    var stmt: ?*c.sqlite3_stmt = null;
    const rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK or stmt == null) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    _ = c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, commit_cid.ptr, @intCast(commit_cid.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_blob(stmt, 3, body.ptr, @intCast(body.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 4, ts);

    const step_rc = c.sqlite3_step(stmt.?);
    if (step_rc != c.SQLITE_DONE) return error.StepFailed;
    const seq = c.sqlite3_last_insert_rowid(db);

    // Update cursor.
    const upd_sql = "UPDATE atp_firehose_cursor SET seq = ? WHERE id = 1";
    var ustmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, upd_sql, -1, &ustmt, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(ustmt);
        _ = c.sqlite3_bind_int64(ustmt, 1, seq);
        _ = c.sqlite3_step(ustmt.?);
    }
    return seq;
}

pub const Event = struct {
    seq: i64,
    did_buf: [256]u8 = undefined,
    did_len: u16 = 0,
    commit_cid_buf: [128]u8 = undefined,
    commit_cid_len: u16 = 0,
    ts: i64 = 0,

    pub fn did(self: *const Event) []const u8 {
        return self.did_buf[0..self.did_len];
    }
    pub fn commitCid(self: *const Event) []const u8 {
        return self.commit_cid_buf[0..self.commit_cid_len];
    }
};

/// Read events with seq > `cursor`, up to `out.len`. Returns the count
/// written.
pub fn readSince(
    db: *c.sqlite3,
    cursor: i64,
    out: []Event,
) StorageError!u32 {
    const sql = "SELECT seq, did, commit_cid, ts FROM atp_firehose_events WHERE seq > ? ORDER BY seq ASC LIMIT ?";
    var stmt: ?*c.sqlite3_stmt = null;
    const rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK or stmt == null) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    _ = c.sqlite3_bind_int64(stmt, 1, cursor);
    _ = c.sqlite3_bind_int64(stmt, 2, @intCast(out.len));

    var n: u32 = 0;
    while (n < out.len) {
        const step_rc = c.sqlite3_step(stmt.?);
        if (step_rc == c.SQLITE_DONE) break;
        if (step_rc != c.SQLITE_ROW) return error.StepFailed;

        var ev: Event = .{ .seq = c.sqlite3_column_int64(stmt, 0) };
        const did_ptr = c.sqlite3_column_text(stmt, 1);
        const did_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        if (did_len > 0 and did_ptr != null) {
            const cap = @min(did_len, ev.did_buf.len);
            @memcpy(ev.did_buf[0..cap], did_ptr[0..cap]);
            ev.did_len = @intCast(cap);
        }
        const cid_ptr = c.sqlite3_column_text(stmt, 2);
        const cid_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
        if (cid_len > 0 and cid_ptr != null) {
            const cap = @min(cid_len, ev.commit_cid_buf.len);
            @memcpy(ev.commit_cid_buf[0..cap], cid_ptr[0..cap]);
            ev.commit_cid_len = @intCast(cap);
        }
        ev.ts = c.sqlite3_column_int64(stmt, 3);
        out[n] = ev;
        n += 1;
    }
    return n;
}

pub fn latestSeq(db: *c.sqlite3) StorageError!i64 {
    const sql = "SELECT seq FROM atp_firehose_cursor WHERE id = 1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    const step_rc = c.sqlite3_step(stmt.?);
    if (step_rc == c.SQLITE_ROW) return c.sqlite3_column_int64(stmt, 0);
    return 0;
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;
const schema_mod = @import("schema.zig");

fn setupDb() !*c.sqlite3 {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    for (schema_mod.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    return db;
}

test "firehose: append + readSince" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    const s1 = try append(db, "did:plc:a", "bafy1", "body1", 1000);
    const s2 = try append(db, "did:plc:b", "bafy2", "body2", 1001);
    const s3 = try append(db, "did:plc:c", "bafy3", "body3", 1002);
    try testing.expect(s2 > s1);
    try testing.expect(s3 > s2);

    var out: [10]Event = undefined;
    const n = try readSince(db, s1, &out);
    try testing.expectEqual(@as(u32, 2), n);
    try testing.expectEqualStrings("did:plc:b", out[0].did());
    try testing.expectEqualStrings("bafy3", out[1].commitCid());
}

test "firehose: latestSeq tracks last append" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    try testing.expectEqual(@as(i64, 0), try latestSeq(db));
    _ = try append(db, "did:plc:x", "c1", "b1", 1);
    _ = try append(db, "did:plc:x", "c2", "b2", 2);
    try testing.expect((try latestSeq(db)) >= 2);
}

test "firehose: empty readSince" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var out: [4]Event = undefined;
    const n = try readSince(db, 0, &out);
    try testing.expectEqual(@as(u32, 0), n);
}
