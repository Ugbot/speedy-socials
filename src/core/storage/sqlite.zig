//! Single-writer SQLite database with a dedicated writer thread.
//!
//! The writer thread is the only entity that touches the writer
//! connection. Other threads either:
//!
//!   (a) push a `Query` onto the channel and receive a completion call
//!       on the writer thread; or
//!   (b) open their own read-only connection (WAL mode allows concurrent
//!       readers — see `handle.zig` for the per-thread reader pool).
//!
//! Tiger Style: no allocator on the hot path. All bind arguments come
//! preformatted in fixed-size `Value` variants. The completion callback
//! receives copies of any text/blob results in inline buffers.

const std = @import("std");
const c = @import("sqlite").c;
const limits = @import("../limits.zig");
const errors = @import("../errors.zig");
const assert_mod = @import("../assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;
const stmts_mod = @import("stmts.zig");
const channel_mod = @import("channel.zig");
const schema_mod = @import("schema.zig");

const StorageError = errors.StorageError;
const StmtTable = stmts_mod.StmtTable;
const Channel = channel_mod.Channel;
const Query = channel_mod.Query;
const Row = channel_mod.Row;
const ResultValue = channel_mod.ResultValue;
const Value = channel_mod.Value;
const QueryStatus = channel_mod.QueryStatus;

/// Sleep for `ns` nanoseconds. Used by the writer thread for short idle
/// parks; `std.Thread.sleep` was removed in Zig 0.16, so we go through
/// the C nanosleep directly.
pub fn sleepNs(ns: u64) void {
    var req: std.c.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.c.nanosleep(&req, &req);
}

/// Open the SQLite writer connection. Sets WAL, NORMAL sync, large mmap.
pub fn openWriter(path: [:0]const u8) StorageError!*c.sqlite3 {
    var db: ?*c.sqlite3 = null;
    const flags: c_int = c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE | c.SQLITE_OPEN_NOMUTEX | c.SQLITE_OPEN_URI;
    const rc = c.sqlite3_open_v2(path.ptr, &db, flags, null);
    if (rc != c.SQLITE_OK or db == null) {
        if (db != null) _ = c.sqlite3_close(db);
        return error.OpenFailed;
    }
    const dbp = db.?;
    // Pragmas. errors here are fatal — we want a known-good config.
    try execPragma(dbp, "PRAGMA journal_mode = WAL;");
    try execPragma(dbp, "PRAGMA synchronous = NORMAL;");
    try execPragma(dbp, "PRAGMA mmap_size = 268435456;"); // 256 MiB
    try execPragma(dbp, "PRAGMA foreign_keys = ON;");
    try execPragma(dbp, "PRAGMA busy_timeout = 5000;");
    return dbp;
}

/// Open a read-only connection to the same DB. WAL allows N readers
/// concurrent with the writer.
pub fn openReader(path: [:0]const u8) StorageError!*c.sqlite3 {
    var db: ?*c.sqlite3 = null;
    const flags: c_int = c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX | c.SQLITE_OPEN_URI;
    const rc = c.sqlite3_open_v2(path.ptr, &db, flags, null);
    if (rc != c.SQLITE_OK or db == null) {
        if (db != null) _ = c.sqlite3_close(db);
        return error.OpenFailed;
    }
    const dbp = db.?;
    try execPragma(dbp, "PRAGMA query_only = ON;");
    try execPragma(dbp, "PRAGMA busy_timeout = 5000;");
    return dbp;
}

pub fn closeDb(db: *c.sqlite3) void {
    _ = c.sqlite3_close_v2(db);
}

fn execPragma(db: *c.sqlite3, sql: [:0]const u8) StorageError!void {
    var errmsg: [*c]u8 = null;
    const rc = c.sqlite3_exec(db, sql.ptr, null, null, &errmsg);
    if (rc != c.SQLITE_OK) {
        if (errmsg != null) c.sqlite3_free(errmsg);
        return error.OpenFailed;
    }
}

/// Bind a single parameter at 1-based position `pos`.
fn bindOne(stmt: *c.sqlite3_stmt, pos: c_int, value: *const Value) StorageError!void {
    const rc: c_int = switch (value.*) {
        .null_ => c.sqlite3_bind_null(stmt, pos),
        .int => |v| c.sqlite3_bind_int64(stmt, pos, v),
        .real => |v| c.sqlite3_bind_double(stmt, pos, v),
        .text_inline => |*t| c.sqlite3_bind_text(stmt, pos, &t.bytes, @intCast(t.len), c.sqliteTransientAsDestructor()),
        .text_borrowed => |s| c.sqlite3_bind_text(stmt, pos, s.ptr, @intCast(s.len), c.sqliteTransientAsDestructor()),
        .blob_inline => |*b| c.sqlite3_bind_blob(stmt, pos, &b.bytes, @intCast(b.len), c.sqliteTransientAsDestructor()),
        .blob_borrowed => |s| c.sqlite3_bind_blob(stmt, pos, s.ptr, @intCast(s.len), c.sqliteTransientAsDestructor()),
    };
    if (rc != c.SQLITE_OK) return error.BindFailed;
}

fn readRow(stmt: *c.sqlite3_stmt, row: *Row) void {
    const ncols = c.sqlite3_column_count(stmt);
    const cap: c_int = @intCast(channel_mod.max_result_columns);
    const used: u8 = @intCast(if (ncols < cap) ncols else cap);
    row.col_count = used;
    var i: c_int = 0;
    while (i < @as(c_int, used)) : (i += 1) {
        const t = c.sqlite3_column_type(stmt, i);
        const cv = &row.cols[@as(usize, @intCast(i))];
        switch (t) {
            c.SQLITE_INTEGER => cv.* = .{ .int = c.sqlite3_column_int64(stmt, i) },
            c.SQLITE_FLOAT => cv.* = .{ .real = c.sqlite3_column_double(stmt, i) },
            c.SQLITE_TEXT => {
                const ptr = c.sqlite3_column_text(stmt, i);
                const n: usize = @intCast(c.sqlite3_column_bytes(stmt, i));
                var holder: ResultValue = .{ .text = .{} };
                const cap_bytes = channel_mod.inline_text_bytes;
                const copy_len: u16 = @intCast(if (n > cap_bytes) cap_bytes else n);
                if (n > 0 and ptr != null) {
                    @memcpy(holder.text.bytes[0..copy_len], ptr[0..copy_len]);
                }
                holder.text.len = copy_len;
                holder.text.truncated = n > cap_bytes;
                cv.* = holder;
            },
            c.SQLITE_BLOB => {
                const ptr = c.sqlite3_column_blob(stmt, i);
                const n: usize = @intCast(c.sqlite3_column_bytes(stmt, i));
                var holder: ResultValue = .{ .blob = .{} };
                const cap_bytes = channel_mod.inline_blob_bytes;
                const copy_len: u16 = @intCast(if (n > cap_bytes) cap_bytes else n);
                if (n > 0 and ptr != null) {
                    const p: [*]const u8 = @ptrCast(ptr);
                    @memcpy(holder.blob.bytes[0..copy_len], p[0..copy_len]);
                }
                holder.blob.len = copy_len;
                holder.blob.truncated = n > cap_bytes;
                cv.* = holder;
            },
            c.SQLITE_NULL => cv.* = .null_,
            else => cv.* = .null_,
        }
    }
}

/// Execute one Query against the prepared statement table. Always invokes
/// `q.completion` exactly once before returning.
pub fn runQuery(db: *c.sqlite3, table: *StmtTable, q: *const Query) void {
    const stmt = table.get(@enumFromInt(q.stmt));
    _ = c.sqlite3_reset(stmt);
    _ = c.sqlite3_clear_bindings(stmt);

    // Bind args.
    var pos: c_int = 1;
    var i: u8 = 0;
    while (i < q.args.count) : (i += 1) {
        bindOne(stmt, pos, &q.args.items[i]) catch {
            q.completion(q.user_data, .bind_failed, &.{}, 0);
            return;
        };
        pos += 1;
    }

    switch (q.kind) {
        .exec => {
            const rc = c.sqlite3_step(stmt);
            if (rc == c.SQLITE_DONE) {
                const changes = c.sqlite3_changes64(db);
                q.completion(q.user_data, .ok, &.{}, changes);
            } else if (rc == c.SQLITE_CONSTRAINT) {
                q.completion(q.user_data, .step_failed, &.{}, 0);
            } else {
                q.completion(q.user_data, .step_failed, &.{}, 0);
            }
        },
        .query_one => {
            const rc = c.sqlite3_step(stmt);
            if (rc == c.SQLITE_ROW) {
                var single: Row = .{};
                readRow(stmt, &single);
                const rows = [_]Row{single};
                q.completion(q.user_data, .ok, &rows, 1);
            } else if (rc == c.SQLITE_DONE) {
                q.completion(q.user_data, .not_found, &.{}, 0);
            } else {
                q.completion(q.user_data, .step_failed, &.{}, 0);
            }
        },
        .query_many => {
            assert(q.rows_buf != null);
            assert(q.rows_cap > 0);
            assertLe(q.rows_cap, channel_mod.max_captured_rows);
            const buf_ptr = q.rows_buf.?;
            var n: u16 = 0;
            while (n < q.rows_cap) {
                const rc = c.sqlite3_step(stmt);
                if (rc == c.SQLITE_ROW) {
                    readRow(stmt, &buf_ptr[n]);
                    n += 1;
                } else if (rc == c.SQLITE_DONE) {
                    break;
                } else {
                    q.completion(q.user_data, .step_failed, &.{}, 0);
                    return;
                }
            }
            const slice = buf_ptr[0..n];
            q.completion(q.user_data, .ok, slice, n);
        },
    }
}

/// Writer thread context. The thread loops over the channel, draining
/// queries one at a time and invoking their completion callbacks.
pub const Writer = struct {
    db: *c.sqlite3,
    table: *StmtTable,
    channel: *Channel,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn init(db: *c.sqlite3, table: *StmtTable, channel: *Channel) Writer {
        return .{ .db = db, .table = table, .channel = channel };
    }

    pub fn start(self: *Writer) !void {
        assert(self.thread == null);
        self.thread = try std.Thread.spawn(.{}, threadMain, .{self});
    }

    fn threadMain(self: *Writer) void {
        while (!self.stop_flag.load(.acquire)) {
            if (self.channel.tryPop()) |q| {
                runQuery(self.db, self.table, &q);
            } else {
                // No work: park briefly. Tiger Style would prefer
                // condition signaling; for Phase 2 a short sleep is the
                // simplest backpressure-aware idle policy.
                sleepNs(50 * std.time.ns_per_us);
            }
        }
        // Drain any remaining queries with a `.closed` status so callers
        // don't hang on completion.
        while (self.channel.tryPop()) |q| {
            q.completion(q.user_data, .closed, &.{}, 0);
        }
    }

    pub fn stop(self: *Writer) void {
        self.channel.close();
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }
};

test "openWriter on :memory: + pragmas succeed" {
    const db = try openWriter(":memory:");
    defer closeDb(db);
}

test "runQuery exec + query_one round-trip" {
    const db = try openWriter(":memory:");
    defer closeDb(db);

    var table = StmtTable.init();
    // Setup table via direct exec (not part of the prepared table).
    var errmsg: [*c]u8 = null;
    _ = c.sqlite3_exec(db, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, score REAL) STRICT;", null, null, &errmsg);
    if (errmsg != null) c.sqlite3_free(errmsg);

    const k_ins = try table.register("ins", "INSERT INTO t(id, name, score) VALUES (?, ?, ?)");
    const k_sel = try table.register("sel", "SELECT id, name, score FROM t WHERE id = ?");
    try table.prepareAll(db);
    defer table.finalizeAll();

    const Out = struct {
        var status: QueryStatus = .ok;
        var got_rows: u16 = 0;
        var got_id: i64 = 0;
        var got_name: [16]u8 = undefined;
        var got_name_len: u16 = 0;
        fn cb(_: ?*anyopaque, st: QueryStatus, rows: []const Row, _: i64) void {
            status = st;
            got_rows = @intCast(rows.len);
            if (rows.len > 0) {
                got_id = rows[0].cols[0].int;
                const t = rows[0].cols[1].text;
                @memcpy(got_name[0..t.len], t.bytes[0..t.len]);
                got_name_len = t.len;
            }
        }
    };

    var ins_args: channel_mod.BindArgs = .{};
    ins_args.push(Value.int64(42));
    ins_args.push(Value.textInline("alice"));
    ins_args.push(Value.real_(3.14));
    runQuery(db, &table, &.{
        .kind = .exec,
        .stmt = k_ins.index(),
        .args = ins_args,
        .user_data = null,
        .completion = Out.cb,
    });
    try std.testing.expectEqual(QueryStatus.ok, Out.status);

    var sel_args: channel_mod.BindArgs = .{};
    sel_args.push(Value.int64(42));
    runQuery(db, &table, &.{
        .kind = .query_one,
        .stmt = k_sel.index(),
        .args = sel_args,
        .user_data = null,
        .completion = Out.cb,
    });
    try std.testing.expectEqual(QueryStatus.ok, Out.status);
    try std.testing.expectEqual(@as(i64, 42), Out.got_id);
    try std.testing.expectEqualStrings("alice", Out.got_name[0..Out.got_name_len]);
}

test "schema applyAll is idempotent" {
    const db = try openWriter(":memory:");
    defer closeDb(db);

    var s = schema_mod.Schema.init();
    try s.register(@import("migrations/0001_core.zig").migration);
    try s.register(.{
        .id = 2,
        .name = "test_create_users",
        .up = "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT) STRICT;",
    });

    try s.applyAll(db);

    // Re-running on a brand new Schema (since applyAll lockedself.locked).
    var s2 = schema_mod.Schema.init();
    try s2.register(@import("migrations/0001_core.zig").migration);
    try s2.register(.{
        .id = 2,
        .name = "test_create_users",
        .up = "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT) STRICT;",
    });
    try s2.applyAll(db); // should no-op.

    // The users table should still exist and accept inserts.
    var errmsg: [*c]u8 = null;
    const rc = c.sqlite3_exec(db, "INSERT INTO users(id, name) VALUES (1, 'x');", null, null, &errmsg);
    if (errmsg != null) c.sqlite3_free(errmsg);
    try std.testing.expectEqual(c.SQLITE_OK, rc);
}

test "writer thread drains queries off channel" {
    const db = try openWriter(":memory:");
    defer closeDb(db);

    var errmsg: [*c]u8 = null;
    _ = c.sqlite3_exec(db, "CREATE TABLE k (v INTEGER) STRICT;", null, null, &errmsg);
    if (errmsg != null) c.sqlite3_free(errmsg);

    var table = StmtTable.init();
    const k_ins = try table.register("ins", "INSERT INTO k(v) VALUES (?)");
    try table.prepareAll(db);
    defer table.finalizeAll();

    var ch = Channel.init();
    var w = Writer.init(db, &table, &ch);
    try w.start();
    defer w.stop();

    const Out = struct {
        var counter = std.atomic.Value(u32).init(0);
        fn cb(_: ?*anyopaque, st: QueryStatus, _: []const Row, _: i64) void {
            if (st == .ok) _ = counter.fetchAdd(1, .release);
        }
    };

    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        var args: channel_mod.BindArgs = .{};
        args.push(Value.int64(@intCast(i)));
        try ch.push(.{
            .kind = .exec,
            .stmt = k_ins.index(),
            .args = args,
            .user_data = null,
            .completion = Out.cb,
        });
    }

    // Wait for all to drain (bounded spin).
    var spin: u32 = 0;
    while (Out.counter.load(.acquire) < 32 and spin < 10_000) : (spin += 1) {
        sleepNs(100 * std.time.ns_per_us);
    }
    try std.testing.expectEqual(@as(u32, 32), Out.counter.load(.acquire));
}
