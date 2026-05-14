//! Plugin-facing storage handle.
//!
//! Plugins receive a `*Handle` via `Context.storage`. To run a query they
//! call `exec`/`queryOne`/`queryMany`, which push onto the writer
//! channel; the writer thread runs them and invokes the completion
//! callback (which fires on the writer thread).
//!
//! For read-mostly paths there is also `queryDirect`, which uses a
//! caller-supplied per-thread reader connection — WAL mode allows N
//! concurrent readers alongside the writer.

const std = @import("std");
const c = @import("sqlite").c;
const errors = @import("../errors.zig");
const assert_mod = @import("../assert.zig");
const assert = assert_mod.assert;
const channel_mod = @import("channel.zig");
const stmts_mod = @import("stmts.zig");
const sqlite_mod = @import("sqlite.zig");

const StorageError = errors.StorageError;
const StmtKey = stmts_mod.StmtKey;
const StmtTable = stmts_mod.StmtTable;
const Channel = channel_mod.Channel;
const Query = channel_mod.Query;
const Row = channel_mod.Row;
const QueryStatus = channel_mod.QueryStatus;
const Value = channel_mod.Value;
const BindArgs = channel_mod.BindArgs;
const CompletionFn = channel_mod.CompletionFn;

pub const Handle = struct {
    /// Writer-side channel. Producers push, the writer thread pops.
    channel: *Channel,
    /// Statement table — readers use it for `queryDirect` paths.
    table: *StmtTable,

    pub fn init(channel: *Channel, table: *StmtTable) Handle {
        return .{ .channel = channel, .table = table };
    }

    /// Push a write/exec onto the channel. Returns `BackpressureRejected`
    /// when the channel is full; callers MUST surface that as a 429 / retry.
    pub fn exec(
        self: *Handle,
        key: StmtKey,
        args: BindArgs,
        user_data: ?*anyopaque,
        completion: CompletionFn,
    ) StorageError!void {
        self.channel.push(.{
            .kind = .exec,
            .stmt = key.index(),
            .args = args,
            .user_data = user_data,
            .completion = completion,
        }) catch |err| switch (err) {
            error.Full => return error.BackpressureRejected,
            error.Closed => return error.BackpressureRejected,
        };
    }

    pub fn queryOne(
        self: *Handle,
        key: StmtKey,
        args: BindArgs,
        user_data: ?*anyopaque,
        completion: CompletionFn,
    ) StorageError!void {
        self.channel.push(.{
            .kind = .query_one,
            .stmt = key.index(),
            .args = args,
            .user_data = user_data,
            .completion = completion,
        }) catch return error.BackpressureRejected;
    }

    pub fn queryMany(
        self: *Handle,
        key: StmtKey,
        args: BindArgs,
        rows_buf: []Row,
        user_data: ?*anyopaque,
        completion: CompletionFn,
    ) StorageError!void {
        assert(rows_buf.len > 0);
        assert(rows_buf.len <= channel_mod.max_captured_rows);
        self.channel.push(.{
            .kind = .query_many,
            .stmt = key.index(),
            .args = args,
            .user_data = user_data,
            .completion = completion,
            .rows_buf = rows_buf.ptr,
            .rows_cap = @intCast(rows_buf.len),
        }) catch return error.BackpressureRejected;
    }

    /// Synchronously execute a read-only query against a caller-owned
    /// reader connection. Uses a one-shot prepared statement lookup
    /// against the shared `StmtTable` and runs `sqlite3_step` inline.
    ///
    /// IMPORTANT: the reader connection must have prepared the same
    /// statements, OR the caller must pass an `inline_sql` form. For
    /// simplicity Phase 2 supports inline SQL only.
    pub fn queryDirect(
        _: *Handle,
        reader_db: *c.sqlite3,
        sql: [:0]const u8,
        args: []const Value,
        row_out: *Row,
    ) StorageError!bool {
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(reader_db, sql.ptr, -1, &stmt, null);
        if (rc != c.SQLITE_OK or stmt == null) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        var pos: c_int = 1;
        for (args) |*v| {
            const brc: c_int = switch (v.*) {
                .null_ => c.sqlite3_bind_null(stmt, pos),
                .int => |x| c.sqlite3_bind_int64(stmt, pos, x),
                .real => |x| c.sqlite3_bind_double(stmt, pos, x),
                .text_inline => |*t| c.sqlite3_bind_text(stmt, pos, &t.bytes, @intCast(t.len), c.sqliteTransientAsDestructor()),
                .text_borrowed => |s| c.sqlite3_bind_text(stmt, pos, s.ptr, @intCast(s.len), c.sqliteTransientAsDestructor()),
                .blob_inline => |*b| c.sqlite3_bind_blob(stmt, pos, &b.bytes, @intCast(b.len), c.sqliteTransientAsDestructor()),
                .blob_borrowed => |s| c.sqlite3_bind_blob(stmt, pos, s.ptr, @intCast(s.len), c.sqliteTransientAsDestructor()),
            };
            if (brc != c.SQLITE_OK) return error.BindFailed;
            pos += 1;
        }

        const step_rc = c.sqlite3_step(stmt.?);
        if (step_rc == c.SQLITE_ROW) {
            // Reuse the same column-copy logic as the writer path.
            readRowInline(stmt.?, row_out);
            return true;
        } else if (step_rc == c.SQLITE_DONE) {
            return false;
        }
        return error.StepFailed;
    }
};

fn readRowInline(stmt: *c.sqlite3_stmt, row: *Row) void {
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
                var holder: channel_mod.ResultValue = .{ .text = .{} };
                const cap_b = channel_mod.inline_text_bytes;
                const copy_len: u16 = @intCast(if (n > cap_b) cap_b else n);
                if (n > 0 and ptr != null) @memcpy(holder.text.bytes[0..copy_len], ptr[0..copy_len]);
                holder.text.len = copy_len;
                holder.text.truncated = n > cap_b;
                cv.* = holder;
            },
            c.SQLITE_BLOB => {
                const ptr = c.sqlite3_column_blob(stmt, i);
                const n: usize = @intCast(c.sqlite3_column_bytes(stmt, i));
                var holder: channel_mod.ResultValue = .{ .blob = .{} };
                const cap_b = channel_mod.inline_blob_bytes;
                const copy_len: u16 = @intCast(if (n > cap_b) cap_b else n);
                if (n > 0 and ptr != null) {
                    const p: [*]const u8 = @ptrCast(ptr);
                    @memcpy(holder.blob.bytes[0..copy_len], p[0..copy_len]);
                }
                holder.blob.len = copy_len;
                holder.blob.truncated = n > cap_b;
                cv.* = holder;
            },
            else => cv.* = .null_,
        }
    }
}

test "Handle exec round-trips through writer thread" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);

    var errmsg: [*c]u8 = null;
    _ = c.sqlite3_exec(db, "CREATE TABLE h (k INTEGER PRIMARY KEY, v TEXT) STRICT;", null, null, &errmsg);
    if (errmsg != null) c.sqlite3_free(errmsg);

    var table = StmtTable.init();
    const k_ins = try table.register("ins", "INSERT INTO h(k, v) VALUES (?, ?)");
    const k_sel = try table.register("sel", "SELECT k, v FROM h WHERE k = ?");
    try table.prepareAll(db);
    defer table.finalizeAll();

    var ch = Channel.init();
    var writer = sqlite_mod.Writer.init(db, &table, &ch);
    try writer.start();
    defer writer.stop();

    var h = Handle.init(&ch, &table);

    const Out = struct {
        var done = std.atomic.Value(u32).init(0);
        var got_status: QueryStatus = .ok;
        var got_v: [16]u8 = undefined;
        var got_v_len: u16 = 0;

        fn execCb(_: ?*anyopaque, st: QueryStatus, _: []const Row, _: i64) void {
            got_status = st;
            _ = done.fetchAdd(1, .release);
        }
        fn selCb(_: ?*anyopaque, st: QueryStatus, rows: []const Row, _: i64) void {
            got_status = st;
            if (rows.len > 0) {
                const t = rows[0].cols[1].text;
                @memcpy(got_v[0..t.len], t.bytes[0..t.len]);
                got_v_len = t.len;
            }
            _ = done.fetchAdd(1, .release);
        }
    };

    var args: BindArgs = .{};
    args.push(Value.int64(7));
    args.push(Value.textInline("hi"));
    try h.exec(k_ins, args, null, Out.execCb);

    // Wait for completion.
    var spin: u32 = 0;
    while (Out.done.load(.acquire) < 1 and spin < 10_000) : (spin += 1) {
        sqlite_mod.sleepNs(50 * std.time.ns_per_us);
    }
    try std.testing.expectEqual(QueryStatus.ok, Out.got_status);

    var sel_args: BindArgs = .{};
    sel_args.push(Value.int64(7));
    try h.queryOne(k_sel, sel_args, null, Out.selCb);
    spin = 0;
    while (Out.done.load(.acquire) < 2 and spin < 10_000) : (spin += 1) {
        sqlite_mod.sleepNs(50 * std.time.ns_per_us);
    }
    try std.testing.expectEqual(QueryStatus.ok, Out.got_status);
    try std.testing.expectEqualStrings("hi", Out.got_v[0..Out.got_v_len]);
}
