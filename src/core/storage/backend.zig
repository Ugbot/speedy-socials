//! INFRA-1: Storage backend vtable.
//!
//! The existing storage layer talks directly to `sqlite3_*`. This
//! module wraps that surface in a thin vtable so the codebase can
//! eventually swap in Postgres / FoundationDB / a remote service
//! without touching every plugin.
//!
//! Today the SQLite implementation forwards every method to the
//! existing `*c.sqlite3` calls. Future backends drop in by
//! implementing the same vtable shape.
//!
//! The interface is **deliberately small**: just enough for the
//! account / admin / label / report / firehose paths. Plugins that
//! need raw SQL (CAR streaming, full-text search, etc.) still keep
//! a direct `*c.sqlite3` handle.

const std = @import("std");
const c = @import("sqlite").c;
const build_options = @import("build_options");

/// Whether the Postgres backend was compiled in (`-Dpostgres`).
pub const postgres_enabled = build_options.postgres;

/// The libpq-backed Postgres backend, present only under `-Dpostgres`.
/// The import is comptime-gated so the default build never analyses its
/// cImport (which needs libpq headers).
pub const PostgresBackend = if (build_options.postgres)
    @import("postgres_backend.zig").PostgresBackend
else
    struct {};

pub const Error = error{
    NotFound,
    AlreadyExists,
    BadStatement,
    BadBinding,
    StepFailed,
    BackendFailed,
    BufferTooSmall,
};

/// One bind argument. Mirrors the high-level value union from
/// `channel.zig` but kept self-contained so backends without
/// SQLite can implement the interface cleanly.
pub const BindValue = union(enum) {
    null_,
    int: i64,
    real: f64,
    text: []const u8,
    blob: []const u8,
};

/// Maximum inline text/blob bytes carried in a `ColumnValue`. Larger
/// values are truncated; callers needing the full payload should use
/// `query` with a streaming callback (which can copy out before the
/// statement is finalized).
pub const max_inline_bytes: usize = 1024;

/// One result column. Text/blob payloads are copied into the inline
/// `bytes_buf` so the slice survives statement finalization.
pub const ColumnValue = struct {
    kind: enum { null_, int, real, text, blob } = .null_,
    bytes_buf: [max_inline_bytes]u8 = undefined,
    bytes_len: u16 = 0,
    int_val: i64 = 0,
    real_val: f64 = 0,

    pub fn bytes(self: *const ColumnValue) []const u8 {
        return self.bytes_buf[0..self.bytes_len];
    }
};

pub const max_columns: usize = 16;

pub const Row = struct {
    columns: [max_columns]ColumnValue = undefined,
    column_count: u8 = 0,
};

/// Result of a streaming query callback. Returns `true` to keep
/// iterating, `false` to stop early.
pub const RowCallback = *const fn (ctx: *anyopaque, row: *const Row) bool;

pub const Backend = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Execute a statement that doesn't return rows (INSERT,
        /// UPDATE, DELETE, CREATE TABLE, ...).
        exec: *const fn (ptr: *anyopaque, sql: []const u8, args: []const BindValue) Error!void,
        /// Execute a statement and stream rows via the callback.
        query: *const fn (ptr: *anyopaque, sql: []const u8, args: []const BindValue, ctx: *anyopaque, cb: RowCallback) Error!void,
        /// Fetch a single row. Sets `out.column_count = 0` if none.
        queryOne: *const fn (ptr: *anyopaque, sql: []const u8, args: []const BindValue, out: *Row) Error!bool,
        /// Rowid of the last INSERT.
        lastInsertId: *const fn (ptr: *anyopaque) i64,
        /// Affected rows for the last write.
        changes: *const fn (ptr: *anyopaque) i64,
        /// Wrap a closure in a transaction (BEGIN/COMMIT/ROLLBACK on error).
        transaction: *const fn (ptr: *anyopaque, ctx: *anyopaque, body: *const fn (ctx: *anyopaque) Error!void) Error!void,
    };

    pub fn exec(self: Backend, sql: []const u8, args: []const BindValue) Error!void {
        return self.vtable.exec(self.ptr, sql, args);
    }
    pub fn query(self: Backend, sql: []const u8, args: []const BindValue, ctx: *anyopaque, cb: RowCallback) Error!void {
        return self.vtable.query(self.ptr, sql, args, ctx, cb);
    }
    pub fn queryOne(self: Backend, sql: []const u8, args: []const BindValue, out: *Row) Error!bool {
        return self.vtable.queryOne(self.ptr, sql, args, out);
    }
    pub fn lastInsertId(self: Backend) i64 {
        return self.vtable.lastInsertId(self.ptr);
    }
    pub fn changes(self: Backend) i64 {
        return self.vtable.changes(self.ptr);
    }
    pub fn transaction(self: Backend, ctx: *anyopaque, body: *const fn (ctx: *anyopaque) Error!void) Error!void {
        return self.vtable.transaction(self.ptr, ctx, body);
    }
};

// ──────────────────────────────────────────────────────────────────────
// Global backend selection.
// ──────────────────────────────────────────────────────────────────────

var global_backend: ?Backend = null;

/// Install the process-wide storage backend (SQLite by default, Postgres
/// under `-Dpostgres` + `STORAGE_BACKEND=postgres`). Code that has been
/// migrated off raw `*c.sqlite3` reaches storage through `global()`.
pub fn setGlobal(b: ?Backend) void {
    global_backend = b;
}

pub fn global() ?Backend {
    return global_backend;
}

// ──────────────────────────────────────────────────────────────────────
// SqliteBackend — default impl wrapping a `*c.sqlite3`.
// ──────────────────────────────────────────────────────────────────────

pub const SqliteBackend = struct {
    db: *c.sqlite3,

    pub fn init(db: *c.sqlite3) SqliteBackend {
        return .{ .db = db };
    }

    fn prepareAndBind(self: *SqliteBackend, sql: []const u8, args: []const BindValue, stmt: *?*c.sqlite3_stmt) Error!void {
        const rc = c.sqlite3_prepare_v2(self.db, sql.ptr, @intCast(sql.len), stmt, null);
        if (rc != c.SQLITE_OK) return error.BadStatement;
        for (args, 0..) |a, i| {
            const idx: c_int = @intCast(i + 1);
            const ok: c_int = switch (a) {
                .null_ => c.sqlite3_bind_null(stmt.*, idx),
                .int => |v| c.sqlite3_bind_int64(stmt.*, idx, v),
                .real => |v| c.sqlite3_bind_double(stmt.*, idx, v),
                .text => |s| c.sqlite3_bind_text(stmt.*, idx, s.ptr, @intCast(s.len), c.sqliteTransientAsDestructor()),
                .blob => |s| c.sqlite3_bind_blob(stmt.*, idx, s.ptr, @intCast(s.len), c.sqliteTransientAsDestructor()),
            };
            if (ok != c.SQLITE_OK) return error.BadBinding;
        }
    }

    fn readRow(stmt: *c.sqlite3_stmt, out: *Row) void {
        const n = c.sqlite3_column_count(stmt);
        const count: u8 = @intCast(@min(n, @as(c_int, max_columns)));
        out.column_count = count;
        var i: c_int = 0;
        while (i < count) : (i += 1) {
            const t = c.sqlite3_column_type(stmt, i);
            var col: ColumnValue = .{};
            switch (t) {
                c.SQLITE_INTEGER => {
                    col.kind = .int;
                    col.int_val = c.sqlite3_column_int64(stmt, i);
                },
                c.SQLITE_FLOAT => {
                    col.kind = .real;
                    col.real_val = c.sqlite3_column_double(stmt, i);
                },
                c.SQLITE_TEXT => {
                    col.kind = .text;
                    const p = c.sqlite3_column_text(stmt, i);
                    const len: usize = @intCast(c.sqlite3_column_bytes(stmt, i));
                    const cap = @min(len, max_inline_bytes);
                    if (cap > 0) @memcpy(col.bytes_buf[0..cap], p[0..cap]);
                    col.bytes_len = @intCast(cap);
                },
                c.SQLITE_BLOB => {
                    col.kind = .blob;
                    const p: [*]const u8 = @ptrCast(c.sqlite3_column_blob(stmt, i));
                    const len: usize = @intCast(c.sqlite3_column_bytes(stmt, i));
                    const cap = @min(len, max_inline_bytes);
                    if (cap > 0) @memcpy(col.bytes_buf[0..cap], p[0..cap]);
                    col.bytes_len = @intCast(cap);
                },
                else => col.kind = .null_,
            }
            out.columns[@intCast(i)] = col;
        }
    }

    fn doExec(ptr: *anyopaque, sql: []const u8, args: []const BindValue) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        var stmt: ?*c.sqlite3_stmt = null;
        try self.prepareAndBind(sql, args, &stmt);
        defer _ = c.sqlite3_finalize(stmt);
        const rc = c.sqlite3_step(stmt.?);
        if (rc != c.SQLITE_DONE) return error.StepFailed;
    }

    fn doQuery(ptr: *anyopaque, sql: []const u8, args: []const BindValue, ctx: *anyopaque, cb: RowCallback) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        var stmt: ?*c.sqlite3_stmt = null;
        try self.prepareAndBind(sql, args, &stmt);
        defer _ = c.sqlite3_finalize(stmt);
        while (true) {
            const rc = c.sqlite3_step(stmt.?);
            if (rc == c.SQLITE_DONE) return;
            if (rc != c.SQLITE_ROW) return error.StepFailed;
            var row: Row = .{};
            readRow(stmt.?, &row);
            if (!cb(ctx, &row)) return;
        }
    }

    fn doQueryOne(ptr: *anyopaque, sql: []const u8, args: []const BindValue, out: *Row) Error!bool {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        var stmt: ?*c.sqlite3_stmt = null;
        try self.prepareAndBind(sql, args, &stmt);
        defer _ = c.sqlite3_finalize(stmt);
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) {
            out.column_count = 0;
            return false;
        }
        if (rc != c.SQLITE_ROW) return error.StepFailed;
        readRow(stmt.?, out);
        return true;
    }

    fn doLastInsertId(ptr: *anyopaque) i64 {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        return c.sqlite3_last_insert_rowid(self.db);
    }

    fn doChanges(ptr: *anyopaque) i64 {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        return c.sqlite3_changes64(self.db);
    }

    fn doTransaction(ptr: *anyopaque, ctx: *anyopaque, body: *const fn (ctx: *anyopaque) Error!void) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        var em: [*c]u8 = null;
        if (c.sqlite3_exec(self.db, "BEGIN", null, null, &em) != c.SQLITE_OK) {
            if (em != null) c.sqlite3_free(em);
            return error.BackendFailed;
        }
        body(ctx) catch |err| {
            _ = c.sqlite3_exec(self.db, "ROLLBACK", null, null, &em);
            if (em != null) c.sqlite3_free(em);
            return err;
        };
        if (c.sqlite3_exec(self.db, "COMMIT", null, null, &em) != c.SQLITE_OK) {
            if (em != null) c.sqlite3_free(em);
            return error.BackendFailed;
        }
    }

    pub fn backend(self: *SqliteBackend) Backend {
        return .{
            .ptr = self,
            .vtable = &.{
                .exec = doExec,
                .query = doQuery,
                .queryOne = doQueryOne,
                .lastInsertId = doLastInsertId,
                .changes = doChanges,
                .transaction = doTransaction,
            },
        };
    }
};

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;
const sqlite = @import("sqlite.zig");

test "INFRA-1: SqliteBackend exec + queryOne round-trip" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(db, "CREATE TABLE t (a INTEGER, b TEXT)", null, null, &em);
    if (em != null) c.sqlite3_free(em);

    var be = SqliteBackend.init(db);
    const b = be.backend();
    try b.exec("INSERT INTO t (a, b) VALUES (?, ?)", &.{ .{ .int = 42 }, .{ .text = "hello" } });
    var row: Row = .{};
    const found = try b.queryOne("SELECT a, b FROM t WHERE a = ?", &.{.{ .int = 42 }}, &row);
    try testing.expect(found);
    try testing.expectEqual(@as(i64, 42), row.columns[0].int_val);
    try testing.expectEqualStrings("hello", row.columns[1].bytes());
}

test "INFRA-1: SqliteBackend transaction rolls back on error" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(db, "CREATE TABLE t (a INTEGER)", null, null, &em);
    if (em != null) c.sqlite3_free(em);

    var be = SqliteBackend.init(db);
    const b = be.backend();
    const Ctx = struct {
        var backend_ptr: Backend = undefined;
        fn body(_: *anyopaque) Error!void {
            try backend_ptr.exec("INSERT INTO t (a) VALUES (1)", &.{});
            return error.BackendFailed;
        }
    };
    Ctx.backend_ptr = b;
    var dummy: u8 = 0;
    try testing.expectError(error.BackendFailed, b.transaction(&dummy, Ctx.body));

    var row: Row = .{};
    const found = try b.queryOne("SELECT COUNT(*) FROM t", &.{}, &row);
    try testing.expect(found);
    try testing.expectEqual(@as(i64, 0), row.columns[0].int_val);
}

test {
    // Pull the Postgres backend's tests in only when it is compiled.
    if (build_options.postgres) _ = @import("postgres_backend.zig");
}

test "Phase G: a non-SQLite backend satisfies the same vtable + global routing" {
    // MockBackend records calls without any SQL engine, proving the
    // Backend interface is engine-agnostic — the same seam a Postgres /
    // remote backend plugs into.
    const Mock = struct {
        exec_calls: u32 = 0,
        last_sql_buf: [128]u8 = undefined,
        last_sql_len: usize = 0,
        last_int_arg: i64 = 0,
        next_row_int: i64 = 0,

        fn doExec(ptr: *anyopaque, sql: []const u8, args: []const BindValue) Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.exec_calls += 1;
            const n = @min(sql.len, self.last_sql_buf.len);
            @memcpy(self.last_sql_buf[0..n], sql[0..n]);
            self.last_sql_len = n;
            for (args) |a| switch (a) {
                .int => |v| self.last_int_arg = v,
                else => {},
            };
        }
        fn doQuery(_: *anyopaque, _: []const u8, _: []const BindValue, _: *anyopaque, _: RowCallback) Error!void {}
        fn doQueryOne(ptr: *anyopaque, _: []const u8, _: []const BindValue, out: *Row) Error!bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            out.column_count = 1;
            out.columns[0] = .{ .kind = .int, .int_val = self.next_row_int };
            return true;
        }
        fn doLastId(_: *anyopaque) i64 {
            return 99;
        }
        fn doChanges(_: *anyopaque) i64 {
            return 1;
        }
        fn doTx(ptr: *anyopaque, ctx: *anyopaque, body: *const fn (ctx: *anyopaque) Error!void) Error!void {
            _ = ptr;
            return body(ctx);
        }
        fn backend(self: *@This()) Backend {
            return .{ .ptr = self, .vtable = &.{
                .exec = doExec,
                .query = doQuery,
                .queryOne = doQueryOne,
                .lastInsertId = doLastId,
                .changes = doChanges,
                .transaction = doTx,
            } };
        }
    };

    var mock: Mock = .{ .next_row_int = 7 };
    const b = mock.backend();

    // Route via the global seam, exactly as migrated code would.
    setGlobal(b);
    defer setGlobal(null);
    const g = global() orelse return error.TestUnexpectedResult;

    try g.exec("INSERT INTO t (a) VALUES (?)", &.{.{ .int = 1234 }});
    try testing.expectEqual(@as(u32, 1), mock.exec_calls);
    try testing.expectEqual(@as(i64, 1234), mock.last_int_arg);
    try testing.expectEqual(@as(i64, 99), g.lastInsertId());

    var row: Row = .{};
    try testing.expect(try g.queryOne("SELECT a FROM t", &.{}, &row));
    try testing.expectEqual(@as(i64, 7), row.columns[0].int_val);
}

test "INFRA-1: SqliteBackend query streams rows" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(db, "CREATE TABLE t (a INTEGER)", null, null, &em);
    if (em != null) c.sqlite3_free(em);

    var be = SqliteBackend.init(db);
    const b = be.backend();
    var i: i64 = 0;
    while (i < 5) : (i += 1) {
        try b.exec("INSERT INTO t (a) VALUES (?)", &.{.{ .int = i }});
    }

    const Counter = struct {
        var seen: u32 = 0;
        fn cb(_: *anyopaque, row: *const Row) bool {
            _ = row;
            seen += 1;
            return true;
        }
    };
    Counter.seen = 0;
    var dummy: u8 = 0;
    try b.query("SELECT a FROM t", &.{}, &dummy, Counter.cb);
    try testing.expectEqual(@as(u32, 5), Counter.seen);
}
