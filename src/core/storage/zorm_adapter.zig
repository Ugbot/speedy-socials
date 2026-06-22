//! Zero-cost bridge from this app's `core.storage.Backend` to the
//! standalone `zorm` library's storage contract.
//!
//! `zorm` is dependency-free and declares its OWN `Backend`/`BindValue`/
//! `Row`/`ColumnValue` types (it can't import `core`). Those types are
//! defined to be *layout-identical* to the ones here, so the bridge is a
//! pointer recast — not a field-by-field copy. The comptime asserts below
//! fail the build if either side's layout drifts.
//!
//! Usage: hold an `Adapter` (which carries the source backend at a stable
//! address) and call `.backend(dialect)` to get a `zorm.Backend`. The
//! forwarders recover the source from the adapter pointer — so multiple
//! adapters (e.g. per-tenant) coexist correctly.

const std = @import("std");
const storage = @import("backend.zig");
const zorm = @import("zorm");

comptime {
    // Layout parity — the recast in the forwarders is only sound if these
    // match exactly. If a field is added/reordered on either side this
    // breaks the build loudly (the intended tripwire).
    std.debug.assert(@sizeOf(storage.BindValue) == @sizeOf(zorm.BindValue));
    std.debug.assert(@sizeOf(storage.ColumnValue) == @sizeOf(zorm.ColumnValue));
    std.debug.assert(@sizeOf(storage.Row) == @sizeOf(zorm.Row));
    std.debug.assert(@offsetOf(storage.ColumnValue, "bytes_len") == @offsetOf(zorm.ColumnValue, "bytes_len"));
    std.debug.assert(@offsetOf(storage.ColumnValue, "int_val") == @offsetOf(zorm.ColumnValue, "int_val"));
    std.debug.assert(@offsetOf(storage.ColumnValue, "real_val") == @offsetOf(zorm.ColumnValue, "real_val"));
    std.debug.assert(@offsetOf(storage.Row, "column_count") == @offsetOf(zorm.Row, "column_count"));
    std.debug.assert(storage.max_columns == zorm.max_columns);
    std.debug.assert(storage.max_inline_bytes == zorm.max_inline_bytes);
}

/// Carries the source backend at a stable address so the zorm-side
/// forwarders can recover it from the `*anyopaque` ptr. Hold one of these
/// for the lifetime of the `zorm.Backend` it produces.
pub const Adapter = struct {
    src: storage.Backend,

    pub fn init(b: storage.Backend) Adapter {
        return .{ .src = b };
    }

    pub fn backend(self: *Adapter, dialect: zorm.Dialect) zorm.Backend {
        return .{ .ptr = self, .vtable = &vtable, .dialect = dialect };
    }
};

fn recastArgs(args: []const zorm.BindValue) []const storage.BindValue {
    return @as([*]const storage.BindValue, @ptrCast(args.ptr))[0..args.len];
}

fn mapErr(e: storage.Error) zorm.Error {
    return switch (e) {
        error.NotFound => zorm.Error.NotFound,
        error.AlreadyExists => zorm.Error.AlreadyExists,
        error.BadStatement => zorm.Error.BadStatement,
        error.BadBinding => zorm.Error.BadBinding,
        error.StepFailed => zorm.Error.StepFailed,
        error.BackendFailed => zorm.Error.BackendFailed,
        error.BufferTooSmall => zorm.Error.BufferTooSmall,
        error.UniqueViolation => zorm.Error.UniqueViolation,
        error.ForeignKeyViolation => zorm.Error.ForeignKeyViolation,
        error.NotNullViolation => zorm.Error.NotNullViolation,
    };
}

fn doExec(ptr: *anyopaque, sql: []const u8, args: []const zorm.BindValue) zorm.Error!void {
    const self: *Adapter = @ptrCast(@alignCast(ptr));
    self.src.exec(sql, recastArgs(args)) catch |e| return mapErr(e);
}

fn doQueryOne(ptr: *anyopaque, sql: []const u8, args: []const zorm.BindValue, out: *zorm.Row) zorm.Error!bool {
    const self: *Adapter = @ptrCast(@alignCast(ptr));
    const storage_out: *storage.Row = @ptrCast(out);
    return self.src.queryOne(sql, recastArgs(args), storage_out) catch |e| return mapErr(e);
}

// query() must route the zorm callback (which takes *const zorm.Row)
// through the source (which calls with *const storage.Row). The callback +
// ctx are stashed thread-local for the duration of the synchronous call.
threadlocal var query_cb: zorm.RowCallback = undefined;
threadlocal var query_ctx: *anyopaque = undefined;

fn trampoline(_: *anyopaque, row: *const storage.Row) bool {
    const zrow: *const zorm.Row = @ptrCast(row);
    return query_cb(query_ctx, zrow);
}

fn doQuery(ptr: *anyopaque, sql: []const u8, args: []const zorm.BindValue, ctx: *anyopaque, cb: zorm.RowCallback) zorm.Error!void {
    const self: *Adapter = @ptrCast(@alignCast(ptr));
    query_cb = cb;
    query_ctx = ctx;
    self.src.query(sql, recastArgs(args), undefined, trampoline) catch |e| return mapErr(e);
}

fn doLastInsertId(ptr: *anyopaque) i64 {
    const self: *Adapter = @ptrCast(@alignCast(ptr));
    return self.src.lastInsertId();
}

fn doChanges(ptr: *anyopaque) i64 {
    const self: *Adapter = @ptrCast(@alignCast(ptr));
    return self.src.changes();
}

// Transaction: the zorm body returns zorm.Error; the source wants
// storage.Error. We capture the original zorm error so a rollback reports
// the body's real failure rather than a generic one.
threadlocal var tx_body: *const fn (ctx: *anyopaque) zorm.Error!void = undefined;
threadlocal var tx_ctx: *anyopaque = undefined;
threadlocal var tx_err: ?zorm.Error = null;

fn txTrampoline(_: *anyopaque) storage.Error!void {
    tx_body(tx_ctx) catch |e| {
        tx_err = e;
        return error.BackendFailed; // signal the source to ROLLBACK
    };
}

fn doTransaction(ptr: *anyopaque, ctx: *anyopaque, body: *const fn (ctx: *anyopaque) zorm.Error!void) zorm.Error!void {
    const self: *Adapter = @ptrCast(@alignCast(ptr));
    tx_body = body;
    tx_ctx = ctx;
    tx_err = null;
    self.src.transaction(undefined, txTrampoline) catch |e| {
        if (tx_err) |ze| return ze; // prefer the body's original error
        return mapErr(e);
    };
}

const vtable: zorm.Backend.VTable = .{
    .exec = doExec,
    .query = doQuery,
    .queryOne = doQueryOne,
    .lastInsertId = doLastInsertId,
    .changes = doChanges,
    .transaction = doTransaction,
};

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const sqlite = @import("sqlite.zig");
const SqliteBackend = storage.SqliteBackend;
const c = @import("sqlite").c;

test "zorm_adapter: round-trips exec + queryOne through a real SqliteBackend" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(db, "CREATE TABLE t (a INTEGER, b TEXT)", null, null, &em);
    if (em != null) c.sqlite3_free(em);

    var be = SqliteBackend.init(db);
    var adapter = Adapter.init(be.backend());
    const zb = adapter.backend(.sqlite);

    try zb.exec("INSERT INTO t (a, b) VALUES (?, ?)", &.{ .{ .int = 7 }, .{ .text = "hi" } });
    var row: zorm.Row = .{};
    const found = try zb.queryOne("SELECT a, b FROM t WHERE a = ?", &.{.{ .int = 7 }}, &row);
    try testing.expect(found);
    try testing.expectEqual(@as(i64, 7), row.columns[0].int_val);
    try testing.expectEqualStrings("hi", row.columns[1].bytes());
}

test "zorm_adapter: maps engine constraint violations to typed zorm errors" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(db, "PRAGMA foreign_keys=ON", null, null, &em);
    if (em != null) c.sqlite3_free(em);
    _ = c.sqlite3_exec(db, "CREATE TABLE parent (id INTEGER PRIMARY KEY)", null, null, &em);
    if (em != null) c.sqlite3_free(em);
    _ = c.sqlite3_exec(db, "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id), label TEXT NOT NULL)", null, null, &em);
    if (em != null) c.sqlite3_free(em);

    var be = SqliteBackend.init(db);
    var adapter = Adapter.init(be.backend());
    const zb = adapter.backend(.sqlite);

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const rand = prng.random();
    const pid: i64 = rand.intRangeAtMost(i64, 1, 1_000_000);

    try zb.exec("INSERT INTO parent (id) VALUES (?)", &.{.{ .int = pid }});

    // UNIQUE / PRIMARY KEY → zorm.Error.UniqueViolation
    try testing.expectError(
        zorm.Error.UniqueViolation,
        zb.exec("INSERT INTO parent (id) VALUES (?)", &.{.{ .int = pid }}),
    );
    // FOREIGN KEY → zorm.Error.ForeignKeyViolation (missing parent)
    try testing.expectError(
        zorm.Error.ForeignKeyViolation,
        zb.exec("INSERT INTO child (id, parent_id, label) VALUES (?, ?, ?)", &.{ .{ .int = 1 }, .{ .int = pid + 1 }, .{ .text = "x" } }),
    );
    // NOT NULL → zorm.Error.NotNullViolation
    try testing.expectError(
        zorm.Error.NotNullViolation,
        zb.exec("INSERT INTO child (id, parent_id, label) VALUES (?, ?, ?)", &.{ .{ .int = 2 }, .{ .int = pid }, .null_ }),
    );
}

test "zorm_adapter: query streams rows + transaction rolls back on error" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(db, "CREATE TABLE t (a INTEGER)", null, null, &em);
    if (em != null) c.sqlite3_free(em);
    var be = SqliteBackend.init(db);
    var adapter = Adapter.init(be.backend());
    const zb = adapter.backend(.sqlite);

    var i: i64 = 0;
    while (i < 4) : (i += 1) try zb.exec("INSERT INTO t (a) VALUES (?)", &.{.{ .int = i }});

    const Counter = struct {
        var seen: u32 = 0;
        fn cb(_: *anyopaque, _: *const zorm.Row) bool {
            seen += 1;
            return true;
        }
    };
    Counter.seen = 0;
    var dummy: u8 = 0;
    try zb.query("SELECT a FROM t", &.{}, &dummy, Counter.cb);
    try testing.expectEqual(@as(u32, 4), Counter.seen);

    const Tx = struct {
        var zbe: zorm.Backend = undefined;
        fn body(_: *anyopaque) zorm.Error!void {
            try zbe.exec("INSERT INTO t (a) VALUES (99)", &.{});
            return zorm.Error.StepFailed; // force rollback
        }
    };
    Tx.zbe = zb;
    try testing.expectError(zorm.Error.StepFailed, zb.transaction(&dummy, Tx.body));

    var cnt: zorm.Row = .{};
    _ = try zb.queryOne("SELECT COUNT(*) FROM t", &.{}, &cnt);
    try testing.expectEqual(@as(i64, 4), cnt.columns[0].int_val); // 99 rolled back
}
