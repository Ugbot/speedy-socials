//! zorm storage contract — the database interface zorm maps types onto.
//!
//! zorm is a standalone, dependency-free library (a "Hibernate for Zig").
//! It must NOT import the host application, so it declares its OWN storage
//! contract here. A host (e.g. speedy-socials) provides a zero-cost adapter
//! from its concrete backend to this contract.
//!
//! IMPORTANT — layout parity: `BindValue`, `ColumnValue`, and `Row` are
//! defined to be *layout-identical* to the host's `core.storage.backend`
//! types so the adapter is a pointer recast, not a field-by-field copy.
//! The adapter asserts `@sizeOf`/`@offsetOf` parity at comptime; if either
//! side drifts, the build fails loudly. Keep these in sync.

const std = @import("std");

pub const Error = error{
    NotFound,
    AlreadyExists,
    BadStatement,
    BadBinding,
    StepFailed,
    BackendFailed,
    BufferTooSmall,
};

/// Which SQL dialect the active backend speaks. zorm generates
/// placeholders + DDL + autoincrement syntax per dialect — it never ships
/// one SQL string to both engines.
pub const Dialect = enum {
    sqlite,
    postgres,
    mysql,

    /// Positional parameter placeholder for the n-th (1-based) bind.
    /// SQLite and MySQL use `?`; Postgres uses `$N`.
    pub fn placeholder(self: Dialect, comptime n: usize) []const u8 {
        return switch (self) {
            .sqlite, .mysql => "?",
            .postgres => std.fmt.comptimePrint("${d}", .{n}),
        };
    }
};

/// One bind argument (layout-identical to the host's BindValue).
pub const BindValue = union(enum) {
    null_,
    int: i64,
    real: f64,
    text: []const u8,
    blob: []const u8,
};

/// Maximum inline text/blob bytes carried in a `ColumnValue` (must equal
/// the host's `max_inline_bytes`).
pub const max_inline_bytes: usize = 1024;

/// One result column (layout-identical to the host's ColumnValue).
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

/// Maximum columns in a single fetched `Row` (must equal the host's
/// `max_columns`). zorm asserts entity column-count ≤ this at comptime.
pub const max_columns: usize = 16;

pub const Row = struct {
    columns: [max_columns]ColumnValue = undefined,
    column_count: u8 = 0,
};

pub const RowCallback = *const fn (ctx: *anyopaque, row: *const Row) bool;

/// The runtime storage backend zorm emits SQL + bindings against. A host
/// supplies one via its adapter; zorm carries the `dialect` so generated
/// SQL matches the engine.
pub const Backend = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    dialect: Dialect,

    pub const VTable = struct {
        exec: *const fn (ptr: *anyopaque, sql: []const u8, args: []const BindValue) Error!void,
        query: *const fn (ptr: *anyopaque, sql: []const u8, args: []const BindValue, ctx: *anyopaque, cb: RowCallback) Error!void,
        queryOne: *const fn (ptr: *anyopaque, sql: []const u8, args: []const BindValue, out: *Row) Error!bool,
        lastInsertId: *const fn (ptr: *anyopaque) i64,
        changes: *const fn (ptr: *anyopaque) i64,
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

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "Dialect.placeholder differs per engine" {
    try testing.expectEqualStrings("?", Dialect.sqlite.placeholder(1));
    try testing.expectEqualStrings("$1", Dialect.postgres.placeholder(1));
    try testing.expectEqualStrings("$7", Dialect.postgres.placeholder(7));
}

test "contract limits match the documented host invariants" {
    try testing.expectEqual(@as(usize, 16), max_columns);
    try testing.expectEqual(@as(usize, 1024), max_inline_bytes);
}
