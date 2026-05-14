//! Prepared statement table.
//!
//! Each storage subsystem (core + plugins) registers SQL strings against
//! a `StmtTable`. At boot, after the connection opens, the writer thread
//! walks the table and calls `sqlite3_prepare_v3` for each entry. Every
//! slot must end up non-NULL or boot fails.
//!
//! Statement keys are typed `u32` newtypes — opaque to plugins, but
//! distinguishable from raw indices. Plugin code holds onto a `StmtKey`
//! returned by `register` and passes it back when enqueuing a Query.

const std = @import("std");
const c = @import("sqlite").c;
const limits = @import("../limits.zig");
const errors = @import("../errors.zig");
const assert_mod = @import("../assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

const StorageError = errors.StorageError;

pub const StmtKey = enum(u32) {
    invalid = std.math.maxInt(u32),
    _,

    pub fn index(self: StmtKey) u32 {
        const v = @intFromEnum(self);
        assert(v != @intFromEnum(StmtKey.invalid));
        return v;
    }
};

/// One entry in the prepared statement table. Owns the prepared handle.
pub const Entry = struct {
    /// The SQL the entry was registered with. Pointer is stable —
    /// strings live in `.rodata`.
    sql: []const u8,
    /// Prepared statement handle. NULL until `prepareAll` runs.
    stmt: ?*c.sqlite3_stmt = null,
    /// Diagnostic name. Optional, helps panics point at the right query.
    name: []const u8,
};

pub const StmtTable = struct {
    entries: [limits.max_prepared_stmts]Entry = undefined,
    count: u32 = 0,
    prepared: bool = false,

    pub fn init() StmtTable {
        return .{};
    }

    /// Register an SQL statement. May only be called *before* `prepareAll`.
    /// Returns an opaque key plugins later pass back to enqueue queries.
    pub fn register(self: *StmtTable, name: []const u8, sql: []const u8) StorageError!StmtKey {
        assert(!self.prepared);
        if (self.count >= limits.max_prepared_stmts) return error.TooManyStatements;
        const idx = self.count;
        self.entries[idx] = .{ .sql = sql, .stmt = null, .name = name };
        self.count += 1;
        assertLe(self.count, limits.max_prepared_stmts);
        return @enumFromInt(idx);
    }

    /// Prepare every registered statement against `db`. Each slot must end
    /// up non-NULL. Called once by the writer thread at boot.
    pub fn prepareAll(self: *StmtTable, db: *c.sqlite3) StorageError!void {
        assert(!self.prepared);
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            const e = &self.entries[i];
            assert(e.stmt == null);
            const rc = c.sqlite3_prepare_v3(
                db,
                e.sql.ptr,
                @intCast(e.sql.len),
                c.SQLITE_PREPARE_PERSISTENT,
                &e.stmt,
                null,
            );
            if (rc != c.SQLITE_OK or e.stmt == null) {
                std.debug.print(
                    "prepare failed for stmt #{d} '{s}': rc={d} msg={s}\n",
                    .{ i, e.name, rc, c.sqlite3_errmsg(db) },
                );
                return error.PrepareFailed;
            }
        }
        self.prepared = true;
    }

    /// Finalize all prepared statements. Called once at shutdown.
    pub fn finalizeAll(self: *StmtTable) void {
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            if (self.entries[i].stmt) |s| {
                _ = c.sqlite3_finalize(s);
                self.entries[i].stmt = null;
            }
        }
        self.prepared = false;
    }

    pub fn get(self: *StmtTable, key: StmtKey) *c.sqlite3_stmt {
        assert(self.prepared);
        const idx = key.index();
        assert(idx < self.count);
        const s = self.entries[idx].stmt orelse @panic("statement not prepared");
        return s;
    }

    pub fn nameOf(self: *const StmtTable, key: StmtKey) []const u8 {
        const idx = key.index();
        assert(idx < self.count);
        return self.entries[idx].name;
    }
};

test "StmtTable registers under capacity" {
    var t = StmtTable.init();
    const k1 = try t.register("a", "SELECT 1");
    const k2 = try t.register("b", "SELECT 2");
    try std.testing.expectEqual(@as(u32, 0), k1.index());
    try std.testing.expectEqual(@as(u32, 1), k2.index());
    try std.testing.expectEqual(@as(u32, 2), t.count);
}

test "StmtTable invalid key panics? no — index assert" {
    // Just confirm invalid sentinel != 0.
    try std.testing.expect(@intFromEnum(StmtKey.invalid) != 0);
}
