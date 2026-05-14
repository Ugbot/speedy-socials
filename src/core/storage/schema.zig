//! Schema migrations.
//!
//! Each plugin pushes `Migration` records via `register_schema`. The
//! writer thread runs them in numeric `id` order at boot, recording each
//! applied id in the `migrations` bookkeeping table.
//!
//! Migrations are append-only: lowering an id after it's been deployed is
//! a hard error. Down-DDL is recorded so a dev can rewind, but the runtime
//! never applies it automatically.

const std = @import("std");
const c = @import("sqlite").c;
const errors = @import("../errors.zig");
const assert_mod = @import("../assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

const StorageError = errors.StorageError;

/// Hard ceiling on the total number of migrations across all plugins.
/// Bumping this is a recompile.
pub const max_migrations: u32 = 256;

pub const Migration = struct {
    /// Globally unique, strictly increasing id. Convention: plugins
    /// namespace ids with a four-digit prefix (core=0xxx, ap=1xxx, atp=2xxx,
    /// relay=3xxx). Asserted unique at registration.
    id: u32,
    /// Human-readable label, used in panic / log messages.
    name: []const u8,
    /// SQL DDL to apply. Multiple statements separated by `;` are allowed.
    up: []const u8,
    /// Optional inverse. Never applied by the runtime — recorded for ops.
    down: ?[]const u8 = null,
};

pub const Schema = struct {
    migrations: [max_migrations]Migration = undefined,
    count: u32 = 0,
    locked: bool = false,

    pub fn init() Schema {
        return .{};
    }

    pub fn register(self: *Schema, m: Migration) StorageError!void {
        assert(!self.locked);
        if (self.count >= max_migrations) return error.TooManyStatements;
        // Reject duplicate ids.
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            assert(self.migrations[i].id != m.id);
        }
        self.migrations[self.count] = m;
        self.count += 1;
        assertLe(self.count, max_migrations);
    }

    /// Sort migrations in-place by id (ascending). Simple insertion sort —
    /// `count` is small (≤ max_migrations) so this is fine.
    pub fn sort(self: *Schema) void {
        var i: u32 = 1;
        while (i < self.count) : (i += 1) {
            var j: u32 = i;
            while (j > 0 and self.migrations[j - 1].id > self.migrations[j].id) : (j -= 1) {
                const tmp = self.migrations[j - 1];
                self.migrations[j - 1] = self.migrations[j];
                self.migrations[j] = tmp;
            }
        }
    }

    /// Apply every migration whose id is not yet recorded in the
    /// bookkeeping table. Idempotent: re-running on a fully migrated DB
    /// is a no-op.
    pub fn applyAll(self: *Schema, db: *c.sqlite3) StorageError!void {
        self.sort();

        // Bootstrap: make sure the bookkeeping table exists. The first
        // registered migration is responsible for creating it; here we
        // also accept that it might not exist yet and `CREATE TABLE IF
        // NOT EXISTS` inside that migration handles it.
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            const m = self.migrations[i];

            // Is it already applied? Skip when migrations table has the id.
            if (try isApplied(db, m.id)) continue;

            // Wrap each migration in a transaction so partial DDL doesn't
            // leave the DB inconsistent.
            try execSimple(db, "BEGIN IMMEDIATE");
            errdefer execSimple(db, "ROLLBACK") catch {};

            try execSql(db, m.up);

            // Record the application. The first migration must create the
            // migrations table — only after that does this insert succeed.
            try recordApplied(db, m.id, m.name);

            try execSimple(db, "COMMIT");
        }

        self.locked = true;
    }
};

fn execSimple(db: *c.sqlite3, sql: []const u8) StorageError!void {
    return execSql(db, sql);
}

fn execSql(db: *c.sqlite3, sql: []const u8) StorageError!void {
    // sqlite3_exec runs multiple statements separated by `;`.
    var errmsg: [*c]u8 = null;
    // sql is a Zig slice — sqlite3_exec wants a 0-terminated cstr. We
    // copy onto the stack to keep the hot path allocator-free. Migration
    // strings are bounded at compile time.
    var buf: [16 * 1024]u8 = undefined;
    if (sql.len + 1 > buf.len) return error.PrepareFailed;
    @memcpy(buf[0..sql.len], sql);
    buf[sql.len] = 0;
    const rc = c.sqlite3_exec(db, &buf, null, null, &errmsg);
    if (rc != c.SQLITE_OK) {
        if (errmsg != null) {
            std.debug.print("sqlite exec error: rc={d} msg={s}\n", .{ rc, errmsg });
            c.sqlite3_free(errmsg);
        } else {
            std.debug.print("sqlite exec error: rc={d}\n", .{rc});
        }
        return error.StepFailed;
    }
}

fn isApplied(db: *c.sqlite3, id: u32) StorageError!bool {
    // SELECT 1 FROM migrations WHERE id = ?
    // If the table doesn't exist yet, sqlite returns SQLITE_ERROR — treat as "no".
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT 1 FROM migrations WHERE id = ?";
    const rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return false; // migrations table missing — by definition no rows.
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, @intCast(id));
    const step_rc = c.sqlite3_step(stmt);
    if (step_rc == c.SQLITE_ROW) return true;
    if (step_rc == c.SQLITE_DONE) return false;
    return error.StepFailed;
}

fn recordApplied(db: *c.sqlite3, id: u32, name: []const u8) StorageError!void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "INSERT INTO migrations(id, name, applied_at) VALUES (?, ?, strftime('%s','now'))";
    const rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return error.PrepareFailed;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, @intCast(id));
    _ = c.sqlite3_bind_text(stmt, 2, name.ptr, @intCast(name.len), c.sqliteTransientAsDestructor());
    const step_rc = c.sqlite3_step(stmt);
    if (step_rc != c.SQLITE_DONE) return error.StepFailed;
}

test "Schema sorts migrations by id" {
    var s = Schema.init();
    try s.register(.{ .id = 10, .name = "b", .up = "" });
    try s.register(.{ .id = 1, .name = "a", .up = "" });
    try s.register(.{ .id = 5, .name = "c", .up = "" });
    s.sort();
    try std.testing.expectEqual(@as(u32, 1), s.migrations[0].id);
    try std.testing.expectEqual(@as(u32, 5), s.migrations[1].id);
    try std.testing.expectEqual(@as(u32, 10), s.migrations[2].id);
}
