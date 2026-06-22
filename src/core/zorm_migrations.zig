//! Host bridge for zorm migrations: converts a `zorm.Migration` (a list of
//! single statements, dialect-correct) into this app's
//! `core.storage.schema.Migration` (one `;`-joined SQL string applied by the
//! existing, battle-tested `Schema.applyAll`) — so zorm-generated schema +
//! foreign keys register alongside the hand-written core/plugin migrations
//! with no second tracking table.
//!
//! The app runs SQLite (its `Schema.applyAll` is SQLite; the Postgres
//! provider's migrate is a no-op), so `registerInitial` generates SQLite
//! DDL. zorm's standalone `Migrator` is the path for the extracted library /
//! other engines.

const std = @import("std");
const zorm = @import("zorm");
const storage = @import("storage.zig");

/// Join a zorm migration's statement list into one `;`-separated SQL string
/// (what the host's `sqlite3_exec`-based `applyAll` consumes). Comptime —
/// the statements are comptime-known DDL.
fn joinStatements(comptime stmts: []const []const u8) []const u8 {
    return comptime blk: {
        var s: []const u8 = "";
        for (stmts, 0..) |st, i| {
            if (i > 0) s = s ++ ";\n";
            s = s ++ st;
        }
        break :blk s;
    };
}

/// Convert a (comptime-known) `zorm.Migration` to a host `storage.Migration`.
pub fn toCoreMigration(comptime m: zorm.Migration) storage.Migration {
    return .{
        .id = m.id,
        .name = m.name,
        .up = comptime joinStatements(m.up),
        .down = if (m.down) |d| comptime joinStatements(d) else null,
    };
}

/// Register each entity's initial (CREATE TABLE + FK indexes) migration into
/// `schema`, ids `base_id + i`. Entities are passed as a tuple of types,
/// e.g. `.{ User, Post }`.
pub fn registerInitial(schema: *storage.Schema, comptime entities: anytype, comptime base_id: u32) !void {
    inline for (entities, 0..) |E, i| {
        try schema.register(toCoreMigration(comptime zorm.initialMigration(E, base_id + i, .sqlite)));
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const sqlite = storage.sqlite;
const c = @import("sqlite").c;
const crud = struct {
    // zorm's CRUD is reached through the public root; alias for brevity.
    const insert = zorm.insert;
    const findByPk = zorm.findByPk;
    const deleteByPk = zorm.deleteByPk;
};

const ZUser = struct {
    pub const zorm_table = "zm_users";
    id: zorm.Pk(64) = .{},
    name: zorm.Text(64) = .{},
};
const ZPost = struct {
    pub const zorm_table = "zm_posts";
    id: zorm.Pk(64) = .{},
    author_id: zorm.Text(64) = .{},
    title: zorm.Text(128) = .{},
    author: zorm.BelongsTo(ZUser, "author_id", .{ .on_delete = .cascade }) = .{},
};

test "toCoreMigration joins zorm statements into one SQL string" {
    const m = comptime toCoreMigration(zorm.initialMigration(ZPost, 5001, .sqlite));
    try testing.expectEqual(@as(u32, 5001), m.id);
    try testing.expectEqualStrings("zm_posts:create", m.name);
    // CREATE TABLE (with FK) ; CREATE INDEX
    try testing.expect(std.mem.indexOf(u8, m.up, "CREATE TABLE IF NOT EXISTS \"zm_posts\" (") != null);
    try testing.expect(std.mem.indexOf(u8, m.up, "FOREIGN KEY (\"author_id\") REFERENCES \"zm_users\" (\"id\") ON DELETE CASCADE") != null);
    try testing.expect(std.mem.indexOf(u8, m.up, ";\nCREATE INDEX IF NOT EXISTS \"ix_zm_posts_author_id\"") != null);
    try testing.expect(m.down != null);
    try testing.expect(std.mem.indexOf(u8, m.down.?, "DROP TABLE IF EXISTS zm_posts") != null);
}

test "registerInitial + Schema.applyAll creates zorm tables; FK is enforced" {
    const db = try sqlite.openWriter(":memory:"); // FK pragma ON
    defer sqlite.closeDb(db);

    var schema = storage.Schema.init();
    try schema.register(storage.bootstrap_migration); // id=1, creates `migrations`
    try registerInitial(&schema, .{ ZUser, ZPost }, 5000); // parent before child
    try schema.applyAll(db);

    // Both tables now exist; drive them through zorm over the same db.
    var be = storage.SqliteBackend.init(db);
    var adapter = storage.zorm_adapter.Adapter.init(be.backend());
    const zb = adapter.backend(.sqlite);

    // Parent + a valid child insert.
    var u = ZUser{ .id = zorm.Pk(64).from("u1"), .name = zorm.Text(64).from("alice") };
    try crud.insert(ZUser, zb, &u);
    var p = ZPost{ .id = zorm.Pk(64).from("p1"), .author_id = zorm.Text(64).from("u1"), .title = zorm.Text(128).from("hi") };
    try crud.insert(ZPost, zb, &p);

    // Orphan child (FK points nowhere) must be REJECTED by the DB.
    var orphan = ZPost{ .id = zorm.Pk(64).from("p2"), .author_id = zorm.Text(64).from("ghost"), .title = zorm.Text(128).from("x") };
    if (crud.insert(ZPost, zb, &orphan)) |_| {
        return error.TestExpectedForeignKeyViolation;
    } else |_| {}

    // ON DELETE CASCADE: deleting the parent removes the child.
    try crud.deleteByPk(ZUser, zb, "u1");
    var got: ZPost = .{};
    try testing.expect(!try crud.findByPk(ZPost, zb, "p1", &got));
}

test "applyAll is idempotent — re-running registered zorm migrations is a no-op" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);

    var schema = storage.Schema.init();
    try schema.register(storage.bootstrap_migration);
    try registerInitial(&schema, .{ ZUser, ZPost }, 5000);
    try schema.applyAll(db);

    // A second Schema with the same ids applies nothing new (tracked by id).
    var schema2 = storage.Schema.init();
    try schema2.register(storage.bootstrap_migration);
    try registerInitial(&schema2, .{ ZUser, ZPost }, 5000);
    try schema2.applyAll(db); // must not error (CREATE TABLE IF NOT EXISTS + id skip)

    // The tables are still usable.
    var be = storage.SqliteBackend.init(db);
    var adapter = storage.zorm_adapter.Adapter.init(be.backend());
    const zb = adapter.backend(.sqlite);
    var u = ZUser{ .id = zorm.Pk(64).from("u9"), .name = zorm.Text(64).from("z") };
    try crud.insert(ZUser, zb, &u);
    var got: ZUser = .{};
    try testing.expect(try crud.findByPk(ZUser, zb, "u9", &got));
}
