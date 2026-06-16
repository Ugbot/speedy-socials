//! Comptime DDL generation: a struct's fields ARE its schema. `createTable`
//! emits dialect-correct `CREATE TABLE IF NOT EXISTS` from `reflect`'s
//! column specs. The host registers the returned string as a migration.
//!
//! Dialect neutrality: column types + autoincrement-PK syntax differ
//! between SQLite and Postgres, so DDL is generated per-dialect (the host
//! knows its dialect at boot and calls `createTable(T, dialect)`).

const std = @import("std");
const reflect = @import("reflect.zig");
const contract = @import("contract.zig");

const Dialect = contract.Dialect;
const ColType = reflect.ColType;

/// SQL type keyword for a column, per dialect. Auto PKs carry their full
/// PRIMARY KEY + identity syntax here.
fn sqlType(comptime col: reflect.ColumnSpec, comptime dialect: Dialect) []const u8 {
    if (col.pk_auto) {
        return switch (dialect) {
            .sqlite => "INTEGER PRIMARY KEY AUTOINCREMENT",
            .postgres => "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY",
            .mysql => "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
        };
    }
    return switch (col.col_type) {
        // MySQL can't index/PK a TEXT column without a key length, but zorm
        // knows the field's capacity — so emit VARCHAR(N) there.
        .text => switch (dialect) {
            .sqlite, .postgres => "TEXT",
            .mysql => std.fmt.comptimePrint("VARCHAR({d})", .{col.byte_cap}),
        },
        .integer => switch (dialect) {
            .sqlite => "INTEGER",
            .postgres, .mysql => "BIGINT",
        },
        .real => switch (dialect) {
            .sqlite => "REAL",
            .postgres => "DOUBLE PRECISION",
            .mysql => "DOUBLE",
        },
        .blob => switch (dialect) {
            .sqlite => "BLOB",
            .postgres => "BYTEA",
            .mysql => std.fmt.comptimePrint("VARBINARY({d})", .{col.byte_cap}),
        },
    };
}

fn buildCreateTable(comptime T: type, comptime dialect: Dialect) []const u8 {
    const info = reflect.TableInfo(T);
    comptime {
        var sql: []const u8 = "CREATE TABLE IF NOT EXISTS " ++ info.table ++ " (";
        for (info.columns, 0..) |col, i| {
            if (i > 0) sql = sql ++ ", ";
            sql = sql ++ col.name ++ " " ++ sqlType(col, dialect);
            // Text PK: PRIMARY KEY + implicitly NOT NULL.
            if (col.is_pk and !col.pk_auto) {
                sql = sql ++ " PRIMARY KEY";
            } else if (!col.nullable and !col.pk_auto) {
                sql = sql ++ " NOT NULL";
            }
        }
        sql = sql ++ ")";
        return sql;
    }
}

/// `CREATE TABLE IF NOT EXISTS` DDL for entity `T` in the given dialect.
/// Returns a comptime-known string (one per (T, dialect) pair).
pub fn createTable(comptime T: type, dialect: Dialect) []const u8 {
    return switch (dialect) {
        .sqlite => comptime buildCreateTable(T, .sqlite),
        .postgres => comptime buildCreateTable(T, .postgres),
        .mysql => comptime buildCreateTable(T, .mysql),
    };
}

/// `DROP TABLE` DDL (for a migration's down step).
pub fn dropTable(comptime T: type) []const u8 {
    return "DROP TABLE IF EXISTS " ++ reflect.TableInfo(T).table;
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const fields = @import("fields.zig");

const Role = enum { member, admin };
const Account = struct {
    pub const zorm_table = "atp_accounts";
    id: fields.Pk(64) = .{},
    handle: fields.Text(253) = .{},
    email: ?fields.Text(320) = null,
    role: Role = .member,
    confirmed: bool = false,
    created_at: fields.Timestamp = .{},
};

test "createTable: SQLite DDL shape" {
    const sql = createTable(Account, .sqlite);
    try testing.expect(std.mem.startsWith(u8, sql, "CREATE TABLE IF NOT EXISTS atp_accounts ("));
    try testing.expect(std.mem.indexOf(u8, sql, "id TEXT PRIMARY KEY") != null);
    try testing.expect(std.mem.indexOf(u8, sql, "handle TEXT NOT NULL") != null);
    try testing.expect(std.mem.indexOf(u8, sql, "email TEXT") != null);
    try testing.expect(std.mem.indexOf(u8, sql, "email TEXT NOT NULL") == null); // nullable
    try testing.expect(std.mem.indexOf(u8, sql, "role TEXT NOT NULL") != null); // enum non-null
    try testing.expect(std.mem.indexOf(u8, sql, "confirmed INTEGER NOT NULL") != null);
    try testing.expect(std.mem.endsWith(u8, sql, ")"));
}

const AutoEntity = struct {
    pub const zorm_table = "things";
    id: fields.AutoPk = .{},
    name: fields.Text(32) = .{},
};

test "createTable: autoincrement PK differs by dialect" {
    const s = createTable(AutoEntity, .sqlite);
    try testing.expect(std.mem.indexOf(u8, s, "id INTEGER PRIMARY KEY AUTOINCREMENT") != null);
    const p = createTable(AutoEntity, .postgres);
    try testing.expect(std.mem.indexOf(u8, p, "id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY") != null);
    try testing.expect(std.mem.indexOf(u8, p, "name TEXT NOT NULL") != null);
}

test "createTable: MySQL dialect — VARCHAR(N), BIGINT, TINYINT-free integers, AUTO_INCREMENT" {
    const a = createTable(Account, .mysql);
    // Text columns become VARCHAR(capacity) (MySQL can't PK/index a TEXT).
    try testing.expect(std.mem.indexOf(u8, a, "id VARCHAR(64) PRIMARY KEY") != null);
    try testing.expect(std.mem.indexOf(u8, a, "handle VARCHAR(253) NOT NULL") != null);
    try testing.expect(std.mem.indexOf(u8, a, "email VARCHAR(320)") != null);
    try testing.expect(std.mem.indexOf(u8, a, "email VARCHAR(320) NOT NULL") == null); // nullable
    try testing.expect(std.mem.indexOf(u8, a, "role VARCHAR") != null); // enum stored as text
    try testing.expect(std.mem.indexOf(u8, a, "confirmed BIGINT NOT NULL") != null); // bool -> integer family
    try testing.expect(std.mem.indexOf(u8, a, "created_at BIGINT NOT NULL") != null);

    const e = createTable(AutoEntity, .mysql);
    try testing.expect(std.mem.indexOf(u8, e, "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY") != null);
    try testing.expect(std.mem.indexOf(u8, e, "name VARCHAR(32) NOT NULL") != null);
}

const BlobEntity = struct {
    pub const zorm_table = "blobs";
    id: fields.Pk(36) = .{},
    data: fields.Bytes(512) = .{},
};

test "createTable: blob type per dialect" {
    try testing.expect(std.mem.indexOf(u8, createTable(BlobEntity, .sqlite), "data BLOB NOT NULL") != null);
    try testing.expect(std.mem.indexOf(u8, createTable(BlobEntity, .postgres), "data BYTEA NOT NULL") != null);
    try testing.expect(std.mem.indexOf(u8, createTable(BlobEntity, .mysql), "data VARBINARY(512) NOT NULL") != null);
}

test "dropTable" {
    try testing.expectEqualStrings("DROP TABLE IF EXISTS things", dropTable(AutoEntity));
}
