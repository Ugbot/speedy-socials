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
const sql = @import("sql.zig");

const Dialect = contract.Dialect;
const ColType = reflect.ColType;
/// Identifier quoting helper shared with `sql.zig` (one definition for both).
const quoteIdent = sql.quoteIdent;

/// SQL type keyword for a column, per dialect. Auto PKs carry their full
/// PRIMARY KEY + identity syntax here.
fn sqlType(comptime col: reflect.ColumnSpec, comptime dialect: Dialect) []const u8 {
    if (col.pk_auto) {
        return switch (dialect) {
            .sqlite => "INTEGER PRIMARY KEY AUTOINCREMENT",
            .postgres => "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY",
            .mysql => "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            .mssql => "BIGINT IDENTITY(1,1) PRIMARY KEY",
        };
    }
    return switch (col.col_type) {
        // MySQL/MSSQL can't index/PK a TEXT/NTEXT column without a key length,
        // but zorm knows the field's capacity — so emit (N)VARCHAR(N) there.
        .text => switch (dialect) {
            .sqlite, .postgres => "TEXT",
            .mysql => std.fmt.comptimePrint("VARCHAR({d})", .{col.byte_cap}),
            .mssql => std.fmt.comptimePrint("NVARCHAR({d})", .{col.byte_cap}),
        },
        .integer => switch (dialect) {
            .sqlite => "INTEGER",
            .postgres, .mysql, .mssql => "BIGINT",
        },
        .real => switch (dialect) {
            .sqlite => "REAL",
            .postgres => "DOUBLE PRECISION",
            .mysql => "DOUBLE",
            .mssql => "FLOAT",
        },
        .blob => switch (dialect) {
            .sqlite => "BLOB",
            .postgres => "BYTEA",
            .mysql => std.fmt.comptimePrint("VARBINARY({d})", .{col.byte_cap}),
            .mssql => std.fmt.comptimePrint("VARBINARY({d})", .{col.byte_cap}),
        },
    };
}

fn buildCreateTable(comptime T: type, comptime dialect: Dialect) []const u8 {
    const info = reflect.TableInfo(T);
    comptime {
        // Column + FK body, shared across dialects.
        var body: []const u8 = "";
        for (info.columns, 0..) |col, i| {
            if (i > 0) body = body ++ ", ";
            body = body ++ quoteIdent(col.name, dialect) ++ " " ++ sqlType(col, dialect);
            // Text PK: PRIMARY KEY + implicitly NOT NULL.
            if (col.is_pk and !col.pk_auto) {
                body = body ++ " PRIMARY KEY";
            } else if (!col.nullable and !col.pk_auto) {
                body = body ++ " NOT NULL";
            }
        }
        // Table-level FOREIGN KEY clauses derived from BelongsTo relations.
        // (Table-level form is identical on all four dialects.)
        for (reflect.foreignKeys(T)) |fk| {
            body = body ++ ", FOREIGN KEY (" ++ quoteIdent(fk.local_col, dialect) ++ ") REFERENCES " ++
                quoteIdent(fk.ref_table, dialect) ++ " (" ++ quoteIdent(fk.ref_col, dialect) ++ ")";
            if (fk.on_delete_sql.len > 0) body = body ++ " ON DELETE " ++ fk.on_delete_sql;
            if (fk.on_update_sql.len > 0) body = body ++ " ON UPDATE " ++ fk.on_update_sql;
        }
        // T-SQL has no `CREATE TABLE IF NOT EXISTS`; guard with OBJECT_ID. The
        // OBJECT_ID guard references the table as a STRING LITERAL (unquoted);
        // only the `CREATE TABLE <ident>` identifier is bracket-quoted.
        return switch (dialect) {
            .sqlite, .postgres, .mysql => "CREATE TABLE IF NOT EXISTS " ++ quoteIdent(info.table, dialect) ++ " (" ++ body ++ ")",
            .mssql => "IF OBJECT_ID(N'" ++ info.table ++ "', N'U') IS NULL CREATE TABLE " ++ quoteIdent(info.table, dialect) ++ " (" ++ body ++ ")",
        };
    }
}

/// `CREATE TABLE IF NOT EXISTS` DDL for entity `T` in the given dialect.
/// Returns a comptime-known string (one per (T, dialect) pair).
pub fn createTable(comptime T: type, dialect: Dialect) []const u8 {
    return switch (dialect) {
        .sqlite => comptime buildCreateTable(T, .sqlite),
        .postgres => comptime buildCreateTable(T, .postgres),
        .mysql => comptime buildCreateTable(T, .mysql),
        .mssql => comptime buildCreateTable(T, .mssql),
    };
}

/// `DROP TABLE` DDL (for a migration's down step).
pub fn dropTable(comptime T: type) []const u8 {
    return "DROP TABLE IF EXISTS " ++ reflect.TableInfo(T).table;
}

/// Index name for `T(cols…)`: `ix_<table>_<col0>[_<col1>…]`.
fn indexName(comptime T: type, comptime cols: []const []const u8) []const u8 {
    comptime {
        var name: []const u8 = "ix_" ++ reflect.TableInfo(T).table;
        for (cols) |c| name = name ++ "_" ++ c;
        return name;
    }
}

/// `CREATE [UNIQUE] INDEX ix_<table>_<cols> ON <table>(<cols>)`, guarded for
/// "if not exists" per dialect. Columns are comptime-validated. SQLite/
/// Postgres/MySQL use `IF NOT EXISTS`; T-SQL (no such clause) wraps the
/// statement in an `IF NOT EXISTS (SELECT … sys.indexes …)` guard.
pub fn createIndex(comptime T: type, comptime cols: []const []const u8, comptime unique: bool, dialect: Dialect) []const u8 {
    return switch (dialect) {
        inline else => |d| comptime buildIndex(T, cols, unique, d),
    };
}

fn buildIndex(comptime T: type, comptime cols: []const []const u8, comptime unique: bool, comptime dialect: Dialect) []const u8 {
    return comptime blk: {
        const info = reflect.TableInfo(T);
        if (cols.len == 0) @compileError("zorm: createIndex needs at least one column");
        for (cols) |c| {
            var found = false;
            for (info.columns) |col| {
                if (std.mem.eql(u8, col.name, c)) found = true;
            }
            if (!found) @compileError("zorm: index column '" ++ c ++ "' is not a column of " ++ @typeName(T));
        }
        var list: []const u8 = "";
        for (cols, 0..) |c, i| {
            if (i > 0) list = list ++ ", ";
            list = list ++ quoteIdent(c, dialect);
        }
        const ix = indexName(T, cols);
        const ix_q = quoteIdent(ix, dialect);
        const tbl_q = quoteIdent(info.table, dialect);
        const kw = if (unique) "CREATE UNIQUE INDEX " else "CREATE INDEX ";
        // The `sys.indexes` guard references the index + table as STRING
        // LITERALS (N'…', unquoted); only the CREATE INDEX / ON identifiers
        // are bracket-quoted.
        break :blk switch (dialect) {
            .sqlite, .postgres, .mysql => (if (unique) "CREATE UNIQUE INDEX IF NOT EXISTS " else "CREATE INDEX IF NOT EXISTS ") ++ ix_q ++ " ON " ++ tbl_q ++ " (" ++ list ++ ")",
            .mssql => "IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'" ++ ix ++ "' AND object_id = OBJECT_ID(N'" ++ info.table ++ "')) " ++ kw ++ ix_q ++ " ON " ++ tbl_q ++ " (" ++ list ++ ")",
        };
    };
}

/// `DROP INDEX` for an index created by `createIndex`. Postgres/SQLite take
/// a bare index name; MySQL and T-SQL need the table (`DROP INDEX … ON <table>`).
pub fn dropIndex(comptime T: type, comptime cols: []const []const u8, dialect: Dialect) []const u8 {
    const name = comptime indexName(T, cols);
    return switch (dialect) {
        inline .sqlite, .postgres => |d| comptime "DROP INDEX IF EXISTS " ++ quoteIdent(name, d),
        inline .mysql, .mssql => |d| comptime "DROP INDEX " ++ quoteIdent(name, d) ++ " ON " ++ quoteIdent(reflect.TableInfo(T).table, d),
    };
}

/// `ALTER TABLE … ADD COLUMN <col> <type>` for an existing entity field
/// (a hand-authored evolution step). Emitted WITHOUT `NOT NULL` — adding a
/// non-null column to a populated table needs a default, which the caller
/// supplies in a follow-up step if required (kept explicit, not faked).
pub fn addColumn(comptime T: type, comptime field_name: []const u8, dialect: Dialect) []const u8 {
    return switch (dialect) {
        inline else => |d| comptime buildAddColumn(T, field_name, d),
    };
}

fn buildAddColumn(comptime T: type, comptime field_name: []const u8, comptime dialect: Dialect) []const u8 {
    return comptime blk: {
        const info = reflect.TableInfo(T);
        for (info.columns) |col| {
            if (std.mem.eql(u8, col.name, field_name)) {
                if (col.pk_auto) @compileError("zorm: cannot ADD COLUMN an auto-increment PK ('" ++ field_name ++ "')");
                // T-SQL spells it `ADD <col>`; the rest use `ADD COLUMN <col>`.
                const add_kw = switch (dialect) {
                    .sqlite, .postgres, .mysql => " ADD COLUMN ",
                    .mssql => " ADD ",
                };
                break :blk "ALTER TABLE " ++ quoteIdent(info.table, dialect) ++ add_kw ++ quoteIdent(col.name, dialect) ++ " " ++ sqlType(col, dialect);
            }
        }
        @compileError("zorm: ADD COLUMN field '" ++ field_name ++ "' is not a column of " ++ @typeName(T));
    };
}

/// `ALTER TABLE <table> DROP COLUMN <col>` — string-based, since a dropped
/// column no longer exists on the (new) struct. Dialect-independent
/// (SQLite ≥3.35, Postgres, MySQL).
pub fn dropColumn(comptime table: []const u8, comptime col: []const u8, dialect: Dialect) []const u8 {
    return switch (dialect) {
        inline else => |d| comptime "ALTER TABLE " ++ quoteIdent(table, d) ++ " DROP COLUMN " ++ quoteIdent(col, d),
    };
}

/// `CREATE INDEX` for every foreign-key column of `T` (one per BelongsTo).
/// Returns a comptime list of statements — the natural companion to an
/// entity's initial migration so FK lookups (and `HasMany`) stay fast.
pub fn foreignKeyIndexes(comptime T: type, dialect: Dialect) []const []const u8 {
    return switch (dialect) {
        inline else => |d| comptime blk: {
            const fks = reflect.foreignKeys(T);
            var stmts: [fks.len][]const u8 = undefined;
            for (fks, 0..) |fk, i| {
                stmts[i] = createIndex(T, &.{fk.local_col}, false, d);
            }
            const out = stmts;
            break :blk &out;
        },
    };
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
    const sql_ddl = createTable(Account, .sqlite);
    try testing.expect(std.mem.startsWith(u8, sql_ddl, "CREATE TABLE IF NOT EXISTS \"atp_accounts\" ("));
    try testing.expect(std.mem.indexOf(u8, sql_ddl, "\"id\" TEXT PRIMARY KEY") != null);
    try testing.expect(std.mem.indexOf(u8, sql_ddl, "\"handle\" TEXT NOT NULL") != null);
    try testing.expect(std.mem.indexOf(u8, sql_ddl, "\"email\" TEXT") != null);
    try testing.expect(std.mem.indexOf(u8, sql_ddl, "\"email\" TEXT NOT NULL") == null); // nullable
    try testing.expect(std.mem.indexOf(u8, sql_ddl, "\"role\" TEXT NOT NULL") != null); // enum non-null
    try testing.expect(std.mem.indexOf(u8, sql_ddl, "\"confirmed\" INTEGER NOT NULL") != null);
    try testing.expect(std.mem.endsWith(u8, sql_ddl, ")"));
}

const AutoEntity = struct {
    pub const zorm_table = "things";
    id: fields.AutoPk = .{},
    name: fields.Text(32) = .{},
};

test "createTable: autoincrement PK differs by dialect" {
    const s = createTable(AutoEntity, .sqlite);
    try testing.expect(std.mem.indexOf(u8, s, "\"id\" INTEGER PRIMARY KEY AUTOINCREMENT") != null);
    const p = createTable(AutoEntity, .postgres);
    try testing.expect(std.mem.indexOf(u8, p, "\"id\" BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY") != null);
    try testing.expect(std.mem.indexOf(u8, p, "\"name\" TEXT NOT NULL") != null);
}

test "createTable: MySQL dialect — VARCHAR(N), BIGINT, TINYINT-free integers, AUTO_INCREMENT" {
    const a = createTable(Account, .mysql);
    // Text columns become VARCHAR(capacity) (MySQL can't PK/index a TEXT).
    try testing.expect(std.mem.indexOf(u8, a, "`id` VARCHAR(64) PRIMARY KEY") != null);
    try testing.expect(std.mem.indexOf(u8, a, "`handle` VARCHAR(253) NOT NULL") != null);
    try testing.expect(std.mem.indexOf(u8, a, "`email` VARCHAR(320)") != null);
    try testing.expect(std.mem.indexOf(u8, a, "`email` VARCHAR(320) NOT NULL") == null); // nullable
    try testing.expect(std.mem.indexOf(u8, a, "`role` VARCHAR(6) NOT NULL") != null); // enum -> VARCHAR(longest tag = "member")
    try testing.expect(std.mem.indexOf(u8, a, "`confirmed` BIGINT NOT NULL") != null); // bool -> integer family
    try testing.expect(std.mem.indexOf(u8, a, "`created_at` BIGINT NOT NULL") != null);

    const e = createTable(AutoEntity, .mysql);
    try testing.expect(std.mem.indexOf(u8, e, "`id` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY") != null);
    try testing.expect(std.mem.indexOf(u8, e, "`name` VARCHAR(32) NOT NULL") != null);
}

test "createTable: MS SQL dialect — OBJECT_ID guard, NVARCHAR(N), BIGINT, IDENTITY" {
    const a = createTable(Account, .mssql);
    // T-SQL has no CREATE TABLE IF NOT EXISTS — guarded with OBJECT_ID. The
    // guard refers to the table as a STRING LITERAL (unquoted); the actual
    // CREATE TABLE identifier is bracket-quoted.
    try testing.expect(std.mem.startsWith(u8, a, "IF OBJECT_ID(N'atp_accounts', N'U') IS NULL CREATE TABLE [atp_accounts] ("));
    try testing.expect(std.mem.indexOf(u8, a, "[id] NVARCHAR(64) PRIMARY KEY") != null);
    try testing.expect(std.mem.indexOf(u8, a, "[handle] NVARCHAR(253) NOT NULL") != null);
    try testing.expect(std.mem.indexOf(u8, a, "[email] NVARCHAR(320)") != null);
    try testing.expect(std.mem.indexOf(u8, a, "[email] NVARCHAR(320) NOT NULL") == null); // nullable
    try testing.expect(std.mem.indexOf(u8, a, "[role] NVARCHAR(6) NOT NULL") != null); // enum
    try testing.expect(std.mem.indexOf(u8, a, "[confirmed] BIGINT NOT NULL") != null);
    try testing.expect(std.mem.indexOf(u8, a, "[created_at] BIGINT NOT NULL") != null);

    const e = createTable(AutoEntity, .mssql);
    try testing.expect(std.mem.indexOf(u8, e, "[id] BIGINT IDENTITY(1,1) PRIMARY KEY") != null);
    try testing.expect(std.mem.indexOf(u8, e, "[name] NVARCHAR(32) NOT NULL") != null);
}

const BlobEntity = struct {
    pub const zorm_table = "blobs";
    id: fields.Pk(36) = .{},
    data: fields.Bytes(512) = .{},
};

test "createTable: blob type per dialect" {
    try testing.expect(std.mem.indexOf(u8, createTable(BlobEntity, .sqlite), "\"data\" BLOB NOT NULL") != null);
    try testing.expect(std.mem.indexOf(u8, createTable(BlobEntity, .postgres), "\"data\" BYTEA NOT NULL") != null);
    try testing.expect(std.mem.indexOf(u8, createTable(BlobEntity, .mysql), "`data` VARBINARY(512) NOT NULL") != null);
    try testing.expect(std.mem.indexOf(u8, createTable(BlobEntity, .mssql), "[data] VARBINARY(512) NOT NULL") != null);
}

test "dropTable" {
    try testing.expectEqualStrings("DROP TABLE IF EXISTS things", dropTable(AutoEntity));
}

// An entity whose table name (`order`) AND a column name (`select`) are SQL
// reserved words — identifier quoting is what makes the DDL valid.
const ReservedDdl = struct {
    pub const zorm_table = "order";
    id: fields.Pk(32) = .{},
    select: fields.Text(16) = .{},
};

test "createTable: reserved-word table + column are quoted per dialect" {
    // SQLite / Postgres → double quotes.
    try testing.expectEqualStrings(
        "CREATE TABLE IF NOT EXISTS \"order\" (\"id\" TEXT PRIMARY KEY, \"select\" TEXT NOT NULL)",
        createTable(ReservedDdl, .sqlite),
    );
    // MySQL → backticks.
    try testing.expectEqualStrings(
        "CREATE TABLE IF NOT EXISTS `order` (`id` VARCHAR(32) PRIMARY KEY, `select` VARCHAR(16) NOT NULL)",
        createTable(ReservedDdl, .mysql),
    );
    // MS SQL → brackets; the OBJECT_ID guard keeps the string-literal table name.
    try testing.expectEqualStrings(
        "IF OBJECT_ID(N'order', N'U') IS NULL CREATE TABLE [order] ([id] NVARCHAR(32) PRIMARY KEY, [select] NVARCHAR(16) NOT NULL)",
        createTable(ReservedDdl, .mssql),
    );
}

test "createIndex/addColumn/dropColumn: reserved-word identifiers are quoted" {
    // Index name + table + column all quoted.
    try testing.expectEqualStrings(
        "CREATE INDEX IF NOT EXISTS \"ix_order_select\" ON \"order\" (\"select\")",
        createIndex(ReservedDdl, &.{"select"}, false, .sqlite),
    );
    try testing.expectEqualStrings(
        "CREATE INDEX IF NOT EXISTS `ix_order_select` ON `order` (`select`)",
        createIndex(ReservedDdl, &.{"select"}, false, .mysql),
    );
    // ADD COLUMN quotes table + column (emitted WITHOUT NOT NULL by design).
    try testing.expectEqualStrings(
        "ALTER TABLE \"order\" ADD COLUMN \"select\" TEXT",
        addColumn(ReservedDdl, "select", .sqlite),
    );
    try testing.expectEqualStrings(
        "ALTER TABLE [order] ADD [select] NVARCHAR(16)",
        addColumn(ReservedDdl, "select", .mssql),
    );
    // DROP COLUMN (string-based) quotes both identifiers per dialect.
    try testing.expectEqualStrings(
        "ALTER TABLE \"order\" DROP COLUMN \"select\"",
        dropColumn("order", "select", .sqlite),
    );
    try testing.expectEqualStrings(
        "ALTER TABLE `order` DROP COLUMN `select`",
        dropColumn("order", "select", .mysql),
    );
}
