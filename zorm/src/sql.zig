//! Comptime SQL statement generation. Each statement is built once per
//! (entity, dialect) pair as a `comptime`-known string — no runtime string
//! building, no allocation. Placeholders, autoincrement handling, and the
//! `RETURNING` clause are dialect-parameterized: zorm NEVER ships one SQL
//! string to both engines.
//!
//! Placeholder numbering matches the bind order the `bind` layer produces:
//!   INSERT — non-auto-PK columns, in `TableInfo` order (1..k).
//!   UPDATE — non-PK columns (SET, 1..m) then the PK (WHERE, m+1).
//!   SELECT/DELETE by PK — the PK is the sole bind ($1 / ?).

const std = @import("std");
const reflect = @import("reflect.zig");
const contract = @import("contract.zig");

const Dialect = contract.Dialect;

/// Quote a SQL identifier (table or column name) for the given dialect so
/// reserved words and special characters are safe. Comptime-only: the result
/// is a comptime-known string, so there is zero runtime cost.
///   sqlite/postgres → "name"   mysql → `name`   mssql → [name]
pub fn quoteIdent(comptime name: []const u8, comptime dialect: Dialect) []const u8 {
    return switch (dialect) {
        .sqlite, .postgres => "\"" ++ name ++ "\"",
        .mysql => "`" ++ name ++ "`",
        .mssql => "[" ++ name ++ "]",
    };
}

/// Comma-joined column-name list for every column (SELECT projection),
/// identifier-quoted for `dialect`.
fn columnList(comptime T: type, comptime dialect: Dialect) []const u8 {
    const info = reflect.TableInfo(T);
    comptime {
        var s: []const u8 = "";
        for (info.columns, 0..) |col, i| {
            if (i > 0) s = s ++ ", ";
            s = s ++ quoteIdent(col.name, dialect);
        }
        return s;
    }
}

fn buildInsert(comptime T: type, comptime dialect: Dialect) []const u8 {
    const info = reflect.TableInfo(T);
    comptime {
        var cols: []const u8 = "";
        var vals: []const u8 = "";
        var n: usize = 0;
        for (info.columns) |col| {
            if (col.pk_auto) continue; // DB assigns the auto PK.
            if (n > 0) {
                cols = cols ++ ", ";
                vals = vals ++ ", ";
            }
            cols = cols ++ quoteIdent(col.name, dialect);
            vals = vals ++ dialect.placeholder(n + 1);
            n += 1;
        }
        var sql: []const u8 = "INSERT INTO " ++ quoteIdent(info.table, dialect) ++ " (" ++ cols ++ ")";
        // SQL Server returns the assigned id via an OUTPUT clause placed
        // between the column list and VALUES.
        if (info.pk_auto and dialect == .mssql) {
            sql = sql ++ " OUTPUT INSERTED." ++ quoteIdent(info.pk_column.name, dialect);
        }
        sql = sql ++ " VALUES (" ++ vals ++ ")";
        // Postgres assigns the auto PK and returns it via RETURNING; SQLite +
        // MySQL use lastInsertId(). Text PKs are caller-supplied (no clause).
        if (info.pk_auto and dialect == .postgres) {
            sql = sql ++ " RETURNING " ++ quoteIdent(info.pk_column.name, dialect);
        }
        return sql;
    }
}

fn buildSelectByPk(comptime T: type, comptime dialect: Dialect) []const u8 {
    const info = reflect.TableInfo(T);
    comptime {
        return "SELECT " ++ columnList(T, dialect) ++ " FROM " ++ quoteIdent(info.table, dialect) ++
            " WHERE " ++ quoteIdent(info.pk_column.name, dialect) ++ " = " ++ dialect.placeholder(1);
    }
}

fn buildUpdate(comptime T: type, comptime dialect: Dialect) []const u8 {
    const info = reflect.TableInfo(T);
    comptime {
        var sets: []const u8 = "";
        var n: usize = 0;
        for (info.columns) |col| {
            if (col.is_pk) continue;
            if (n > 0) sets = sets ++ ", ";
            sets = sets ++ quoteIdent(col.name, dialect) ++ " = " ++ dialect.placeholder(n + 1);
            n += 1;
        }
        return "UPDATE " ++ quoteIdent(info.table, dialect) ++ " SET " ++ sets ++
            " WHERE " ++ quoteIdent(info.pk_column.name, dialect) ++ " = " ++ dialect.placeholder(n + 1);
    }
}

fn buildDeleteByPk(comptime T: type, comptime dialect: Dialect) []const u8 {
    const info = reflect.TableInfo(T);
    comptime {
        return "DELETE FROM " ++ quoteIdent(info.table, dialect) ++
            " WHERE " ++ quoteIdent(info.pk_column.name, dialect) ++ " = " ++ dialect.placeholder(1);
    }
}

// ── Public API (switch runtime dialect → comptime-built string) ─────────

/// `INSERT` for `T`. For an auto-PK entity on Postgres this ends in
/// `RETURNING <pk>`; on SQLite the caller reads `lastInsertId()`.
pub fn insert(comptime T: type, dialect: Dialect) []const u8 {
    return switch (dialect) {
        .sqlite => comptime buildInsert(T, .sqlite),
        .postgres => comptime buildInsert(T, .postgres),
        .mysql => comptime buildInsert(T, .mysql),
        .mssql => comptime buildInsert(T, .mssql),
    };
}

/// `SELECT <all columns> FROM <table>` with no clauses — the base a query
/// builder appends WHERE/ORDER BY/LIMIT onto. Identifiers are quoted per
/// dialect (only the value placeholders in a WHERE differ, which the builder
/// adds).
pub fn selectAll(comptime T: type, dialect: Dialect) []const u8 {
    return switch (dialect) {
        inline else => |d| comptime "SELECT " ++ columnList(T, d) ++ " FROM " ++ quoteIdent(reflect.TableInfo(T).table, d),
    };
}

/// The comma-joined projection column list (full row, `TableInfo` order),
/// identifier-quoted for `dialect`.
pub fn projection(comptime T: type, dialect: Dialect) []const u8 {
    return switch (dialect) {
        inline else => |d| comptime columnList(T, d),
    };
}

/// `SELECT … WHERE pk = ?` (full projection, `TableInfo` column order).
pub fn selectByPk(comptime T: type, dialect: Dialect) []const u8 {
    return switch (dialect) {
        .sqlite => comptime buildSelectByPk(T, .sqlite),
        .postgres => comptime buildSelectByPk(T, .postgres),
        .mysql => comptime buildSelectByPk(T, .mysql),
        .mssql => comptime buildSelectByPk(T, .mssql),
    };
}

/// `UPDATE … SET <all non-PK cols> WHERE pk = ?`.
pub fn update(comptime T: type, dialect: Dialect) []const u8 {
    return switch (dialect) {
        .sqlite => comptime buildUpdate(T, .sqlite),
        .postgres => comptime buildUpdate(T, .postgres),
        .mysql => comptime buildUpdate(T, .mysql),
        .mssql => comptime buildUpdate(T, .mssql),
    };
}

/// `DELETE … WHERE pk = ?`.
pub fn deleteByPk(comptime T: type, dialect: Dialect) []const u8 {
    return switch (dialect) {
        .sqlite => comptime buildDeleteByPk(T, .sqlite),
        .postgres => comptime buildDeleteByPk(T, .postgres),
        .mysql => comptime buildDeleteByPk(T, .mysql),
        .mssql => comptime buildDeleteByPk(T, .mssql),
    };
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const fields = @import("fields.zig");

const Role = enum { member, admin };
const Account = struct {
    pub const zorm_table = "atp_accounts";
    id: fields.Pk(64) = .{},
    handle: fields.Text(64) = .{},
    email: ?fields.Text(64) = null,
    role: Role = .member,
};

const AutoEntity = struct {
    pub const zorm_table = "things";
    id: fields.AutoPk = .{},
    name: fields.Text(32) = .{},
};

test "INSERT: text PK, SQLite placeholders, no RETURNING" {
    try testing.expectEqualStrings(
        "INSERT INTO \"atp_accounts\" (\"id\", \"handle\", \"email\", \"role\") VALUES (?, ?, ?, ?)",
        insert(Account, .sqlite),
    );
}

test "INSERT: Postgres uses $N placeholders" {
    try testing.expectEqualStrings(
        "INSERT INTO \"atp_accounts\" (\"id\", \"handle\", \"email\", \"role\") VALUES ($1, $2, $3, $4)",
        insert(Account, .postgres),
    );
}

test "INSERT: auto PK is omitted; Postgres appends RETURNING, SQLite does not" {
    try testing.expectEqualStrings(
        "INSERT INTO \"things\" (\"name\") VALUES (?)",
        insert(AutoEntity, .sqlite),
    );
    try testing.expectEqualStrings(
        "INSERT INTO \"things\" (\"name\") VALUES ($1) RETURNING \"id\"",
        insert(AutoEntity, .postgres),
    );
}

test "MySQL: ? placeholders, no RETURNING (auto PK via lastInsertId)" {
    try testing.expectEqualStrings(
        "INSERT INTO `atp_accounts` (`id`, `handle`, `email`, `role`) VALUES (?, ?, ?, ?)",
        insert(Account, .mysql),
    );
    // Auto-PK INSERT omits the id and does NOT append RETURNING on MySQL.
    try testing.expectEqualStrings(
        "INSERT INTO `things` (`name`) VALUES (?)",
        insert(AutoEntity, .mysql),
    );
    try testing.expectEqualStrings(
        "SELECT `id`, `handle`, `email`, `role` FROM `atp_accounts` WHERE `id` = ?",
        selectByPk(Account, .mysql),
    );
    try testing.expectEqualStrings(
        "UPDATE `atp_accounts` SET `handle` = ?, `email` = ?, `role` = ? WHERE `id` = ?",
        update(Account, .mysql),
    );
    try testing.expectEqualStrings(
        "DELETE FROM `things` WHERE `id` = ?",
        deleteByPk(AutoEntity, .mysql),
    );
}

test "MS SQL: @pN placeholders, OUTPUT INSERTED for auto PK" {
    try testing.expectEqualStrings(
        "INSERT INTO [atp_accounts] ([id], [handle], [email], [role]) VALUES (@p1, @p2, @p3, @p4)",
        insert(Account, .mssql),
    );
    // Auto-PK INSERT: OUTPUT INSERTED.<pk> sits between the column list + VALUES.
    try testing.expectEqualStrings(
        "INSERT INTO [things] ([name]) OUTPUT INSERTED.[id] VALUES (@p1)",
        insert(AutoEntity, .mssql),
    );
    try testing.expectEqualStrings(
        "SELECT [id], [handle], [email], [role] FROM [atp_accounts] WHERE [id] = @p1",
        selectByPk(Account, .mssql),
    );
    try testing.expectEqualStrings(
        "UPDATE [atp_accounts] SET [handle] = @p1, [email] = @p2, [role] = @p3 WHERE [id] = @p4",
        update(Account, .mssql),
    );
    try testing.expectEqualStrings(
        "DELETE FROM [things] WHERE [id] = @p1",
        deleteByPk(AutoEntity, .mssql),
    );
}

test "SELECT by PK projects all columns in order" {
    try testing.expectEqualStrings(
        "SELECT \"id\", \"handle\", \"email\", \"role\" FROM \"atp_accounts\" WHERE \"id\" = ?",
        selectByPk(Account, .sqlite),
    );
    try testing.expectEqualStrings(
        "SELECT \"id\", \"handle\", \"email\", \"role\" FROM \"atp_accounts\" WHERE \"id\" = $1",
        selectByPk(Account, .postgres),
    );
}

test "UPDATE sets non-PK columns then binds PK last" {
    try testing.expectEqualStrings(
        "UPDATE \"atp_accounts\" SET \"handle\" = ?, \"email\" = ?, \"role\" = ? WHERE \"id\" = ?",
        update(Account, .sqlite),
    );
    try testing.expectEqualStrings(
        "UPDATE \"atp_accounts\" SET \"handle\" = $1, \"email\" = $2, \"role\" = $3 WHERE \"id\" = $4",
        update(Account, .postgres),
    );
}

test "DELETE by PK" {
    try testing.expectEqualStrings(
        "DELETE FROM \"atp_accounts\" WHERE \"id\" = ?",
        deleteByPk(Account, .sqlite),
    );
    try testing.expectEqualStrings(
        "DELETE FROM \"things\" WHERE \"id\" = $1",
        deleteByPk(AutoEntity, .postgres),
    );
}

test "quoteIdent: bracket/backtick/double-quote per dialect" {
    try testing.expectEqualStrings("\"order\"", quoteIdent("order", .sqlite));
    try testing.expectEqualStrings("\"order\"", quoteIdent("order", .postgres));
    try testing.expectEqualStrings("`order`", quoteIdent("order", .mysql));
    try testing.expectEqualStrings("[order]", quoteIdent("order", .mssql));
}

// An entity whose column name (`order`) AND table name (`select`) are SQL
// reserved words — quoting is what makes the emitted SQL valid.
const Reserved = struct {
    pub const zorm_table = "select";
    id: fields.Pk(32) = .{},
    order: fields.Text(16) = .{},
};

test "reserved-word table + column produce valid quoted SQL per dialect" {
    // SQLite / Postgres → double quotes.
    try testing.expectEqualStrings(
        "INSERT INTO \"select\" (\"id\", \"order\") VALUES (?, ?)",
        insert(Reserved, .sqlite),
    );
    try testing.expectEqualStrings(
        "SELECT \"id\", \"order\" FROM \"select\" WHERE \"id\" = $1",
        selectByPk(Reserved, .postgres),
    );
    try testing.expectEqualStrings(
        "UPDATE \"select\" SET \"order\" = ? WHERE \"id\" = ?",
        update(Reserved, .sqlite),
    );
    // MySQL → backticks.
    try testing.expectEqualStrings(
        "INSERT INTO `select` (`id`, `order`) VALUES (?, ?)",
        insert(Reserved, .mysql),
    );
    try testing.expectEqualStrings(
        "UPDATE `select` SET `order` = ? WHERE `id` = ?",
        update(Reserved, .mysql),
    );
    // MS SQL → brackets.
    try testing.expectEqualStrings(
        "INSERT INTO [select] ([id], [order]) VALUES (@p1, @p2)",
        insert(Reserved, .mssql),
    );
    try testing.expectEqualStrings(
        "DELETE FROM [select] WHERE [id] = @p1",
        deleteByPk(Reserved, .mssql),
    );
    // selectAll + projection are also quoted.
    try testing.expectEqualStrings(
        "SELECT `id`, `order` FROM `select`",
        selectAll(Reserved, .mysql),
    );
    try testing.expectEqualStrings("[id], [order]", projection(Reserved, .mssql));
}
