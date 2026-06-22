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

/// `INSERT … <conflict resolution on PK>` — an upsert. The row is supplied
/// in full (every non-auto-PK column, same bind order as `buildInsert`), and
/// on a PK collision the NON-PK columns are overwritten with the incoming
/// values; the PK itself is the conflict key (never in the SET list).
///
/// Auto-PK note: an `AutoPk` entity has its id DB-assigned and omitted from
/// the INSERT column list, so the conflict target is that auto id. A freshly
/// added row (id unset) can never collide with an existing auto id, so for
/// auto-PK entities `upsert` degrades to a plain INSERT-with-new-id; it only
/// updates when the caller re-supplies a known id (not expressible through
/// the auto-PK INSERT, which omits id). Upsert is therefore meaningful for
/// text / explicit PKs; for auto PKs it is a safe INSERT. The conflict clause
/// is still emitted so a caller who DOES write the id (via a non-auto path)
/// gets correct semantics.
fn buildUpsert(comptime T: type, comptime dialect: Dialect) []const u8 {
    const info = reflect.TableInfo(T);
    comptime {
        // Column list + value placeholders, identical to buildInsert: every
        // non-auto-PK column in TableInfo order.
        var cols: []const u8 = "";
        var vals: []const u8 = "";
        var src_cols: []const u8 = ""; // MERGE source column aliases
        var n: usize = 0;
        for (info.columns) |col| {
            if (col.pk_auto) continue;
            if (n > 0) {
                cols = cols ++ ", ";
                vals = vals ++ ", ";
                src_cols = src_cols ++ ", ";
            }
            cols = cols ++ quoteIdent(col.name, dialect);
            vals = vals ++ dialect.placeholder(n + 1);
            src_cols = src_cols ++ quoteIdent(col.name, dialect);
            n += 1;
        }

        const pk = quoteIdent(info.pk_column.name, dialect);
        const table = quoteIdent(info.table, dialect);

        // The conflict target / merge key: every PK column. For a single PK
        // this is byte-identical to the old `<pk>` forms.
        var pk_list: []const u8 = ""; // `pk1, pk2, …` — ON CONFLICT target
        var merge_on: []const u8 = ""; // `tgt.pk1 = src.pk1 AND …` — MERGE key
        for (0..info.pk_count) |pk_k| {
            const c = quoteIdent(info.pkColumn(pk_k).name, dialect);
            if (pk_k > 0) {
                pk_list = pk_list ++ ", ";
                merge_on = merge_on ++ " AND ";
            }
            pk_list = pk_list ++ c;
            merge_on = merge_on ++ "tgt." ++ c ++ " = src." ++ c;
        }

        switch (dialect) {
            // SQLite / Postgres share the ON CONFLICT (<pk>) DO UPDATE SET
            // col = excluded.col form. SQLite spells the pseudo-table
            // `excluded`, Postgres `EXCLUDED`.
            .sqlite, .postgres => {
                const ref = if (dialect == .sqlite) "excluded." else "EXCLUDED.";
                var sets: []const u8 = "";
                var m: usize = 0;
                for (info.columns) |col| {
                    if (col.is_pk) continue;
                    if (m > 0) sets = sets ++ ", ";
                    const c = quoteIdent(col.name, dialect);
                    sets = sets ++ c ++ " = " ++ ref ++ c;
                    m += 1;
                }
                var s: []const u8 = "INSERT INTO " ++ table ++ " (" ++ cols ++ ") VALUES (" ++ vals ++ ")" ++
                    " ON CONFLICT (" ++ pk_list ++ ") DO UPDATE SET " ++ sets;
                // No non-PK columns (a PK-only table): nothing to update on
                // conflict — fall back to DO NOTHING so the statement is valid.
                if (m == 0) s = "INSERT INTO " ++ table ++ " (" ++ cols ++ ") VALUES (" ++ vals ++ ")" ++
                    " ON CONFLICT (" ++ pk_list ++ ") DO NOTHING";
                return s;
            },
            // MySQL: INSERT … ON DUPLICATE KEY UPDATE col = VALUES(col).
            .mysql => {
                var sets: []const u8 = "";
                var m: usize = 0;
                for (info.columns) |col| {
                    if (col.is_pk) continue;
                    if (m > 0) sets = sets ++ ", ";
                    const c = quoteIdent(col.name, dialect);
                    sets = sets ++ c ++ " = VALUES(" ++ c ++ ")";
                    m += 1;
                }
                if (m == 0) {
                    // PK-only: a no-op assignment keeps the statement valid +
                    // idempotent (re-assign the PK to itself).
                    sets = pk ++ " = VALUES(" ++ pk ++ ")";
                }
                return "INSERT INTO " ++ table ++ " (" ++ cols ++ ") VALUES (" ++ vals ++ ")" ++
                    " ON DUPLICATE KEY UPDATE " ++ sets;
            },
            // SQL Server has no INSERT…ON CONFLICT; the portable upsert is a
            // MERGE keyed on the PK.
            .mssql => {
                // The placeholders are bound exactly ONCE — in the USING
                // source row. Both the UPDATE SET and the NOT-MATCHED INSERT
                // reference the source columns (`src.<col>`), so the bind
                // order stays 1..N (same as buildInsert) with no re-binding.
                var sets: []const u8 = "";
                var ins_vals: []const u8 = ""; // src.col, … for the INSERT
                var m: usize = 0;
                var k: usize = 0;
                for (info.columns) |col| {
                    if (col.pk_auto) continue;
                    const c = quoteIdent(col.name, dialect);
                    if (k > 0) ins_vals = ins_vals ++ ", ";
                    ins_vals = ins_vals ++ "src." ++ c;
                    k += 1;
                    if (col.is_pk) continue;
                    if (m > 0) sets = sets ++ ", ";
                    sets = sets ++ c ++ " = src." ++ c;
                    m += 1;
                }
                var s: []const u8 = "MERGE " ++ table ++ " AS tgt USING (VALUES (" ++ vals ++ ")) AS src (" ++ src_cols ++ ")" ++
                    " ON " ++ merge_on;
                if (m > 0) s = s ++ " WHEN MATCHED THEN UPDATE SET " ++ sets;
                s = s ++ " WHEN NOT MATCHED THEN INSERT (" ++ cols ++ ") VALUES (" ++ ins_vals ++ ");";
                return s;
            },
        }
    }
}

/// `pk1 = <ph> AND pk2 = <ph> …` — the WHERE clause matching the full
/// primary key, identifier-quoted, with dialect placeholders numbered from
/// `start_ph` (1-based). For a single PK this is `pk = <ph>` (byte-identical
/// to the old shape). The placeholders advance in PK declaration order, which
/// matches the bind order `bind.bindPkAll`/`bindPkValueAll` produce.
fn pkWhere(comptime T: type, comptime dialect: Dialect, comptime start_ph: usize) []const u8 {
    const info = reflect.TableInfo(T);
    comptime {
        var s: []const u8 = "";
        for (0..info.pk_count) |k| {
            if (k > 0) s = s ++ " AND ";
            s = s ++ quoteIdent(info.pkColumn(k).name, dialect) ++ " = " ++ dialect.placeholder(start_ph + k);
        }
        return s;
    }
}

fn buildSelectByPk(comptime T: type, comptime dialect: Dialect) []const u8 {
    const info = reflect.TableInfo(T);
    comptime {
        return "SELECT " ++ columnList(T, dialect) ++ " FROM " ++ quoteIdent(info.table, dialect) ++
            " WHERE " ++ pkWhere(T, dialect, 1);
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
            " WHERE " ++ pkWhere(T, dialect, n + 1);
    }
}

fn buildDeleteByPk(comptime T: type, comptime dialect: Dialect) []const u8 {
    const info = reflect.TableInfo(T);
    comptime {
        return "DELETE FROM " ++ quoteIdent(info.table, dialect) ++
            " WHERE " ++ pkWhere(T, dialect, 1);
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

/// `INSERT … <conflict resolution>` — upsert keyed on the PK. On a PK
/// collision the non-PK columns are overwritten with the incoming row; the
/// bind order matches `insert` (every non-auto-PK column, 1..k). Dialects:
///   sqlite   → `… ON CONFLICT (<pk>) DO UPDATE SET col = excluded.col …`
///   postgres → `… ON CONFLICT (<pk>) DO UPDATE SET col = EXCLUDED.col …`
///   mysql    → `… ON DUPLICATE KEY UPDATE col = VALUES(col) …`
///   mssql    → `MERGE … WHEN MATCHED THEN UPDATE … WHEN NOT MATCHED THEN INSERT …`
pub fn upsert(comptime T: type, dialect: Dialect) []const u8 {
    return switch (dialect) {
        .sqlite => comptime buildUpsert(T, .sqlite),
        .postgres => comptime buildUpsert(T, .postgres),
        .mysql => comptime buildUpsert(T, .mysql),
        .mssql => comptime buildUpsert(T, .mssql),
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

test "UPSERT: SQLite ON CONFLICT DO UPDATE SET col = excluded.col" {
    try testing.expectEqualStrings(
        "INSERT INTO \"atp_accounts\" (\"id\", \"handle\", \"email\", \"role\") VALUES (?, ?, ?, ?)" ++
            " ON CONFLICT (\"id\") DO UPDATE SET \"handle\" = excluded.\"handle\", \"email\" = excluded.\"email\", \"role\" = excluded.\"role\"",
        upsert(Account, .sqlite),
    );
}

test "UPSERT: Postgres ON CONFLICT DO UPDATE SET col = EXCLUDED.col, $N placeholders" {
    try testing.expectEqualStrings(
        "INSERT INTO \"atp_accounts\" (\"id\", \"handle\", \"email\", \"role\") VALUES ($1, $2, $3, $4)" ++
            " ON CONFLICT (\"id\") DO UPDATE SET \"handle\" = EXCLUDED.\"handle\", \"email\" = EXCLUDED.\"email\", \"role\" = EXCLUDED.\"role\"",
        upsert(Account, .postgres),
    );
}

test "UPSERT: MySQL ON DUPLICATE KEY UPDATE col = VALUES(col)" {
    try testing.expectEqualStrings(
        "INSERT INTO `atp_accounts` (`id`, `handle`, `email`, `role`) VALUES (?, ?, ?, ?)" ++
            " ON DUPLICATE KEY UPDATE `handle` = VALUES(`handle`), `email` = VALUES(`email`), `role` = VALUES(`role`)",
        upsert(Account, .mysql),
    );
}

test "UPSERT: MS SQL MERGE keyed on PK, source bound once" {
    try testing.expectEqualStrings(
        "MERGE [atp_accounts] AS tgt USING (VALUES (@p1, @p2, @p3, @p4)) AS src ([id], [handle], [email], [role])" ++
            " ON tgt.[id] = src.[id]" ++
            " WHEN MATCHED THEN UPDATE SET [handle] = src.[handle], [email] = src.[email], [role] = src.[role]" ++
            " WHEN NOT MATCHED THEN INSERT ([id], [handle], [email], [role]) VALUES (src.[id], src.[handle], src.[email], src.[role]);",
        upsert(Account, .mssql),
    );
}

test "UPSERT: auto-PK entity omits the id column, conflict targets the auto id" {
    // The auto PK is DB-assigned, so it is absent from the column list; the
    // conflict key is still the auto id and the lone non-PK column is updated.
    try testing.expectEqualStrings(
        "INSERT INTO \"things\" (\"name\") VALUES (?)" ++
            " ON CONFLICT (\"id\") DO UPDATE SET \"name\" = excluded.\"name\"",
        upsert(AutoEntity, .sqlite),
    );
    try testing.expectEqualStrings(
        "INSERT INTO `things` (`name`) VALUES (?)" ++
            " ON DUPLICATE KEY UPDATE `name` = VALUES(`name`)",
        upsert(AutoEntity, .mysql),
    );
    try testing.expectEqualStrings(
        "MERGE [things] AS tgt USING (VALUES (@p1)) AS src ([name])" ++
            " ON tgt.[id] = src.[id]" ++
            " WHEN MATCHED THEN UPDATE SET [name] = src.[name]" ++
            " WHEN NOT MATCHED THEN INSERT ([name]) VALUES (src.[name]);",
        upsert(AutoEntity, .mssql),
    );
}

test "UPSERT: PK-only table degrades to DO NOTHING (sqlite/postgres)" {
    const PkOnly = struct {
        pub const zorm_table = "tags";
        id: fields.Pk(32) = .{},
    };
    try testing.expectEqualStrings(
        "INSERT INTO \"tags\" (\"id\") VALUES (?) ON CONFLICT (\"id\") DO NOTHING",
        upsert(PkOnly, .sqlite),
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

// ── Composite primary key (Z4) ──────────────────────────────────────────

// Composite PK with two TEXT parts (the common multi-tenant shape:
// (tenant, resource)). Declaring two PK fields forms the composite key; the
// WHERE / conflict clauses cover BOTH columns in declaration order.
const TenantDoc = struct {
    pub const zorm_table = "tenant_docs";
    tenant: fields.Pk(32) = .{},
    doc_id: fields.Pk(32) = .{},
    title: fields.Text(64) = .{},
};

// A heterogeneous composite PK: (tenant_id TEXT, seq INTEGER) — proves the
// int-bound PK part in the WHERE clause.
const Membership = struct {
    pub const zorm_table = "memberships";
    tenant_id: fields.Pk(32) = .{},
    seq: fields.PkInt = .{},
    role: fields.Text(16) = .{},
};

test "composite PK (text+int): WHERE binds both, int part included" {
    try testing.expectEqualStrings(
        "SELECT \"tenant_id\", \"seq\", \"role\" FROM \"memberships\" WHERE \"tenant_id\" = $1 AND \"seq\" = $2",
        selectByPk(Membership, .postgres),
    );
    try testing.expectEqualStrings(
        "UPDATE \"memberships\" SET \"role\" = ? WHERE \"tenant_id\" = ? AND \"seq\" = ?",
        update(Membership, .sqlite),
    );
}

test "composite PK: selectByPk WHERE ANDs every PK column (all dialects)" {
    try testing.expectEqualStrings(
        "SELECT \"tenant\", \"doc_id\", \"title\" FROM \"tenant_docs\" WHERE \"tenant\" = ? AND \"doc_id\" = ?",
        selectByPk(TenantDoc, .sqlite),
    );
    try testing.expectEqualStrings(
        "SELECT \"tenant\", \"doc_id\", \"title\" FROM \"tenant_docs\" WHERE \"tenant\" = $1 AND \"doc_id\" = $2",
        selectByPk(TenantDoc, .postgres),
    );
    try testing.expectEqualStrings(
        "SELECT `tenant`, `doc_id`, `title` FROM `tenant_docs` WHERE `tenant` = ? AND `doc_id` = ?",
        selectByPk(TenantDoc, .mysql),
    );
    try testing.expectEqualStrings(
        "SELECT [tenant], [doc_id], [title] FROM [tenant_docs] WHERE [tenant] = @p1 AND [doc_id] = @p2",
        selectByPk(TenantDoc, .mssql),
    );
}

test "composite PK: update SETs non-PK then ANDs all PK columns in WHERE" {
    // SET has 1 col (title → $1); WHERE binds the two PK parts ($2, $3).
    try testing.expectEqualStrings(
        "UPDATE \"tenant_docs\" SET \"title\" = $1 WHERE \"tenant\" = $2 AND \"doc_id\" = $3",
        update(TenantDoc, .postgres),
    );
    try testing.expectEqualStrings(
        "UPDATE \"tenant_docs\" SET \"title\" = ? WHERE \"tenant\" = ? AND \"doc_id\" = ?",
        update(TenantDoc, .sqlite),
    );
    try testing.expectEqualStrings(
        "UPDATE [tenant_docs] SET [title] = @p1 WHERE [tenant] = @p2 AND [doc_id] = @p3",
        update(TenantDoc, .mssql),
    );
}

test "composite PK: deleteByPk ANDs all PK columns" {
    try testing.expectEqualStrings(
        "DELETE FROM \"tenant_docs\" WHERE \"tenant\" = ? AND \"doc_id\" = ?",
        deleteByPk(TenantDoc, .sqlite),
    );
    try testing.expectEqualStrings(
        "DELETE FROM `tenant_docs` WHERE `tenant` = ? AND `doc_id` = ?",
        deleteByPk(TenantDoc, .mysql),
    );
}

test "composite PK: upsert conflict target / merge key lists every PK column" {
    // sqlite/postgres: ON CONFLICT (pk1, pk2)
    try testing.expectEqualStrings(
        "INSERT INTO \"tenant_docs\" (\"tenant\", \"doc_id\", \"title\") VALUES (?, ?, ?)" ++
            " ON CONFLICT (\"tenant\", \"doc_id\") DO UPDATE SET \"title\" = excluded.\"title\"",
        upsert(TenantDoc, .sqlite),
    );
    try testing.expectEqualStrings(
        "INSERT INTO \"tenant_docs\" (\"tenant\", \"doc_id\", \"title\") VALUES ($1, $2, $3)" ++
            " ON CONFLICT (\"tenant\", \"doc_id\") DO UPDATE SET \"title\" = EXCLUDED.\"title\"",
        upsert(TenantDoc, .postgres),
    );
    // mssql MERGE: ON tgt.pk1 = src.pk1 AND tgt.pk2 = src.pk2
    try testing.expectEqualStrings(
        "MERGE [tenant_docs] AS tgt USING (VALUES (@p1, @p2, @p3)) AS src ([tenant], [doc_id], [title])" ++
            " ON tgt.[tenant] = src.[tenant] AND tgt.[doc_id] = src.[doc_id]" ++
            " WHEN MATCHED THEN UPDATE SET [title] = src.[title]" ++
            " WHEN NOT MATCHED THEN INSERT ([tenant], [doc_id], [title]) VALUES (src.[tenant], src.[doc_id], src.[title]);",
        upsert(TenantDoc, .mssql),
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
