//! Comptime entity reflection. Turns a plain Zig struct (declared with
//! `fields.zig` types + native scalars/enums/optionals) into the column
//! metadata zorm needs — with zero runtime cost. All of this runs in
//! `comptime`; the results are `comptime`-known arrays the DDL/SQL/codec
//! layers consume.
//!
//! Entity contract: a struct with `pub const zorm_table: []const u8` and
//! at least one primary-key field (`Pk(N)` / `AutoPk` / `pk_text`). A single
//! PK is the common case; declaring two or more PK fields forms a COMPOSITE
//! primary key (every PK field becomes part of the key, in declaration
//! order). An auto-increment PK (`AutoPk`) may only appear as a SINGLE-column
//! PK — a composite key is made of caller-supplied (text/explicit) columns.
//! ≤16 columns, each text/blob field ≤1024 bytes (the backend's `Row`
//! limits) — violations fail the build.

const std = @import("std");
const fields = @import("fields.zig");

pub const ColType = enum { text, integer, real, blob, decimal, uuid, json, date, datetime };
pub const BindKind = enum { int, real, text, blob };

pub const ColumnSpec = struct {
    name: []const u8, // == field name
    col_type: ColType,
    bind_kind: BindKind,
    nullable: bool,
    is_pk: bool,
    pk_auto: bool, // i64 autoincrement PK (DB-assigned id)
    byte_cap: usize, // text/blob/json capacity (0 for scalars)
    is_enum: bool, // stored as text by @tagName; read via stringToEnum
    field_index: usize, // index in std.meta.fields(T)
    // Decimal numeric type only: total precision + fractional scale.
    decimal_precision: usize = 0,
    decimal_scale: usize = 0,
};

/// Strip a leading `?` and report nullability.
fn unwrapOptional(comptime F: type) struct { T: type, nullable: bool } {
    return switch (@typeInfo(F)) {
        .optional => |o| .{ .T = o.child, .nullable = true },
        else => .{ .T = F, .nullable = false },
    };
}

/// Is this field type a relation (BelongsTo/HasMany/HasOne)? Relations
/// don't own a column on this table (except BelongsTo's FK, which is a
/// separate scalar field). Detected by the `zorm_relation` marker.
pub fn isRelation(comptime F: type) bool {
    const u = unwrapOptional(F);
    return @typeInfo(u.T) == .@"struct" and @hasDecl(u.T, "zorm_relation");
}

/// Map one field (name + type) to its column spec. Caller guarantees the
/// field is not a relation.
pub fn columnSpec(comptime field_name: []const u8, comptime F: type, comptime idx: usize) ColumnSpec {
    const u = unwrapOptional(F);
    const T = u.T;
    var spec: ColumnSpec = .{
        .name = field_name,
        .col_type = .text,
        .bind_kind = .text,
        .nullable = u.nullable,
        .is_pk = false,
        .pk_auto = false,
        .byte_cap = 0,
        .is_enum = false,
        .field_index = idx,
    };

    const is_container = switch (@typeInfo(T)) {
        .@"struct", .@"enum", .@"union", .@"opaque" => true,
        else => false,
    };
    if (is_container and @hasDecl(T, "zorm_kind")) {
        switch (T.zorm_kind) {
            .text => {
                spec.col_type = .text;
                spec.bind_kind = .text;
                spec.byte_cap = T.capacity;
            },
            .pk_text => {
                spec.col_type = .text;
                spec.bind_kind = .text;
                spec.byte_cap = T.capacity;
                spec.is_pk = true;
            },
            .bytes => {
                spec.col_type = .blob;
                spec.bind_kind = .blob;
                spec.byte_cap = T.capacity;
            },
            .pk_auto => {
                spec.col_type = .integer;
                spec.bind_kind = .int;
                spec.is_pk = true;
                spec.pk_auto = true;
            },
            .pk_int => {
                spec.col_type = .integer;
                spec.bind_kind = .int;
                spec.is_pk = true;
                // NOT auto: caller supplies the value (composite-key member).
            },
            .timestamp => {
                spec.col_type = .integer;
                spec.bind_kind = .int;
            },
            // The following all marshal as text (lossless string forms) but
            // carry distinct ColTypes so the DDL layer emits the right SQL
            // type keyword per dialect.
            .decimal => {
                spec.col_type = .decimal;
                spec.bind_kind = .text;
                spec.byte_cap = T.capacity;
                spec.decimal_precision = T.sql_precision;
                spec.decimal_scale = T.sql_scale;
            },
            .uuid => {
                spec.col_type = .uuid;
                spec.bind_kind = .text;
                spec.byte_cap = T.capacity; // 36 (canonical string)
            },
            .json => {
                spec.col_type = .json;
                spec.bind_kind = .text;
                spec.byte_cap = T.capacity;
            },
            .date => {
                spec.col_type = .date;
                spec.bind_kind = .text;
                spec.byte_cap = T.capacity;
            },
            .datetime => {
                spec.col_type = .datetime;
                spec.bind_kind = .text;
                spec.byte_cap = T.capacity;
            },
        }
        return spec;
    }

    // Native types.
    switch (@typeInfo(T)) {
        .int => {
            spec.col_type = .integer;
            spec.bind_kind = .int;
        },
        .float => {
            spec.col_type = .real;
            spec.bind_kind = .real;
        },
        .bool => {
            spec.col_type = .integer;
            spec.bind_kind = .int;
        },
        .@"enum" => {
            spec.col_type = .text;
            spec.bind_kind = .text;
            spec.is_enum = true;
            // Capacity = longest tag name, so dialects that need a length
            // (MySQL VARCHAR(N) / MSSQL NVARCHAR(N)) emit a valid, tight type.
            var max_tag: usize = 1;
            for (std.meta.fields(T)) |ef| {
                if (ef.name.len > max_tag) max_tag = ef.name.len;
            }
            spec.byte_cap = max_tag;
        },
        else => @compileError("zorm: unsupported field type '" ++ @typeName(T) ++ "' for field '" ++ field_name ++ "' — use a zorm field type, an int/float/bool, or an enum"),
    }
    return spec;
}

/// Compile-time table metadata for entity `T`.
pub fn TableInfo(comptime T: type) type {
    comptime {
        if (!@hasDecl(T, "zorm_table")) {
            @compileError("zorm: entity '" ++ @typeName(T) ++ "' must declare `pub const zorm_table: []const u8`");
        }
        const all = std.meta.fields(T);

        // Collect column specs (skipping relation fields) and the indexes of
        // every PK column (in declaration order — a composite key keeps that
        // order for its WHERE clause and bind layout).
        var cols: [all.len]ColumnSpec = undefined;
        var pk_idxs: [all.len]usize = undefined;
        var n: usize = 0;
        var pk_n: usize = 0;
        var pk_is_auto = false;
        for (all, 0..) |f, i| {
            if (isRelation(f.type)) continue;
            const spec = columnSpec(f.name, f.type, i);
            if (spec.is_pk) {
                if (spec.pk_auto) pk_is_auto = true;
                pk_idxs[pk_n] = n;
                pk_n += 1;
            }
            if (spec.byte_cap > 1024) @compileError("zorm: field '" ++ spec.name ++ "' capacity exceeds the 1024-byte column limit");
            cols[n] = spec;
            n += 1;
        }
        if (n == 0) @compileError("zorm: entity '" ++ @typeName(T) ++ "' has no persisted columns");
        if (n > 16) @compileError("zorm: entity '" ++ @typeName(T) ++ "' has more than 16 columns (the backend Row limit)");
        if (pk_n == 0) @compileError("zorm: entity '" ++ @typeName(T) ++ "' has no primary key (add a `Pk(N)` / `AutoPk` field)");
        // An auto-increment PK is DB-assigned, so it cannot be one column of a
        // composite (caller-supplied) key.
        if (pk_is_auto and pk_n > 1) @compileError("zorm: entity '" ++ @typeName(T) ++ "' mixes an auto-increment PK with other PK columns — a composite key must be all caller-supplied columns");

        const final = cols[0..n].*;
        const final_pk_idxs = pk_idxs[0..pk_n].*;
        return struct {
            pub const Entity = T;
            pub const table: []const u8 = T.zorm_table;
            pub const columns = final;
            pub const column_count = n;
            // Composite-PK metadata: indexes (into `columns`) of every PK
            // column, in declaration order, plus the count.
            pub const pk_indexes = final_pk_idxs;
            pub const pk_count: usize = pk_n;
            pub const composite_pk: bool = pk_n > 1;
            // Single-PK accessors (the common case): the FIRST PK column. For a
            // composite key these still resolve to its first part, which is all
            // the single-PK code paths (auto-PK write-back, FK ref column) need.
            pub const pk_index: usize = final_pk_idxs[0];
            pub const pk_auto: bool = pk_is_auto;
            pub const pk_column: ColumnSpec = final[final_pk_idxs[0]];
            /// The ColumnSpec of PK part `k` (0-based, in declaration order).
            pub fn pkColumn(comptime k: usize) ColumnSpec {
                return final[final_pk_idxs[k]];
            }
        };
    }
}

/// One foreign-key constraint derived from a `BelongsTo` relation field.
/// The ON DELETE / ON UPDATE actions are pre-resolved to their SQL clause
/// text so this layer needs no dependency on `relations`.
pub const FkSpec = struct {
    /// FK column on THIS table (the relation's `foreign_key`).
    local_col: []const u8,
    /// Referenced table (the parent entity's `zorm_table`).
    ref_table: []const u8,
    /// Referenced column (the parent's primary key).
    ref_col: []const u8,
    /// "" (default) or "CASCADE" / "RESTRICT" / "SET NULL" / "SET DEFAULT".
    on_delete_sql: []const u8,
    on_update_sql: []const u8,
};

/// Foreign keys for entity `T`, derived from its `BelongsTo` relation fields.
/// A relation is recognised structurally (the `zorm_relation` marker + a
/// `belongs_to` `kind`), so `reflect` stays independent of `relations`.
pub fn foreignKeys(comptime T: type) []const FkSpec {
    const out = comptime blk: {
        const all = std.meta.fields(T);
        var specs: [all.len]FkSpec = undefined;
        var n: usize = 0;
        for (all) |f| {
            const F = f.type;
            if (@typeInfo(F) != .@"struct") continue;
            if (!@hasDecl(F, "zorm_relation")) continue;
            if (!@hasDecl(F, "kind")) continue;
            if (!std.mem.eql(u8, @tagName(F.kind), "belongs_to")) continue;

            // The FK column must be a real column of T.
            const info = TableInfo(T);
            var found = false;
            for (info.columns) |c| {
                if (std.mem.eql(u8, c.name, F.foreign_key)) found = true;
            }
            if (!found) @compileError("zorm: BelongsTo foreign key '" ++ F.foreign_key ++ "' is not a column of " ++ @typeName(T));

            const pinfo = TableInfo(F.Target);
            specs[n] = .{
                .local_col = F.foreign_key,
                .ref_table = pinfo.table,
                .ref_col = pinfo.pk_column.name,
                .on_delete_sql = F.fk_opts.on_delete.sql(),
                .on_update_sql = F.fk_opts.on_update.sql(),
            };
            n += 1;
        }
        break :blk specs[0..n].*;
    };
    return &out;
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

const Role = enum { member, admin };
const Account = struct {
    pub const zorm_table = "atp_accounts";
    id: fields.Pk(64) = .{},
    handle: fields.Text(253) = .{},
    email: ?fields.Text(320) = null,
    role: Role = .member,
    confirmed: bool = false,
    created_at: fields.Timestamp = .{},
    score: f64 = 0,
};

test "TableInfo: maps Account columns + detects PK + enum + nullable" {
    const info = TableInfo(Account);
    try testing.expectEqualStrings("atp_accounts", info.table);
    try testing.expectEqual(@as(usize, 7), info.column_count);
    try testing.expectEqual(@as(usize, 0), info.pk_index);
    try testing.expect(!info.pk_auto);
    try testing.expectEqualStrings("id", info.pk_column.name);

    // Column kinds.
    try testing.expectEqual(ColType.text, info.columns[0].col_type); // id Pk
    try testing.expect(info.columns[0].is_pk);
    try testing.expectEqual(ColType.text, info.columns[1].col_type); // handle Text
    try testing.expect(info.columns[2].nullable); // email ?Text
    try testing.expect(info.columns[3].is_enum); // role enum
    try testing.expectEqual(ColType.integer, info.columns[4].col_type); // confirmed bool
    try testing.expectEqual(ColType.integer, info.columns[5].col_type); // created_at Timestamp
    try testing.expectEqual(ColType.real, info.columns[6].col_type); // score f64
}

const AutoEntity = struct {
    pub const zorm_table = "things";
    id: fields.AutoPk = .{},
    name: fields.Text(32) = .{},
};

test "TableInfo: AutoPk detected as auto primary key" {
    const info = TableInfo(AutoEntity);
    try testing.expectEqual(@as(usize, 2), info.column_count);
    try testing.expect(info.pk_auto);
    try testing.expectEqual(ColType.integer, info.pk_column.col_type);
    // Single-PK metadata: one PK part, not composite.
    try testing.expectEqual(@as(usize, 1), info.pk_count);
    try testing.expect(!info.composite_pk);
}

const TenantDoc = struct {
    pub const zorm_table = "tenant_docs";
    tenant: fields.Pk(32) = .{},
    seq: fields.PkInt = .{},
    title: fields.Text(64) = .{},
};

test "TableInfo: composite PK collects every PK column in declaration order" {
    const info = TableInfo(TenantDoc);
    try testing.expectEqual(@as(usize, 3), info.column_count);
    try testing.expect(info.composite_pk);
    try testing.expectEqual(@as(usize, 2), info.pk_count);
    // Indexes into `columns`, in declaration order.
    try testing.expectEqual(@as(usize, 0), info.pk_indexes[0]);
    try testing.expectEqual(@as(usize, 1), info.pk_indexes[1]);
    // pkColumn(k) resolves each PK part; bind kinds differ (text, int).
    try testing.expectEqualStrings("tenant", info.pkColumn(0).name);
    try testing.expectEqual(BindKind.text, info.pkColumn(0).bind_kind);
    try testing.expectEqualStrings("seq", info.pkColumn(1).name);
    try testing.expectEqual(BindKind.int, info.pkColumn(1).bind_kind);
    try testing.expect(!info.pkColumn(1).pk_auto); // PkInt is caller-supplied
    // Single-PK accessors still resolve to the FIRST PK part (compat).
    try testing.expectEqual(@as(usize, 0), info.pk_index);
    try testing.expectEqualStrings("tenant", info.pk_column.name);
    try testing.expect(!info.pk_auto);
}
