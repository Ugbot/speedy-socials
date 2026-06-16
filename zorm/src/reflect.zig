//! Comptime entity reflection. Turns a plain Zig struct (declared with
//! `fields.zig` types + native scalars/enums/optionals) into the column
//! metadata zorm needs — with zero runtime cost. All of this runs in
//! `comptime`; the results are `comptime`-known arrays the DDL/SQL/codec
//! layers consume.
//!
//! Entity contract: a struct with `pub const zorm_table: []const u8` and
//! exactly one primary-key field (`Pk(N)` or `AutoPk`). ≤16 columns, each
//! text/blob field ≤1024 bytes (the backend's `Row` limits) — violations
//! fail the build.

const std = @import("std");
const fields = @import("fields.zig");

pub const ColType = enum { text, integer, real, blob };
pub const BindKind = enum { int, real, text, blob };

pub const ColumnSpec = struct {
    name: []const u8, // == field name
    col_type: ColType,
    bind_kind: BindKind,
    nullable: bool,
    is_pk: bool,
    pk_auto: bool, // i64 autoincrement PK (DB-assigned id)
    byte_cap: usize, // text/blob capacity (0 for scalars)
    is_enum: bool, // stored as text by @tagName; read via stringToEnum
    field_index: usize, // index in std.meta.fields(T)
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
            .timestamp => {
                spec.col_type = .integer;
                spec.bind_kind = .int;
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

        // Collect column specs (skipping relation fields).
        var cols: [all.len]ColumnSpec = undefined;
        var n: usize = 0;
        var pk_idx: ?usize = null;
        var pk_is_auto = false;
        for (all, 0..) |f, i| {
            if (isRelation(f.type)) continue;
            const spec = columnSpec(f.name, f.type, i);
            if (spec.is_pk) {
                if (pk_idx != null) @compileError("zorm: entity '" ++ @typeName(T) ++ "' has more than one primary key (v1 supports exactly one)");
                pk_idx = n;
                pk_is_auto = spec.pk_auto;
            }
            if (spec.byte_cap > 1024) @compileError("zorm: field '" ++ spec.name ++ "' capacity exceeds the 1024-byte column limit");
            cols[n] = spec;
            n += 1;
        }
        if (n == 0) @compileError("zorm: entity '" ++ @typeName(T) ++ "' has no persisted columns");
        if (n > 16) @compileError("zorm: entity '" ++ @typeName(T) ++ "' has more than 16 columns (the backend Row limit)");
        if (pk_idx == null) @compileError("zorm: entity '" ++ @typeName(T) ++ "' has no primary key (add a `Pk(N)` or `AutoPk` field)");

        const final = cols[0..n].*;
        return struct {
            pub const Entity = T;
            pub const table: []const u8 = T.zorm_table;
            pub const columns = final;
            pub const column_count = n;
            pub const pk_index: usize = pk_idx.?;
            pub const pk_auto: bool = pk_is_auto;
            pub const pk_column: ColumnSpec = final[pk_idx.?];
        };
    }
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
}
