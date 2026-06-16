//! Marshaling between entity fields and the storage contract's
//! `BindValue` (write) / `ColumnValue` (read). All per-field dispatch is
//! comptime (`inline for` over `TableInfo(T).columns`); no runtime
//! reflection, no allocation.

const std = @import("std");
const contract = @import("contract.zig");
const reflect = @import("reflect.zig");
const fields = @import("fields.zig");

const BindValue = contract.BindValue;
const ColumnValue = contract.ColumnValue;

/// The Zig type of a primary key value passed to find/delete: `[]const u8`
/// for a text PK, `i64` for an auto/integer PK.
pub fn PkValue(comptime T: type) type {
    const info = reflect.TableInfo(T);
    return if (info.pk_column.bind_kind == .text) []const u8 else i64;
}

/// Convert a NON-optional field, given a POINTER into the caller's entity,
/// to a `BindValue`. The pointer (not a copy) is essential: text/blob
/// `BindValue`s borrow the field's bytes, so they must reference the
/// caller's stable entity — a by-value copy would dangle on return.
fn bindScalar(comptime col: reflect.ColumnSpec, ptr: anytype) BindValue {
    const V = @TypeOf(ptr.*);
    return switch (col.bind_kind) {
        .text => if (col.is_enum)
            .{ .text = @tagName(ptr.*) }
        else
            .{ .text = ptr.slice() }, // Text/Bytes/Pk (slice() takes *const Self)
        .blob => .{ .blob = ptr.slice() },
        .int => blk: {
            // Timestamp / AutoPk wrappers, bool, or native int.
            if (@typeInfo(V) == .@"struct") {
                if (@hasField(V, "unix")) break :blk .{ .int = ptr.unix };
                if (@hasField(V, "value")) break :blk .{ .int = ptr.value };
            }
            if (V == bool) break :blk .{ .int = if (ptr.*) @as(i64, 1) else 0 };
            break :blk .{ .int = @intCast(ptr.*) };
        },
        .real => .{ .real = @floatCast(ptr.*) },
    };
}

/// `BindValue` for one column of `entity`. Honors nullability. Borrows
/// bytes from `entity`, which must outlive the returned `BindValue`.
pub fn bindColumn(comptime T: type, comptime col: reflect.ColumnSpec, entity: *const T) BindValue {
    if (col.nullable) {
        if (@field(entity.*, col.name)) |*inner| return bindScalar(col, inner);
        return .null_;
    }
    return bindScalar(col, &@field(entity.*, col.name));
}

/// Fill `out` with bind values for every column, in `TableInfo` order.
/// Returns the count written. `out.len` must be ≥ column_count.
pub fn bindAll(comptime T: type, entity: *const T, out: []BindValue) usize {
    const info = reflect.TableInfo(T);
    inline for (info.columns, 0..) |col, i| {
        out[i] = bindColumn(T, col, entity);
    }
    return info.column_count;
}

/// Fill `out` with bind values for every NON-auto-PK column (the columns an
/// INSERT supplies; an auto PK is DB-assigned). Returns count written.
pub fn bindInsert(comptime T: type, entity: *const T, out: []BindValue) usize {
    const info = reflect.TableInfo(T);
    var n: usize = 0;
    inline for (info.columns) |col| {
        if (col.pk_auto) continue;
        out[n] = bindColumn(T, col, entity);
        n += 1;
    }
    return n;
}

/// Fill `out` with bind values in UPDATE order: every NON-PK column (the
/// SET list, in `TableInfo` order) followed by the PK (the WHERE clause).
/// Matches the placeholder numbering `sql.update` emits. Returns count.
pub fn bindUpdate(comptime T: type, entity: *const T, out: []BindValue) usize {
    const info = reflect.TableInfo(T);
    var n: usize = 0;
    inline for (info.columns) |col| {
        if (col.is_pk) continue;
        out[n] = bindColumn(T, col, entity);
        n += 1;
    }
    out[n] = bindColumn(T, info.pk_column, entity);
    return n + 1;
}

/// The PK column's bind value for `entity`.
pub fn bindPk(comptime T: type, entity: *const T) BindValue {
    const info = reflect.TableInfo(T);
    return bindColumn(T, info.pk_column, entity);
}

/// A bind value from a free-standing PK value (for find/delete-by-pk).
pub fn bindPkValue(comptime T: type, pk: PkValue(T)) BindValue {
    const info = reflect.TableInfo(T);
    return if (info.pk_column.bind_kind == .text) .{ .text = pk } else .{ .int = pk };
}

/// Read one `ColumnValue` into the corresponding entity field.
pub fn readColumn(comptime T: type, comptime col: reflect.ColumnSpec, cv: *const ColumnValue, out: *T) void {
    const F = @TypeOf(@field(out.*, col.name));

    if (col.nullable) {
        if (cv.kind == .null_) {
            @field(out.*, col.name) = null;
            return;
        }
        // Non-null: build the inner value, then wrap.
        const Inner = @typeInfo(F).optional.child;
        var inner: Inner = if (@typeInfo(Inner) == .@"struct") .{} else undefined;
        readScalar(col, Inner, cv, &inner);
        @field(out.*, col.name) = inner;
        return;
    }
    readScalar(col, F, cv, &@field(out.*, col.name));
}

fn readScalar(comptime col: reflect.ColumnSpec, comptime F: type, cv: *const ColumnValue, dst: *F) void {
    switch (col.bind_kind) {
        .text => {
            if (col.is_enum) {
                dst.* = std.meta.stringToEnum(F, cv.bytes()) orelse dst.*;
            } else {
                dst.set(cv.bytes()); // Text/Bytes/Pk
            }
        },
        .blob => dst.set(cv.bytes()),
        .int => {
            if (@typeInfo(F) == .@"struct") {
                if (@hasField(F, "unix")) {
                    dst.unix = cv.int_val;
                } else if (@hasField(F, "value")) {
                    dst.value = cv.int_val;
                }
            } else if (F == bool) {
                dst.* = cv.int_val != 0;
            } else {
                dst.* = @intCast(cv.int_val);
            }
        },
        .real => dst.* = @floatCast(cv.real_val),
    }
}

/// Materialize a full `Row` into an entity (columns in `TableInfo` order).
pub fn rowToEntity(comptime T: type, row: *const contract.Row, out: *T) void {
    const info = reflect.TableInfo(T);
    inline for (info.columns, 0..) |col, i| {
        readColumn(T, col, &row.columns[i], out);
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

const Role = enum { member, admin };
const Account = struct {
    pub const zorm_table = "atp_accounts";
    id: fields.Pk(64) = .{},
    handle: fields.Text(64) = .{},
    email: ?fields.Text(64) = null,
    role: Role = .member,
    confirmed: bool = false,
    created_at: fields.Timestamp = .{},
    score: f64 = 0,
};

test "bindAll + rowToEntity round-trips every field kind" {
    var a = Account{
        .id = fields.Pk(64).from("did:plc:abc"),
        .handle = fields.Text(64).from("alice"),
        .email = fields.Text(64).from("a@x.test"),
        .role = .admin,
        .confirmed = true,
        .created_at = .{ .unix = 1234 },
        .score = 2.5,
    };

    var args: [16]BindValue = undefined;
    const n = bindAll(Account, &a, &args);
    try testing.expectEqual(@as(usize, 7), n);
    try testing.expectEqualStrings("did:plc:abc", args[0].text);
    try testing.expectEqualStrings("alice", args[1].text);
    try testing.expectEqualStrings("a@x.test", args[2].text);
    try testing.expectEqualStrings("admin", args[3].text); // enum by name
    try testing.expectEqual(@as(i64, 1), args[4].int); // bool
    try testing.expectEqual(@as(i64, 1234), args[5].int); // timestamp
    try testing.expectEqual(@as(f64, 2.5), args[6].real);

    // Build a Row from the binds and read it back.
    var row: contract.Row = .{};
    row.column_count = 7;
    inline for (0..7) |i| {
        switch (args[i]) {
            .text => |s| {
                row.columns[i].kind = .text;
                @memcpy(row.columns[i].bytes_buf[0..s.len], s);
                row.columns[i].bytes_len = @intCast(s.len);
            },
            .int => |v| {
                row.columns[i].kind = .int;
                row.columns[i].int_val = v;
            },
            .real => |v| {
                row.columns[i].kind = .real;
                row.columns[i].real_val = v;
            },
            else => {},
        }
    }
    var b: Account = .{};
    rowToEntity(Account, &row, &b);
    try testing.expectEqualStrings("did:plc:abc", b.id.slice());
    try testing.expectEqualStrings("alice", b.handle.slice());
    try testing.expect(b.email != null);
    try testing.expectEqualStrings("a@x.test", b.email.?.slice());
    try testing.expectEqual(Role.admin, b.role);
    try testing.expect(b.confirmed);
    try testing.expectEqual(@as(i64, 1234), b.created_at.unix);
    try testing.expectEqual(@as(f64, 2.5), b.score);
}

test "nullable column binds null + reads back null" {
    var a = Account{ .id = fields.Pk(64).from("x"), .handle = fields.Text(64).from("h") };
    var args: [16]BindValue = undefined;
    _ = bindAll(Account, &a, &args);
    try testing.expectEqual(BindValue.null_, args[2]); // email null

    var row: contract.Row = .{};
    row.column_count = 7;
    row.columns[2].kind = .null_;
    var b: Account = .{ .email = fields.Text(64).from("stale") };
    readColumn(Account, reflect.TableInfo(Account).columns[2], &row.columns[2], &b);
    try testing.expect(b.email == null);
}

test "bindInsert skips the auto PK column" {
    const Auto = struct {
        pub const zorm_table = "t";
        id: fields.AutoPk = .{},
        name: fields.Text(8) = .{},
    };
    var e = Auto{ .name = fields.Text(8).from("hi") };
    var args: [16]BindValue = undefined;
    const n = bindInsert(Auto, &e, &args);
    try testing.expectEqual(@as(usize, 1), n); // only `name`
    try testing.expectEqualStrings("hi", args[0].text);
}
