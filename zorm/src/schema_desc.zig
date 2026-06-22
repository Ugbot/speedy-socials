//! zorm S7 — comptime SCHEMA DESCRIPTOR.
//!
//! Turns a zorm entity into stable, cross-language schema metadata:
//!   * an ordered list of `{name, wire_type, nullable}` fields,
//!   * a stable 64-bit version `fingerprint` (FNV-1a over the canonical
//!     schema text) that changes iff a field is added/removed/renamed/
//!     retyped or the table name changes, and is identical across builds
//!     otherwise, and
//!   * `toJson` — emit a JSON descriptor into a caller-supplied buffer
//!     (bounded, no heap) for schema-registry / cross-language consumers.
//!
//! Dependency-free (imports nothing from the host app). All reflection at
//! comptime; the wire codec in `codec.zig` consumes `Schema(T)` to encode
//! payloads positionally with this fingerprint prefixed.

const std = @import("std");
const contract = @import("contract.zig");
const reflect = @import("reflect.zig");

const Error = contract.Error;

/// Logical wire type a column maps onto. Distinct from `reflect.ColType`
/// (storage type) because the wire codec must distinguish, e.g., a plain
/// i64 from a `timestamp`, an `enum` (text-by-name) from arbitrary text,
/// and bytes (blob) from text. This is the cross-language type alphabet.
pub const WireType = enum {
    i64,
    f64,
    bool,
    text,
    bytes,
    enum_text,
    timestamp,
    decimal,
    uuid,
    json,
    date,
    datetime,

    /// Canonical, stable spelling used in the fingerprint + JSON. Never
    /// reorder/rename these strings without intending a fingerprint break.
    pub fn name(self: WireType) []const u8 {
        return switch (self) {
            .i64 => "i64",
            .f64 => "f64",
            .bool => "bool",
            .text => "text",
            .bytes => "bytes",
            .enum_text => "enum_text",
            .timestamp => "timestamp",
            .decimal => "decimal",
            .uuid => "uuid",
            .json => "json",
            .date => "date",
            .datetime => "datetime",
        };
    }
};

/// One field in the wire schema, in TableInfo column order.
pub const FieldDesc = struct {
    name: []const u8,
    wire_type: WireType,
    nullable: bool,
};

/// Map a reflected column spec to its wire type. The mapping is:
///   text / pk_text → text, bytes → bytes, pk_auto → i64,
///   timestamp → timestamp, int → i64, float → f64, bool → bool,
///   enum → enum_text.
/// Driven entirely by `reflect.ColumnSpec` so it stays in lock-step with
/// the storage reflection.
pub fn wireTypeFor(comptime spec: reflect.ColumnSpec) WireType {
    if (spec.pk_auto) return .i64; // i64 autoincrement PK
    if (spec.is_enum) return .enum_text;
    return switch (spec.bind_kind) {
        .int => switch (spec.col_type) {
            // Timestamp + bool + plain int all bind as `int`; disambiguate
            // via the column type / enum flag set by reflect.
            .integer => disambiguateInt(spec),
            else => .i64,
        },
        .real => .f64,
        // Text-bound columns: distinguish the typed string forms (decimal,
        // uuid, json, date, datetime) from arbitrary text via col_type.
        .text => switch (spec.col_type) {
            .decimal => .decimal,
            .uuid => .uuid,
            .json => .json,
            .date => .date,
            .datetime => .datetime,
            else => .text,
        },
        .blob => .bytes,
    };
}

/// `int`-bound columns cover plain ints, bools, and timestamps. reflect
/// gives bools `col_type=.integer` (same as int) but we can tell a
/// timestamp apart because its byte_cap is 0 and it is not an enum/pk —
/// however int and timestamp are indistinguishable from ColumnSpec alone.
/// So we resolve via the field's declared zorm_kind at the Schema level
/// instead; here we conservatively return .i64 and let `fieldDesc` (which
/// has the field type) override for timestamp/bool.
fn disambiguateInt(comptime spec: reflect.ColumnSpec) WireType {
    _ = spec;
    return .i64;
}

/// Resolve the wire type for a concrete entity field, with full access to
/// the field's Zig type (so `Timestamp` and `bool` are distinguishable
/// from a plain `i64`, which a `ColumnSpec` alone cannot express).
fn fieldWireType(comptime F: type, comptime spec: reflect.ColumnSpec) WireType {
    const T = switch (@typeInfo(F)) {
        .optional => |o| o.child,
        else => F,
    };
    // zorm field-type containers carry a `zorm_kind` marker.
    const is_container = switch (@typeInfo(T)) {
        .@"struct", .@"enum", .@"union", .@"opaque" => true,
        else => false,
    };
    if (is_container and @hasDecl(T, "zorm_kind")) {
        return switch (T.zorm_kind) {
            .text, .pk_text => .text,
            .bytes => .bytes,
            .pk_auto, .pk_int => .i64,
            .timestamp => .timestamp,
            .decimal => .decimal,
            .uuid => .uuid,
            .json => .json,
            .date => .date,
            .datetime => .datetime,
        };
    }
    return switch (@typeInfo(T)) {
        .int => .i64,
        .float => .f64,
        .bool => .bool,
        .@"enum" => .enum_text,
        else => @compileError("zorm schema: unsupported field type '" ++ @typeName(T) ++ "' for field '" ++ spec.name ++ "'"),
    };
}

/// Comptime schema metadata for entity `T`.
pub fn Schema(comptime T: type) type {
    comptime {
        const info = reflect.TableInfo(T);
        const all = std.meta.fields(T);

        var descs: [info.column_count]FieldDesc = undefined;
        for (info.columns, 0..) |spec, i| {
            const F = all[spec.field_index].type;
            descs[i] = .{
                .name = spec.name,
                .wire_type = fieldWireType(F, spec),
                .nullable = spec.nullable,
            };
        }
        const final_descs = descs;

        // Canonical schema text → fingerprint. Format (stable, never
        // reformat without intending a break):
        //   "<table>\n<name>:<wiretype>:<0|1>\n..." (one line per field,
        //   trailing newline per field). FNV-1a/64 with the standard
        //   offset basis is build-stable (pure function of the bytes).
        var hasher = std.hash.Fnv1a_64.init();
        hasher.update(info.table);
        hasher.update("\n");
        for (final_descs) |d| {
            hasher.update(d.name);
            hasher.update(":");
            hasher.update(d.wire_type.name());
            hasher.update(":");
            hasher.update(if (d.nullable) "1" else "0");
            hasher.update("\n");
        }
        const fp = hasher.final();

        return struct {
            pub const Entity = T;
            pub const table: []const u8 = info.table;
            pub const fields_desc = final_descs;
            pub const field_count: usize = info.column_count;
            /// Stable 64-bit version fingerprint (FNV-1a over canonical text).
            pub const fingerprint: u64 = fp;
        };
    }
}

/// Emit a JSON schema descriptor into the caller buffer `out`:
///   {"table":"...","fingerprint":<u64>,"fields":[
///     {"name":"...","type":"...","nullable":true|false},...]}
/// Bounded — returns `error.BufferTooSmall` (a zorm `Error`) if it does
/// not fit. Returns the written slice. No heap allocation.
pub fn toJson(comptime T: type, out: []u8) Error![]const u8 {
    const S = Schema(T);
    var w = Writer{ .out = out };

    try w.write("{\"table\":");
    try w.writeJsonString(S.table);
    try w.write(",\"fingerprint\":");
    try w.writeU64(S.fingerprint);
    try w.write(",\"fields\":[");

    inline for (S.fields_desc, 0..) |d, i| {
        if (i != 0) try w.write(",");
        try w.write("{\"name\":");
        try w.writeJsonString(d.name);
        try w.write(",\"type\":");
        try w.writeJsonString(d.wire_type.name());
        try w.write(",\"nullable\":");
        try w.write(if (d.nullable) "true" else "false");
        try w.write("}");
    }
    try w.write("]}");

    return w.slice();
}

/// Minimal bounded writer over a caller slice. Every write bounds-checks
/// and surfaces `error.BufferTooSmall` on overflow — no panics, no heap.
const Writer = struct {
    out: []u8,
    pos: usize = 0,

    fn write(self: *Writer, s: []const u8) Error!void {
        if (self.pos + s.len > self.out.len) return Error.BufferTooSmall;
        @memcpy(self.out[self.pos .. self.pos + s.len], s);
        self.pos += s.len;
    }

    fn writeByte(self: *Writer, b: u8) Error!void {
        if (self.pos + 1 > self.out.len) return Error.BufferTooSmall;
        self.out[self.pos] = b;
        self.pos += 1;
    }

    /// Write `v` as a JSON string with the minimal escaping JSON requires
    /// (", \\, and control chars < 0x20 as \uXXXX). Schema identifiers are
    /// ASCII in practice, but we escape defensively to keep output valid.
    fn writeJsonString(self: *Writer, v: []const u8) Error!void {
        try self.writeByte('"');
        for (v) |c| {
            switch (c) {
                '"' => try self.write("\\\""),
                '\\' => try self.write("\\\\"),
                0x08 => try self.write("\\b"),
                0x0c => try self.write("\\f"),
                '\n' => try self.write("\\n"),
                '\r' => try self.write("\\r"),
                '\t' => try self.write("\\t"),
                else => {
                    if (c < 0x20) {
                        var buf: [6]u8 = undefined;
                        const s = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c}) catch unreachable;
                        try self.write(s);
                    } else {
                        try self.writeByte(c);
                    }
                },
            }
        }
        try self.writeByte('"');
    }

    fn writeU64(self: *Writer, v: u64) Error!void {
        var buf: [20]u8 = undefined; // max u64 decimal digits = 20
        const s = std.fmt.bufPrint(&buf, "{d}", .{v}) catch return Error.BufferTooSmall;
        try self.write(s);
    }

    fn slice(self: *const Writer) []const u8 {
        return self.out[0..self.pos];
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

const fields = @import("fields.zig");
const testing = std.testing;

const Role = enum { member, admin, owner };

const Rich = struct {
    pub const zorm_table = "rich_entities";
    id: fields.Pk(64) = .{},
    handle: fields.Text(128) = .{},
    bio: ?fields.Text(256) = null,
    role: Role = .member,
    active: bool = false,
    count: i64 = 0,
    ratio: f64 = 0,
    created_at: fields.Timestamp = .{},
    avatar: fields.Bytes(512) = .{},
};

test "Schema: field descriptors map wire types in column order" {
    const S = Schema(Rich);
    try testing.expectEqualStrings("rich_entities", S.table);
    try testing.expectEqual(@as(usize, 9), S.field_count);

    const expect = [_]struct { n: []const u8, w: WireType, nul: bool }{
        .{ .n = "id", .w = .text, .nul = false },
        .{ .n = "handle", .w = .text, .nul = false },
        .{ .n = "bio", .w = .text, .nul = true },
        .{ .n = "role", .w = .enum_text, .nul = false },
        .{ .n = "active", .w = .bool, .nul = false },
        .{ .n = "count", .w = .i64, .nul = false },
        .{ .n = "ratio", .w = .f64, .nul = false },
        .{ .n = "created_at", .w = .timestamp, .nul = false },
        .{ .n = "avatar", .w = .bytes, .nul = false },
    };
    inline for (expect, 0..) |e, i| {
        try testing.expectEqualStrings(e.n, S.fields_desc[i].name);
        try testing.expectEqual(e.w, S.fields_desc[i].wire_type);
        try testing.expectEqual(e.nul, S.fields_desc[i].nullable);
    }
}

test "Schema: fingerprint is stable across calls" {
    const a = Schema(Rich).fingerprint;
    const b = Schema(Rich).fingerprint;
    try testing.expectEqual(a, b);
    try testing.expect(a != 0);
}

test "Schema: structurally different entity → different fingerprint" {
    const Other = struct {
        pub const zorm_table = "rich_entities"; // same table name…
        id: fields.Pk(64) = .{},
        handle: fields.Text(128) = .{},
        // …but `bio` renamed/retyped and a field dropped → must differ.
        biography: ?fields.Text(256) = null,
        role: Role = .member,
    };
    try testing.expect(Schema(Rich).fingerprint != Schema(Other).fingerprint);
}

test "Schema: renaming the table changes the fingerprint" {
    const Renamed = struct {
        pub const zorm_table = "rich_entities_v2";
        id: fields.Pk(64) = .{},
        handle: fields.Text(128) = .{},
        bio: ?fields.Text(256) = null,
        role: Role = .member,
        active: bool = false,
        count: i64 = 0,
        ratio: f64 = 0,
        created_at: fields.Timestamp = .{},
        avatar: fields.Bytes(512) = .{},
    };
    try testing.expect(Schema(Rich).fingerprint != Schema(Renamed).fingerprint);
}

test "Schema: retyping a field (i64 → f64) changes the fingerprint" {
    const Retyped = struct {
        pub const zorm_table = "rich_entities";
        id: fields.Pk(64) = .{},
        handle: fields.Text(128) = .{},
        bio: ?fields.Text(256) = null,
        role: Role = .member,
        active: bool = false,
        count: f64 = 0, // was i64
        ratio: f64 = 0,
        created_at: fields.Timestamp = .{},
        avatar: fields.Bytes(512) = .{},
    };
    try testing.expect(Schema(Rich).fingerprint != Schema(Retyped).fingerprint);
}

test "Schema: toggling nullability changes the fingerprint" {
    const NonNull = struct {
        pub const zorm_table = "rich_entities";
        id: fields.Pk(64) = .{},
        handle: fields.Text(128) = .{},
        bio: fields.Text(256) = .{}, // was ?Text
        role: Role = .member,
        active: bool = false,
        count: i64 = 0,
        ratio: f64 = 0,
        created_at: fields.Timestamp = .{},
        avatar: fields.Bytes(512) = .{},
    };
    try testing.expect(Schema(Rich).fingerprint != Schema(NonNull).fingerprint);
}

test "toJson: emits valid-looking JSON with table + every field name" {
    var buf: [2048]u8 = undefined;
    const json = try toJson(Rich, &buf);

    // Structural sanity.
    try testing.expect(json.len > 2);
    try testing.expectEqual(@as(u8, '{'), json[0]);
    try testing.expectEqual(@as(u8, '}'), json[json.len - 1]);

    try testing.expect(std.mem.indexOf(u8, json, "\"table\":\"rich_entities\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"fingerprint\":") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"fields\":[") != null);

    // Every field name appears.
    inline for (Schema(Rich).fields_desc) |d| {
        var needle_buf: [80]u8 = undefined;
        const needle = try std.fmt.bufPrint(&needle_buf, "\"name\":\"{s}\"", .{d.name});
        try testing.expect(std.mem.indexOf(u8, json, needle) != null);
    }

    // Wire-type spellings appear.
    try testing.expect(std.mem.indexOf(u8, json, "\"type\":\"enum_text\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"type\":\"timestamp\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"type\":\"bytes\"") != null);
    // Nullability surfaced both ways.
    try testing.expect(std.mem.indexOf(u8, json, "\"nullable\":true") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"nullable\":false") != null);

    // The embedded fingerprint matches Schema(T).fingerprint.
    var fp_buf: [40]u8 = undefined;
    const fp_needle = try std.fmt.bufPrint(&fp_buf, "\"fingerprint\":{d}", .{Schema(Rich).fingerprint});
    try testing.expect(std.mem.indexOf(u8, json, fp_needle) != null);
}

test "toJson: too-small buffer returns error.BufferTooSmall" {
    var tiny: [8]u8 = undefined;
    try testing.expectError(Error.BufferTooSmall, toJson(Rich, &tiny));

    // Exactly-too-small by one byte also errors (boundary check).
    var sized: [4096]u8 = undefined;
    const full = try toJson(Rich, &sized);
    var oneshort: [4096]u8 = undefined;
    try testing.expectError(Error.BufferTooSmall, toJson(Rich, oneshort[0 .. full.len - 1]));
}
