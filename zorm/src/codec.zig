//! zorm S7 — typed wire CODEC.
//!
//! A compact, versioned, positional binary codec (Avro-ish): the schema
//! (`schema_desc.Schema(T)`) defines field *order*; the payload is purely
//! positional (no per-field tags). An 8-byte schema fingerprint is
//! prefixed so consumers can detect the writer's schema version and reject
//! a mismatch.
//!
//! Wire format (all multi-byte integers little-endian):
//!
//!   [fingerprint : u64 LE]                       -- Schema(T).fingerprint
//!   then, for each column in TableInfo(T) order:
//!       nullable column → [present : u8] (0 = null, 1 = present)
//!                         followed by the value encoding iff present == 1
//!       non-null column → the value encoding directly
//!
//!   value encodings by wire_type:
//!       i64        → 8 bytes LE (two's complement)
//!       timestamp  → 8 bytes LE (the unix seconds, two's complement)
//!       bool       → 1 byte (0 / 1)
//!       f64        → 8 bytes LE of @bitCast(f64 → u64)
//!       text       → [len : u32 LE][len bytes UTF-8]
//!       enum_text  → [len : u32 LE][len bytes of @tagName]
//!       bytes      → [len : u32 LE][len raw bytes]
//!
//! Bounded + no heap: the caller supplies the `out` slice on serialize and
//! the source `bytes` on deserialize. Every write checks remaining space
//! (`error.BufferTooSmall`); every read bounds-checks (`error.BadStatement`
//! on truncation/overrun). Reflection is entirely `inline for` at comptime.
//!
//! Error variants used (all from `contract.Error`):
//!   * BufferTooSmall — serialize `out` too small.
//!   * BadStatement   — fingerprint mismatch on deserialize, OR a truncated
//!                      / malformed payload (read past end, bad enum tag,
//!                      negative/oversized length).

const std = @import("std");
const contract = @import("contract.zig");
const reflect = @import("reflect.zig");
const schema_desc = @import("schema_desc.zig");

const Error = contract.Error;
const WireType = schema_desc.WireType;

/// Serialize `value` into `out`, returning the written prefix slice.
pub fn serialize(comptime T: type, value: *const T, out: []u8) Error![]const u8 {
    const S = schema_desc.Schema(T);
    const info = reflect.TableInfo(T);
    const all = std.meta.fields(T);

    var w = Cursor{ .buf = out };
    try w.putU64(S.fingerprint);

    inline for (info.columns, 0..) |spec, ci| {
        const field_name = all[spec.field_index].name;
        const F = all[spec.field_index].type;
        const wt = S.fields_desc[ci].wire_type;
        const fp = &@field(value, field_name);

        switch (@typeInfo(F)) {
            .optional => {
                if (fp.*) |inner| {
                    try w.putU8(1);
                    try encodeValue(&w, wt, &inner);
                } else {
                    try w.putU8(0);
                }
            },
            else => try encodeValue(&w, wt, fp),
        }
    }
    return w.written();
}

/// Encode one (non-optional, present) value of the given wire type from a
/// pointer to the concrete field value `vp` (`*const FieldType`).
fn encodeValue(w: *Cursor, comptime wt: WireType, vp: anytype) Error!void {
    const VT = @TypeOf(vp.*);
    switch (wt) {
        .i64 => {
            // VT is either a native int (e.g. i64) or fields.AutoPk{value}.
            const v: i64 = if (@typeInfo(VT) == .int) @intCast(vp.*) else vp.*.value;
            try w.putI64(v);
        },
        .timestamp => try w.putI64(vp.*.unix), // fields.Timestamp{unix}
        .bool => try w.putU8(if (vp.*) 1 else 0),
        .f64 => try w.putU64(@bitCast(@as(f64, vp.*))),
        .text => try w.putBytes(vp.*.slice()), // Text(N)/Pk(N)
        .bytes => try w.putBytes(vp.*.slice()), // Bytes(N)
        .enum_text => try w.putBytes(@tagName(vp.*)),
    }
}

/// Deserialize `bytes` into `out`. Verifies the fingerprint first, then
/// reads each column positionally.
pub fn deserialize(comptime T: type, bytes: []const u8, out: *T) Error!void {
    const S = schema_desc.Schema(T);
    const info = reflect.TableInfo(T);
    const all = std.meta.fields(T);

    var r = Reader{ .buf = bytes };
    const fp = try r.getU64();
    if (fp != S.fingerprint) return Error.BadStatement; // schema mismatch

    inline for (info.columns, 0..) |spec, ci| {
        const field_name = all[spec.field_index].name;
        const F = all[spec.field_index].type;
        const wt = S.fields_desc[ci].wire_type;
        const dst = &@field(out, field_name);

        switch (@typeInfo(F)) {
            .optional => |o| {
                const present = try r.getU8();
                if (present == 1) {
                    var inner: o.child = undefined;
                    try decodeValue(&r, wt, o.child, &inner);
                    dst.* = inner;
                } else if (present == 0) {
                    dst.* = null;
                } else {
                    return Error.BadStatement; // invalid presence flag
                }
            },
            else => try decodeValue(&r, wt, F, dst),
        }
    }

    // Trailing garbage is tolerated (a longer payload from a compatible
    // writer): the fingerprint already pinned the schema. We only require
    // that we did not read past the end, which the Reader enforces.
}

/// Decode one value of wire type `wt` into `*VT` (the concrete field type).
fn decodeValue(r: *Reader, comptime wt: WireType, comptime VT: type, dst: *VT) Error!void {
    switch (wt) {
        .i64 => {
            const v = try r.getI64();
            if (@typeInfo(VT) == .int) {
                dst.* = @intCast(v); // native int (incl. i64)
            } else {
                dst.*.value = v; // fields.AutoPk
            }
        },
        .timestamp => {
            dst.*.unix = try r.getI64(); // fields.Timestamp
        },
        .bool => {
            const b = try r.getU8();
            if (b > 1) return Error.BadStatement;
            dst.* = (b == 1);
        },
        .f64 => {
            dst.* = @bitCast(try r.getU64());
        },
        .text, .bytes => {
            const s = try r.getBytes();
            dst.*.set(s); // Text(N)/Pk(N)/Bytes(N) — truncates at capacity
        },
        .enum_text => {
            const s = try r.getBytes();
            dst.* = std.meta.stringToEnum(VT, s) orelse return Error.BadStatement;
        },
    }
}

/// Bounded forward writer over a caller slice. Surfaces BufferTooSmall.
const Cursor = struct {
    buf: []u8,
    pos: usize = 0,

    fn ensure(self: *Cursor, n: usize) Error!void {
        if (self.pos + n > self.buf.len) return Error.BufferTooSmall;
    }
    fn putU8(self: *Cursor, v: u8) Error!void {
        try self.ensure(1);
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn putU64(self: *Cursor, v: u64) Error!void {
        try self.ensure(8);
        std.mem.writeInt(u64, self.buf[self.pos..][0..8], v, .little);
        self.pos += 8;
    }
    fn putI64(self: *Cursor, v: i64) Error!void {
        try self.ensure(8);
        std.mem.writeInt(i64, self.buf[self.pos..][0..8], v, .little);
        self.pos += 8;
    }
    fn putBytes(self: *Cursor, s: []const u8) Error!void {
        if (s.len > std.math.maxInt(u32)) return Error.BufferTooSmall;
        try self.ensure(4 + s.len);
        std.mem.writeInt(u32, self.buf[self.pos..][0..4], @intCast(s.len), .little);
        self.pos += 4;
        @memcpy(self.buf[self.pos .. self.pos + s.len], s);
        self.pos += s.len;
    }
    fn written(self: *const Cursor) []const u8 {
        return self.buf[0..self.pos];
    }
};

/// Bounded forward reader over a caller slice. Surfaces BadStatement on any
/// read past the end or a malformed length.
const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return Error.BadStatement;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }
    fn getU8(self: *Reader) Error!u8 {
        const s = try self.take(1);
        return s[0];
    }
    fn getU64(self: *Reader) Error!u64 {
        const s = try self.take(8);
        return std.mem.readInt(u64, s[0..8], .little);
    }
    fn getI64(self: *Reader) Error!i64 {
        const s = try self.take(8);
        return std.mem.readInt(i64, s[0..8], .little);
    }
    fn getBytes(self: *Reader) Error![]const u8 {
        const ls = try self.take(4);
        const len = std.mem.readInt(u32, ls[0..4], .little);
        return self.take(len);
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

const fields = @import("fields.zig");
const testing = std.testing;

const Role = enum { member, admin, owner };

const Rich = struct {
    pub const zorm_table = "rich_codec";
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

/// Build a randomized Rich. `bio_present` controls the nullable field.
fn randomRich(prng: *std.Random.DefaultPrng, bio_present: bool) Rich {
    const rnd = prng.random();
    var v: Rich = .{};

    // Random text/bytes of random lengths within capacity.
    var sbuf: [600]u8 = undefined;
    const id_len = rnd.intRangeAtMost(usize, 1, 64);
    for (0..id_len) |i| sbuf[i] = rnd.intRangeAtMost(u8, 'a', 'z');
    v.id.set(sbuf[0..id_len]);

    const h_len = rnd.intRangeAtMost(usize, 0, 128);
    for (0..h_len) |i| sbuf[i] = rnd.intRangeAtMost(u8, 'A', 'Z');
    v.handle.set(sbuf[0..h_len]);

    if (bio_present) {
        const b_len = rnd.intRangeAtMost(usize, 0, 256);
        for (0..b_len) |i| sbuf[i] = rnd.intRangeAtMost(u8, ' ', '~');
        var bio: fields.Text(256) = .{};
        bio.set(sbuf[0..b_len]);
        v.bio = bio;
    } else {
        v.bio = null;
    }

    v.role = switch (rnd.intRangeAtMost(u8, 0, 2)) {
        0 => .member,
        1 => .admin,
        else => .owner,
    };
    v.active = rnd.boolean();
    v.count = rnd.int(i64);
    v.ratio = @bitCast(rnd.int(u64)); // any bit pattern (incl. NaN/inf)
    v.created_at = .{ .unix = rnd.int(i64) };

    const a_len = rnd.intRangeAtMost(usize, 0, 512);
    for (0..a_len) |i| sbuf[i] = rnd.int(u8);
    v.avatar.set(sbuf[0..a_len]);

    return v;
}

fn expectRichEqual(a: *const Rich, b: *const Rich) !void {
    try testing.expectEqualStrings(a.id.slice(), b.id.slice());
    try testing.expectEqualStrings(a.handle.slice(), b.handle.slice());
    if (a.bio == null) {
        try testing.expect(b.bio == null);
    } else {
        try testing.expect(b.bio != null);
        try testing.expectEqualStrings(a.bio.?.slice(), b.bio.?.slice());
    }
    try testing.expectEqual(a.role, b.role);
    try testing.expectEqual(a.active, b.active);
    try testing.expectEqual(a.count, b.count);
    // ratio compared bitwise to be NaN-safe.
    try testing.expectEqual(@as(u64, @bitCast(a.ratio)), @as(u64, @bitCast(b.ratio)));
    try testing.expectEqual(a.created_at.unix, b.created_at.unix);
    try testing.expectEqualStrings(a.avatar.slice(), b.avatar.slice());
}

test "codec: round-trip randomized rich entity (bio present)" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234);
    var buf: [4096]u8 = undefined;

    var iter: usize = 0;
    while (iter < 64) : (iter += 1) {
        const src = randomRich(&prng, true);
        const wire = try serialize(Rich, &src, &buf);
        try testing.expect(wire.len >= 8); // at least the fingerprint

        var dst: Rich = .{};
        try deserialize(Rich, wire, &dst);
        try expectRichEqual(&src, &dst);
    }
}

test "codec: round-trip randomized rich entity (bio null)" {
    var prng = std.Random.DefaultPrng.init(0xBADC0DE_99);
    var buf: [4096]u8 = undefined;

    var iter: usize = 0;
    while (iter < 64) : (iter += 1) {
        const src = randomRich(&prng, false);
        const wire = try serialize(Rich, &src, &buf);

        var dst: Rich = .{};
        // poison dst.bio so we prove null is actually written
        dst.bio = fields.Text(256).from("garbage");
        try deserialize(Rich, wire, &dst);
        try expectRichEqual(&src, &dst);
        try testing.expect(dst.bio == null);
    }
}

test "codec: wire begins with the schema fingerprint (LE)" {
    var buf: [4096]u8 = undefined;
    const src: Rich = .{};
    const wire = try serialize(Rich, &src, &buf);
    const fp = std.mem.readInt(u64, wire[0..8], .little);
    try testing.expectEqual(schema_desc.Schema(Rich).fingerprint, fp);
}

test "codec: serialize into too-small buffer errors" {
    var src: Rich = .{};
    src.handle.set("a-reasonably-long-handle-value-here");
    var tiny: [4]u8 = undefined; // can't even fit the fingerprint
    try testing.expectError(Error.BufferTooSmall, serialize(Rich, &src, &tiny));

    var medium: [16]u8 = undefined; // fingerprint fits, body doesn't
    try testing.expectError(Error.BufferTooSmall, serialize(Rich, &src, &medium));
}

test "codec: deserialize rejects a wrong fingerprint" {
    var buf: [4096]u8 = undefined;
    const src: Rich = .{};
    const wire = try serialize(Rich, &src, &buf);

    // Corrupt the fingerprint prefix in a mutable copy.
    var copy: [4096]u8 = undefined;
    @memcpy(copy[0..wire.len], wire);
    copy[0] ^= 0xFF;

    var dst: Rich = .{};
    try testing.expectError(Error.BadStatement, deserialize(Rich, copy[0..wire.len], &dst));
}

test "codec: deserialize rejects a truncated payload" {
    var buf: [4096]u8 = undefined;
    var src: Rich = .{};
    src.handle.set("hello world");
    src.avatar.set("some binary-ish payload");
    const wire = try serialize(Rich, &src, &buf);

    var dst: Rich = .{};
    // Drop the last byte → a length-prefixed read should overrun.
    try testing.expectError(Error.BadStatement, deserialize(Rich, wire[0 .. wire.len - 1], &dst));
    // Only the fingerprint present → first column read overruns.
    try testing.expectError(Error.BadStatement, deserialize(Rich, wire[0..8], &dst));
    // Shorter than the fingerprint → fingerprint read overruns.
    try testing.expectError(Error.BadStatement, deserialize(Rich, wire[0..3], &dst));
}

test "codec: round-trip an AutoPk entity" {
    const Auto = struct {
        pub const zorm_table = "auto_codec";
        id: fields.AutoPk = .{},
        name: fields.Text(32) = .{},
        n: i64 = 0,
    };
    var prng = std.Random.DefaultPrng.init(0x5151_AA);
    var buf: [512]u8 = undefined;

    var iter: usize = 0;
    while (iter < 32) : (iter += 1) {
        var src: Auto = .{};
        src.id.value = prng.random().int(i64);
        src.n = prng.random().int(i64);
        src.name.set("auto-entity-name");

        const wire = try serialize(Auto, &src, &buf);
        var dst: Auto = .{};
        try deserialize(Auto, wire, &dst);

        try testing.expectEqual(src.id.value, dst.id.value);
        try testing.expectEqual(src.n, dst.n);
        try testing.expectEqualStrings(src.name.slice(), dst.name.slice());
    }
}

test "codec: empty text/bytes round-trip (zero-length length prefix)" {
    var buf: [4096]u8 = undefined;
    var src: Rich = .{};
    src.id.set("k"); // pk must be non-empty in practice
    src.handle.set(""); // empty text
    src.avatar.set(""); // empty bytes
    src.bio = null;
    const wire = try serialize(Rich, &src, &buf);

    var dst: Rich = .{};
    try deserialize(Rich, wire, &dst);
    try testing.expectEqual(@as(usize, 0), dst.handle.slice().len);
    try testing.expectEqual(@as(usize, 0), dst.avatar.slice().len);
}
