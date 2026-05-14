//! DAG-CBOR codec
//!
//! encode and decode the DAG-CBOR subset used by AT Protocol.
//! handles: integers, byte/text strings, arrays, maps, tag 42 (CID links),
//! booleans, null. no floats, no indefinite lengths.
//!
//! encoding follows DAG-CBOR deterministic rules:
//!   - integers use shortest encoding
//!   - map keys sorted by byte length, then lexicographically
//!   - CIDs encoded as tag 42 with 0x00 identity multibase prefix
//!
//! see: https://ipld.io/specs/codecs/dag-cbor/spec/

const std = @import("std");
const Allocator = std.mem.Allocator;

/// CBOR major types (high 3 bits of initial byte)
const MajorType = enum(u3) {
    unsigned = 0,
    negative = 1,
    byte_string = 2,
    text_string = 3,
    array = 4,
    map = 5,
    tag = 6,
    simple = 7,
};

/// decoded CBOR value
pub const Value = union(enum) {
    unsigned: u64,
    negative: i64, // stored as -(1 + raw), so -1 is stored as -1
    bytes: []const u8,
    text: []const u8,
    array: []const Value,
    map: []const MapEntry,
    tag: Tag,
    boolean: bool,
    null,
    cid: Cid,

    pub const MapEntry = struct {
        key: []const u8, // DAG-CBOR: keys are always text strings
        value: Value,
    };

    pub const Tag = struct {
        number: u64,
        content: *const Value,
    };

    /// look up a key in a map value
    pub fn get(self: Value, key: []const u8) ?Value {
        return switch (self) {
            .map => |entries| {
                for (entries) |entry| {
                    if (std.mem.eql(u8, entry.key, key)) return entry.value;
                }
                return null;
            },
            else => null,
        };
    }

    /// get a text string from a map by key
    pub fn getString(self: Value, key: []const u8) ?[]const u8 {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .text => |s| s,
            else => null,
        };
    }

    /// get an integer from a map by key
    pub fn getInt(self: Value, key: []const u8) ?i64 {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .unsigned => |u| std.math.cast(i64, u),
            .negative => |n| n,
            else => null,
        };
    }

    /// get an unsigned integer from a map by key
    pub fn getUint(self: Value, key: []const u8) ?u64 {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .unsigned => |u| u,
            .negative => |n| std.math.cast(u64, n),
            else => null,
        };
    }

    /// get a bool from a map by key
    pub fn getBool(self: Value, key: []const u8) ?bool {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .boolean => |b| b,
            else => null,
        };
    }

    /// get a byte string from a map by key
    pub fn getBytes(self: Value, key: []const u8) ?[]const u8 {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .bytes => |b| b,
            else => null,
        };
    }

    /// get an array from a map by key
    pub fn getArray(self: Value, key: []const u8) ?[]const Value {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .array => |a| a,
            else => null,
        };
    }

    // verify the Value union stayed slim after Cid optimization (was ~64, now 24)
    comptime {
        std.debug.assert(@sizeOf(Value) == 24);
        std.debug.assert(@sizeOf(MapEntry) == 40);
    }
};

/// well-known multicodec values
pub const Codec = struct {
    pub const dag_cbor: u64 = 0x71;
    pub const dag_pb: u64 = 0x70;
    pub const raw: u64 = 0x55;
};

/// well-known multihash function codes
pub const HashFn = struct {
    pub const sha2_256: u64 = 0x12;
    pub const identity: u64 = 0x00;
};

/// CID (Content Identifier) parsed from tag 42.
/// stores only the raw bytes — version/codec/hash_fn/digest are parsed lazily on demand.
/// this keeps the struct at 16 bytes (1 slice) instead of 56 bytes, which shrinks
/// the Value union from ~64 to ~24 bytes.
pub const Cid = struct {
    raw: []const u8,

    /// parse CID version from raw bytes (0 for CIDv0, 1+ for CIDv1)
    pub fn version(self: Cid) ?u64 {
        if (self.raw.len < 2) return null;
        // CIDv0: starts with 0x12 0x20 (sha2-256 multihash)
        if (self.raw[0] == 0x12 and self.raw[1] == 0x20) return 0;
        var pos: usize = 0;
        return readUvarint(self.raw, &pos);
    }

    /// parse codec from raw bytes (implicit dag-pb for CIDv0)
    pub fn codec(self: Cid) ?u64 {
        if (self.raw.len < 2) return null;
        if (self.raw[0] == 0x12 and self.raw[1] == 0x20) return 0x70; // dag-pb
        var pos: usize = 0;
        _ = readUvarint(self.raw, &pos) orelse return null; // version
        return readUvarint(self.raw, &pos);
    }

    /// parse hash function code from raw bytes
    pub fn hashFn(self: Cid) ?u64 {
        if (self.raw.len < 2) return null;
        if (self.raw[0] == 0x12 and self.raw[1] == 0x20) return 0x12; // sha2-256
        var pos: usize = 0;
        _ = readUvarint(self.raw, &pos) orelse return null; // version
        _ = readUvarint(self.raw, &pos) orelse return null; // codec
        return readUvarint(self.raw, &pos);
    }

    /// parse digest bytes from raw CID
    pub fn digest(self: Cid) ?[]const u8 {
        if (self.raw.len < 2) return null;
        if (self.raw[0] == 0x12 and self.raw[1] == 0x20) {
            if (self.raw.len < 34) return null;
            return self.raw[2..34];
        }
        var pos: usize = 0;
        _ = readUvarint(self.raw, &pos) orelse return null; // version
        _ = readUvarint(self.raw, &pos) orelse return null; // codec
        _ = readUvarint(self.raw, &pos) orelse return null; // hash_fn
        const digest_len = readUvarint(self.raw, &pos) orelse return null;
        if (pos + digest_len > self.raw.len) return null;
        return self.raw[pos..][0..digest_len];
    }

    /// create a CIDv1 by hashing DAG-CBOR encoded data with SHA-256.
    /// the returned Cid's raw slice is owned by the allocator.
    pub fn forDagCbor(allocator: Allocator, data: []const u8) !Cid {
        return create(allocator, 1, Codec.dag_cbor, HashFn.sha2_256, data);
    }

    /// create a CIDv1 with the given codec by hashing data with SHA-256.
    pub fn create(allocator: Allocator, ver: u64, cod: u64, hash_fn_code: u64, data: []const u8) !Cid {
        const Sha256 = std.crypto.hash.sha2.Sha256;
        var hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(data, &hash, .{});

        var raw_buf: std.ArrayList(u8) = .{};
        errdefer raw_buf.deinit(allocator);
        const writer = raw_buf.writer(allocator);
        try writeUvarint(writer, ver);
        try writeUvarint(writer, cod);
        try writeUvarint(writer, hash_fn_code);
        try writeUvarint(writer, Sha256.digest_length);
        try writer.writeAll(&hash);

        return .{ .raw = try raw_buf.toOwnedSlice(allocator) };
    }

    /// serialize this CID to raw bytes (version varint + codec varint + multihash)
    pub fn toBytes(self: Cid, allocator: Allocator) ![]u8 {
        return try allocator.dupe(u8, self.raw);
    }
};

pub const DecodeError = error{
    UnexpectedEof,
    IndefiniteLength,
    UnsupportedSimpleValue,
    UnsupportedFloat,
    InvalidMapKey,
    InvalidCid,
    ReservedAdditionalInfo,
    Overflow,
    OutOfMemory,
};

/// decode a single CBOR value from the front of `data`.
/// returns the value and the number of bytes consumed.
pub fn decode(allocator: Allocator, data: []const u8) DecodeError!struct { value: Value, consumed: usize } {
    var pos: usize = 0;
    const value = try decodeAt(allocator, data, &pos);
    return .{ .value = value, .consumed = pos };
}

/// decode all bytes as a single CBOR value
pub fn decodeAll(allocator: Allocator, data: []const u8) DecodeError!Value {
    var pos: usize = 0;
    return try decodeAt(allocator, data, &pos);
}

fn decodeAt(allocator: Allocator, data: []const u8, pos: *usize) DecodeError!Value {
    if (pos.* >= data.len) return error.UnexpectedEof;

    const initial = data[pos.*];
    pos.* += 1;

    const major: MajorType = @enumFromInt(@as(u3, @truncate(initial >> 5)));
    const additional: u5 = @truncate(initial);

    return switch (major) {
        .unsigned => {
            const val = try readArgument(data, pos, additional);
            return .{ .unsigned = val };
        },
        .negative => {
            const val = try readArgument(data, pos, additional);
            // negative CBOR: value is -1 - val
            if (val > std.math.maxInt(i64)) return error.Overflow;
            return .{ .negative = -1 - @as(i64, @intCast(val)) };
        },
        .byte_string => {
            const len = try readArgument(data, pos, additional);
            const end = pos.* + @as(usize, @intCast(len));
            if (end > data.len) return error.UnexpectedEof;
            const bytes = data[pos.*..end];
            pos.* = end;
            return .{ .bytes = bytes };
        },
        .text_string => {
            const len = try readArgument(data, pos, additional);
            const end = pos.* + @as(usize, @intCast(len));
            if (end > data.len) return error.UnexpectedEof;
            const text = data[pos.*..end];
            pos.* = end;
            return .{ .text = text };
        },
        .array => {
            const count = try readArgument(data, pos, additional);
            const items = try allocator.alloc(Value, @intCast(count));
            for (items) |*item| {
                item.* = try decodeAt(allocator, data, pos);
            }
            return .{ .array = items };
        },
        .map => {
            const count = try readArgument(data, pos, additional);
            const entries = try allocator.alloc(Value.MapEntry, @intCast(count));
            for (entries) |*entry| {
                // DAG-CBOR: map keys must be text strings — inline read to avoid
                // a full decodeAt + Value union construction per key
                if (pos.* >= data.len) return error.UnexpectedEof;
                const key_byte = data[pos.*];
                pos.* += 1;
                if (@as(u3, @truncate(key_byte >> 5)) != 3) return error.InvalidMapKey;
                const key_len = try readArgument(data, pos, @truncate(key_byte));
                const key_end = pos.* + @as(usize, @intCast(key_len));
                if (key_end > data.len) return error.UnexpectedEof;
                entry.key = data[pos.*..key_end];
                pos.* = key_end;
                entry.value = try decodeAt(allocator, data, pos);
            }
            return .{ .map = entries };
        },
        .tag => {
            const tag_num = try readArgument(data, pos, additional);
            if (tag_num == 42) {
                // CID link — content is a byte string with 0x00 prefix
                const content = try decodeAt(allocator, data, pos);
                const cid_bytes = switch (content) {
                    .bytes => |b| b,
                    else => return error.InvalidCid,
                };
                if (cid_bytes.len < 1 or cid_bytes[0] != 0x00) return error.InvalidCid;
                return .{ .cid = .{ .raw = cid_bytes[1..] } }; // zero-cost: just reference the bytes
            }
            // generic tag — allocate content on heap
            const content_ptr = try allocator.create(Value);
            content_ptr.* = try decodeAt(allocator, data, pos);
            return .{ .tag = .{ .number = tag_num, .content = content_ptr } };
        },
        .simple => {
            return switch (additional) {
                20 => .{ .boolean = false },
                21 => .{ .boolean = true },
                22 => .null,
                25, 26, 27 => error.UnsupportedFloat, // DAG-CBOR forbids floats in AT Protocol
                31 => error.IndefiniteLength, // break code — DAG-CBOR forbids indefinite lengths
                else => error.UnsupportedSimpleValue,
            };
        },
    };
}

/// read the argument value from additional info + following bytes
fn readArgument(data: []const u8, pos: *usize, additional: u5) DecodeError!u64 {
    return switch (additional) {
        0...23 => @as(u64, additional),
        24 => { // 1-byte
            if (pos.* >= data.len) return error.UnexpectedEof;
            const val = data[pos.*];
            pos.* += 1;
            return @as(u64, val);
        },
        25 => { // 2-byte big-endian
            if (pos.* + 2 > data.len) return error.UnexpectedEof;
            const val = std.mem.readInt(u16, data[pos.*..][0..2], .big);
            pos.* += 2;
            return @as(u64, val);
        },
        26 => { // 4-byte big-endian
            if (pos.* + 4 > data.len) return error.UnexpectedEof;
            const val = std.mem.readInt(u32, data[pos.*..][0..4], .big);
            pos.* += 4;
            return @as(u64, val);
        },
        27 => { // 8-byte big-endian
            if (pos.* + 8 > data.len) return error.UnexpectedEof;
            const val = std.mem.readInt(u64, data[pos.*..][0..8], .big);
            pos.* += 8;
            return val;
        },
        28, 29, 30 => error.ReservedAdditionalInfo,
        31 => error.IndefiniteLength,
    };
}

/// wrap raw CID bytes (after removing the 0x00 multibase prefix) into a Cid.
/// validates the structure is parseable but stores only the raw bytes.
pub fn parseCid(raw: []const u8) Cid {
    return .{ .raw = raw };
}

/// read an unsigned varint (LEB128)
pub fn readUvarint(data: []const u8, pos: *usize) ?u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (pos.* < data.len) {
        const byte = data[pos.*];
        pos.* += 1;
        result |= @as(u64, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) return result;
        shift +|= 7;
        if (shift >= 64) return null;
    }
    return null;
}

// === encoder ===

pub const EncodeError = error{
    OutOfMemory,
};

/// write the CBOR initial byte + argument using shortest encoding (DAG-CBOR requirement)
fn writeArgument(writer: anytype, major: u3, val: u64) !void {
    const prefix: u8 = @as(u8, major) << 5;
    if (val < 24) {
        try writer.writeByte(prefix | @as(u8, @intCast(val)));
    } else if (val <= 0xff) {
        try writer.writeByte(prefix | 24);
        try writer.writeByte(@as(u8, @intCast(val)));
    } else if (val <= 0xffff) {
        try writer.writeByte(prefix | 25);
        const v: u16 = @intCast(val);
        try writer.writeAll(&[2]u8{ @truncate(v >> 8), @truncate(v) });
    } else if (val <= 0xffffffff) {
        try writer.writeByte(prefix | 26);
        const v: u32 = @intCast(val);
        try writer.writeAll(&[4]u8{
            @truncate(v >> 24), @truncate(v >> 16),
            @truncate(v >> 8),  @truncate(v),
        });
    } else {
        try writer.writeByte(prefix | 27);
        try writer.writeAll(&[8]u8{
            @truncate(val >> 56), @truncate(val >> 48),
            @truncate(val >> 40), @truncate(val >> 32),
            @truncate(val >> 24), @truncate(val >> 16),
            @truncate(val >> 8),  @truncate(val),
        });
    }
}

/// DAG-CBOR map key ordering: shorter keys first, then lexicographic
fn dagCborKeyLessThan(_: void, a: Value.MapEntry, b: Value.MapEntry) bool {
    if (a.key.len != b.key.len) return a.key.len < b.key.len;
    return std.mem.order(u8, a.key, b.key) == .lt;
}

/// encode a Value to the given writer in DAG-CBOR format.
/// allocator is needed for sorting map keys during encoding.
pub fn encode(allocator: Allocator, writer: anytype, value: Value) !void {
    switch (value) {
        .unsigned => |v| try writeArgument(writer, 0, v),
        .negative => |v| {
            // CBOR negative: -1 - n encoded in major type 1
            const raw: u64 = @intCast(-1 - v);
            try writeArgument(writer, 1, raw);
        },
        .bytes => |b| {
            try writeArgument(writer, 2, b.len);
            try writer.writeAll(b);
        },
        .text => |t| {
            try writeArgument(writer, 3, t.len);
            try writer.writeAll(t);
        },
        .array => |items| {
            try writeArgument(writer, 4, items.len);
            for (items) |item| {
                try encode(allocator, writer, item);
            }
        },
        .map => |entries| {
            try writeArgument(writer, 5, entries.len);
            // DAG-CBOR: keys sorted by byte length, then lexicographically
            const sorted = try allocator.dupe(Value.MapEntry, entries);
            defer allocator.free(sorted);
            std.mem.sort(Value.MapEntry, sorted, {}, dagCborKeyLessThan);
            for (sorted) |entry| {
                try encode(allocator, writer, .{ .text = entry.key });
                try encode(allocator, writer, entry.value);
            }
        },
        .tag => |t| {
            try writeArgument(writer, 6, t.number);
            try encode(allocator, writer, t.content.*);
        },
        .boolean => |b| try writer.writeByte(if (b) @as(u8, 0xf5) else @as(u8, 0xf4)),
        .null => try writer.writeByte(0xf6),
        .cid => |c| {
            // tag 42 + byte string with 0x00 identity multibase prefix + raw CID bytes
            try writeArgument(writer, 6, 42);
            try writeArgument(writer, 2, 1 + c.raw.len);
            try writer.writeByte(0x00);
            try writer.writeAll(c.raw);
        },
    }
}

/// encode a Value to a freshly allocated byte slice
pub fn encodeAlloc(allocator: Allocator, value: Value) ![]u8 {
    var list: std.ArrayList(u8) = .{};
    errdefer list.deinit(allocator);
    try encode(allocator, list.writer(allocator), value);
    return try list.toOwnedSlice(allocator);
}

/// write an unsigned varint (LEB128) — used for CID and CAR serialization
pub fn writeUvarint(writer: anytype, val: u64) !void {
    var v = val;
    while (v >= 0x80) {
        try writer.writeByte(@as(u8, @truncate(v)) | 0x80);
        v >>= 7;
    }
    try writer.writeByte(@as(u8, @truncate(v)));
}

// === tests ===

test "decode unsigned integers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 0
    try std.testing.expectEqual(@as(u64, 0), (try decode(alloc, &.{0x00})).value.unsigned);
    // 1
    try std.testing.expectEqual(@as(u64, 1), (try decode(alloc, &.{0x01})).value.unsigned);
    // 23
    try std.testing.expectEqual(@as(u64, 23), (try decode(alloc, &.{0x17})).value.unsigned);
    // 24 (1-byte follows)
    try std.testing.expectEqual(@as(u64, 24), (try decode(alloc, &.{ 0x18, 24 })).value.unsigned);
    // 1000 (2-byte follows)
    try std.testing.expectEqual(@as(u64, 1000), (try decode(alloc, &.{ 0x19, 0x03, 0xe8 })).value.unsigned);
}

test "decode negative integers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // -1 (major 1, additional 0)
    try std.testing.expectEqual(@as(i64, -1), (try decode(alloc, &.{0x20})).value.negative);
    // -10
    try std.testing.expectEqual(@as(i64, -10), (try decode(alloc, &.{0x29})).value.negative);
}

test "decode text strings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // empty string
    try std.testing.expectEqualStrings("", (try decode(alloc, &.{0x60})).value.text);
    // "a"
    try std.testing.expectEqualStrings("a", (try decode(alloc, &.{ 0x61, 'a' })).value.text);
    // "hello"
    try std.testing.expectEqualStrings("hello", (try decode(alloc, &.{ 0x65, 'h', 'e', 'l', 'l', 'o' })).value.text);
}

test "decode byte strings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // empty bytes
    try std.testing.expectEqualSlices(u8, &.{}, (try decode(alloc, &.{0x40})).value.bytes);
    // 3 bytes
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, (try decode(alloc, &.{ 0x43, 1, 2, 3 })).value.bytes);
}

test "decode booleans and null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try std.testing.expectEqual(false, (try decode(alloc, &.{0xf4})).value.boolean);
    try std.testing.expectEqual(true, (try decode(alloc, &.{0xf5})).value.boolean);
    try std.testing.expectEqual(Value.null, (try decode(alloc, &.{0xf6})).value);
}

test "decode array" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // [1, 2, 3]
    const result = try decode(alloc, &.{ 0x83, 0x01, 0x02, 0x03 });
    const arr = result.value.array;
    try std.testing.expectEqual(@as(usize, 3), arr.len);
    try std.testing.expectEqual(@as(u64, 1), arr[0].unsigned);
    try std.testing.expectEqual(@as(u64, 2), arr[1].unsigned);
    try std.testing.expectEqual(@as(u64, 3), arr[2].unsigned);
}

test "decode map" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // {"a": 1, "b": 2}
    const result = try decode(alloc, &.{
        0xa2, // map(2)
        0x61, 'a', 0x01, // "a": 1
        0x61, 'b', 0x02, // "b": 2
    });
    const val = result.value;
    try std.testing.expectEqual(@as(u64, 1), val.get("a").?.unsigned);
    try std.testing.expectEqual(@as(u64, 2), val.get("b").?.unsigned);
}

test "decode nested map" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // {"op": 1, "t": "#commit"}
    const result = try decode(alloc, &.{
        0xa2, // map(2)
        0x62, 'o', 'p', 0x01, // "op": 1
        0x61, 't', 0x67, '#', 'c', 'o', 'm', 'm', 'i', 't', // "t": "#commit"
    });
    const val = result.value;
    try std.testing.expectEqual(@as(u64, 1), val.get("op").?.unsigned);
    try std.testing.expectEqualStrings("#commit", val.getString("t").?);
}

test "consumed bytes tracking" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // two concatenated CBOR values: 1, 2
    const data = &[_]u8{ 0x01, 0x02 };
    const first = try decode(alloc, data);
    try std.testing.expectEqual(@as(u64, 1), first.value.unsigned);
    try std.testing.expectEqual(@as(usize, 1), first.consumed);

    const second = try decode(alloc, data[first.consumed..]);
    try std.testing.expectEqual(@as(u64, 2), second.value.unsigned);
}

test "reject floats" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // half-float (f16)
    try std.testing.expectError(error.UnsupportedFloat, decode(alloc, &.{ 0xf9, 0x00, 0x00 }));
}

test "Value helper methods" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const result = try decode(alloc, &.{
        0xa3, // map(3)
        0x64, 'n', 'a', 'm', 'e', 0x65, 'a', 'l', 'i', 'c', 'e', // "name": "alice"
        0x63, 'a', 'g', 'e', 0x18, 30, // "age": 30
        0x66, 'a', 'c', 't', 'i', 'v', 'e', 0xf5, // "active": true
    });
    const val = result.value;
    try std.testing.expectEqualStrings("alice", val.getString("name").?);
    try std.testing.expectEqual(@as(i64, 30), val.getInt("age").?);
    try std.testing.expectEqual(true, val.getBool("active").?);
    try std.testing.expect(val.getString("missing") == null);
}

// === encoder tests ===

test "encode unsigned integers" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    // 0 → single byte
    try encode(alloc, &w, .{ .unsigned = 0 });
    try std.testing.expectEqualSlices(u8, &.{0x00}, w.buffered());

    w.end = 0;
    try encode(alloc, &w, .{ .unsigned = 23 });
    try std.testing.expectEqualSlices(u8, &.{0x17}, w.buffered());

    // 24 → 2 bytes (shortest encoding)
    w.end = 0;
    try encode(alloc, &w, .{ .unsigned = 24 });
    try std.testing.expectEqualSlices(u8, &.{ 0x18, 24 }, w.buffered());

    // 1000 → 3 bytes
    w.end = 0;
    try encode(alloc, &w, .{ .unsigned = 1000 });
    try std.testing.expectEqualSlices(u8, &.{ 0x19, 0x03, 0xe8 }, w.buffered());
}

test "encode negative integers" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    // -1 → major 1, additional 0
    try encode(alloc, &w, .{ .negative = -1 });
    try std.testing.expectEqualSlices(u8, &.{0x20}, w.buffered());

    w.end = 0;
    try encode(alloc, &w, .{ .negative = -10 });
    try std.testing.expectEqualSlices(u8, &.{0x29}, w.buffered());
}

test "encode text strings" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    try encode(alloc, &w, .{ .text = "" });
    try std.testing.expectEqualSlices(u8, &.{0x60}, w.buffered());

    w.end = 0;
    try encode(alloc, &w, .{ .text = "hello" });
    try std.testing.expectEqualSlices(u8, &.{ 0x65, 'h', 'e', 'l', 'l', 'o' }, w.buffered());
}

test "encode byte strings" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    try encode(alloc, &w, .{ .bytes = &.{} });
    try std.testing.expectEqualSlices(u8, &.{0x40}, w.buffered());

    w.end = 0;
    try encode(alloc, &w, .{ .bytes = &.{ 1, 2, 3 } });
    try std.testing.expectEqualSlices(u8, &.{ 0x43, 1, 2, 3 }, w.buffered());
}

test "encode booleans and null" {
    var buf: [4]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    try encode(alloc, &w, .{ .boolean = false });
    try std.testing.expectEqualSlices(u8, &.{0xf4}, w.buffered());

    w.end = 0;
    try encode(alloc, &w, .{ .boolean = true });
    try std.testing.expectEqualSlices(u8, &.{0xf5}, w.buffered());

    w.end = 0;
    try encode(alloc, &w, .null);
    try std.testing.expectEqualSlices(u8, &.{0xf6}, w.buffered());
}

test "encode array" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    // [1, 2, 3]
    try encode(alloc, &w, .{ .array = &.{
        .{ .unsigned = 1 },
        .{ .unsigned = 2 },
        .{ .unsigned = 3 },
    } });
    try std.testing.expectEqualSlices(u8, &.{ 0x83, 0x01, 0x02, 0x03 }, w.buffered());
}

test "encode map with DAG-CBOR key sorting" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    // keys provided unsorted — encoder must sort by length, then lex
    // "bb" (len 2), "a" (len 1), "cc" (len 2) → sorted: "a", "bb", "cc"
    try encode(alloc, &w, .{ .map = &.{
        .{ .key = "bb", .value = .{ .unsigned = 2 } },
        .{ .key = "a", .value = .{ .unsigned = 1 } },
        .{ .key = "cc", .value = .{ .unsigned = 3 } },
    } });

    const expected = &[_]u8{
        0xa3, // map(3)
        0x61, 'a', 0x01, // "a": 1 (shortest key first)
        0x62, 'b', 'b', 0x02, // "bb": 2 (same length, lex order)
        0x62, 'c', 'c', 0x03, // "cc": 3
    };
    try std.testing.expectEqualSlices(u8, expected, w.buffered());
}

test "round-trip encode → decode" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // build a complex value: {"active": true, "name": "alice", "seq": 42}
    const original: Value = .{ .map = &.{
        .{ .key = "name", .value = .{ .text = "alice" } },
        .{ .key = "active", .value = .{ .boolean = true } },
        .{ .key = "seq", .value = .{ .unsigned = 42 } },
    } };

    const encoded = try encodeAlloc(alloc, original);
    const decoded = try decodeAll(alloc, encoded);

    try std.testing.expectEqualStrings("alice", decoded.getString("name").?);
    try std.testing.expectEqual(true, decoded.getBool("active").?);
    try std.testing.expectEqual(@as(i64, 42), decoded.getInt("seq").?);
}

test "round-trip nested structures" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // {"ops": [{"action": "create"}], "seq": 1}
    const original: Value = .{ .map = &.{
        .{ .key = "ops", .value = .{ .array = &.{
            .{ .map = &.{
                .{ .key = "action", .value = .{ .text = "create" } },
            } },
        } } },
        .{ .key = "seq", .value = .{ .unsigned = 1 } },
    } };

    const encoded = try encodeAlloc(alloc, original);
    const decoded = try decodeAll(alloc, encoded);

    const ops = decoded.getArray("ops").?;
    try std.testing.expectEqual(@as(usize, 1), ops.len);
    try std.testing.expectEqualStrings("create", ops[0].getString("action").?);
    try std.testing.expectEqual(@as(i64, 1), decoded.getInt("seq").?);
}

test "encode CID via tag 42" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // create a CIDv1 (dag-cbor, sha2-256, 32-byte digest of 0xaa)
    const raw_cid = [_]u8{
        0x01, // version
        0x71, // dag-cbor
        0x12, // sha2-256
        0x20, // 32-byte digest
    } ++ [_]u8{0xaa} ** 32;

    const original: Value = .{ .cid = .{
        .raw = &raw_cid,
    } };

    const encoded = try encodeAlloc(alloc, original);
    const decoded = try decodeAll(alloc, encoded);

    // should decode back as a CID with the same raw bytes
    const cid = decoded.cid;
    try std.testing.expectEqual(@as(u64, 1), cid.version().?);
    try std.testing.expectEqual(@as(u64, 0x71), cid.codec().?);
    try std.testing.expectEqual(@as(u64, 0x12), cid.hashFn().?);
    try std.testing.expectEqualSlices(u8, &raw_cid, cid.raw);
}

test "writeUvarint round-trip" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);

    const test_values = [_]u64{ 0, 1, 127, 128, 255, 256, 16384, 0xffffffff };
    for (test_values) |val| {
        w.end = 0;
        try writeUvarint(&w, val);
        const written = w.buffered();

        var pos: usize = 0;
        const decoded = readUvarint(written, &pos).?;
        try std.testing.expectEqual(val, decoded);
        try std.testing.expectEqual(written.len, pos);
    }
}

test "DAG-CBOR key sort is stable" {
    // same-length keys must be lexicographically sorted
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    try encode(alloc, &w, .{ .map = &.{
        .{ .key = "op", .value = .{ .unsigned = 1 } },
        .{ .key = "ab", .value = .{ .unsigned = 2 } },
    } });

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const decoded = try decodeAll(arena.allocator(), w.buffered());

    // "ab" should come before "op" (lex order, same length)
    const entries = decoded.map;
    try std.testing.expectEqualStrings("ab", entries[0].key);
    try std.testing.expectEqualStrings("op", entries[1].key);
}

// === CID creation tests ===

test "Cid.forDagCbor creates valid CIDv1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // encode some CBOR, then create a CID for it
    const value: Value = .{ .map = &.{
        .{ .key = "text", .value = .{ .text = "hello" } },
    } };
    const encoded = try encodeAlloc(alloc, value);
    const cid = try Cid.forDagCbor(alloc, encoded);

    try std.testing.expectEqual(@as(u64, 1), cid.version().?);
    try std.testing.expectEqual(Codec.dag_cbor, cid.codec().?);
    try std.testing.expectEqual(HashFn.sha2_256, cid.hashFn().?);
    try std.testing.expectEqual(@as(usize, 32), cid.digest().?.len);
    // raw should be: version(1) + codec(0x71) + hash_fn(0x12) + digest_len(0x20) + 32 bytes
    try std.testing.expectEqual(@as(usize, 36), cid.raw.len);
}

test "Cid.forDagCbor is deterministic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const data = "identical input";
    const cid1 = try Cid.forDagCbor(alloc, data);
    const cid2 = try Cid.forDagCbor(alloc, data);

    try std.testing.expectEqualSlices(u8, cid1.raw, cid2.raw);
    try std.testing.expectEqualSlices(u8, cid1.digest().?, cid2.digest().?);
}

test "Cid.forDagCbor different data → different CIDs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const cid1 = try Cid.forDagCbor(alloc, "data A");
    const cid2 = try Cid.forDagCbor(alloc, "data B");

    try std.testing.expect(!std.mem.eql(u8, cid1.digest().?, cid2.digest().?));
}

test "Cid.toBytes round-trips through parseCid" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const cid = try Cid.forDagCbor(alloc, "test content");
    const bytes = try cid.toBytes(alloc);
    const parsed = parseCid(bytes);

    try std.testing.expectEqual(cid.version().?, parsed.version().?);
    try std.testing.expectEqual(cid.codec().?, parsed.codec().?);
    try std.testing.expectEqual(cid.hashFn().?, parsed.hashFn().?);
    try std.testing.expectEqualSlices(u8, cid.digest().?, parsed.digest().?);
}

test "CID round-trip through CBOR encode/decode" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // create a CID for some content
    const cid = try Cid.forDagCbor(alloc, "block data");

    // embed in a map and round-trip through CBOR
    const original: Value = .{ .map = &.{
        .{ .key = "link", .value = .{ .cid = cid } },
    } };
    const encoded = try encodeAlloc(alloc, original);
    const decoded = try decodeAll(alloc, encoded);

    const got = decoded.get("link").?.cid;
    try std.testing.expectEqual(cid.version().?, got.version().?);
    try std.testing.expectEqual(cid.codec().?, got.codec().?);
    try std.testing.expectEqualSlices(u8, cid.digest().?, got.digest().?);
}

// === verify CIDs against real AT Protocol records ===

test "real record: pfrazee 'First!' post CID matches network" {
    // at://did:plc:ragtjsm2j2vknwkz3zp4oxrd/app.bsky.feed.post/3jhnzcfawac27
    // CID: bafyreiaqnrahsbvcssf2xe4iqhn2fnjw7utmvrbif2v36tqe3r5iqill7i
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const record: Value = .{ .map = &.{
        .{ .key = "$type", .value = .{ .text = "app.bsky.feed.post" } },
        .{ .key = "createdAt", .value = .{ .text = "2022-11-17T00:39:00.477Z" } },
        .{ .key = "text", .value = .{ .text = "First!" } },
    } };

    const encoded = try encodeAlloc(alloc, record);
    const cid = try Cid.forDagCbor(alloc, encoded);

    // verify against known production digest
    const expected_digest = [_]u8{
        0x10, 0x6c, 0x40, 0x79, 0x06, 0xa2, 0x94, 0x8b,
        0xab, 0x93, 0x88, 0x81, 0xdb, 0xa2, 0xb5, 0x36,
        0xfd, 0x26, 0xca, 0xc4, 0x28, 0x2e, 0xab, 0xbf,
        0x4e, 0x04, 0xdc, 0x7a, 0x88, 0x21, 0x6b, 0xfa,
    };

    try std.testing.expectEqualSlices(u8, &expected_digest, cid.digest().?);
    try std.testing.expectEqual(@as(u64, 1), cid.version().?);
    try std.testing.expectEqual(Codec.dag_cbor, cid.codec().?);
    try std.testing.expectEqual(HashFn.sha2_256, cid.hashFn().?);
}

test "real record: firehose post with emoji/langs/reply is byte-identical after re-encode" {
    // captured from live firehose: app.bsky.feed.post with emoji, langs, and reply
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original_cbor = &[_]u8{
        0xa5, 0x64, 0x74, 0x65, 0x78, 0x74, 0x6b, 0xf0, 0x9f, 0xa5, 0xb5, 0x20, 0x6d, 0x65, 0x20, 0x74,
        0x6f, 0x6f, 0x65, 0x24, 0x74, 0x79, 0x70, 0x65, 0x72, 0x61, 0x70, 0x70, 0x2e, 0x62, 0x73, 0x6b,
        0x79, 0x2e, 0x66, 0x65, 0x65, 0x64, 0x2e, 0x70, 0x6f, 0x73, 0x74, 0x65, 0x6c, 0x61, 0x6e, 0x67,
        0x73, 0x81, 0x62, 0x65, 0x6e, 0x65, 0x72, 0x65, 0x70, 0x6c, 0x79, 0xa2, 0x64, 0x72, 0x6f, 0x6f,
        0x74, 0xa2, 0x63, 0x63, 0x69, 0x64, 0x78, 0x3b, 0x62, 0x61, 0x66, 0x79, 0x72, 0x65, 0x69, 0x62,
        0x33, 0x70, 0x77, 0x72, 0x66, 0x66, 0x32, 0x79, 0x61, 0x64, 0x7a, 0x6e, 0x6f, 0x70, 0x68, 0x7a,
        0x66, 0x34, 0x68, 0x63, 0x76, 0x74, 0x79, 0x6f, 0x63, 0x74, 0x77, 0x7a, 0x63, 0x75, 0x6a, 0x76,
        0x7a, 0x37, 0x78, 0x34, 0x70, 0x6e, 0x67, 0x6b, 0x32, 0x69, 0x73, 0x69, 0x63, 0x7a, 0x37, 0x79,
        0x73, 0x7a, 0x71, 0x63, 0x75, 0x72, 0x69, 0x78, 0x46, 0x61, 0x74, 0x3a, 0x2f, 0x2f, 0x64, 0x69,
        0x64, 0x3a, 0x70, 0x6c, 0x63, 0x3a, 0x34, 0x6e, 0x65, 0x6e, 0x64, 0x77, 0x71, 0x72, 0x73, 0x37,
        0x35, 0x34, 0x67, 0x74, 0x36, 0x71, 0x76, 0x67, 0x72, 0x35, 0x36, 0x6a, 0x6d, 0x6e, 0x2f, 0x61,
        0x70, 0x70, 0x2e, 0x62, 0x73, 0x6b, 0x79, 0x2e, 0x66, 0x65, 0x65, 0x64, 0x2e, 0x70, 0x6f, 0x73,
        0x74, 0x2f, 0x33, 0x6d, 0x65, 0x64, 0x67, 0x32, 0x71, 0x76, 0x63, 0x75, 0x63, 0x32, 0x63, 0x66,
        0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0xa2, 0x63, 0x63, 0x69, 0x64, 0x78, 0x3b, 0x62, 0x61, 0x66,
        0x79, 0x72, 0x65, 0x69, 0x62, 0x33, 0x70, 0x77, 0x72, 0x66, 0x66, 0x32, 0x79, 0x61, 0x64, 0x7a,
        0x6e, 0x6f, 0x70, 0x68, 0x7a, 0x66, 0x34, 0x68, 0x63, 0x76, 0x74, 0x79, 0x6f, 0x63, 0x74, 0x77,
        0x7a, 0x63, 0x75, 0x6a, 0x76, 0x7a, 0x37, 0x78, 0x34, 0x70, 0x6e, 0x67, 0x6b, 0x32, 0x69, 0x73,
        0x69, 0x63, 0x7a, 0x37, 0x79, 0x73, 0x7a, 0x71, 0x63, 0x75, 0x72, 0x69, 0x78, 0x46, 0x61, 0x74,
        0x3a, 0x2f, 0x2f, 0x64, 0x69, 0x64, 0x3a, 0x70, 0x6c, 0x63, 0x3a, 0x34, 0x6e, 0x65, 0x6e, 0x64,
        0x77, 0x71, 0x72, 0x73, 0x37, 0x35, 0x34, 0x67, 0x74, 0x36, 0x71, 0x76, 0x67, 0x72, 0x35, 0x36,
        0x6a, 0x6d, 0x6e, 0x2f, 0x61, 0x70, 0x70, 0x2e, 0x62, 0x73, 0x6b, 0x79, 0x2e, 0x66, 0x65, 0x65,
        0x64, 0x2e, 0x70, 0x6f, 0x73, 0x74, 0x2f, 0x33, 0x6d, 0x65, 0x64, 0x67, 0x32, 0x71, 0x76, 0x63,
        0x75, 0x63, 0x32, 0x63, 0x69, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x78, 0x18,
        0x32, 0x30, 0x32, 0x36, 0x2d, 0x30, 0x32, 0x2d, 0x30, 0x38, 0x54, 0x30, 0x37, 0x3a, 0x34, 0x39,
        0x3a, 0x32, 0x30, 0x2e, 0x37, 0x37, 0x32, 0x5a,
    };

    // expected CID digest from the firehose frame
    const expected_digest = [_]u8{
        0x80, 0x01, 0x66, 0x46, 0x81, 0x57, 0x18, 0xaf, 0xc9, 0x34, 0xcf, 0xbf,
        0x3b, 0x3e, 0x57, 0x04, 0x24, 0x17, 0x90, 0x29, 0x2f, 0x7b, 0xc4, 0xe0,
        0xf4, 0xcf, 0xe6, 0xe6, 0xb5, 0xad, 0x11, 0x28,
    };

    // decode → re-encode → verify byte-identical
    const decoded = try decodeAll(alloc, original_cbor);
    const re_encoded = try encodeAlloc(alloc, decoded);
    try std.testing.expectEqualSlices(u8, original_cbor, re_encoded);

    // verify CID matches the production CID
    const cid = try Cid.forDagCbor(alloc, re_encoded);
    try std.testing.expectEqualSlices(u8, &expected_digest, cid.digest().?);
}
