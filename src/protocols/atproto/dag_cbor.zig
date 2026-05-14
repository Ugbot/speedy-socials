//! Deterministic DAG-CBOR encoder + decoder.
//!
//! Conforms to the IPLD DAG-CBOR profile used by AT Protocol:
//!   * canonical integer encoding (shortest form, no leading zeros)
//!   * map keys must be text strings, sorted by length-then-lex
//!   * floats encoded only as 64-bit IEEE-754 (we never emit half/single)
//!   * CIDs are tag-42 byte strings (multibase 0x00 prefix + binary CID)
//!   * indefinite-length encodings are rejected
//!
//! Tiger Style:
//!   * Encoder writes into a caller-provided `[]u8`. No allocator. Returns
//!     bytes written.
//!   * Decoder is pull-style with an explicit operand stack — no
//!     recursion. The caller passes a `Visitor` (a comptime-generic
//!     handler with `onUInt`/`onText`/etc.) that observes events.
//!   * Every walk loop is bounded by `max_decode_items` /
//!     `max_decode_depth`. Overflow → `error.BadCbor`.
//!
//! Refs:
//!   * RFC 8949 (CBOR core)
//!   * https://ipld.io/specs/codecs/dag-cbor/spec/
//!   * https://atproto.com/specs/data-model

const std = @import("std");
const core = @import("core");
const AtpError = core.errors.AtpError;
const assertLe = core.assert.assertLe;
const assert = core.assert.assert;

// CBOR major types.
pub const MajorType = enum(u3) {
    uint = 0,
    nint = 1,
    bytes = 2,
    text = 3,
    array = 4,
    map = 5,
    tag = 6,
    float_or_simple = 7,
};

/// Maximum logical items the decoder will yield in one pass (across all
/// nesting). A bound far above real AT Protocol records.
pub const max_decode_items: u32 = 65_536;

/// Maximum container nesting depth.
pub const max_decode_depth: u32 = 64;

/// IPLD tag for CIDs (RFC 8949 §3.4.4 family, IPLD-specific).
pub const cid_tag: u64 = 42;

// ── Encoder ────────────────────────────────────────────────────────

/// Cursor over a caller-provided buffer. Writes append; out-of-room
/// returns `error.BufferTooSmall`.
pub const Encoder = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) Encoder {
        return .{ .buf = buf };
    }

    pub fn written(self: Encoder) []const u8 {
        return self.buf[0..self.pos];
    }

    pub fn writeByte(self: *Encoder, b: u8) AtpError!void {
        if (self.pos >= self.buf.len) return error.BufferTooSmall;
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    fn writeBytes(self: *Encoder, src: []const u8) AtpError!void {
        if (self.pos + src.len > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos..][0..src.len], src);
        self.pos += src.len;
    }

    /// Write a CBOR head with the canonical (shortest) integer encoding.
    fn writeHead(self: *Encoder, mt: MajorType, value: u64) AtpError!void {
        const mt_bits: u8 = @as(u8, @intFromEnum(mt)) << 5;
        if (value < 24) {
            try self.writeByte(mt_bits | @as(u8, @intCast(value)));
        } else if (value <= 0xff) {
            try self.writeByte(mt_bits | 24);
            try self.writeByte(@as(u8, @intCast(value)));
        } else if (value <= 0xffff) {
            try self.writeByte(mt_bits | 25);
            try self.writeByte(@as(u8, @intCast((value >> 8) & 0xff)));
            try self.writeByte(@as(u8, @intCast(value & 0xff)));
        } else if (value <= 0xffff_ffff) {
            try self.writeByte(mt_bits | 26);
            var i: i32 = 3;
            while (i >= 0) : (i -= 1) {
                try self.writeByte(@as(u8, @intCast((value >> @as(u6, @intCast(i * 8))) & 0xff)));
            }
        } else {
            try self.writeByte(mt_bits | 27);
            var i: i32 = 7;
            while (i >= 0) : (i -= 1) {
                try self.writeByte(@as(u8, @intCast((value >> @as(u6, @intCast(i * 8))) & 0xff)));
            }
        }
    }

    pub fn writeUInt(self: *Encoder, v: u64) AtpError!void {
        try self.writeHead(.uint, v);
    }

    /// Encode a signed integer; uses major-type 1 (nint) for negatives.
    pub fn writeInt(self: *Encoder, v: i64) AtpError!void {
        if (v >= 0) {
            try self.writeHead(.uint, @as(u64, @intCast(v)));
        } else {
            // nint encodes -1 - n
            const n: u64 = @intCast(-(v + 1));
            try self.writeHead(.nint, n);
        }
    }

    pub fn writeBool(self: *Encoder, b: bool) AtpError!void {
        // major 7: 20=false, 21=true.
        try self.writeByte(if (b) 0xf5 else 0xf4);
    }

    pub fn writeNull(self: *Encoder) AtpError!void {
        try self.writeByte(0xf6);
    }

    pub fn writeFloat64(self: *Encoder, f: f64) AtpError!void {
        // DAG-CBOR mandates 64-bit float encoding.
        try self.writeByte(0xfb);
        const bits: u64 = @bitCast(f);
        var i: i32 = 7;
        while (i >= 0) : (i -= 1) {
            try self.writeByte(@as(u8, @intCast((bits >> @as(u6, @intCast(i * 8))) & 0xff)));
        }
    }

    pub fn writeBytesValue(self: *Encoder, bytes: []const u8) AtpError!void {
        try self.writeHead(.bytes, bytes.len);
        try self.writeBytes(bytes);
    }

    pub fn writeText(self: *Encoder, s: []const u8) AtpError!void {
        try self.writeHead(.text, s.len);
        try self.writeBytes(s);
    }

    pub fn writeArrayHeader(self: *Encoder, count: u64) AtpError!void {
        try self.writeHead(.array, count);
    }

    pub fn writeMapHeader(self: *Encoder, pair_count: u64) AtpError!void {
        try self.writeHead(.map, pair_count);
    }

    pub fn writeTag(self: *Encoder, tag: u64) AtpError!void {
        try self.writeHead(.tag, tag);
    }

    /// Write a CID as a tag-42 byte string. `cid_bytes` should be the
    /// raw binary CID (no multibase prefix). Per the IPLD/DAG-CBOR spec
    /// we prepend a single 0x00 multibase identity byte.
    pub fn writeCidLink(self: *Encoder, cid_bytes: []const u8) AtpError!void {
        try self.writeTag(cid_tag);
        try self.writeHead(.bytes, cid_bytes.len + 1);
        try self.writeByte(0x00);
        try self.writeBytes(cid_bytes);
    }
};

/// In-memory key→value record used by `writeCanonicalMap` to sort
/// already-encoded entries before writing them out. Each entry's `body`
/// is the full CBOR encoding of the value (head + payload).
pub const MapEntry = struct {
    key: []const u8,
    body: []const u8,
};

/// Write a map whose entries are already encoded, applying the
/// length-then-byte-lex key ordering DAG-CBOR mandates. The caller
/// guarantees no duplicate keys.
pub fn writeCanonicalMap(enc: *Encoder, entries: []MapEntry) AtpError!void {
    // Sort entries in place. Caller-owned slice — small (record-scale).
    std.sort.pdq(MapEntry, entries, {}, lessKey);

    try enc.writeMapHeader(entries.len);
    var i: usize = 0;
    while (i < entries.len) : (i += 1) {
        assertLe(i, entries.len);
        try enc.writeText(entries[i].key);
        // The body is already canonical CBOR — append verbatim.
        if (enc.pos + entries[i].body.len > enc.buf.len) return error.BufferTooSmall;
        @memcpy(enc.buf[enc.pos..][0..entries[i].body.len], entries[i].body);
        enc.pos += entries[i].body.len;
    }
}

fn lessKey(_: void, a: MapEntry, b: MapEntry) bool {
    if (a.key.len != b.key.len) return a.key.len < b.key.len;
    return std.mem.lessThan(u8, a.key, b.key);
}

// ── Decoder ────────────────────────────────────────────────────────

/// One CBOR event yielded by the decoder.
pub const Event = union(enum) {
    uint: u64,
    nint: u64, // raw nint payload; logical value is -1 - nint
    int: i64, // synthesized helper (only when value fits i64)
    bytes: []const u8,
    text: []const u8,
    array_start: u64,
    map_start: u64,
    boolean: bool,
    null_,
    float64: f64,
    cid: []const u8, // includes the leading 0x00 identity byte stripped
};

/// Streaming decoder. Holds the input slice and a position cursor; the
/// caller drives it with `nextEvent` until end of input. Container
/// elements are flat: the decoder reports a `map_start` / `array_start`
/// event with the count, then the caller is responsible for consuming
/// that many key/value (or element) events. The bounded stack inside
/// `walkAll` enforces correct nesting.
pub const Decoder = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Decoder {
        return .{ .buf = buf };
    }

    pub fn atEnd(self: Decoder) bool {
        return self.pos >= self.buf.len;
    }

    fn readByte(self: *Decoder) AtpError!u8 {
        if (self.pos >= self.buf.len) return error.BadCbor;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }

    fn readN(self: *Decoder, n: usize) AtpError![]const u8 {
        if (self.pos + n > self.buf.len) return error.BadCbor;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }

    fn readArg(self: *Decoder, info: u5) AtpError!u64 {
        // Reject indefinite-length (info == 31).
        if (info < 24) return @as(u64, info);
        switch (info) {
            24 => return @as(u64, try self.readByte()),
            25 => {
                const hi = try self.readByte();
                const lo = try self.readByte();
                return (@as(u64, hi) << 8) | @as(u64, lo);
            },
            26 => {
                var v: u64 = 0;
                var i: u32 = 0;
                while (i < 4) : (i += 1) {
                    v = (v << 8) | @as(u64, try self.readByte());
                }
                return v;
            },
            27 => {
                var v: u64 = 0;
                var i: u32 = 0;
                while (i < 8) : (i += 1) {
                    v = (v << 8) | @as(u64, try self.readByte());
                }
                return v;
            },
            else => return error.BadCbor, // 28..31 unused / indefinite
        }
    }

    /// Yields one logical event. Tag 42 + bytes is collapsed into a
    /// single `cid` event. Indefinite encodings are rejected.
    pub fn nextEvent(self: *Decoder) AtpError!Event {
        if (self.atEnd()) return error.BadCbor;
        const initial = try self.readByte();
        const mt: MajorType = @enumFromInt(@as(u3, @intCast(initial >> 5)));
        const info: u5 = @intCast(initial & 0x1f);

        switch (mt) {
            .uint => {
                const v = try self.readArg(info);
                return .{ .uint = v };
            },
            .nint => {
                const v = try self.readArg(info);
                return .{ .nint = v };
            },
            .bytes => {
                const len = try self.readArg(info);
                if (len > std.math.maxInt(usize)) return error.BadCbor;
                const s = try self.readN(@intCast(len));
                return .{ .bytes = s };
            },
            .text => {
                const len = try self.readArg(info);
                if (len > std.math.maxInt(usize)) return error.BadCbor;
                const s = try self.readN(@intCast(len));
                // We do not verify UTF-8 here for speed; AT Protocol payloads
                // are constructed from upstream Zig strings and we re-validate
                // in higher-level handlers where required.
                return .{ .text = s };
            },
            .array => {
                const n = try self.readArg(info);
                return .{ .array_start = n };
            },
            .map => {
                const n = try self.readArg(info);
                return .{ .map_start = n };
            },
            .tag => {
                const tag = try self.readArg(info);
                if (tag != cid_tag) return error.BadCbor;
                // Following item MUST be a byte string with identity prefix.
                const head = try self.readByte();
                const head_mt: MajorType = @enumFromInt(@as(u3, @intCast(head >> 5)));
                const head_info: u5 = @intCast(head & 0x1f);
                if (head_mt != .bytes) return error.BadCbor;
                const blen = try self.readArg(head_info);
                if (blen == 0) return error.BadCbor;
                if (blen > std.math.maxInt(usize)) return error.BadCbor;
                const raw = try self.readN(@intCast(blen));
                if (raw[0] != 0x00) return error.BadCbor;
                return .{ .cid = raw[1..] };
            },
            .float_or_simple => switch (info) {
                20 => return .{ .boolean = false },
                21 => return .{ .boolean = true },
                22 => return .null_,
                // DAG-CBOR forbids `undefined` (23), half (25), single (26).
                23 => return error.BadCbor,
                25 => return error.BadCbor,
                26 => return error.BadCbor,
                27 => {
                    var v: u64 = 0;
                    var i: u32 = 0;
                    while (i < 8) : (i += 1) {
                        v = (v << 8) | @as(u64, try self.readByte());
                    }
                    return .{ .float64 = @bitCast(v) };
                },
                else => return error.BadCbor,
            },
        }
    }
};

/// Visitor contract. Pass a *pointer* to a struct that implements as many
/// of the optional handlers as your application needs. Missing handlers
/// become no-ops.
pub fn walkAll(comptime Visitor: type, visitor: *Visitor, dec: *Decoder) AtpError!void {
    // Container frame stack — pending element counts. When a frame's
    // count reaches 0, pop it. For maps each pair counts as two
    // remaining elements (key, value).
    var frames: [max_decode_depth]u64 = undefined;
    var top: u32 = 0;

    var items: u32 = 0;
    while (!dec.atEnd() or top > 0) {
        items += 1;
        if (items > max_decode_items) return error.BadCbor;

        if (dec.atEnd()) return error.BadCbor; // ran out mid-container

        const ev = try dec.nextEvent();
        dispatch(Visitor, visitor, ev);

        switch (ev) {
            .array_start => |n| {
                if (top >= max_decode_depth) return error.BadCbor;
                frames[top] = n;
                top += 1;
            },
            .map_start => |n| {
                if (top >= max_decode_depth) return error.BadCbor;
                if (n > std.math.maxInt(u64) / 2) return error.BadCbor;
                frames[top] = n * 2;
                top += 1;
            },
            else => {},
        }

        // Decrement the innermost container counter (the event we just
        // emitted consumes one slot). Skip if we just *opened* a
        // container — the open event itself is a child of the *parent*.
        // Adjust: opening a container does count as one item in the parent
        // but we've already incremented `top` above, so we still need to
        // tick the parent down.
        // Implementation: walk from top-1 down to 0, but only decrement
        // the frame that "owned" this event. That's exactly the frame
        // that was on top *before* we pushed (if we pushed). To keep this
        // simple and bounded, we use a sentinel: if we just pushed, the
        // event belonged to top-2 (the new parent). Otherwise top-1.
        if (top > 0) {
            const pushed = switch (ev) {
                .array_start, .map_start => true,
                else => false,
            };
            const parent_index: i64 = if (pushed) @as(i64, top) - 2 else @as(i64, top) - 1;
            if (parent_index >= 0) {
                const idx: u32 = @intCast(parent_index);
                if (frames[idx] == 0) return error.BadCbor;
                frames[idx] -= 1;
                // Pop completed frames.
                while (top > 0 and frames[top - 1] == 0) : (top -= 1) {}
            }
        }
        // No container — just a top-level item. Loop ends when the
        // decoder is exhausted and the stack is empty.
    }

    if (top != 0) return error.BadCbor;
}

fn dispatch(comptime Visitor: type, visitor: *Visitor, ev: Event) void {
    switch (ev) {
        .uint => |v| if (@hasDecl(Visitor, "onUInt")) visitor.onUInt(v),
        .nint => |v| if (@hasDecl(Visitor, "onNInt")) visitor.onNInt(v),
        .int => |v| if (@hasDecl(Visitor, "onInt")) visitor.onInt(v),
        .bytes => |s| if (@hasDecl(Visitor, "onBytes")) visitor.onBytes(s),
        .text => |s| if (@hasDecl(Visitor, "onText")) visitor.onText(s),
        .array_start => |n| if (@hasDecl(Visitor, "onArrayStart")) visitor.onArrayStart(n),
        .map_start => |n| if (@hasDecl(Visitor, "onMapStart")) visitor.onMapStart(n),
        .boolean => |b| if (@hasDecl(Visitor, "onBool")) visitor.onBool(b),
        .null_ => if (@hasDecl(Visitor, "onNull")) visitor.onNull(),
        .float64 => |f| if (@hasDecl(Visitor, "onFloat64")) visitor.onFloat64(f),
        .cid => |c| if (@hasDecl(Visitor, "onCid")) visitor.onCid(c),
    }
}

// ── Tests ──────────────────────────────────────────────────────────

test "cbor: encode small uint, head byte only" {
    var buf: [16]u8 = undefined;
    var enc = Encoder.init(&buf);
    try enc.writeUInt(0);
    try enc.writeUInt(23);
    try enc.writeUInt(24);
    try enc.writeUInt(255);
    try enc.writeUInt(256);
    const got = enc.written();
    // 0 -> 0x00; 23 -> 0x17; 24 -> 0x18 0x18; 255 -> 0x18 0xff; 256 -> 0x19 0x01 0x00
    const expected = [_]u8{ 0x00, 0x17, 0x18, 0x18, 0x18, 0xff, 0x19, 0x01, 0x00 };
    try std.testing.expectEqualSlices(u8, &expected, got);
}

test "cbor: encode int signs" {
    var buf: [16]u8 = undefined;
    var enc = Encoder.init(&buf);
    try enc.writeInt(-1);
    try enc.writeInt(-24);
    try enc.writeInt(-25);
    const got = enc.written();
    const expected = [_]u8{ 0x20, 0x37, 0x38, 0x18 };
    try std.testing.expectEqualSlices(u8, &expected, got);
}

test "cbor: encode bool, null, float" {
    var buf: [16]u8 = undefined;
    var enc = Encoder.init(&buf);
    try enc.writeBool(true);
    try enc.writeBool(false);
    try enc.writeNull();
    try enc.writeFloat64(1.5);
    const got = enc.written();
    // 1.5 → 0xfb 0x3f 0xf8 0x00 ... 0
    try std.testing.expectEqual(@as(u8, 0xf5), got[0]);
    try std.testing.expectEqual(@as(u8, 0xf4), got[1]);
    try std.testing.expectEqual(@as(u8, 0xf6), got[2]);
    try std.testing.expectEqual(@as(u8, 0xfb), got[3]);
    try std.testing.expectEqual(@as(u8, 0x3f), got[4]);
    try std.testing.expectEqual(@as(u8, 0xf8), got[5]);
}

test "cbor: text + bytes" {
    var buf: [32]u8 = undefined;
    var enc = Encoder.init(&buf);
    try enc.writeText("hello");
    try enc.writeBytesValue("\x00\x01\x02");
    const expected = [_]u8{ 0x65, 'h', 'e', 'l', 'l', 'o', 0x43, 0x00, 0x01, 0x02 };
    try std.testing.expectEqualSlices(u8, &expected, enc.written());
}

test "cbor: BufferTooSmall propagates" {
    var buf: [3]u8 = undefined;
    var enc = Encoder.init(&buf);
    try std.testing.expectError(error.BufferTooSmall, enc.writeText("hello"));
}

test "cbor: encode + decode roundtrip of mixed values" {
    var buf: [64]u8 = undefined;
    var enc = Encoder.init(&buf);
    try enc.writeUInt(42);
    try enc.writeInt(-7);
    try enc.writeText("at");
    try enc.writeBool(true);

    var dec = Decoder.init(enc.written());
    const e1 = try dec.nextEvent();
    try std.testing.expectEqual(@as(u64, 42), e1.uint);
    const e2 = try dec.nextEvent();
    try std.testing.expectEqual(@as(u64, 6), e2.nint); // -7 == nint(6)
    const e3 = try dec.nextEvent();
    try std.testing.expectEqualStrings("at", e3.text);
    const e4 = try dec.nextEvent();
    try std.testing.expect(e4.boolean);
}

test "cbor: tag-42 CID roundtrip" {
    var buf: [64]u8 = undefined;
    var enc = Encoder.init(&buf);
    const raw_cid = [_]u8{ 0x01, 0x71, 0x12, 0x20, 0xaa, 0xbb, 0xcc };
    try enc.writeCidLink(&raw_cid);

    var dec = Decoder.init(enc.written());
    const ev = try dec.nextEvent();
    try std.testing.expectEqualSlices(u8, &raw_cid, ev.cid);
}

test "cbor: canonical map ordering — short before long, lex within length" {
    var buf: [128]u8 = undefined;
    var enc = Encoder.init(&buf);

    // Pre-encode three values, each in its own buffer slice.
    var v_b: [4]u8 = undefined;
    var v_aa: [4]u8 = undefined;
    var v_bb: [4]u8 = undefined;
    var e_b = Encoder.init(&v_b);
    var e_aa = Encoder.init(&v_aa);
    var e_bb = Encoder.init(&v_bb);
    try e_b.writeUInt(1);
    try e_aa.writeUInt(2);
    try e_bb.writeUInt(3);

    var entries = [_]MapEntry{
        .{ .key = "aa", .body = e_aa.written() },
        .{ .key = "b", .body = e_b.written() },
        .{ .key = "bb", .body = e_bb.written() },
    };
    try writeCanonicalMap(&enc, &entries);

    // Expect: map header 0xa3, then "b":1, "aa":2, "bb":3.
    const got = enc.written();
    try std.testing.expectEqual(@as(u8, 0xa3), got[0]); // map(3)
    // First key: "b" (length 1).
    try std.testing.expectEqual(@as(u8, 0x61), got[1]);
    try std.testing.expectEqual(@as(u8, 'b'), got[2]);
    try std.testing.expectEqual(@as(u8, 0x01), got[3]);
    // Second key: "aa".
    try std.testing.expectEqual(@as(u8, 0x62), got[4]);
    try std.testing.expectEqual(@as(u8, 'a'), got[5]);
    try std.testing.expectEqual(@as(u8, 'a'), got[6]);
    try std.testing.expectEqual(@as(u8, 0x02), got[7]);
    // Third key: "bb".
    try std.testing.expectEqual(@as(u8, 0x62), got[8]);
    try std.testing.expectEqual(@as(u8, 'b'), got[9]);
    try std.testing.expectEqual(@as(u8, 'b'), got[10]);
    try std.testing.expectEqual(@as(u8, 0x03), got[11]);
}

test "cbor: decoder rejects indefinite length" {
    // 0x9f = indefinite-length array
    const bad = [_]u8{ 0x9f, 0xff };
    var dec = Decoder.init(&bad);
    try std.testing.expectError(error.BadCbor, dec.nextEvent());
}

test "cbor: walkAll counts items in nested map + array" {
    var buf: [128]u8 = undefined;
    var enc = Encoder.init(&buf);
    // { "xs": [1, 2, 3], "k": "v" }
    try enc.writeMapHeader(2);
    try enc.writeText("xs");
    try enc.writeArrayHeader(3);
    try enc.writeUInt(1);
    try enc.writeUInt(2);
    try enc.writeUInt(3);
    try enc.writeText("k");
    try enc.writeText("v");

    const Counter = struct {
        items: u32 = 0,
        fn onUInt(self: *@This(), _: u64) void {
            self.items += 1;
        }
        fn onText(self: *@This(), _: []const u8) void {
            self.items += 1;
        }
        fn onArrayStart(self: *@This(), _: u64) void {
            self.items += 1;
        }
        fn onMapStart(self: *@This(), _: u64) void {
            self.items += 1;
        }
    };
    var counter: Counter = .{};
    var dec = Decoder.init(enc.written());
    try walkAll(Counter, &counter, &dec);
    // Map(1) + "xs"(2) + Array(3) + 1,2,3(6) + "k"(7) + "v"(8) → 8
    try std.testing.expectEqual(@as(u32, 8), counter.items);
}
