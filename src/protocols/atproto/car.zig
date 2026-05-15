//! CAR v1 — Content-Addressable aRchive reader + writer.
//!
//! Format:
//!   <header-len varint><dag-cbor header>
//!   <block-len varint><cid-bytes><dag-cbor block-data>...
//!
//! The header is a dag-cbor map: {"version":1, "roots":[<cid>...]}.
//! Each block's `<block-len>` is a varint of `cid.bytes.len + data.len`.
//!
//! Tiger Style: no allocator. Writer streams into a caller-supplied
//! buffer; reader yields blocks via iterator over a slice.
//!
//! Spec: https://ipld.io/specs/transport/car/carv1/

const std = @import("std");
const core = @import("core");
const AtpError = core.errors.AtpError;
const assertLe = core.assert.assertLe;

const cid_mod = @import("cid.zig");
const dag = @import("dag_cbor.zig");

pub const max_block_bytes: usize = 64 * 1024;

/// Encode an unsigned LEB128 varint into `dst`. Returns bytes written.
pub fn writeVarint(value: u64, dst: []u8) AtpError!usize {
    var v = value;
    var i: usize = 0;
    // Bounded: max 10 bytes for u64.
    while (i < 10) : (i += 1) {
        if (i >= dst.len) return error.BufferTooSmall;
        const byte: u8 = @intCast(v & 0x7f);
        v >>= 7;
        if (v == 0) {
            dst[i] = byte;
            return i + 1;
        }
        dst[i] = byte | 0x80;
    }
    return error.BadCbor;
}

pub fn readVarint(src: []const u8) AtpError!struct { value: u64, consumed: usize } {
    var v: u64 = 0;
    var shift: u6 = 0;
    var i: usize = 0;
    while (i < src.len and i < 10) : (i += 1) {
        const b = src[i];
        v |= @as(u64, b & 0x7f) << shift;
        if ((b & 0x80) == 0) return .{ .value = v, .consumed = i + 1 };
        shift += 7;
    }
    return error.BadCbor;
}

/// Write a CAR v1 header into `dst`. Returns bytes written.
pub fn writeHeader(roots: []const cid_mod.Cid, dst: []u8) AtpError!usize {
    // Build header CBOR: {"roots":[cid...], "version":1}
    var header_buf: [1024]u8 = undefined;
    var enc = dag.Encoder.init(&header_buf);
    try enc.writeMapHeader(2);
    try enc.writeText("roots");
    try enc.writeArrayHeader(roots.len);
    var i: usize = 0;
    while (i < roots.len) : (i += 1) {
        assertLe(i, roots.len);
        try enc.writeCidLink(roots[i].raw());
    }
    try enc.writeText("version");
    try enc.writeUInt(1);

    const header = enc.written();
    var pos: usize = 0;
    const vn = try writeVarint(header.len, dst);
    pos += vn;
    if (pos + header.len > dst.len) return error.BufferTooSmall;
    @memcpy(dst[pos..][0..header.len], header);
    pos += header.len;
    return pos;
}

/// Write a CAR block (cid + data) into `dst`. Returns bytes written.
pub fn writeBlock(cid: cid_mod.Cid, data: []const u8, dst: []u8) AtpError!usize {
    const total = cid_mod.raw_cid_len + data.len;
    if (total > max_block_bytes) return error.BufferTooSmall;
    var pos: usize = 0;
    const vn = try writeVarint(total, dst);
    pos += vn;
    if (pos + cid_mod.raw_cid_len > dst.len) return error.BufferTooSmall;
    @memcpy(dst[pos..][0..cid_mod.raw_cid_len], cid.raw());
    pos += cid_mod.raw_cid_len;
    if (pos + data.len > dst.len) return error.BufferTooSmall;
    @memcpy(dst[pos..][0..data.len], data);
    pos += data.len;
    return pos;
}

pub const Reader = struct {
    buf: []const u8,
    pos: usize,
    /// Header parsed lazily on first call to `next` or `header`.
    header_consumed: bool = false,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf, .pos = 0 };
    }

    pub fn skipHeader(self: *Reader) AtpError!void {
        if (self.header_consumed) return;
        const v = try readVarint(self.buf[self.pos..]);
        self.pos += v.consumed;
        if (self.pos + v.value > self.buf.len) return error.BadCbor;
        self.pos += @intCast(v.value);
        self.header_consumed = true;
    }

    pub const Block = struct {
        cid: cid_mod.Cid,
        data: []const u8,
    };

    pub fn next(self: *Reader) AtpError!?Block {
        try self.skipHeader();
        if (self.pos >= self.buf.len) return null;
        const v = try readVarint(self.buf[self.pos..]);
        self.pos += v.consumed;
        if (self.pos + v.value > self.buf.len) return error.BadCbor;
        const total: usize = @intCast(v.value);
        if (total < cid_mod.raw_cid_len) return error.BadCbor;
        var cid: cid_mod.Cid = .{ .bytes = undefined };
        @memcpy(cid.bytes[0..], self.buf[self.pos..][0..cid_mod.raw_cid_len]);
        const data = self.buf[self.pos + cid_mod.raw_cid_len .. self.pos + total];
        self.pos += total;
        return .{ .cid = cid, .data = data };
    }
};

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "car: varint round trip" {
    var buf: [10]u8 = undefined;
    inline for (.{ @as(u64, 0), 1, 127, 128, 16384, 1_000_000, std.math.maxInt(u32) }) |v| {
        const n = try writeVarint(v, &buf);
        const r = try readVarint(buf[0..n]);
        try testing.expectEqual(@as(u64, v), r.value);
        try testing.expectEqual(n, r.consumed);
    }
}

test "car: write+read header + blocks" {
    const cid_a = cid_mod.computeDagCbor("alpha");
    const cid_b = cid_mod.computeDagCbor("beta");

    var out: [4096]u8 = undefined;
    var pos: usize = 0;
    const roots = [_]cid_mod.Cid{cid_a};
    pos += try writeHeader(&roots, out[pos..]);
    pos += try writeBlock(cid_a, "alpha", out[pos..]);
    pos += try writeBlock(cid_b, "beta", out[pos..]);

    var r = Reader.init(out[0..pos]);
    try r.skipHeader();
    const b1 = (try r.next()).?;
    try testing.expectEqualSlices(u8, cid_a.raw(), b1.cid.raw());
    try testing.expectEqualStrings("alpha", b1.data);
    const b2 = (try r.next()).?;
    try testing.expectEqualSlices(u8, cid_b.raw(), b2.cid.raw());
    try testing.expectEqualStrings("beta", b2.data);
    try testing.expect((try r.next()) == null);
}

test "car: BufferTooSmall on short dst" {
    var out: [4]u8 = undefined;
    const roots = [_]cid_mod.Cid{cid_mod.computeDagCbor("x")};
    try testing.expectError(error.BufferTooSmall, writeHeader(&roots, &out));
}

// ── W2.3 streamer tests ────────────────────────────────────────────

test "car: empty roots header round-trips" {
    var out: [256]u8 = undefined;
    const roots: [0]cid_mod.Cid = .{};
    const n = try writeHeader(&roots, &out);
    var r = Reader.init(out[0..n]);
    try r.skipHeader();
    try testing.expect((try r.next()) == null);
}

test "car: multi-block stream preserves order" {
    var buf: [4096]u8 = undefined;
    var pos: usize = 0;
    const cids = [_]cid_mod.Cid{
        cid_mod.computeDagCbor("block-1"),
        cid_mod.computeDagCbor("block-2"),
        cid_mod.computeDagCbor("block-3"),
    };
    const roots = [_]cid_mod.Cid{cids[0]};
    pos += try writeHeader(&roots, buf[pos..]);
    pos += try writeBlock(cids[0], "block-1", buf[pos..]);
    pos += try writeBlock(cids[1], "block-2", buf[pos..]);
    pos += try writeBlock(cids[2], "block-3", buf[pos..]);

    var r = Reader.init(buf[0..pos]);
    var i: usize = 0;
    while (try r.next()) |b| : (i += 1) {
        try testing.expectEqualSlices(u8, cids[i].raw(), b.cid.raw());
    }
    try testing.expectEqual(@as(usize, 3), i);
}

test "car: varint encodes max u64 in 10 bytes" {
    var buf: [10]u8 = undefined;
    const n = try writeVarint(std.math.maxInt(u64), &buf);
    try testing.expectEqual(@as(usize, 10), n);
    const r = try readVarint(buf[0..n]);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), r.value);
}
