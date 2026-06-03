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
const HttpError = core.errors.HttpError;
const assertLe = core.assert.assertLe;
const response_stream = core.http.response_stream;
const response = core.http.response;

const cid_mod = @import("cid.zig");
const dag = @import("dag_cbor.zig");

pub const max_block_bytes: usize = 64 * 1024;

/// Capacity of the in-flight chunk ring used by `ChunkedWriter`. Power of two.
/// Each pending chunk references bytes owned by an external scratch (the
/// CAR encoder's per-block frame buffer or the carrying request arena),
/// so this only bounds *how many* frames may be in flight, not their size.
pub const chunked_ring_capacity: u32 = 64;
pub const ChunkRingT = response_stream.ChunkRing(chunked_ring_capacity);

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

/// Alias kept for ChunkedWriter (which shadows the module-level
/// `writeBlock` method-name).
pub const encodeBlock = writeBlock;

// ── ChunkedWriter ─────────────────────────────────────────────────
//
// Streams a CAR (header + N blocks + final zero-length chunk) as
// HTTP/1.1 chunked transfer encoding into a `response.Builder`. The
// caller drives it: it owns the response builder and feeds blocks one
// at a time via `writeBlock`. Each block is framed as either:
//
//   * a CAR header chunk (called once, via `writeHeaderChunk`), or
//   * one CAR block chunk (varint(total) + cid.raw() + data), or
//   * the final `0\r\n\r\n` zero-length chunk (via `finish`).
//
// The encoder writes each frame into the response builder buffer as
// `<hex>\r\n<payload>\r\n`. The ring serves as a bounded staging area
// for the drain helper; today every push is followed by an inline
// drain so the ring is empty after each `writeBlock`. The ring's
// existence keeps the API future-compatible with the server pushing
// frames to the socket between blocks (W3.3 plumbing).
//
// Tiger Style: per-block CAR encode scratch is bounded by
// `chunked_block_scratch_bytes`. No recursion. Every loop is bounded
// by the ring size.

/// Per-block CAR-encode scratch. Sized to comfortably hold one block
/// (varint + raw_cid + record CBOR). Largest record bodies seen in
/// the AT lexicon today are ~32 KiB; CAR's `max_block_bytes` caps at
/// 64 KiB so we match.
pub const chunked_block_scratch_bytes: usize = max_block_bytes + 32;

pub const ChunkedWriter = struct {
    ring: *ChunkRingT,
    response_writer: *response.Builder,
    /// Scratch for the current block's CAR-encoded bytes. Stable across
    /// calls because we drain inline before returning, so the storage
    /// only needs to outlive one writeBlock invocation.
    block_scratch: [chunked_block_scratch_bytes]u8 = undefined,
    bytes_so_far: usize = 0,
    headers_written: bool = false,
    finished: bool = false,

    pub fn init(ring: *ChunkRingT, response_writer: *response.Builder) ChunkedWriter {
        return .{
            .ring = ring,
            .response_writer = response_writer,
        };
    }

    /// Emit the HTTP response head with chunked framing into the response
    /// builder. After this returns the body region is open for chunks.
    pub fn writeHttpHead(self: *ChunkedWriter, content_type: []const u8) HttpError!void {
        const remaining = self.response_writer.buffer[self.response_writer.pos..];
        const n = try response_stream.writeChunkedHead(remaining, .ok, content_type);
        self.response_writer.pos += n;
        self.response_writer.headers_finalized = true;
        self.headers_written = true;
    }

    /// Frame and emit the CAR header (`{version:1, roots:[...]}`) as
    /// one chunked frame. Must be called exactly once, before any
    /// `writeBlock`.
    pub fn writeHeaderChunk(self: *ChunkedWriter, roots: []const cid_mod.Cid) anyerror!void {
        if (!self.headers_written) return error.BadCbor;
        const n = try writeHeader(roots, &self.block_scratch);
        try self.pushAndDrain(self.block_scratch[0..n], false);
    }

    /// Frame and emit one CAR block. Bounded by `max_block_bytes`.
    pub fn writeBlock(self: *ChunkedWriter, cid: cid_mod.Cid, payload: []const u8) anyerror!void {
        if (!self.headers_written) return error.BadCbor;
        const n = try encodeBlock(cid, payload, &self.block_scratch);
        try self.pushAndDrain(self.block_scratch[0..n], false);
    }

    /// Emit the final zero-length chunk that terminates the response.
    pub fn finish(self: *ChunkedWriter) anyerror!void {
        if (self.finished) return;
        const remaining = self.response_writer.buffer[self.response_writer.pos..];
        const n = try response_stream.writeChunkedEnd(remaining);
        self.response_writer.pos += n;
        self.finished = true;
    }

    fn pushAndDrain(self: *ChunkedWriter, payload: []const u8, final: bool) anyerror!void {
        // Push into the ring — bounded, asserted-empty after drain.
        self.ring.push(.{ .bytes = payload, .final = final }) catch return error.BufferTooSmall;
        try self.drain();
    }

    /// Pop every chunk from the ring and emit it as a chunked frame.
    /// Today this is inline-after-push; once the server forwards
    /// streams socket-side, the drain will be invoked by the I/O layer
    /// instead of the handler.
    pub fn drain(self: *ChunkedWriter) anyerror!void {
        var drained: u32 = 0;
        while (drained < chunked_ring_capacity) : (drained += 1) {
            assertLe(drained, chunked_ring_capacity);
            const chunk = self.ring.pop() orelse return;
            const remaining = self.response_writer.buffer[self.response_writer.pos..];
            const n = response_stream.writeChunkFrame(remaining, chunk.bytes) catch return error.BufferTooSmall;
            self.response_writer.pos += n;
            self.bytes_so_far += chunk.bytes.len;
        }
    }
};

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

// ── ChunkedWriter tests ────────────────────────────────────────────

/// Helper for the streaming tests: parse the body region of an HTTP
/// chunked response into a single linear buffer. Returns total bytes
/// of payload (the original CAR stream).
fn decodeChunkedBody(chunked: []const u8, out: []u8) !usize {
    var i: usize = 0;
    var w: usize = 0;
    var guard: u32 = 0;
    while (i < chunked.len) {
        guard += 1;
        if (guard > 100_000) return error.BadCbor;
        // Read hex size up to CRLF.
        const lf = std.mem.indexOfScalarPos(u8, chunked, i, '\n') orelse return error.BadCbor;
        if (lf == 0 or chunked[lf - 1] != '\r') return error.BadCbor;
        const hex = chunked[i .. lf - 1];
        const size = try std.fmt.parseInt(usize, hex, 16);
        i = lf + 1;
        if (size == 0) return w;
        if (i + size + 2 > chunked.len) return error.BadCbor;
        if (w + size > out.len) return error.BufferTooSmall;
        @memcpy(out[w..][0..size], chunked[i..][0..size]);
        w += size;
        i += size;
        if (chunked[i] != '\r' or chunked[i + 1] != '\n') return error.BadCbor;
        i += 2;
    }
    return w;
}

test "car: ChunkedWriter writes head + header + one block + final chunk" {
    var buf: [4096]u8 = undefined;
    var rb = response.Builder.init(&buf);
    var ring = ChunkRingT.init();
    var cw = ChunkedWriter.init(&ring, &rb);

    try cw.writeHttpHead("application/vnd.ipld.car");
    const cid_a = cid_mod.computeDagCbor("alpha");
    const roots = [_]cid_mod.Cid{cid_a};
    try cw.writeHeaderChunk(&roots);
    try cw.writeBlock(cid_a, "alpha");
    try cw.finish();

    const out = rb.bytes();
    try testing.expect(std.mem.startsWith(u8, out, "HTTP/1.1 200 OK"));
    try testing.expect(std.mem.indexOf(u8, out, "Transfer-Encoding: chunked\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, out, "0\r\n\r\n"));

    // Body region starts after the first \r\n\r\n.
    const body_start = std.mem.indexOf(u8, out, "\r\n\r\n").? + 4;
    var car_buf: [2048]u8 = undefined;
    const car_len = try decodeChunkedBody(out[body_start..], &car_buf);

    var r = Reader.init(car_buf[0..car_len]);
    try r.skipHeader();
    const b = (try r.next()).?;
    try testing.expectEqualStrings("alpha", b.data);
    try testing.expect((try r.next()) == null);
}

test "car: ChunkedWriter streams a >50 KiB repo end-to-end" {
    // The encoded CAR body must exceed 50 KiB; with 128 blocks × ~400 B
    // each (varint + raw_cid (36 B) + ~360 B record payload) we land
    // ~52 KiB of body. The response builder must be sized to hold the
    // chunked encoding (body + framing overhead + HTTP head).
    const num_blocks: usize = 144;
    const block_payload_size: usize = 384;

    // The response builder buffer for the chunked encoding itself.
    // Body (~52 KiB) + framing overhead (~9 B/chunk) + head (~150 B).
    const builder_buf = try testing.allocator.alloc(u8, 96 * 1024);
    defer testing.allocator.free(builder_buf);
    var rb = response.Builder.init(builder_buf);

    var ring = ChunkRingT.init();
    var cw = ChunkedWriter.init(&ring, &rb);

    // Generate deterministic CIDs + payloads so the test is reproducible.
    var rng = std.Random.DefaultPrng.init(0xC0DEFADE);
    var payload_pool = try testing.allocator.alloc(u8, num_blocks * block_payload_size);
    defer testing.allocator.free(payload_pool);
    rng.fill(payload_pool);

    // Compute CIDs (one per block) up front.
    var cids = try testing.allocator.alloc(cid_mod.Cid, num_blocks);
    defer testing.allocator.free(cids);
    var bi: usize = 0;
    while (bi < num_blocks) : (bi += 1) {
        cids[bi] = cid_mod.computeDagCbor(payload_pool[bi * block_payload_size ..][0..block_payload_size]);
    }

    try cw.writeHttpHead("application/vnd.ipld.car");
    const roots = [_]cid_mod.Cid{cids[0]};
    try cw.writeHeaderChunk(&roots);
    bi = 0;
    while (bi < num_blocks) : (bi += 1) {
        const slice = payload_pool[bi * block_payload_size ..][0..block_payload_size];
        try cw.writeBlock(cids[bi], slice);
    }
    try cw.finish();

    const out = rb.bytes();
    try testing.expect(std.mem.endsWith(u8, out, "0\r\n\r\n"));

    const body_start = std.mem.indexOf(u8, out, "\r\n\r\n").? + 4;
    const chunked_body = out[body_start..];

    // Decode the chunked transfer encoding back into raw CAR bytes.
    const car_buf = try testing.allocator.alloc(u8, 128 * 1024);
    defer testing.allocator.free(car_buf);
    const car_len = try decodeChunkedBody(chunked_body, car_buf);
    try testing.expect(car_len > 50 * 1024); // exceeds the old 12 KiB scratch

    // Re-parse the CAR and assert byte-identical recovery of each block.
    var r = Reader.init(car_buf[0..car_len]);
    try r.skipHeader();
    bi = 0;
    while (try r.next()) |block| : (bi += 1) {
        try testing.expectEqualSlices(u8, cids[bi].raw(), block.cid.raw());
        const expected = payload_pool[bi * block_payload_size ..][0..block_payload_size];
        try testing.expectEqualSlices(u8, expected, block.data);
    }
    try testing.expectEqual(num_blocks, bi);
}

test "car: ChunkedWriter empty roots + no blocks produces a valid empty stream" {
    var buf: [512]u8 = undefined;
    var rb = response.Builder.init(&buf);
    var ring = ChunkRingT.init();
    var cw = ChunkedWriter.init(&ring, &rb);
    try cw.writeHttpHead("application/vnd.ipld.car");
    const empty: [0]cid_mod.Cid = .{};
    try cw.writeHeaderChunk(&empty);
    try cw.finish();
    try testing.expect(std.mem.endsWith(u8, rb.bytes(), "0\r\n\r\n"));
}

test "car: ChunkedWriter returns BufferTooSmall when builder runs out" {
    // Builder is too small to fit even the head; writeHttpHead bubbles
    // ResponseBufferFull (HttpError).
    var tiny: [32]u8 = undefined;
    var rb = response.Builder.init(&tiny);
    var ring = ChunkRingT.init();
    var cw = ChunkedWriter.init(&ring, &rb);
    try testing.expectError(error.ResponseBufferFull, cw.writeHttpHead("application/vnd.ipld.car"));
}

test "car: varint encodes max u64 in 10 bytes" {
    var buf: [10]u8 = undefined;
    const n = try writeVarint(std.math.maxInt(u64), &buf);
    try testing.expectEqual(@as(usize, 10), n);
    const r = try readVarint(buf[0..n]);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), r.value);
}
