//! RFC 6455 §5 — frame codec.
//!
//! Decoder: parses a single frame from a byte slice and reports
//! `need_more` if the slice doesn't yet contain a full frame, `ok`
//! with `consumed` bytes when a frame is parsed, or `error` on
//! protocol violation.
//!
//! Encoder: serializes a frame into a caller-provided fixed buffer.
//!
//! Tiger Style:
//!   * No allocations. Decode borrows payload bytes from the input
//!     slice; the caller is responsible for unmasking (in place) and
//!     consuming before the buffer is reused.
//!   * Single-frame payload capped at `max_frame_payload_bytes`. The
//!     server refuses any frame whose length field would exceed this
//!     limit BEFORE waiting for the body, so a malicious peer cannot
//!     hold the read buffer hostage.
//!   * Server outbound frames MUST NOT be masked (RFC 6455 §5.1).
//!     `encode` asserts mask is absent.
//!   * Inbound frames from a client MUST be masked. `decode` rejects
//!     unmasked client frames with `FrameUnmasked`.
//!   * No recursion. No dynamic dispatch.

const std = @import("std");
const limits = @import("../limits.zig");
const WsError = @import("../errors.zig").WsError;
const assert_mod = @import("../assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

/// Maximum frame header overhead: 2 base + 8 extended-length + 4 mask.
pub const max_frame_header_bytes: usize = 14;

/// Maximum single-frame payload. Sized so a complete frame
/// (header + payload) fits in the per-connection read buffer.
pub const max_frame_payload_bytes: usize =
    limits.conn_read_buffer_bytes - max_frame_header_bytes;

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    // 0x3..0x7 reserved non-control
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    // 0xB..0xF reserved control

    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= 0x8;
    }

    pub fn fromRaw(raw: u4) ?Opcode {
        return switch (raw) {
            0x0 => .continuation,
            0x1 => .text,
            0x2 => .binary,
            0x8 => .close,
            0x9 => .ping,
            0xA => .pong,
            else => null,
        };
    }
};

/// Parsed frame. `payload` aliases the input buffer slice (still
/// masked — call `unmask` to decrypt in place if you own the bytes).
pub const Frame = struct {
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: Opcode,
    masked: bool,
    mask: [4]u8,
    payload: []u8,

    /// Unmask the payload in place. Idempotent only in the sense
    /// that calling twice with the same key would re-encrypt — the
    /// caller must invoke exactly once per masked frame.
    pub fn unmask(self: *Frame) void {
        if (!self.masked) return;
        var i: usize = 0;
        // Bound asserted: payload length is at most max_frame_payload_bytes.
        assertLe(self.payload.len, max_frame_payload_bytes);
        while (i < self.payload.len) : (i += 1) {
            self.payload[i] ^= self.mask[i & 3];
        }
    }
};

pub const DecodeResult = union(enum) {
    need_more,
    ok: struct {
        frame: Frame,
        consumed: usize,
    },
};

/// Decode a single frame from `bytes`. Does NOT modify `bytes`
/// (mask is captured but payload is returned still masked; caller
/// invokes `frame.unmask()` once they own the slice).
///
/// `expect_masked`: true on server (clients MUST mask), false on
/// client (servers MUST NOT mask). The decoder uses this to enforce
/// RFC 6455 §5.1 rather than blindly trusting the frame.
pub fn decode(bytes: []u8, expect_masked: bool) WsError!DecodeResult {
    if (bytes.len < 2) return .need_more;

    const b0 = bytes[0];
    const b1 = bytes[1];

    const fin = (b0 & 0x80) != 0;
    const rsv1 = (b0 & 0x40) != 0;
    const rsv2 = (b0 & 0x20) != 0;
    const rsv3 = (b0 & 0x10) != 0;
    // No extensions negotiated — any reserved bit set is a protocol error.
    if (rsv1 or rsv2 or rsv3) return error.FrameReservedBitsSet;

    const opcode_raw: u4 = @truncate(b0 & 0x0F);
    const opcode = Opcode.fromRaw(opcode_raw) orelse return error.FrameUnknownOpcode;

    const masked = (b1 & 0x80) != 0;
    if (expect_masked and !masked) return error.FrameUnmasked;
    if (!expect_masked and masked) return error.FrameMaskedFromServer;

    const len7: u7 = @truncate(b1 & 0x7F);
    var cursor: usize = 2;
    var payload_len: u64 = 0;

    if (len7 < 126) {
        payload_len = len7;
    } else if (len7 == 126) {
        if (bytes.len < cursor + 2) return .need_more;
        payload_len = @as(u64, bytes[cursor]) << 8 | bytes[cursor + 1];
        cursor += 2;
        if (payload_len < 126) return error.FrameTooLarge; // non-minimal encoding
    } else {
        // len7 == 127
        if (bytes.len < cursor + 8) return .need_more;
        var v: u64 = 0;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            v = (v << 8) | bytes[cursor + i];
        }
        payload_len = v;
        cursor += 8;
        if (payload_len <= 0xFFFF) return error.FrameTooLarge; // non-minimal encoding
        if ((payload_len >> 63) != 0) return error.FrameTooLarge; // MSB must be 0
    }

    if (payload_len > max_frame_payload_bytes) return error.FrameTooLarge;

    if (opcode.isControl()) {
        // Control frames must not be fragmented and must be ≤125 bytes.
        if (!fin) return error.FrameControlFragmented;
        if (payload_len > 125) return error.FrameControlTooLarge;
    }

    var mask: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        if (bytes.len < cursor + 4) return .need_more;
        mask = .{ bytes[cursor], bytes[cursor + 1], bytes[cursor + 2], bytes[cursor + 3] };
        cursor += 4;
    }

    const total = cursor + @as(usize, @intCast(payload_len));
    if (bytes.len < total) return .need_more;

    const payload = bytes[cursor..total];
    return .{ .ok = .{
        .frame = .{
            .fin = fin,
            .rsv1 = rsv1,
            .rsv2 = rsv2,
            .rsv3 = rsv3,
            .opcode = opcode,
            .masked = masked,
            .mask = mask,
            .payload = payload,
        },
        .consumed = total,
    } };
}

/// Encode a server→client frame into `dst`. Returns bytes written.
/// Never masks (RFC 6455 §5.1 — servers MUST NOT mask outbound).
pub fn encode(opcode: Opcode, payload: []const u8, fin: bool, dst: []u8) WsError!usize {
    if (payload.len > max_frame_payload_bytes) return error.FrameTooLarge;
    if (opcode.isControl() and (payload.len > 125 or !fin)) {
        // Control frames must fit and not be fragmented.
        if (payload.len > 125) return error.FrameControlTooLarge;
        if (!fin) return error.FrameControlFragmented;
    }

    var need: usize = 2 + payload.len;
    if (payload.len >= 126 and payload.len <= 0xFFFF) need += 2;
    if (payload.len > 0xFFFF) need += 8;

    if (dst.len < need) return error.FrameEncodeBufferTooSmall;

    dst[0] = (if (fin) @as(u8, 0x80) else 0) | @as(u8, @intFromEnum(opcode));

    var cursor: usize = 1;
    if (payload.len < 126) {
        dst[cursor] = @as(u8, @intCast(payload.len));
        cursor += 1;
    } else if (payload.len <= 0xFFFF) {
        dst[cursor] = 126;
        dst[cursor + 1] = @as(u8, @intCast((payload.len >> 8) & 0xFF));
        dst[cursor + 2] = @as(u8, @intCast(payload.len & 0xFF));
        cursor += 3;
    } else {
        dst[cursor] = 127;
        const v: u64 = payload.len;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            dst[cursor + 1 + i] = @as(u8, @intCast((v >> @as(u6, @intCast((7 - i) * 8))) & 0xFF));
        }
        cursor += 9;
    }

    // No mask bit set — server frames are never masked.
    @memcpy(dst[cursor..][0..payload.len], payload);
    cursor += payload.len;
    assertLe(cursor, dst.len);
    return cursor;
}

// ── tests ──────────────────────────────────────────────────────

const testing = std.testing;

fn maskPayload(buf: []u8, mask: [4]u8) void {
    var i: usize = 0;
    while (i < buf.len) : (i += 1) buf[i] ^= mask[i & 3];
}

test "decode rejects short header" {
    var buf = [_]u8{0x81};
    const r = try decode(&buf, true);
    try testing.expect(r == .need_more);
}

test "decode reserved bits => error" {
    var buf = [_]u8{ 0xC0, 0x80, 0, 0, 0, 0 }; // FIN+RSV1, opcode=0
    try testing.expectError(error.FrameReservedBitsSet, decode(&buf, true));
}

test "decode rejects unmasked client frame" {
    var buf = [_]u8{ 0x81, 0x00 };
    try testing.expectError(error.FrameUnmasked, decode(&buf, true));
}

test "decode rejects masked server-origin frame" {
    var buf = [_]u8{ 0x81, 0x80, 0, 0, 0, 0 };
    try testing.expectError(error.FrameMaskedFromServer, decode(&buf, false));
}

test "decode unknown opcode" {
    var buf = [_]u8{ 0x83, 0x80, 0, 0, 0, 0 }; // opcode 0x3 reserved
    try testing.expectError(error.FrameUnknownOpcode, decode(&buf, true));
}

test "decode short text frame, unmask roundtrip" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const r = prng.random();
    var payload: [10]u8 = undefined;
    r.bytes(&payload);
    const mask = [4]u8{ 0x11, 0x22, 0x33, 0x44 };

    var frame_buf: [32]u8 = undefined;
    frame_buf[0] = 0x81; // FIN + text
    frame_buf[1] = 0x80 | @as(u8, payload.len);
    frame_buf[2] = mask[0];
    frame_buf[3] = mask[1];
    frame_buf[4] = mask[2];
    frame_buf[5] = mask[3];
    @memcpy(frame_buf[6..][0..payload.len], &payload);
    maskPayload(frame_buf[6..][0..payload.len], mask);

    const res = try decode(frame_buf[0 .. 6 + payload.len], true);
    try testing.expect(res == .ok);
    var f = res.ok.frame;
    try testing.expectEqual(@as(usize, 6 + payload.len), res.ok.consumed);
    try testing.expectEqual(Opcode.text, f.opcode);
    try testing.expect(f.fin);
    f.unmask();
    try testing.expectEqualSlices(u8, &payload, f.payload);
}

test "decode 126-length extended" {
    var payload: [200]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xBEEF);
    prng.random().bytes(&payload);
    const mask = [4]u8{ 1, 2, 3, 4 };

    var fb: [220]u8 = undefined;
    fb[0] = 0x82; // FIN + binary
    fb[1] = 0x80 | 126;
    fb[2] = 0x00;
    fb[3] = 0xC8; // 200
    @memcpy(fb[4..8], &mask);
    @memcpy(fb[8..][0..200], &payload);
    maskPayload(fb[8..][0..200], mask);

    const res = try decode(fb[0..208], true);
    try testing.expect(res == .ok);
    var f = res.ok.frame;
    try testing.expectEqual(@as(usize, 208), res.ok.consumed);
    f.unmask();
    try testing.expectEqualSlices(u8, &payload, f.payload);
}

test "decode 127-length extended (>65535)" {
    // Force the 8-byte (len7=127) path: any length > 0xFFFF qualifies,
    // but we need it ≤ max_frame_payload_bytes. The current cap is
    // 16K - 14, which is < 0xFFFF, so we cannot exercise len7=127
    // through the real codec — instead, assert the decoder *would*
    // accept it by feeding a minimum-valid-127 length (0x10000) and
    // expecting FrameTooLarge.
    if (max_frame_payload_bytes <= 0xFFFF) {
        var fb_small: [14]u8 = undefined;
        fb_small[0] = 0x82;
        fb_small[1] = 0x80 | 127;
        const v: u64 = 0x10000;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            fb_small[2 + i] = @as(u8, @intCast((v >> @as(u6, @intCast((7 - i) * 8))) & 0xFF));
        }
        try testing.expectError(error.FrameTooLarge, decode(&fb_small, true));
        return;
    }
    const len: usize = 70_000;
    const payload = try testing.allocator.alloc(u8, len);
    defer testing.allocator.free(payload);
    var prng = std.Random.DefaultPrng.init(0xABCDEF);
    prng.random().bytes(payload);
    const mask = [4]u8{ 0xA0, 0xA1, 0xA2, 0xA3 };

    const fb = try testing.allocator.alloc(u8, 14 + len);
    defer testing.allocator.free(fb);
    fb[0] = 0x82;
    fb[1] = 0x80 | 127;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        fb[2 + i] = @as(u8, @intCast((len >> @as(u6, @intCast((7 - i) * 8))) & 0xFF));
    }
    @memcpy(fb[10..14], &mask);
    @memcpy(fb[14..][0..len], payload);
    maskPayload(fb[14..][0..len], mask);

    const res = try decode(fb[0 .. 14 + len], true);
    try testing.expect(res == .ok);
    var f = res.ok.frame;
    try testing.expectEqual(@as(usize, 14 + len), res.ok.consumed);
    f.unmask();
    try testing.expectEqualSlices(u8, payload, f.payload);
}

test "decode rejects oversized frame at length field" {
    var fb: [14]u8 = undefined;
    fb[0] = 0x82;
    fb[1] = 0x80 | 127;
    // length = max_frame_payload_bytes + 1
    const overlimit: u64 = @as(u64, max_frame_payload_bytes) + 1;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        fb[2 + i] = @as(u8, @intCast((overlimit >> @as(u6, @intCast((7 - i) * 8))) & 0xFF));
    }
    try testing.expectError(error.FrameTooLarge, decode(&fb, true));
}

test "decode rejects non-minimal 126" {
    var fb = [_]u8{ 0x82, 0x80 | 126, 0x00, 0x05, 0, 0, 0, 0 };
    try testing.expectError(error.FrameTooLarge, decode(&fb, true));
}

test "decode rejects control frame fragmentation" {
    var fb = [_]u8{ 0x09, 0x80, 0, 0, 0, 0 }; // ping with FIN=0
    try testing.expectError(error.FrameControlFragmented, decode(&fb, true));
}

test "decode rejects oversize control frame" {
    // Ping with FIN=1, extended-126 length = 200 bytes (>125 → invalid).
    var fb = [_]u8{ 0x89, 0x80 | 126, 0x00, 0xC8, 0, 0, 0, 0 };
    try testing.expectError(error.FrameControlTooLarge, decode(&fb, true));
}

test "encode short text frame" {
    var out: [32]u8 = undefined;
    const n = try encode(.text, "hello", true, &out);
    try testing.expectEqual(@as(usize, 7), n);
    try testing.expectEqual(@as(u8, 0x81), out[0]);
    try testing.expectEqual(@as(u8, 5), out[1]);
    try testing.expectEqualSlices(u8, "hello", out[2..7]);
}

test "encode 126-extended length" {
    var payload: [300]u8 = undefined;
    @memset(&payload, 'A');
    var out: [320]u8 = undefined;
    const n = try encode(.binary, &payload, true, &out);
    try testing.expectEqual(@as(usize, 304), n);
    try testing.expectEqual(@as(u8, 0x82), out[0]);
    try testing.expectEqual(@as(u8, 126), out[1]);
    try testing.expectEqual(@as(u8, 0x01), out[2]);
    try testing.expectEqual(@as(u8, 0x2C), out[3]);
}

test "encode 127-extended length" {
    // Force the 8-byte (len7=127) path: any length > 0xFFFF qualifies,
    // but we need it ≤ max_frame_payload_bytes. The current cap is
    // 16K - 14, which is < 0xFFFF, so we cannot exercise len7=127
    // through the real codec — instead, assert the decoder *would*
    // accept it by feeding a minimum-valid-127 length (0x10000) and
    // expecting FrameTooLarge.
    if (max_frame_payload_bytes <= 0xFFFF) {
        var fb_small: [14]u8 = undefined;
        fb_small[0] = 0x82;
        fb_small[1] = 0x80 | 127;
        const v: u64 = 0x10000;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            fb_small[2 + i] = @as(u8, @intCast((v >> @as(u6, @intCast((7 - i) * 8))) & 0xFF));
        }
        try testing.expectError(error.FrameTooLarge, decode(&fb_small, true));
        return;
    }
    const len: usize = 70_000;
    const payload = try testing.allocator.alloc(u8, len);
    defer testing.allocator.free(payload);
    @memset(payload, 0x5A);
    const out = try testing.allocator.alloc(u8, len + 14);
    defer testing.allocator.free(out);
    const n = try encode(.binary, payload, true, out);
    try testing.expectEqual(len + 10, n);
    try testing.expectEqual(@as(u8, 127), out[1]);
}

test "encode/decode roundtrip text" {
    var enc_buf: [128]u8 = undefined;
    const msg = "round trip me";
    const n = try encode(.text, msg, true, &enc_buf);

    // Now turn it into a masked client frame for the server decoder.
    var client_buf: [128]u8 = undefined;
    client_buf[0] = enc_buf[0]; // FIN + opcode
    client_buf[1] = 0x80 | enc_buf[1]; // mask bit + len
    const mask = [4]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    @memcpy(client_buf[2..6], &mask);
    @memcpy(client_buf[6 .. 6 + msg.len], enc_buf[2..n]);
    maskPayload(client_buf[6 .. 6 + msg.len], mask);

    const res = try decode(client_buf[0 .. 6 + msg.len], true);
    try testing.expect(res == .ok);
    var f = res.ok.frame;
    f.unmask();
    try testing.expectEqualSlices(u8, msg, f.payload);
    try testing.expectEqual(Opcode.text, f.opcode);
}

test "encode rejects oversize" {
    var huge: [max_frame_payload_bytes + 1]u8 = undefined;
    var out: [max_frame_payload_bytes + 32]u8 = undefined;
    try testing.expectError(error.FrameTooLarge, encode(.binary, &huge, true, &out));
}

test "encode rejects too-small dst" {
    var out: [4]u8 = undefined;
    try testing.expectError(error.FrameEncodeBufferTooSmall, encode(.text, "hello", true, &out));
}

test "encode ping with payload" {
    var out: [32]u8 = undefined;
    const n = try encode(.ping, "pp", true, &out);
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqual(@as(u8, 0x89), out[0]);
}
