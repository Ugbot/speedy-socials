//! Multicodec prefix table.
//!
//! `https://github.com/multiformats/multicodec/blob/master/table.csv`
//!
//! We only need the subset used by AT Protocol + IPLD: Ed25519
//! (`0xed`), secp256k1 (`0xe7`), P-256 (`0x1200`), plus the DAG-CBOR
//! tag (`0x71`). The codes are varint-encoded but every one we care
//! about fits in 1–2 bytes.

const std = @import("std");

pub const Codec = enum(u16) {
    ed25519_pub = 0xed,
    secp256k1_pub = 0xe7,
    p256_pub = 0x1200,
    dag_cbor = 0x71,
    raw = 0x55,
};

/// Encode `c` as multicodec varint into `out`. Returns bytes written.
/// Tiger Style: every codec we care about is ≤ 2 bytes.
pub fn writeVarint(c: Codec, out: []u8) error{BufferTooSmall}!usize {
    var v: u32 = @intFromEnum(c);
    var i: usize = 0;
    while (true) {
        if (i >= out.len) return error.BufferTooSmall;
        const byte: u8 = @intCast(v & 0x7f);
        v >>= 7;
        if (v == 0) {
            out[i] = byte;
            return i + 1;
        }
        out[i] = byte | 0x80;
        i += 1;
        // Tiger Style: bound the loop. No codec we touch is > 5 bytes.
        if (i > 4) return error.BufferTooSmall;
    }
}

/// Decode the multicodec varint at the front of `bytes`. Returns the
/// codec value plus the byte count consumed.
pub fn readVarint(bytes: []const u8) error{ Truncated, TooLarge }!struct { codec: u32, consumed: usize } {
    var v: u32 = 0;
    var shift: u5 = 0;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        if (i >= 5) return error.TooLarge;
        const b = bytes[i];
        v |= @as(u32, b & 0x7f) << shift;
        if ((b & 0x80) == 0) return .{ .codec = v, .consumed = i + 1 };
        shift += 7;
    }
    return error.Truncated;
}

// ── Tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "multicodec: varint round-trip" {
    inline for ([_]Codec{ .ed25519_pub, .secp256k1_pub, .p256_pub, .dag_cbor, .raw }) |c| {
        var buf: [4]u8 = undefined;
        const n = try writeVarint(c, &buf);
        const dec = try readVarint(buf[0..n]);
        try testing.expectEqual(@as(u32, @intFromEnum(c)), dec.codec);
        try testing.expectEqual(n, dec.consumed);
    }
}

test "multicodec: readVarint rejects truncated input" {
    try testing.expectError(error.Truncated, readVarint(&[_]u8{0x80}));
}
