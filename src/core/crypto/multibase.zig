//! Multibase codecs — base58btc (z…) + base32 (b…).
//!
//! Used by:
//!   * AT Protocol: `did:key:z…` formatting (base58btc).
//!   * ActivityPub: not (AP uses PEM); preserved here so it lives in one
//!     place when AP eventually exposes did:key for its Ed25519 actors.
//!   * IPFS-style CIDv1: base32 lower-case ("b" prefix).
//!
//! Tiger Style: allocator-free, bounded. Callers supply destination
//! buffers sized for worst-case expansion:
//!   * base58btc encode: dst.len >= ceil(src.len * 138 / 100) + 1
//!   * base32 encode: dst.len >= ceil(src.len * 8 / 5)

const std = @import("std");

pub const Error = error{
    BufferTooSmall,
    BadAlphabet,
};

// ── base58btc ─────────────────────────────────────────────────────────

const b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58_decode_table: [256]i8 = blk: {
    var t: [256]i8 = .{-1} ** 256;
    for (b58_alphabet, 0..) |c, i| t[c] = @intCast(i);
    break :blk t;
};

/// Encode `src` to base58btc (no multibase prefix). Returns bytes written
/// into `dst`.
pub fn base58btcEncode(src: []const u8, dst: []u8) Error!usize {
    @memset(dst, 0);
    var size: usize = 0;
    var leading_zeros: usize = 0;
    var i: usize = 0;
    while (i < src.len and src[i] == 0) : (i += 1) leading_zeros += 1;

    var j: usize = leading_zeros;
    while (j < src.len) : (j += 1) {
        var carry: u32 = src[j];
        var k: usize = 0;
        while (k < size or carry != 0) : (k += 1) {
            if (k >= dst.len) return error.BufferTooSmall;
            const idx = dst.len - 1 - k;
            carry += @as(u32, dst[idx]) * 256;
            dst[idx] = @as(u8, @intCast(carry % 58));
            carry /= 58;
        }
        size = k;
    }

    const total = leading_zeros + size;
    if (total > dst.len) return error.BufferTooSmall;

    var out_idx: usize = 0;
    var z: usize = 0;
    while (z < leading_zeros) : (z += 1) {
        dst[out_idx] = '1';
        out_idx += 1;
    }
    var d: usize = 0;
    while (d < size) : (d += 1) {
        const idx = dst.len - size + d;
        dst[out_idx] = b58_alphabet[dst[idx]];
        out_idx += 1;
    }
    var tail: usize = out_idx;
    while (tail < dst.len) : (tail += 1) dst[tail] = 0;
    return out_idx;
}

/// Decode base58btc into `dst`. Returns bytes written.
pub fn base58btcDecode(src: []const u8, dst: []u8) Error!usize {
    if (src.len == 0) return 0;
    var leading_zeros: usize = 0;
    var i: usize = 0;
    while (i < src.len and src[i] == '1') : (i += 1) leading_zeros += 1;

    @memset(dst, 0);
    var size: usize = 0;
    while (i < src.len) : (i += 1) {
        const c = src[i];
        const v = b58_decode_table[c];
        if (v < 0) return error.BadAlphabet;
        var carry: u32 = @intCast(v);
        var k: usize = 0;
        while (k < size or carry != 0) : (k += 1) {
            if (k >= dst.len) return error.BufferTooSmall;
            const idx = dst.len - 1 - k;
            carry += @as(u32, dst[idx]) * 58;
            dst[idx] = @as(u8, @intCast(carry & 0xff));
            carry >>= 8;
        }
        size = k;
    }
    const total = leading_zeros + size;
    if (total > dst.len) return error.BufferTooSmall;
    var out_idx: usize = 0;
    var z: usize = 0;
    while (z < leading_zeros) : (z += 1) {
        dst[out_idx] = 0;
        out_idx += 1;
    }
    var d: usize = 0;
    while (d < size) : (d += 1) {
        const idx = dst.len - size + d;
        dst[out_idx] = dst[idx];
        out_idx += 1;
    }
    var tail: usize = out_idx;
    while (tail < dst.len) : (tail += 1) dst[tail] = 0;
    return out_idx;
}

// ── base32 (RFC 4648, no padding, lowercase) ──────────────────────────

const b32_alphabet = "abcdefghijklmnopqrstuvwxyz234567";
const b32_decode_table: [256]i8 = blk: {
    var t: [256]i8 = .{-1} ** 256;
    for (b32_alphabet, 0..) |c, i| t[c] = @intCast(i);
    // Accept upper-case input as well.
    var k: usize = 0;
    while (k < 26) : (k += 1) t['A' + k] = @intCast(k);
    break :blk t;
};

pub fn base32Encode(src: []const u8, dst: []u8) Error!usize {
    var o: usize = 0;
    var acc: u32 = 0;
    var bits: u5 = 0;
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        acc = (acc << 8) | src[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (o >= dst.len) return error.BufferTooSmall;
            dst[o] = b32_alphabet[(acc >> bits) & 0x1f];
            o += 1;
        }
    }
    if (bits > 0) {
        if (o >= dst.len) return error.BufferTooSmall;
        dst[o] = b32_alphabet[(acc << (5 - bits)) & 0x1f];
        o += 1;
    }
    return o;
}

pub fn base32Decode(src: []const u8, dst: []u8) Error!usize {
    var o: usize = 0;
    var acc: u32 = 0;
    var bits: u5 = 0;
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        const v = b32_decode_table[src[i]];
        if (v < 0) return error.BadAlphabet;
        acc = (acc << 5) | @as(u32, @intCast(v));
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (o >= dst.len) return error.BufferTooSmall;
            dst[o] = @intCast((acc >> bits) & 0xff);
            o += 1;
        }
    }
    return o;
}

// ── Tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "base58btc: round-trip random bytes" {
    var rng = std.Random.DefaultPrng.init(0xDEAD_BEEF);
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        var src: [33]u8 = undefined;
        rng.random().bytes(&src);
        var enc: [80]u8 = undefined;
        const en = try base58btcEncode(&src, &enc);
        var dec: [33]u8 = undefined;
        const dn = try base58btcDecode(enc[0..en], &dec);
        try testing.expectEqual(@as(usize, 33), dn);
        try testing.expectEqualSlices(u8, &src, dec[0..dn]);
    }
}

test "base58btc: leading-zero bytes preserved" {
    const src = [_]u8{ 0, 0, 1, 2, 3 };
    var enc: [16]u8 = undefined;
    const en = try base58btcEncode(&src, &enc);
    // The first two encoded bytes must be '1' for the leading zeros.
    try testing.expectEqual(@as(u8, '1'), enc[0]);
    try testing.expectEqual(@as(u8, '1'), enc[1]);
    var dec: [5]u8 = undefined;
    const dn = try base58btcDecode(enc[0..en], &dec);
    try testing.expectEqualSlices(u8, &src, dec[0..dn]);
}

test "base58btc: rejects invalid character" {
    var dec: [16]u8 = undefined;
    try testing.expectError(error.BadAlphabet, base58btcDecode("0OIl", &dec));
}

test "base32: round-trip ascii" {
    const src = "hello speedy socials";
    var enc: [40]u8 = undefined;
    const en = try base32Encode(src, &enc);
    var dec: [20]u8 = undefined;
    const dn = try base32Decode(enc[0..en], &dec);
    try testing.expectEqualStrings(src, dec[0..dn]);
}
