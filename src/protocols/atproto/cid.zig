//! CIDv1 — Content Identifier.
//!
//! Encodes / decodes the CIDv1 form used throughout AT Protocol:
//!     version=1 (0x01) ++ codec=dag-cbor (0x71) ++
//!         multihash(sha2-256=0x12, len=0x20) ++ digest(32 bytes)
//!
//! The string form is base32-lower with the `b` multibase prefix, no
//! padding. All buffers are fixed-size — the only dynamic length comes
//! from the caller-provided output slice.
//!
//! Refs:
//!   * https://github.com/multiformats/cid
//!   * https://atproto.com/specs/data-model#link-and-cid-formats

const std = @import("std");
const core = @import("core");
const AtpError = core.errors.AtpError;
const assertLe = core.assert.assertLe;
const assert = core.assert.assert;

pub const dag_cbor_codec: u8 = 0x71;
pub const raw_codec: u8 = 0x55;
pub const sha2_256_code: u8 = 0x12;
pub const sha2_256_len: u8 = 0x20;

/// Raw binary CID: version + codec + (mh code + mh len + 32-byte digest)
/// = 1 + 1 + 1 + 1 + 32 = 36 bytes.
pub const raw_cid_len: usize = 36;

/// String length: 1 base prefix + ceil(36 * 8 / 5) = 1 + 58 = 59.
pub const string_cid_len: usize = 59;

pub const Cid = struct {
    bytes: [raw_cid_len]u8,

    pub fn version(self: Cid) u8 {
        return self.bytes[0];
    }
    pub fn codec(self: Cid) u8 {
        return self.bytes[1];
    }
    pub fn digest(self: *const Cid) []const u8 {
        return self.bytes[4..];
    }
    pub fn raw(self: *const Cid) []const u8 {
        return self.bytes[0..];
    }
};

/// Compute a CIDv1 dag-cbor sha2-256 over the supplied data.
pub fn computeDagCbor(data: []const u8) Cid {
    var c: Cid = .{ .bytes = undefined };
    c.bytes[0] = 0x01;
    c.bytes[1] = dag_cbor_codec;
    c.bytes[2] = sha2_256_code;
    c.bytes[3] = sha2_256_len;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    @memcpy(c.bytes[4..36], &hash);
    return c;
}

/// Encode CID to base32-lower string (`b` prefix). Writes into `out` and
/// returns the slice written. `out.len` must be at least `string_cid_len`.
pub fn encodeString(cid: Cid, out: []u8) AtpError![]const u8 {
    if (out.len < string_cid_len) return error.BufferTooSmall;
    out[0] = 'b';
    const written = base32LowerEncode(cid.bytes[0..], out[1..]);
    assertLe(written, out.len - 1);
    return out[0 .. 1 + written];
}

/// Parse a base32-lower CIDv1 string into a `Cid`. Verifies prefix +
/// codec + multihash framing.
pub fn parseString(s: []const u8) AtpError!Cid {
    if (s.len < 4) return error.BadCid;
    if (s[0] != 'b') return error.BadCid;

    var raw_buf: [raw_cid_len]u8 = undefined;
    const n = try base32LowerDecode(s[1..], &raw_buf);
    if (n != raw_cid_len) return error.BadCid;

    if (raw_buf[0] != 0x01) return error.BadCid;
    if (raw_buf[1] != dag_cbor_codec) return error.BadCid;
    if (raw_buf[2] != sha2_256_code) return error.BadCid;
    if (raw_buf[3] != sha2_256_len) return error.BadCid;

    return .{ .bytes = raw_buf };
}

// ── base32-lower (RFC 4648, lowercase, no padding) ─────────────────

const b32_alphabet = "abcdefghijklmnopqrstuvwxyz234567";

const b32_decode_table: [256]i8 = blk: {
    var t: [256]i8 = .{-1} ** 256;
    for (b32_alphabet, 0..) |c, i| t[c] = @intCast(i);
    break :blk t;
};

/// Encode `src` as base32-lower into `dst`. Returns bytes written.
/// `dst.len` must be at least `(src.len * 8 + 4) / 5`.
fn base32LowerEncode(src: []const u8, dst: []u8) usize {
    var bit_buf: u32 = 0;
    var bits: u5 = 0;
    var pos: usize = 0;
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        assertLe(i, src.len);
        bit_buf = (bit_buf << 8) | @as(u32, src[i]);
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            const idx: u5 = @truncate(bit_buf >> bits);
            dst[pos] = b32_alphabet[idx];
            pos += 1;
        }
    }
    if (bits > 0) {
        const idx: u5 = @truncate(bit_buf << (@as(u5, 5) - bits));
        dst[pos] = b32_alphabet[idx];
        pos += 1;
    }
    return pos;
}

/// Decode base32-lower `src` into `dst`. Returns bytes written, or
/// `error.BadCid` on invalid character.
fn base32LowerDecode(src: []const u8, dst: []u8) AtpError!usize {
    var bit_buf: u32 = 0;
    var bits: u5 = 0;
    var pos: usize = 0;
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        assertLe(i, src.len);
        const c = src[i];
        if (c == '=') break;
        const v = b32_decode_table[c];
        if (v < 0) return error.BadCid;
        bit_buf = (bit_buf << 5) | @as(u32, @intCast(v));
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (pos >= dst.len) return error.BadCid;
            dst[pos] = @truncate(bit_buf >> bits);
            pos += 1;
        }
    }
    return pos;
}

// ── Tests ──────────────────────────────────────────────────────────

test "cid: compute + encode + parse roundtrip" {
    const payload = "hello, atproto";
    const cid = computeDagCbor(payload);
    try std.testing.expectEqual(@as(u8, 0x01), cid.version());
    try std.testing.expectEqual(@as(u8, 0x71), cid.codec());

    var sbuf: [string_cid_len]u8 = undefined;
    const s = try encodeString(cid, &sbuf);
    try std.testing.expectEqual(@as(u8, 'b'), s[0]);
    try std.testing.expect(std.mem.startsWith(u8, s, "bafyrei"));

    const parsed = try parseString(s);
    try std.testing.expectEqualSlices(u8, cid.raw(), parsed.raw());
}

test "cid: digest matches std SHA-256" {
    const payload = "x";
    const cid = computeDagCbor(payload);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &hash, .{});
    try std.testing.expectEqualSlices(u8, &hash, cid.digest());
}

test "cid: parseString rejects bad prefix / bad codec / wrong length" {
    try std.testing.expectError(error.BadCid, parseString("zabc"));
    try std.testing.expectError(error.BadCid, parseString("b"));
    // Garbage non-base32 char.
    var bad = [_]u8{ 'b', '!', 'a', 'b' } ++ [_]u8{'a'} ** 55;
    try std.testing.expectError(error.BadCid, parseString(&bad));
}

test "cid: BufferTooSmall on short output" {
    const cid = computeDagCbor("y");
    var small: [10]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encodeString(cid, &small));
}

test "cid: distinct inputs yield distinct CIDs" {
    const a = computeDagCbor("alpha");
    const b = computeDagCbor("beta");
    try std.testing.expect(!std.mem.eql(u8, a.raw(), b.raw()));
}
