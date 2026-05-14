//! Argon2id password hashing — RFC 9106.
//!
//! Wraps `std.crypto.pwhash.argon2` with our Tiger Style sensibilities:
//! fixed buffers, no allocator-after-boot, deterministic salt input from
//! the caller. The encoded output uses the PHC string format
//! (`$argon2id$v=19$m=…,t=…,p=…$<salt-b64>$<hash-b64>`) that any
//! Argon2-compliant verifier (passlib, libsodium, OpenSSL >=3.2)
//! accepts.
//!
//! Tunings target a single PDS account create / password-login flow:
//!   * memory = 64 MiB
//!   * iterations = 3
//!   * parallelism = 1
//!
//! These match the OWASP 2024 minimum for interactive logins on a server
//! that handles human-rate password verification (≤ 50 ms/op). Increase
//! `params` at startup if your deployment can absorb more latency.

const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;

pub const params: argon2.Params = .{ .t = 3, .m = 64 * 1024, .p = 1 };

pub const salt_length: usize = 16;
pub const hash_length: usize = 32;
/// PHC-encoded string length is variable; this is a generous ceiling
/// for the params above (well over the typical ~110 byte output).
pub const max_phc_bytes: usize = 256;

pub const Error = error{
    BufferTooSmall,
    HashFailed,
    VerifyFailed,
};

/// Hash `password` with `salt` and return a PHC-encoded ASCII string
/// written into `out`. Returns the slice consumed.
///
/// `allocator` is required by the stdlib API; supply a temporary
/// allocator (worker arena is ideal). The function does not retain it
/// past return.
pub fn hash(
    allocator: std.mem.Allocator,
    io: std.Io,
    password: []const u8,
    salt: [salt_length]u8,
    out: []u8,
) Error![]const u8 {
    if (out.len < max_phc_bytes) return error.BufferTooSmall;
    var raw_hash: [hash_length]u8 = undefined;
    argon2.kdf(
        allocator,
        &raw_hash,
        password,
        &salt,
        params,
        .argon2id,
        io,
    ) catch return error.HashFailed;
    const written = std.fmt.bufPrint(
        out,
        "$argon2id$v=19$m={d},t={d},p={d}$",
        .{ params.m, params.t, params.p },
    ) catch return error.BufferTooSmall;
    var pos = written.len;
    // Salt — base64url no-padding.
    pos += b64UrlNoPadEncode(&salt, out[pos..]);
    if (pos >= out.len) return error.BufferTooSmall;
    out[pos] = '$';
    pos += 1;
    pos += b64UrlNoPadEncode(&raw_hash, out[pos..]);
    return out[0..pos];
}

/// Verify `password` against a previously-encoded PHC string.
///
/// The encoded form must have been produced by `hash` (same params).
/// Returns `true` on match, `false` on mismatch, error on malformed
/// input.
pub fn verify(
    allocator: std.mem.Allocator,
    io: std.Io,
    password: []const u8,
    encoded: []const u8,
) Error!bool {
    // Parse PHC: `$argon2id$v=19$m=<>,t=<>,p=<>$<salt>$<hash>`
    var it = std.mem.splitScalar(u8, encoded, '$');
    if (it.next() == null) return error.VerifyFailed; // empty prefix
    const algo = it.next() orelse return error.VerifyFailed;
    if (!std.mem.eql(u8, algo, "argon2id")) return error.VerifyFailed;
    _ = it.next() orelse return error.VerifyFailed; // version
    const param_str = it.next() orelse return error.VerifyFailed;
    const salt_b64 = it.next() orelse return error.VerifyFailed;
    const hash_b64 = it.next() orelse return error.VerifyFailed;

    var p: argon2.Params = .{ .t = 1, .m = 1024, .p = 1 };
    var ps = std.mem.splitScalar(u8, param_str, ',');
    while (ps.next()) |kv| {
        if (kv.len < 2) continue;
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        const k = kv[0..eq];
        const v = kv[eq + 1 ..];
        const n = std.fmt.parseInt(u32, v, 10) catch return error.VerifyFailed;
        if (std.mem.eql(u8, k, "m")) p.m = n;
        if (std.mem.eql(u8, k, "t")) p.t = n;
        if (std.mem.eql(u8, k, "p")) p.p = @intCast(n);
    }

    var salt_buf: [salt_length * 2]u8 = undefined;
    const salt_len = b64UrlNoPadDecode(salt_b64, &salt_buf) catch return error.VerifyFailed;
    var hash_buf: [hash_length * 2]u8 = undefined;
    const expected_len = b64UrlNoPadDecode(hash_b64, &hash_buf) catch return error.VerifyFailed;
    if (expected_len == 0 or expected_len > hash_buf.len) return error.VerifyFailed;

    var got: [hash_length]u8 = undefined;
    if (expected_len > got.len) return error.VerifyFailed;
    argon2.kdf(
        allocator,
        got[0..expected_len],
        password,
        salt_buf[0..salt_len],
        p,
        .argon2id,
        io,
    ) catch return error.VerifyFailed;
    return constantTimeEq(got[0..expected_len], hash_buf[0..expected_len]);
}

fn constantTimeEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    var i: usize = 0;
    while (i < a.len) : (i += 1) diff |= a[i] ^ b[i];
    return diff == 0;
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64UrlNoPadEncode(src: []const u8, dst: []u8) usize {
    var i: usize = 0;
    var o: usize = 0;
    while (i + 3 <= src.len) : (i += 3) {
        const b0 = src[i];
        const b1 = src[i + 1];
        const b2 = src[i + 2];
        dst[o + 0] = alphabet[b0 >> 2];
        dst[o + 1] = alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        dst[o + 2] = alphabet[((b1 & 0x0F) << 2) | (b2 >> 6)];
        dst[o + 3] = alphabet[b2 & 0x3F];
        o += 4;
    }
    const rem = src.len - i;
    if (rem == 1) {
        dst[o + 0] = alphabet[src[i] >> 2];
        dst[o + 1] = alphabet[(src[i] & 0x03) << 4];
        o += 2;
    } else if (rem == 2) {
        const b0 = src[i];
        const b1 = src[i + 1];
        dst[o + 0] = alphabet[b0 >> 2];
        dst[o + 1] = alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        dst[o + 2] = alphabet[(b1 & 0x0F) << 2];
        o += 3;
    }
    return o;
}

const decode_table: [256]i8 = blk: {
    var t: [256]i8 = .{-1} ** 256;
    for (alphabet, 0..) |c, i| t[c] = @intCast(i);
    break :blk t;
};

fn b64UrlNoPadDecode(src: []const u8, dst: []u8) error{BadAlphabet}!usize {
    var i: usize = 0;
    var o: usize = 0;
    var acc: u32 = 0;
    var bits: u5 = 0;
    while (i < src.len) : (i += 1) {
        const v = decode_table[src[i]];
        if (v < 0) return error.BadAlphabet;
        acc = (acc << 6) | @as(u32, @intCast(v));
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= dst.len) return error.BadAlphabet;
            dst[o] = @intCast((acc >> bits) & 0xff);
            o += 1;
        }
    }
    return o;
}

// ── Tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

fn testIo() std.Io {
    // We need a real Io to pass to argon2.kdf. The threaded backend
    // is fine for tests but requires an allocator; provide a static
    // wrapper via the test allocator.
    const T = struct {
        var threaded: ?std.Io.Threaded = null;
    };
    if (T.threaded == null) T.threaded = std.Io.Threaded.init(testing.allocator, .{});
    return T.threaded.?.io();
}

test "argon2id: hash + verify round-trip" {
    var salt: [salt_length]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(0xCAFE_F00D_BABE_BEEF);
    rng.random().bytes(&salt);
    var out: [max_phc_bytes]u8 = undefined;
    const io = testIo();
    const enc = try hash(testing.allocator, io, "correct horse battery staple", salt, &out);
    try testing.expect(std.mem.startsWith(u8, enc, "$argon2id$"));
    try testing.expect(try verify(testing.allocator, io, "correct horse battery staple", enc));
    try testing.expect(!try verify(testing.allocator, io, "Tr0ub4dor&3", enc));
}

test "argon2id: encoded form is reproducible for identical salt" {
    var salt: [salt_length]u8 = undefined;
    @memset(&salt, 0x42);
    var out_a: [max_phc_bytes]u8 = undefined;
    var out_b: [max_phc_bytes]u8 = undefined;
    const io = testIo();
    const a = try hash(testing.allocator, io, "hunter2", salt, &out_a);
    const b = try hash(testing.allocator, io, "hunter2", salt, &out_b);
    try testing.expectEqualStrings(a, b);
}

test "argon2id: verify rejects tampered encoded blob" {
    const salt: [salt_length]u8 = [_]u8{0xAB} ** salt_length;
    var out: [max_phc_bytes]u8 = undefined;
    const io = testIo();
    const enc = try hash(testing.allocator, io, "pw1", salt, &out);
    var copy: [max_phc_bytes]u8 = undefined;
    @memcpy(copy[0..enc.len], enc);
    copy[enc.len - 1] = if (copy[enc.len - 1] == 'A') 'B' else 'A';
    try testing.expect(!try verify(testing.allocator, io, "pw1", copy[0..enc.len]));
}
