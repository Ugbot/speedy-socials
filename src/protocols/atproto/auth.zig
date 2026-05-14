//! JWT auth for AT Protocol.
//!
//! Access tokens: Ed25519-signed JWTs, 1h TTL.
//! Refresh tokens: Ed25519-signed JWTs, 90d TTL, rotated on use.
//!
//! This is the legacy auth path (kept for backward compatibility with
//! clients pre-OAuth). Real OAuth/DPoP lives in `oauth_dpop.zig`.
//!
//! Tiger Style: no allocator on the hot path; encode/decode into
//! caller-supplied buffers. Body is a fixed-shape JSON payload.

const std = @import("std");
const core = @import("core");
const AtpError = core.errors.AtpError;
const assertLe = core.assert.assertLe;

const keypair = @import("keypair.zig");

pub const access_ttl_seconds: i64 = 60 * 60;
pub const refresh_ttl_seconds: i64 = 60 * 60 * 24 * 90;

pub const max_jwt_bytes: usize = 1024;
pub const max_did_bytes: usize = 256;
pub const max_jti_bytes: usize = 32;

pub const Scope = enum {
    access,
    refresh,

    pub fn str(self: Scope) []const u8 {
        return switch (self) {
            .access => "com.atproto.access",
            .refresh => "com.atproto.refresh",
        };
    }
};

pub const Claims = struct {
    /// Subject — the DID this token authorizes.
    sub_buf: [max_did_bytes]u8 = undefined,
    sub_len: u16 = 0,
    /// Scope — access/refresh.
    scope: Scope,
    /// Issued-at (unix seconds).
    iat: i64,
    /// Expires-at (unix seconds).
    exp: i64,
    /// JWT id — random opaque, used for refresh rotation tracking.
    jti_buf: [max_jti_bytes]u8 = undefined,
    jti_len: u8 = 0,

    pub fn sub(self: *const Claims) []const u8 {
        return self.sub_buf[0..self.sub_len];
    }
    pub fn jti(self: *const Claims) []const u8 {
        return self.jti_buf[0..self.jti_len];
    }

    pub fn setSub(self: *Claims, s: []const u8) AtpError!void {
        if (s.len > max_did_bytes) return error.BufferTooSmall;
        @memcpy(self.sub_buf[0..s.len], s);
        self.sub_len = @intCast(s.len);
    }

    pub fn setJti(self: *Claims, s: []const u8) AtpError!void {
        if (s.len > max_jti_bytes) return error.BufferTooSmall;
        @memcpy(self.jti_buf[0..s.len], s);
        self.jti_len = @intCast(s.len);
    }
};

// Header is fixed: {"alg":"EdDSA","typ":"JWT"} (base64url encoded).
const header_b64 = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9";

/// Sign a JWT into `out`. Returns the slice written. `out.len` must be
/// at least `max_jwt_bytes`.
pub fn sign(kp: keypair.Ed25519KeyPair, claims: Claims, out: []u8) AtpError![]const u8 {
    if (out.len < max_jwt_bytes) return error.BufferTooSmall;

    // Build payload JSON in a scratch buffer.
    var payload_buf: [512]u8 = undefined;
    const payload_json = std.fmt.bufPrint(
        &payload_buf,
        "{{\"sub\":\"{s}\",\"scope\":\"{s}\",\"iat\":{d},\"exp\":{d},\"jti\":\"{s}\"}}",
        .{ claims.sub(), claims.scope.str(), claims.iat, claims.exp, claims.jti() },
    ) catch return error.BufferTooSmall;

    var pos: usize = 0;
    // Header.
    @memcpy(out[pos..][0..header_b64.len], header_b64);
    pos += header_b64.len;
    out[pos] = '.';
    pos += 1;

    // Payload (base64url, no padding).
    const payload_len = b64UrlEncode(payload_json, out[pos..]);
    if (payload_len == 0 and payload_json.len > 0) return error.BufferTooSmall;
    pos += payload_len;

    // Signature over header.payload.
    const signing_input = out[0..pos];
    const sig_bytes = kp.sign(signing_input);

    out[pos] = '.';
    pos += 1;
    const sig_len = b64UrlEncode(&sig_bytes, out[pos..]);
    if (sig_len == 0) return error.BufferTooSmall;
    pos += sig_len;

    assertLe(pos, out.len);
    return out[0..pos];
}

pub const VerifyError = error{
    Malformed,
    BadSignature,
    Expired,
    NotImplemented,
};

/// Verify a JWT signature and parse claims. `now_unix` is the current
/// wall-clock unix-seconds used for the expiry check.
pub fn verify(
    token: []const u8,
    public_key: [keypair.ed25519_public_len]u8,
    now_unix: i64,
    out: *Claims,
) VerifyError!void {
    // Split on '.'.
    const dot1 = std.mem.indexOfScalar(u8, token, '.') orelse return error.Malformed;
    const rest = token[dot1 + 1 ..];
    const dot2_rel = std.mem.indexOfScalar(u8, rest, '.') orelse return error.Malformed;
    const dot2 = dot1 + 1 + dot2_rel;

    const header_part = token[0..dot1];
    const payload_part = token[dot1 + 1 .. dot2];
    const sig_part = token[dot2 + 1 ..];

    // Header must match the fixed Ed25519 header.
    if (!std.mem.eql(u8, header_part, header_b64)) return error.Malformed;

    // Decode signature.
    var sig_buf: [keypair.ed25519_signature_len]u8 = undefined;
    const sig_len = b64UrlDecode(sig_part, &sig_buf) catch return error.Malformed;
    if (sig_len != keypair.ed25519_signature_len) return error.Malformed;

    // Verify signature over header.payload.
    const signing_input = token[0..dot2];
    if (!keypair.verifyEd25519(signing_input, sig_buf, public_key)) return error.BadSignature;

    // Decode payload and parse minimal claims.
    var payload_dec: [512]u8 = undefined;
    const payload_len = b64UrlDecode(payload_part, &payload_dec) catch return error.Malformed;
    parseClaimsJson(payload_dec[0..payload_len], out) catch return error.Malformed;

    if (out.exp <= now_unix) return error.Expired;
}

fn parseClaimsJson(body: []const u8, out: *Claims) !void {
    // Single-pass key extractor: looks for "sub","scope","iat","exp","jti".
    out.sub_len = 0;
    out.jti_len = 0;
    out.iat = 0;
    out.exp = 0;
    out.scope = .access;

    if (try extractStringField(body, "sub")) |v| try out.setSub(v);
    if (try extractStringField(body, "jti")) |v| try out.setJti(v);
    if (try extractStringField(body, "scope")) |v| {
        if (std.mem.eql(u8, v, "com.atproto.refresh")) out.scope = .refresh else out.scope = .access;
    }
    out.iat = try extractIntField(body, "iat");
    out.exp = try extractIntField(body, "exp");
    if (out.sub_len == 0) return error.Malformed;
}

fn extractStringField(body: []const u8, key: []const u8) !?[]const u8 {
    // find "key":"
    var needle_buf: [64]u8 = undefined;
    if (key.len + 4 > needle_buf.len) return error.Malformed;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..key.len], key);
    needle_buf[1 + key.len] = '"';
    needle_buf[2 + key.len] = ':';
    needle_buf[3 + key.len] = '"';
    const needle = needle_buf[0 .. 4 + key.len];
    const start = std.mem.indexOf(u8, body, needle) orelse return null;
    const value_start = start + needle.len;
    const value_end_rel = std.mem.indexOfScalar(u8, body[value_start..], '"') orelse return error.Malformed;
    return body[value_start .. value_start + value_end_rel];
}

fn extractIntField(body: []const u8, key: []const u8) !i64 {
    var needle_buf: [64]u8 = undefined;
    if (key.len + 3 > needle_buf.len) return error.Malformed;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..key.len], key);
    needle_buf[1 + key.len] = '"';
    needle_buf[2 + key.len] = ':';
    const needle = needle_buf[0 .. 3 + key.len];
    const start = std.mem.indexOf(u8, body, needle) orelse return error.Malformed;
    var i: usize = start + needle.len;
    // Skip optional whitespace.
    while (i < body.len and (body[i] == ' ' or body[i] == '\t')) : (i += 1) {}
    var sign_mul: i64 = 1;
    if (i < body.len and body[i] == '-') {
        sign_mul = -1;
        i += 1;
    }
    var val: i64 = 0;
    var digits: u32 = 0;
    while (i < body.len and body[i] >= '0' and body[i] <= '9') : (i += 1) {
        if (digits > 18) return error.Malformed;
        val = val * 10 + @as(i64, body[i] - '0');
        digits += 1;
    }
    if (digits == 0) return error.Malformed;
    return val * sign_mul;
}

// ── Base64URL (no padding) ─────────────────────────────────────────

const b64url_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const b64url_decode_table: [256]i8 = blk: {
    var t: [256]i8 = .{-1} ** 256;
    for (b64url_alphabet, 0..) |ch, i| t[ch] = @intCast(i);
    break :blk t;
};

fn b64UrlEncode(src: []const u8, dst: []u8) usize {
    var i: usize = 0;
    var o: usize = 0;
    // Bounded — each pass consumes ≤ 3 bytes.
    while (i + 3 <= src.len) : (i += 3) {
        if (o + 4 > dst.len) return 0;
        const b0 = src[i];
        const b1 = src[i + 1];
        const b2 = src[i + 2];
        dst[o + 0] = b64url_alphabet[b0 >> 2];
        dst[o + 1] = b64url_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        dst[o + 2] = b64url_alphabet[((b1 & 0x0F) << 2) | (b2 >> 6)];
        dst[o + 3] = b64url_alphabet[b2 & 0x3F];
        o += 4;
    }
    const rem = src.len - i;
    if (rem == 1) {
        if (o + 2 > dst.len) return 0;
        const b0 = src[i];
        dst[o + 0] = b64url_alphabet[b0 >> 2];
        dst[o + 1] = b64url_alphabet[(b0 & 0x03) << 4];
        o += 2;
    } else if (rem == 2) {
        if (o + 3 > dst.len) return 0;
        const b0 = src[i];
        const b1 = src[i + 1];
        dst[o + 0] = b64url_alphabet[b0 >> 2];
        dst[o + 1] = b64url_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        dst[o + 2] = b64url_alphabet[(b1 & 0x0F) << 2];
        o += 3;
    }
    return o;
}

fn b64UrlDecode(src: []const u8, dst: []u8) !usize {
    var i: usize = 0;
    var o: usize = 0;
    var acc: u32 = 0;
    var bits: u5 = 0;
    while (i < src.len) : (i += 1) {
        const ch = src[i];
        const v = b64url_decode_table[ch];
        if (v < 0) return error.Malformed;
        acc = (acc << 6) | @as(u32, @intCast(v));
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= dst.len) return error.Malformed;
            dst[o] = @intCast((acc >> bits) & 0xff);
            o += 1;
        }
    }
    return o;
}

/// Constant-time byte comparison. Returns true if both buffers are
/// equal-length and identical.
pub fn constantTimeEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "jwt: sign then verify roundtrip" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x7);
    const kp = keypair.Ed25519KeyPair.fromSeed(seed);

    var claims: Claims = .{ .scope = .access, .iat = 1000, .exp = 5000 };
    try claims.setSub("did:plc:abc123");
    try claims.setJti("jti-abcdef");

    var token_buf: [max_jwt_bytes]u8 = undefined;
    const tok = try sign(kp, claims, &token_buf);
    try testing.expect(tok.len > 64);

    var got: Claims = .{ .scope = .access, .iat = 0, .exp = 0 };
    try verify(tok, kp.public_key, 2000, &got);
    try testing.expectEqualStrings("did:plc:abc123", got.sub());
    try testing.expectEqualStrings("jti-abcdef", got.jti());
    try testing.expectEqual(Scope.access, got.scope);
    try testing.expectEqual(@as(i64, 5000), got.exp);
}

test "jwt: verify rejects expired" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x8);
    const kp = keypair.Ed25519KeyPair.fromSeed(seed);
    var claims: Claims = .{ .scope = .access, .iat = 100, .exp = 200 };
    try claims.setSub("did:plc:exp");
    try claims.setJti("z");
    var buf: [max_jwt_bytes]u8 = undefined;
    const tok = try sign(kp, claims, &buf);
    var got: Claims = .{ .scope = .access, .iat = 0, .exp = 0 };
    try testing.expectError(error.Expired, verify(tok, kp.public_key, 500, &got));
}

test "jwt: verify rejects tampered signature" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x9);
    const kp = keypair.Ed25519KeyPair.fromSeed(seed);
    var claims: Claims = .{ .scope = .access, .iat = 1, .exp = 999_999 };
    try claims.setSub("did:plc:tamper");
    try claims.setJti("a");
    var buf: [max_jwt_bytes]u8 = undefined;
    const tok = try sign(kp, claims, &buf);
    // Flip a byte in the signature region (last char).
    buf[tok.len - 1] = if (buf[tok.len - 1] == 'A') 'B' else 'A';
    var got: Claims = .{ .scope = .access, .iat = 0, .exp = 0 };
    try testing.expectError(error.BadSignature, verify(tok, kp.public_key, 100, &got));
}

test "constantTimeEq" {
    try testing.expect(constantTimeEq("abc", "abc"));
    try testing.expect(!constantTimeEq("abc", "abd"));
    try testing.expect(!constantTimeEq("abc", "abcd"));
}
