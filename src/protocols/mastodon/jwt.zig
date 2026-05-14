//! Ed25519-signed JWTs for Mastodon OAuth bearer tokens.
//!
//! Mirrors `src/protocols/atproto/auth.zig` but with Mastodon-specific
//! claim names (`sub` = numeric user id, `app` = numeric app id,
//! `scopes` = space-delimited scope list). Tokens are bound to a `jti`
//! that is also persisted in `mastodon_tokens` for revocation.

const std = @import("std");
const kp_mod = @import("keypair_ed25519.zig");

pub const access_ttl_seconds: i64 = 60 * 60 * 24 * 7; // 7 days
pub const max_jwt_bytes: usize = 1024;
pub const max_jti_bytes: usize = 32;
pub const max_scopes_bytes: usize = 128;

pub const Claims = struct {
    user_id: i64 = 0, // 0 = client-only (no user)
    app_id: i64 = 0,
    iat: i64 = 0,
    exp: i64 = 0,
    jti_buf: [max_jti_bytes]u8 = undefined,
    jti_len: u8 = 0,
    scopes_buf: [max_scopes_bytes]u8 = undefined,
    scopes_len: u16 = 0,

    pub fn jti(self: *const Claims) []const u8 {
        return self.jti_buf[0..self.jti_len];
    }
    pub fn scopes(self: *const Claims) []const u8 {
        return self.scopes_buf[0..self.scopes_len];
    }
    pub fn setJti(self: *Claims, s: []const u8) !void {
        if (s.len > max_jti_bytes) return error.BufferTooSmall;
        @memcpy(self.jti_buf[0..s.len], s);
        self.jti_len = @intCast(s.len);
    }
    pub fn setScopes(self: *Claims, s: []const u8) !void {
        if (s.len > max_scopes_bytes) return error.BufferTooSmall;
        @memcpy(self.scopes_buf[0..s.len], s);
        self.scopes_len = @intCast(s.len);
    }
    pub fn hasScope(self: *const Claims, needle: []const u8) bool {
        const list = self.scopes();
        var it = std.mem.splitScalar(u8, list, ' ');
        while (it.next()) |s| {
            if (std.mem.eql(u8, s, needle)) return true;
        }
        return false;
    }
};

const header_b64 = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9";

pub fn sign(key: kp_mod.Ed25519KeyPair, claims: Claims, out: []u8) ![]const u8 {
    if (out.len < max_jwt_bytes) return error.BufferTooSmall;

    var payload_buf: [768]u8 = undefined;
    const payload_json = std.fmt.bufPrint(
        &payload_buf,
        "{{\"uid\":{d},\"aid\":{d},\"iat\":{d},\"exp\":{d},\"jti\":\"{s}\",\"scp\":\"{s}\"}}",
        .{ claims.user_id, claims.app_id, claims.iat, claims.exp, claims.jti(), claims.scopes() },
    ) catch return error.BufferTooSmall;

    var pos: usize = 0;
    @memcpy(out[pos..][0..header_b64.len], header_b64);
    pos += header_b64.len;
    out[pos] = '.';
    pos += 1;

    const payload_len = b64UrlEncode(payload_json, out[pos..]);
    if (payload_len == 0 and payload_json.len > 0) return error.BufferTooSmall;
    pos += payload_len;

    const signing_input = out[0..pos];
    const sig_bytes = key.sign(signing_input);

    out[pos] = '.';
    pos += 1;
    const sig_len = b64UrlEncode(&sig_bytes, out[pos..]);
    if (sig_len == 0) return error.BufferTooSmall;
    pos += sig_len;
    return out[0..pos];
}

pub const VerifyError = error{ Malformed, BadSignature, Expired };

pub fn verify(token: []const u8, public_key: [kp_mod.ed25519_public_len]u8, now_unix: i64, out: *Claims) VerifyError!void {
    const dot1 = std.mem.indexOfScalar(u8, token, '.') orelse return error.Malformed;
    const rest = token[dot1 + 1 ..];
    const dot2_rel = std.mem.indexOfScalar(u8, rest, '.') orelse return error.Malformed;
    const dot2 = dot1 + 1 + dot2_rel;

    const header_part = token[0..dot1];
    const payload_part = token[dot1 + 1 .. dot2];
    const sig_part = token[dot2 + 1 ..];

    if (!std.mem.eql(u8, header_part, header_b64)) return error.Malformed;

    var sig_buf: [kp_mod.ed25519_signature_len]u8 = undefined;
    const sig_len = b64UrlDecode(sig_part, &sig_buf) catch return error.Malformed;
    if (sig_len != kp_mod.ed25519_signature_len) return error.Malformed;

    const signing_input = token[0..dot2];
    if (!kp_mod.verifyEd25519(signing_input, sig_buf, public_key)) return error.BadSignature;

    var payload_dec: [768]u8 = undefined;
    const payload_len = b64UrlDecode(payload_part, &payload_dec) catch return error.Malformed;
    parseClaimsJson(payload_dec[0..payload_len], out) catch return error.Malformed;

    if (out.exp <= now_unix) return error.Expired;
}

fn parseClaimsJson(body: []const u8, out: *Claims) !void {
    out.user_id = extractIntField(body, "uid") catch 0;
    out.app_id = extractIntField(body, "aid") catch 0;
    out.iat = extractIntField(body, "iat") catch 0;
    out.exp = try extractIntField(body, "exp");
    if (try extractStringField(body, "jti")) |v| try out.setJti(v);
    if (try extractStringField(body, "scp")) |v| try out.setScopes(v);
}

fn extractStringField(body: []const u8, key: []const u8) !?[]const u8 {
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

pub fn b64UrlEncode(src: []const u8, dst: []u8) usize {
    var i: usize = 0;
    var o: usize = 0;
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

pub fn b64UrlDecode(src: []const u8, dst: []u8) !usize {
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

const testing = std.testing;

test "jwt sign/verify roundtrip" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x33);
    const key = kp_mod.Ed25519KeyPair.fromSeed(seed);

    var claims: Claims = .{ .user_id = 42, .app_id = 7, .iat = 1000, .exp = 9000 };
    try claims.setJti("abc123");
    try claims.setScopes("read write");

    var token_buf: [max_jwt_bytes]u8 = undefined;
    const tok = try sign(key, claims, &token_buf);

    var got: Claims = .{};
    try verify(tok, key.public_key, 1500, &got);
    try testing.expectEqual(@as(i64, 42), got.user_id);
    try testing.expectEqual(@as(i64, 7), got.app_id);
    try testing.expectEqualStrings("abc123", got.jti());
    try testing.expectEqualStrings("read write", got.scopes());
    try testing.expect(got.hasScope("read"));
    try testing.expect(got.hasScope("write"));
    try testing.expect(!got.hasScope("follow"));
}

test "jwt rejects expired" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x44);
    const key = kp_mod.Ed25519KeyPair.fromSeed(seed);
    var claims: Claims = .{ .iat = 100, .exp = 200 };
    try claims.setJti("z");
    try claims.setScopes("read");
    var buf: [max_jwt_bytes]u8 = undefined;
    const tok = try sign(key, claims, &buf);
    var got: Claims = .{};
    try testing.expectError(error.Expired, verify(tok, key.public_key, 500, &got));
}

test "jwt rejects bad signature" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x55);
    const key = kp_mod.Ed25519KeyPair.fromSeed(seed);
    var claims: Claims = .{ .iat = 1, .exp = 9_999_999 };
    try claims.setJti("z");
    try claims.setScopes("read");
    var buf: [max_jwt_bytes]u8 = undefined;
    const tok_const = try sign(key, claims, &buf);
    const tok_len = tok_const.len;
    // Flip multiple characters in the trailing signature section.
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        const idx = tok_len - 1 - i;
        buf[idx] = if (buf[idx] == 'A') 'B' else 'A';
    }
    var got: Claims = .{};
    try testing.expectError(error.BadSignature, verify(buf[0..tok_len], key.public_key, 100, &got));
}
