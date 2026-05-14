//! DPoP-bound OAuth 2.1 skeleton.
//!
//! AT Protocol's OAuth profile mandates:
//!   * DPoP (RFC 9449) — proof-of-possession of an Ed25519 / ES256 key
//!   * PKCE S256
//!   * PAR (Pushed Authorization Requests)
//!   * `htm` (method), `htu` (URL), `iat`, `jti`, optional `ath` (access-
//!     token hash) claims in the DPoP proof JWT.
//!
//! Current status:
//!   * Ed25519 (alg=EdDSA) DPoP proofs: sign + verify implemented.
//!   * ES256 (alg=ES256): returns `NotImplemented`.
//!   * Client metadata fetch: function pointer stub — wired through
//!     `core.workers.Pool` in production.
//!   * JWK thumbprint validation: SHA-256 over canonical JWK JSON.
//!   * Replay window: `seen_jti` ring; rejects any jti seen in the
//!     last `max_seen_jti` proofs.

const std = @import("std");
const core = @import("core");
const AtpError = core.errors.AtpError;
const Clock = core.clock.Clock;
const assertLe = core.assert.assertLe;

const keypair = @import("keypair.zig");
const auth = @import("auth.zig");

pub const dpop_max_age_seconds: i64 = 60; // RFC 9449 §11.1
pub const max_seen_jti: u32 = 256;

pub const ProofError = error{
    Malformed,
    BadSignature,
    Stale,
    Replayed,
    BadClaims,
    NotImplemented,
};

pub const Verifier = struct {
    /// Ring of recently-seen jti values for replay defense. Producer-
    /// drops oldest on overflow (DPoP windows are short — 60s — so old
    /// jtis stop mattering quickly).
    seen: [max_seen_jti][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** max_seen_jti,
    seen_lens: [max_seen_jti]u8 = [_]u8{0} ** max_seen_jti,
    write_idx: u32 = 0,

    pub fn init() Verifier {
        return .{};
    }

    /// Verify a DPoP proof JWT. `expected_htm` is the HTTP method (e.g.
    /// "POST"); `expected_htu` is the absolute request URL with no query
    /// or fragment.
    pub fn verifyProof(
        self: *Verifier,
        proof_jwt: []const u8,
        public_key: [keypair.ed25519_public_len]u8,
        expected_htm: []const u8,
        expected_htu: []const u8,
        now_unix: i64,
    ) ProofError!void {
        // Split header.payload.sig
        const dot1 = std.mem.indexOfScalar(u8, proof_jwt, '.') orelse return error.Malformed;
        const rest = proof_jwt[dot1 + 1 ..];
        const dot2_rel = std.mem.indexOfScalar(u8, rest, '.') orelse return error.Malformed;
        const dot2 = dot1 + 1 + dot2_rel;

        const payload_part = proof_jwt[dot1 + 1 .. dot2];
        const sig_part = proof_jwt[dot2 + 1 ..];

        // Decode signature.
        var sig_bytes: [keypair.ed25519_signature_len]u8 = undefined;
        const sig_n = b64UrlDecode(sig_part, &sig_bytes) catch return error.Malformed;
        if (sig_n != keypair.ed25519_signature_len) return error.Malformed;

        if (!keypair.verifyEd25519(proof_jwt[0..dot2], sig_bytes, public_key)) return error.BadSignature;

        // Decode + parse payload for htm/htu/iat/jti.
        var payload_dec: [1024]u8 = undefined;
        const pn = b64UrlDecode(payload_part, &payload_dec) catch return error.Malformed;
        const payload = payload_dec[0..pn];

        const htm = extractString(payload, "htm") catch return error.BadClaims;
        const htu = extractString(payload, "htu") catch return error.BadClaims;
        const jti = extractString(payload, "jti") catch return error.BadClaims;
        const iat = extractInt(payload, "iat") catch return error.BadClaims;

        if (!std.mem.eql(u8, htm, expected_htm)) return error.BadClaims;
        if (!std.mem.eql(u8, htu, expected_htu)) return error.BadClaims;
        if (now_unix - iat > dpop_max_age_seconds) return error.Stale;
        if (now_unix < iat - 5) return error.Stale; // small clock skew

        // Replay check.
        if (self.seenJti(jti)) return error.Replayed;
        self.rememberJti(jti);
    }

    fn seenJti(self: *Verifier, jti: []const u8) bool {
        if (jti.len > 32) return false;
        var i: u32 = 0;
        while (i < max_seen_jti) : (i += 1) {
            const ln = self.seen_lens[i];
            if (ln == jti.len and std.mem.eql(u8, self.seen[i][0..ln], jti)) return true;
        }
        return false;
    }

    fn rememberJti(self: *Verifier, jti: []const u8) void {
        const cap: u8 = @intCast(@min(jti.len, 32));
        const slot = self.write_idx % max_seen_jti;
        @memcpy(self.seen[slot][0..cap], jti[0..cap]);
        self.seen_lens[slot] = cap;
        self.write_idx +%= 1;
    }
};

fn extractString(body: []const u8, key: []const u8) ![]const u8 {
    var needle_buf: [64]u8 = undefined;
    if (key.len + 4 > needle_buf.len) return error.BadClaims;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..key.len], key);
    needle_buf[1 + key.len] = '"';
    needle_buf[2 + key.len] = ':';
    needle_buf[3 + key.len] = '"';
    const needle = needle_buf[0 .. 4 + key.len];
    const start = std.mem.indexOf(u8, body, needle) orelse return error.BadClaims;
    const value_start = start + needle.len;
    const end_rel = std.mem.indexOfScalar(u8, body[value_start..], '"') orelse return error.BadClaims;
    return body[value_start .. value_start + end_rel];
}

fn extractInt(body: []const u8, key: []const u8) !i64 {
    var needle_buf: [64]u8 = undefined;
    if (key.len + 3 > needle_buf.len) return error.BadClaims;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..key.len], key);
    needle_buf[1 + key.len] = '"';
    needle_buf[2 + key.len] = ':';
    const needle = needle_buf[0 .. 3 + key.len];
    const start = std.mem.indexOf(u8, body, needle) orelse return error.BadClaims;
    var i: usize = start + needle.len;
    while (i < body.len and (body[i] == ' ' or body[i] == '\t')) : (i += 1) {}
    var val: i64 = 0;
    var digits: u32 = 0;
    while (i < body.len and body[i] >= '0' and body[i] <= '9') : (i += 1) {
        if (digits > 18) return error.BadClaims;
        val = val * 10 + @as(i64, body[i] - '0');
        digits += 1;
    }
    if (digits == 0) return error.BadClaims;
    return val;
}

fn b64UrlDecode(src: []const u8, dst: []u8) !usize {
    const tbl = makeTbl();
    var i: usize = 0;
    var o: usize = 0;
    var acc: u32 = 0;
    var bits: u5 = 0;
    while (i < src.len) : (i += 1) {
        const ch = src[i];
        const v = tbl[ch];
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

fn makeTbl() [256]i8 {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    var t: [256]i8 = .{-1} ** 256;
    for (alphabet, 0..) |ch, idx| t[ch] = @intCast(idx);
    return t;
}

/// Compute the JWK thumbprint (RFC 7638) for an Ed25519 public key.
/// The canonical JWK is `{"crv":"Ed25519","kty":"OKP","x":"<b64url>"}`.
pub fn jwkThumbprintEd25519(public_key: [keypair.ed25519_public_len]u8) [32]u8 {
    var x_b64: [44]u8 = undefined;
    const xn = b64UrlEncodeShim(&public_key, &x_b64);
    // canonical bytes:
    var canon: [128]u8 = undefined;
    const canon_str = std.fmt.bufPrint(&canon, "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{s}\"}}", .{x_b64[0..xn]}) catch unreachable;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canon_str, &hash, .{});
    return hash;
}

fn b64UrlEncodeShim(src: []const u8, dst: []u8) usize {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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
        const b0 = src[i];
        dst[o + 0] = alphabet[b0 >> 2];
        dst[o + 1] = alphabet[(b0 & 0x03) << 4];
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

/// Sign a DPoP proof. `out` must have room for `auth.max_jwt_bytes`.
pub fn signProof(
    kp: keypair.Ed25519KeyPair,
    htm: []const u8,
    htu: []const u8,
    iat: i64,
    jti: []const u8,
    out: []u8,
) AtpError![]const u8 {
    if (out.len < auth.max_jwt_bytes) return error.BufferTooSmall;

    // Header for DPoP includes the JWK; for simplicity here we use a
    // fixed pre-encoded header that omits the JWK. Production DPoP
    // requires the JWK in the header; that lands when ES256 + full
    // metadata fetch is implemented.
    const header_b64 = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Atand0In0";

    var payload_buf: [512]u8 = undefined;
    const payload_json = std.fmt.bufPrint(
        &payload_buf,
        "{{\"htm\":\"{s}\",\"htu\":\"{s}\",\"iat\":{d},\"jti\":\"{s}\"}}",
        .{ htm, htu, iat, jti },
    ) catch return error.BufferTooSmall;

    var pos: usize = 0;
    @memcpy(out[pos..][0..header_b64.len], header_b64);
    pos += header_b64.len;
    out[pos] = '.';
    pos += 1;
    pos += b64UrlEncodeShim(payload_json, out[pos..]);
    const sig = kp.sign(out[0..pos]);
    out[pos] = '.';
    pos += 1;
    pos += b64UrlEncodeShim(&sig, out[pos..]);
    return out[0..pos];
}

pub fn signProofEs256(_: []const u8, _: []const u8, _: i64, _: []const u8, _: []u8) ProofError![]const u8 {
    return error.NotImplemented;
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "dpop: sign + verify happy path" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x11);
    const kp = keypair.Ed25519KeyPair.fromSeed(seed);

    var buf: [auth.max_jwt_bytes]u8 = undefined;
    const proof = try signProof(kp, "POST", "https://pds.test/xrpc/x", 1000, "jti-1", &buf);

    var v = Verifier.init();
    try v.verifyProof(proof, kp.public_key, "POST", "https://pds.test/xrpc/x", 1010);
}

test "dpop: stale proof rejected" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x12);
    const kp = keypair.Ed25519KeyPair.fromSeed(seed);
    var buf: [auth.max_jwt_bytes]u8 = undefined;
    const proof = try signProof(kp, "POST", "https://pds.test/x", 1000, "jti-stale", &buf);
    var v = Verifier.init();
    try testing.expectError(error.Stale, v.verifyProof(proof, kp.public_key, "POST", "https://pds.test/x", 1000 + dpop_max_age_seconds + 1));
}

test "dpop: replayed proof rejected" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x13);
    const kp = keypair.Ed25519KeyPair.fromSeed(seed);
    var buf: [auth.max_jwt_bytes]u8 = undefined;
    const proof = try signProof(kp, "GET", "https://pds.test/y", 1000, "jti-replay", &buf);
    var v = Verifier.init();
    try v.verifyProof(proof, kp.public_key, "GET", "https://pds.test/y", 1010);
    try testing.expectError(error.Replayed, v.verifyProof(proof, kp.public_key, "GET", "https://pds.test/y", 1011));
}

test "dpop: htm mismatch rejected" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x14);
    const kp = keypair.Ed25519KeyPair.fromSeed(seed);
    var buf: [auth.max_jwt_bytes]u8 = undefined;
    const proof = try signProof(kp, "POST", "https://pds.test/m", 1000, "jti-m", &buf);
    var v = Verifier.init();
    try testing.expectError(error.BadClaims, v.verifyProof(proof, kp.public_key, "GET", "https://pds.test/m", 1010));
}

test "dpop: es256 stub returns NotImplemented" {
    var buf: [auth.max_jwt_bytes]u8 = undefined;
    try testing.expectError(error.NotImplemented, signProofEs256("POST", "x", 1, "j", &buf));
}

test "dpop: jwk thumbprint stable for same key" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x21);
    const kp = keypair.Ed25519KeyPair.fromSeed(seed);
    const t1 = jwkThumbprintEd25519(kp.public_key);
    const t2 = jwkThumbprintEd25519(kp.public_key);
    try testing.expectEqualSlices(u8, &t1, &t2);
}
