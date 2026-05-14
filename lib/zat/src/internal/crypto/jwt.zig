//! JWT parsing and verification for AT Protocol
//!
//! parses and verifies JWTs used in AT Protocol service auth.
//! supports ES256 (P-256) and ES256K (secp256k1) signing.
//!
//! see: https://atproto.com/specs/xrpc#service-auth

const std = @import("std");
const crypto = std.crypto;
const json = @import("../xrpc/json.zig");
const multibase = @import("multibase.zig");
const multicodec = @import("multicodec.zig");

/// JWT signing algorithm
pub const Algorithm = enum {
    ES256, // P-256 / secp256r1
    ES256K, // secp256k1

    pub fn fromString(s: []const u8) ?Algorithm {
        if (std.mem.eql(u8, s, "ES256")) return .ES256;
        if (std.mem.eql(u8, s, "ES256K")) return .ES256K;
        return null;
    }
};

/// parsed JWT header
pub const Header = struct {
    alg: Algorithm,
    typ: []const u8,
};

/// parsed JWT payload (AT Protocol service auth claims)
pub const Payload = struct {
    /// issuer DID (account making the request)
    iss: []const u8,
    /// audience DID (service receiving the request)
    aud: []const u8,
    /// expiration timestamp (unix seconds)
    exp: i64,
    /// issued-at timestamp (unix seconds)
    iat: ?i64 = null,
    /// unique nonce for replay prevention
    jti: ?[]const u8 = null,
    /// lexicon method (optional, may become required)
    lxm: ?[]const u8 = null,
};

/// parsed JWT with raw components
pub const Jwt = struct {
    allocator: std.mem.Allocator,

    /// decoded header
    header: Header,
    /// decoded payload
    payload: Payload,
    /// raw signature bytes (r || s, 64 bytes)
    signature: []u8,
    /// the signed portion (header.payload) for verification
    signed_input: []const u8,
    /// original token for reference
    raw_token: []const u8,

    /// parse a JWT token string
    pub fn parse(allocator: std.mem.Allocator, token: []const u8) !Jwt {
        // split on dots: header.payload.signature
        var parts: [3][]const u8 = undefined;
        var part_idx: usize = 0;
        var it = std.mem.splitScalar(u8, token, '.');

        while (it.next()) |part| {
            if (part_idx >= 3) return error.InvalidJwt;
            parts[part_idx] = part;
            part_idx += 1;
        }

        if (part_idx != 3) return error.InvalidJwt;

        const header_b64 = parts[0];
        const payload_b64 = parts[1];
        const sig_b64 = parts[2];

        // find signed input (everything before last dot)
        const last_dot = std.mem.lastIndexOfScalar(u8, token, '.') orelse return error.InvalidJwt;
        const signed_input = token[0..last_dot];

        // decode header
        const header_json = try base64UrlDecode(allocator, header_b64);
        defer allocator.free(header_json);

        const header = try parseHeader(allocator, header_json);

        // decode payload
        const payload_json = try base64UrlDecode(allocator, payload_b64);
        defer allocator.free(payload_json);

        const payload = try parsePayload(allocator, payload_json);

        // decode signature
        const signature = try base64UrlDecode(allocator, sig_b64);
        errdefer allocator.free(signature);

        // JWT signatures should be 64 bytes (r || s)
        if (signature.len != 64) {
            allocator.free(signature);
            return error.InvalidSignatureLength;
        }

        return .{
            .allocator = allocator,
            .header = header,
            .payload = payload,
            .signature = signature,
            .signed_input = signed_input,
            .raw_token = token,
        };
    }

    /// verify the JWT signature against a public key
    /// public_key should be multibase-encoded (from DID document)
    pub fn verify(self: *const Jwt, public_key_multibase: []const u8) !void {
        // decode multibase key
        const key_bytes = try multibase.decode(self.allocator, public_key_multibase);
        defer self.allocator.free(key_bytes);

        // parse multicodec to get key type and raw bytes
        const parsed_key = try multicodec.parsePublicKey(key_bytes);

        // verify key type matches algorithm
        switch (self.header.alg) {
            .ES256K => {
                if (parsed_key.key_type != .secp256k1) return error.AlgorithmKeyMismatch;
                try verifySecp256k1(self.signed_input, self.signature, parsed_key.raw);
            },
            .ES256 => {
                if (parsed_key.key_type != .p256) return error.AlgorithmKeyMismatch;
                try verifyP256(self.signed_input, self.signature, parsed_key.raw);
            },
        }
    }

    /// check if the token is expired
    pub fn isExpired(self: *const Jwt) bool {
        const now = std.time.timestamp();
        return now > self.payload.exp;
    }

    /// check if the token is expired with clock skew tolerance (in seconds)
    pub fn isExpiredWithSkew(self: *const Jwt, skew_seconds: i64) bool {
        const now = std.time.timestamp();
        return now > (self.payload.exp + skew_seconds);
    }

    pub fn deinit(self: *Jwt) void {
        self.allocator.free(self.signature);
        self.allocator.free(self.payload.iss);
        self.allocator.free(self.payload.aud);
        if (self.payload.jti) |s| self.allocator.free(s);
        if (self.payload.lxm) |s| self.allocator.free(s);
    }
};

// === internal helpers ===

pub fn base64UrlDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const decoder = &std.base64.url_safe_no_pad.Decoder;
    const size = try decoder.calcSizeForSlice(input);
    const output = try allocator.alloc(u8, size);
    errdefer allocator.free(output);
    try decoder.decode(output, input);
    return output;
}

pub fn base64UrlEncode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const encoder = &std.base64.url_safe_no_pad.Encoder;
    const len = encoder.calcSize(data.len);
    const buf = try allocator.alloc(u8, len);
    _ = encoder.encode(buf, data);
    return buf;
}

fn parseHeader(allocator: std.mem.Allocator, header_json: []const u8) !Header {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, header_json, .{});
    defer parsed.deinit();

    const alg_str = json.getString(parsed.value, "alg") orelse return error.MissingAlgorithm;
    const alg = Algorithm.fromString(alg_str) orelse return error.UnsupportedAlgorithm;

    return .{
        .alg = alg,
        .typ = "JWT", // static string, no need to dupe
    };
}

fn parsePayload(allocator: std.mem.Allocator, payload_json: []const u8) !Payload {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();

    const iss_raw = json.getString(parsed.value, "iss") orelse return error.MissingIssuer;
    const aud_raw = json.getString(parsed.value, "aud") orelse return error.MissingAudience;
    const exp = json.getInt(parsed.value, "exp") orelse return error.MissingExpiration;

    // dupe strings so they outlive parsed
    const iss = try allocator.dupe(u8, iss_raw);
    errdefer allocator.free(iss);

    const aud = try allocator.dupe(u8, aud_raw);
    errdefer allocator.free(aud);

    const jti: ?[]const u8 = if (json.getString(parsed.value, "jti")) |s|
        try allocator.dupe(u8, s)
    else
        null;
    errdefer if (jti) |s| allocator.free(s);

    const lxm: ?[]const u8 = if (json.getString(parsed.value, "lxm")) |s|
        try allocator.dupe(u8, s)
    else
        null;

    return .{
        .iss = iss,
        .aud = aud,
        .exp = exp,
        .iat = json.getInt(parsed.value, "iat"),
        .jti = jti,
        .lxm = lxm,
    };
}

/// compare two 32-byte big-endian values: true if a > b
fn bigEndianGt(a: [32]u8, b: [32]u8) bool {
    for (a, b) |ab, bb| {
        if (ab > bb) return true;
        if (ab < bb) return false;
    }
    return false;
}

/// reject high-S signatures (atproto requires low-S normalization).
/// s is high-S if s > curve_order / 2.
fn rejectHighS(comptime half_order: [32]u8, s_bytes: [32]u8) error{HighSSignature}!void {
    if (bigEndianGt(s_bytes, half_order)) return error.HighSSignature;
}

// secp256k1 order/2 (big-endian)
// order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
const secp256k1_half_order: [32]u8 = .{
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
    0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
};

// P-256 order/2 (big-endian)
// order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
const p256_half_order: [32]u8 = .{
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
    0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
};

/// ECDSA signature (r || s, 64 bytes)
pub const Signature = struct {
    bytes: [64]u8,
};

/// sign a message with deterministic RFC 6979 ECDSA and low-S normalization
fn signEcdsa(comptime Scheme: type, comptime Curve: type, comptime half_order: [32]u8, message: []const u8, secret_key_bytes: []const u8) !Signature {
    if (secret_key_bytes.len != 32) return error.InvalidSecretKey;
    const sk = Scheme.SecretKey.fromBytes(secret_key_bytes[0..32].*) catch return error.InvalidSecretKey;
    const kp = Scheme.KeyPair.fromSecretKey(sk) catch return error.InvalidSecretKey;

    var sig = kp.sign(message, null) catch return error.SigningFailed;

    if (bigEndianGt(sig.s, half_order)) {
        sig.s = Curve.scalar.neg(sig.s, .big) catch return error.SigningFailed;
    }

    return .{ .bytes = sig.toBytes() };
}

/// verify an ECDSA signature, rejecting high-S
fn verifyEcdsa(comptime Scheme: type, comptime half_order: [32]u8, message: []const u8, sig_bytes: []const u8, public_key_raw: []const u8) !void {
    if (sig_bytes.len != 64) return error.InvalidSignature;
    const sig = Scheme.Signature.fromBytes(sig_bytes[0..64].*);

    rejectHighS(half_order, sig.s) catch return error.SignatureVerificationFailed;

    if (public_key_raw.len != 33) return error.InvalidPublicKey;
    const public_key = Scheme.PublicKey.fromSec1(public_key_raw) catch return error.InvalidPublicKey;

    sig.verify(message, public_key) catch return error.SignatureVerificationFailed;
}

pub fn signSecp256k1(message: []const u8, secret_key_bytes: []const u8) !Signature {
    return signEcdsa(crypto.sign.ecdsa.EcdsaSecp256k1Sha256, crypto.ecc.Secp256k1, secp256k1_half_order, message, secret_key_bytes);
}

pub fn signP256(message: []const u8, secret_key_bytes: []const u8) !Signature {
    return signEcdsa(crypto.sign.ecdsa.EcdsaP256Sha256, crypto.ecc.P256, p256_half_order, message, secret_key_bytes);
}

pub fn verifySecp256k1(message: []const u8, sig_bytes: []const u8, public_key_raw: []const u8) !void {
    return verifyEcdsa(crypto.sign.ecdsa.EcdsaSecp256k1Sha256, secp256k1_half_order, message, sig_bytes, public_key_raw);
}

pub fn verifyP256(message: []const u8, sig_bytes: []const u8, public_key_raw: []const u8) !void {
    return verifyEcdsa(crypto.sign.ecdsa.EcdsaP256Sha256, p256_half_order, message, sig_bytes, public_key_raw);
}

// === tests ===

test "parse jwt structure" {
    // a minimal valid JWT structure (signature won't verify, just testing parsing)
    // header: {"alg":"ES256K","typ":"JWT"}
    // payload: {"iss":"did:plc:test","aud":"did:plc:service","exp":9999999999}
    const token = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJkaWQ6cGxjOnRlc3QiLCJhdWQiOiJkaWQ6cGxjOnNlcnZpY2UiLCJleHAiOjk5OTk5OTk5OTl9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    var jwt = try Jwt.parse(std.testing.allocator, token);
    defer jwt.deinit();

    try std.testing.expectEqual(Algorithm.ES256K, jwt.header.alg);
    try std.testing.expectEqualStrings("did:plc:test", jwt.payload.iss);
    try std.testing.expectEqualStrings("did:plc:service", jwt.payload.aud);
    try std.testing.expectEqual(@as(i64, 9999999999), jwt.payload.exp);
}

test "reject invalid jwt format" {
    // missing parts
    try std.testing.expectError(error.InvalidJwt, Jwt.parse(std.testing.allocator, "onlyonepart"));
    try std.testing.expectError(error.InvalidJwt, Jwt.parse(std.testing.allocator, "two.parts"));
    try std.testing.expectError(error.InvalidJwt, Jwt.parse(std.testing.allocator, "too.many.parts.here"));
}

test "verify ES256K signature - official fixture" {
    // test vector from bluesky-social/indigo atproto/auth/jwt_test.go
    // pubkey: did:key:zQ3shscXNYZQZSPwegiv7uQZZV5kzATLBRtgJhs7uRY7pfSk4
    // iss: did:example:iss, aud: did:example:aud, exp: 1713571012
    const token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3MiLCJhdWQiOiJkaWQ6ZXhhbXBsZTphdWQiLCJleHAiOjE3MTM1NzEwMTJ9.J_In_PQCMjygeeoIKyjybORD89ZnEy1bZTd--sdq_78qv3KCO9181ZAh-2Pl0qlXZjfUlxgIa6wiak2NtsT98g";

    // extract multibase key from did:key (strip "did:key:" prefix)
    const did_key = "did:key:zQ3shscXNYZQZSPwegiv7uQZZV5kzATLBRtgJhs7uRY7pfSk4";
    const multibase_key = did_key["did:key:".len..];

    var jwt = try Jwt.parse(std.testing.allocator, token);
    defer jwt.deinit();

    // verify claims
    try std.testing.expectEqual(Algorithm.ES256K, jwt.header.alg);
    try std.testing.expectEqualStrings("did:example:iss", jwt.payload.iss);
    try std.testing.expectEqualStrings("did:example:aud", jwt.payload.aud);

    // verify signature
    try jwt.verify(multibase_key);
}

test "verify ES256 signature - official fixture" {
    // test vector from bluesky-social/indigo atproto/auth/jwt_test.go
    // pubkey: did:key:zDnaeXRDKRCEUoYxi8ZJS2pDsgfxUh3pZiu3SES9nbY4DoART
    // iss: did:example:iss, aud: did:example:aud, exp: 1713571554
    const token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3MiLCJhdWQiOiJkaWQ6ZXhhbXBsZTphdWQiLCJleHAiOjE3MTM1NzE1NTR9.FFRLm7SGbDUp6cL0WoCs0L5oqNkjCXB963TqbgI-KxIjbiqMQATVCalcMJx17JGTjMmfVHJP6Op_V4Z0TTjqog";

    // extract multibase key from did:key
    const did_key = "did:key:zDnaeXRDKRCEUoYxi8ZJS2pDsgfxUh3pZiu3SES9nbY4DoART";
    const multibase_key = did_key["did:key:".len..];

    var jwt = try Jwt.parse(std.testing.allocator, token);
    defer jwt.deinit();

    // verify claims
    try std.testing.expectEqual(Algorithm.ES256, jwt.header.alg);
    try std.testing.expectEqualStrings("did:example:iss", jwt.payload.iss);
    try std.testing.expectEqualStrings("did:example:aud", jwt.payload.aud);

    // verify signature
    try jwt.verify(multibase_key);
}

test "reject signature with wrong key" {
    // ES256K token
    const token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3MiLCJhdWQiOiJkaWQ6ZXhhbXBsZTphdWQiLCJleHAiOjE3MTM1NzEwMTJ9.J_In_PQCMjygeeoIKyjybORD89ZnEy1bZTd--sdq_78qv3KCO9181ZAh-2Pl0qlXZjfUlxgIa6wiak2NtsT98g";

    // different ES256K key (second fixture from indigo)
    const wrong_key = "zQ3shqKrpHzQ5HDfhgcYMWaFcpBK3SS39wZLdTjA5GeakX8G5";

    var jwt = try Jwt.parse(std.testing.allocator, token);
    defer jwt.deinit();

    // should fail verification with wrong key
    try std.testing.expectError(error.SignatureVerificationFailed, jwt.verify(wrong_key));
}

test "sign and verify round-trip - secp256k1" {
    // generate a deterministic keypair using a fixed seed
    const Scheme = crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const sk_bytes = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    const message = "hello atproto";
    const sig = try signSecp256k1(message, &sk_bytes);

    // verify low-S: s must be <= half_order
    const s = sig.bytes[32..64].*;
    try std.testing.expect(!bigEndianGt(s, secp256k1_half_order));

    // verify with the corresponding public key
    const sk = try Scheme.SecretKey.fromBytes(sk_bytes);
    const kp = try Scheme.KeyPair.fromSecretKey(sk);
    const pk_bytes = kp.public_key.toCompressedSec1();

    try verifySecp256k1(message, &sig.bytes, &pk_bytes);
}

test "sign and verify round-trip - P-256" {
    const Scheme = crypto.sign.ecdsa.EcdsaP256Sha256;
    const sk_bytes = [_]u8{
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    };

    const message = "hello atproto p256";
    const sig = try signP256(message, &sk_bytes);

    // verify low-S
    const s = sig.bytes[32..64].*;
    try std.testing.expect(!bigEndianGt(s, p256_half_order));

    // verify with the corresponding public key
    const sk = try Scheme.SecretKey.fromBytes(sk_bytes);
    const kp = try Scheme.KeyPair.fromSecretKey(sk);
    const pk_bytes = kp.public_key.toCompressedSec1();

    try verifyP256(message, &sig.bytes, &pk_bytes);
}

test "sign produces deterministic signatures" {
    const sk_bytes = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };
    const message = "deterministic test";

    const sig1 = try signSecp256k1(message, &sk_bytes);
    const sig2 = try signSecp256k1(message, &sk_bytes);
    try std.testing.expectEqualSlices(u8, &sig1.bytes, &sig2.bytes);
}
