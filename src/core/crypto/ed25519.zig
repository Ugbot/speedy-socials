//! Ed25519 sign + verify + keypair generation + PEM serialization.
//!
//! Consolidated home for Ed25519. Both `protocols/activitypub/keys.zig`
//! and `protocols/atproto/keypair.zig` re-export from here so the
//! algorithm lives in exactly one place.
//!
//! Tiger Style: bounded buffers, no allocator, no recursion. PEM helpers
//! work into caller-supplied fixed buffers.

const std = @import("std");
const base64 = std.base64.standard;
const StdEd25519 = std.crypto.sign.Ed25519;

pub const public_length: usize = StdEd25519.PublicKey.encoded_length; // 32
pub const secret_length: usize = StdEd25519.SecretKey.encoded_length; // 64
pub const signature_length: usize = StdEd25519.Signature.encoded_length; // 64
pub const seed_length: usize = StdEd25519.KeyPair.seed_length; // 32

pub const SignError = error{InvalidSeed};

pub const KeyPair = struct {
    public_key: [public_length]u8,
    secret_key: [secret_length]u8,
};

/// Deterministic keypair from a 32-byte seed.
pub fn fromSeed(seed: [seed_length]u8) SignError!KeyPair {
    const kp = StdEd25519.KeyPair.generateDeterministic(seed) catch return error.InvalidSeed;
    return .{
        .public_key = kp.public_key.toBytes(),
        .secret_key = kp.secret_key.toBytes(),
    };
}

/// Sign `message` with `secret_key`. The signature is deterministic
/// (RFC 8032).
pub fn sign(secret_key: [secret_length]u8, message: []const u8) [signature_length]u8 {
    const sk = StdEd25519.SecretKey.fromBytes(secret_key) catch unreachable;
    const kp = StdEd25519.KeyPair.fromSecretKey(sk) catch unreachable;
    const sig = kp.sign(message, null) catch unreachable;
    return sig.toBytes();
}

/// Verify `signature` over `message` with `public_key`. Returns true on
/// success.
pub fn verify(
    public_key: [public_length]u8,
    message: []const u8,
    signature: [signature_length]u8,
) bool {
    const pk = StdEd25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = StdEd25519.Signature.fromBytes(signature);
    sig.verify(message, pk) catch return false;
    return true;
}

// ── PEM (SPKI) serialization ──────────────────────────────────────────

/// RFC 8410 SPKI prefix for Ed25519: SEQUENCE { SEQUENCE { OID
/// 1.3.101.112 }, BIT STRING(0, pk) }.
pub const spki_prefix = [12]u8{
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
    0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
};
pub const spki_der_len: usize = 12 + public_length;

pub const max_pem_bytes: usize = 2048;

const pem_header = "-----BEGIN PUBLIC KEY-----\n";
const pem_footer = "\n-----END PUBLIC KEY-----";

pub const PemError = error{
    BufferTooSmall,
    InvalidPem,
    InvalidBase64,
    InvalidDerLength,
};

/// Serialize an Ed25519 public key into PEM form. Returns the number of
/// bytes written.
pub fn writePublicPem(public_key: [public_length]u8, out: []u8) PemError!usize {
    var der: [spki_der_len]u8 = undefined;
    @memcpy(der[0..12], &spki_prefix);
    @memcpy(der[12..], &public_key);

    var b64_buf: [base64.Encoder.calcSize(spki_der_len)]u8 = undefined;
    const b64 = base64.Encoder.encode(&b64_buf, &der);

    const total = pem_header.len + b64.len + pem_footer.len;
    if (out.len < total) return error.BufferTooSmall;

    var pos: usize = 0;
    @memcpy(out[pos .. pos + pem_header.len], pem_header);
    pos += pem_header.len;
    @memcpy(out[pos .. pos + b64.len], b64);
    pos += b64.len;
    @memcpy(out[pos .. pos + pem_footer.len], pem_footer);
    pos += pem_footer.len;
    return pos;
}

/// Parse a PEM SPKI blob. On success writes the 32-byte Ed25519 public
/// key into `out`. Returns true if the blob carried an Ed25519 OID; false
/// if the DER decoded successfully but the OID is not Ed25519 — in which
/// case `der_out` holds the raw DER bytes (for RSA dispatch) and
/// `der_len` is set.
pub const ParsedSpki = struct {
    is_ed25519: bool,
    /// When `is_ed25519` is true, this slice holds the 32-byte key.
    /// When false, this slice holds the full DER blob (for RSA).
    der: []const u8,
};

/// Parse PEM into the appropriate SPKI form. `der_buf` must have room for
/// at least the largest expected DER (e.g. 2 KiB for RSA-4096).
pub fn parsePublicPem(pem: []const u8, der_buf: []u8) PemError!ParsedSpki {
    const h_marker = "-----BEGIN PUBLIC KEY-----";
    const f_marker = "-----END PUBLIC KEY-----";
    const h_start = std.mem.indexOf(u8, pem, h_marker) orelse return error.InvalidPem;
    const h_end = h_start + h_marker.len;
    const f_start_rel = std.mem.indexOf(u8, pem[h_end..], f_marker) orelse return error.InvalidPem;
    const b64_region = pem[h_end .. h_end + f_start_rel];

    // Strip whitespace into a bounded scratch.
    var stripped: [max_pem_bytes]u8 = undefined;
    var s_len: usize = 0;
    var i: usize = 0;
    while (i < b64_region.len) : (i += 1) {
        const c = b64_region[i];
        if (c == ' ' or c == '\r' or c == '\n' or c == '\t') continue;
        if (s_len >= stripped.len) return error.InvalidPem;
        stripped[s_len] = c;
        s_len += 1;
    }
    if (s_len == 0) return error.InvalidPem;

    const der_len = base64.Decoder.calcSizeForSlice(stripped[0..s_len]) catch return error.InvalidBase64;
    if (der_len == 0 or der_len > der_buf.len) return error.InvalidDerLength;
    base64.Decoder.decode(der_buf[0..der_len], stripped[0..s_len]) catch return error.InvalidBase64;

    if (der_len == spki_der_len and std.mem.eql(u8, der_buf[0..12], &spki_prefix)) {
        return .{ .is_ed25519 = true, .der = der_buf[12..der_len] };
    }
    return .{ .is_ed25519 = false, .der = der_buf[0..der_len] };
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

fn testSeed(salt: u8) [seed_length]u8 {
    var s: [seed_length]u8 = undefined;
    var i: usize = 0;
    while (i < s.len) : (i += 1) s[i] = @intCast((i +% salt) & 0xff);
    return s;
}

test "ed25519: deterministic keypair from seed" {
    var s: [seed_length]u8 = undefined;
    @memset(&s, 0x42);
    const a = try fromSeed(s);
    const b = try fromSeed(s);
    try testing.expectEqualSlices(u8, &a.public_key, &b.public_key);
    try testing.expectEqualSlices(u8, &a.secret_key, &b.secret_key);
}

test "ed25519: sign + verify round-trip" {
    const kp = try fromSeed(testSeed(1));
    const msg = "the quick brown fox";
    const sig = sign(kp.secret_key, msg);
    try testing.expect(verify(kp.public_key, msg, sig));
    try testing.expect(!verify(kp.public_key, "the quick brown FOX", sig));
}

test "ed25519: pem write + parse roundtrip" {
    const kp = try fromSeed(testSeed(2));
    var pem_buf: [max_pem_bytes]u8 = undefined;
    const n = try writePublicPem(kp.public_key, &pem_buf);
    var der_buf: [256]u8 = undefined;
    const parsed = try parsePublicPem(pem_buf[0..n], &der_buf);
    try testing.expect(parsed.is_ed25519);
    try testing.expectEqualSlices(u8, &kp.public_key, parsed.der);
}

test "ed25519: parsePublicPem yields RSA fallback" {
    // Hand-roll a foreign SPKI: 64 bytes of SEQUENCE-shaped padding.
    var der: [64]u8 = undefined;
    @memset(&der, 0xCD);
    der[0] = 0x30;
    der[1] = 0x3e;
    var b64_buf: [base64.Encoder.calcSize(64)]u8 = undefined;
    const b64 = base64.Encoder.encode(&b64_buf, &der);
    var pem_buf: [max_pem_bytes]u8 = undefined;
    var pos: usize = 0;
    @memcpy(pem_buf[pos .. pos + pem_header.len], pem_header);
    pos += pem_header.len;
    @memcpy(pem_buf[pos .. pos + b64.len], b64);
    pos += b64.len;
    @memcpy(pem_buf[pos .. pos + pem_footer.len], pem_footer);
    pos += pem_footer.len;
    var der_buf: [256]u8 = undefined;
    const parsed = try parsePublicPem(pem_buf[0..pos], &der_buf);
    try testing.expect(!parsed.is_ed25519);
    try testing.expectEqual(@as(usize, 64), parsed.der.len);
    try testing.expectEqualSlices(u8, &der, parsed.der);
}
