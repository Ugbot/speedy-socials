//! ActivityPub key material.
//!
//! Two algorithms are first-class:
//!
//!   * Ed25519 — Zig stdlib supports sign + verify directly. This is what
//!     modern fediverse servers (e.g. Mastodon 4.5+ optionally) advertise
//!     via RFC 9421 with `alg="ed25519"`.
//!
//!   * RSA-2048 PKCS1-v1_5 over SHA-256 — the legacy draft-cavage workhorse
//!     for Mastodon. Zig stdlib's RSA is too thin for verify-from-SPKI
//!     today, so we model the shape (SPKI DER bytes + modulus length) and
//!     dispatch verification through a function pointer the host wires at
//!     boot. Phase 3 integration will plug BoringSSL in here. Until then,
//!     the function pointer is null and RSA verify returns
//!     `SignatureInvalid`. The signing-string + parser paths are exercised
//!     regardless.
//!
//! Tiger Style: all key bytes inline (no allocator). PEM helpers write
//! into caller-supplied fixed buffers.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const base64 = std.base64.standard;
const core = @import("core");
const assert = core.assert.assert;

pub const FedError = core.errors.FedError;

/// Maximum length of a keyId (URI). Mastodon publishes
/// `https://server/users/{name}#main-key` style ids; 256 covers reality
/// with room to spare.
pub const max_key_id_bytes: usize = 256;

/// Maximum DER-encoded SPKI we accept for an RSA public key. RSA-4096
/// SPKI is ~550 bytes; cap at 1024 to allow some over-encoding slack.
pub const max_rsa_spki_bytes: usize = 1024;

/// Maximum PEM bytes for a key (header + base64 + footer + newlines).
pub const max_pem_bytes: usize = 2048;

pub const Algorithm = enum {
    ed25519,
    rsa_sha256,
};

pub const KeyId = struct {
    bytes: [max_key_id_bytes]u8 = undefined,
    len: usize = 0,

    pub fn fromSlice(s: []const u8) FedError!KeyId {
        if (s.len == 0 or s.len > max_key_id_bytes) return error.SignatureMalformed;
        var k: KeyId = .{};
        @memcpy(k.bytes[0..s.len], s);
        k.len = s.len;
        return k;
    }

    pub fn slice(self: *const KeyId) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// The Ed25519 SPKI DER prefix used by RFC 8410:
///   SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING(0, pk) }
pub const ed25519_spki_prefix = [12]u8{
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
    0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
};

pub const ed25519_spki_der_len: usize = 12 + 32;

pub const PublicKey = struct {
    algo: Algorithm,
    key_id: KeyId,

    /// Algorithm-specific bytes:
    ///   - ed25519: bytes[0..32] is the public key.
    ///   - rsa_sha256: bytes[0..rsa_len] is the SPKI DER blob; the host
    ///     verify hook is responsible for parsing it.
    bytes: [max_rsa_spki_bytes]u8 = undefined,
    rsa_len: usize = 0,

    pub fn ed25519FromBytes(key_id: KeyId, pk: [32]u8) PublicKey {
        var out: PublicKey = .{ .algo = .ed25519, .key_id = key_id };
        @memcpy(out.bytes[0..32], &pk);
        return out;
    }

    pub fn rsaFromSpki(key_id: KeyId, spki: []const u8) FedError!PublicKey {
        if (spki.len == 0 or spki.len > max_rsa_spki_bytes) {
            return error.SignatureMalformed;
        }
        var out: PublicKey = .{ .algo = .rsa_sha256, .key_id = key_id };
        @memcpy(out.bytes[0..spki.len], spki);
        out.rsa_len = spki.len;
        return out;
    }

    pub fn ed25519Bytes(self: *const PublicKey) [32]u8 {
        assert(self.algo == .ed25519);
        var out: [32]u8 = undefined;
        @memcpy(&out, self.bytes[0..32]);
        return out;
    }

    pub fn rsaSpki(self: *const PublicKey) []const u8 {
        assert(self.algo == .rsa_sha256);
        return self.bytes[0..self.rsa_len];
    }
};

pub const PrivateKey = struct {
    algo: Algorithm,
    key_id: KeyId,
    /// ed25519: 64 bytes. rsa: opaque blob the host owns; we never see it
    /// in Phase 3a (signing is done by the host's BoringSSL hook).
    bytes: [64]u8 = undefined,

    pub fn ed25519FromBytes(key_id: KeyId, sk: [64]u8) PrivateKey {
        var out: PrivateKey = .{ .algo = .ed25519, .key_id = key_id };
        @memcpy(out.bytes[0..64], &sk);
        return out;
    }

    pub fn ed25519SecretBytes(self: *const PrivateKey) [64]u8 {
        assert(self.algo == .ed25519);
        var out: [64]u8 = undefined;
        @memcpy(&out, self.bytes[0..64]);
        return out;
    }
};

/// Deterministic Ed25519 keypair generation from a 32-byte seed. The
/// host wires a CSPRNG-derived seed at boot (see `core/rng.zig` plus the
/// OS getentropy syscall in the production build); tests pass a fixed
/// seed for reproducibility.
pub fn generateEd25519FromSeed(
    key_id: KeyId,
    seed: [Ed25519.KeyPair.seed_length]u8,
) FedError!struct { public: PublicKey, private: PrivateKey } {
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.SignatureMalformed;
    return .{
        .public = PublicKey.ed25519FromBytes(key_id, kp.public_key.toBytes()),
        .private = PrivateKey.ed25519FromBytes(key_id, kp.secret_key.toBytes()),
    };
}

// ──────────────────────────────────────────────────────────────────────
// PEM serialization
// ──────────────────────────────────────────────────────────────────────

const ed25519_pem_header = "-----BEGIN PUBLIC KEY-----\n";
const ed25519_pem_footer = "\n-----END PUBLIC KEY-----";

pub const PemError = error{
    BufferTooSmall,
    InvalidPem,
    InvalidBase64,
    InvalidDerLength,
    InvalidSpkiPrefix,
    Unsupported,
};

/// Serialize an Ed25519 public key into PEM form, written to `out`.
/// Returns the number of bytes written. `out` must be at least
/// `max_pem_bytes`.
pub fn writeEd25519PublicPem(pk: [32]u8, out: []u8) PemError!usize {
    var der: [ed25519_spki_der_len]u8 = undefined;
    @memcpy(der[0..12], &ed25519_spki_prefix);
    @memcpy(der[12..], &pk);

    var b64_buf: [base64.Encoder.calcSize(ed25519_spki_der_len)]u8 = undefined;
    const b64 = base64.Encoder.encode(&b64_buf, &der);

    const total = ed25519_pem_header.len + b64.len + ed25519_pem_footer.len;
    if (out.len < total) return error.BufferTooSmall;

    var pos: usize = 0;
    @memcpy(out[pos .. pos + ed25519_pem_header.len], ed25519_pem_header);
    pos += ed25519_pem_header.len;
    @memcpy(out[pos .. pos + b64.len], b64);
    pos += b64.len;
    @memcpy(out[pos .. pos + ed25519_pem_footer.len], ed25519_pem_footer);
    pos += ed25519_pem_footer.len;
    return pos;
}

/// Parse a PEM-encoded SPKI public key blob. Detects Ed25519 by SPKI OID;
/// RSA blobs are returned as raw SPKI bytes (DER decoded only).
pub fn parsePublicKeyPem(pem: []const u8, key_id: KeyId) PemError!PublicKey {
    // Locate header / footer markers without recursion.
    const header_marker = "-----BEGIN PUBLIC KEY-----";
    const footer_marker = "-----END PUBLIC KEY-----";
    const header_start = std.mem.indexOf(u8, pem, header_marker) orelse return error.InvalidPem;
    const header_end = header_start + header_marker.len;
    const footer_start = std.mem.indexOf(u8, pem[header_end..], footer_marker) orelse return error.InvalidPem;
    const b64_region = pem[header_end .. header_end + footer_start];

    // Strip whitespace into a stack buffer (bounded).
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
    if (der_len == 0 or der_len > max_rsa_spki_bytes) return error.InvalidDerLength;

    var der: [max_rsa_spki_bytes]u8 = undefined;
    base64.Decoder.decode(der[0..der_len], stripped[0..s_len]) catch return error.InvalidBase64;

    // Ed25519 SPKI is exactly 44 bytes with our prefix.
    if (der_len == ed25519_spki_der_len and std.mem.eql(u8, der[0..12], &ed25519_spki_prefix)) {
        var pk: [32]u8 = undefined;
        @memcpy(&pk, der[12..44]);
        return PublicKey.ed25519FromBytes(key_id, pk);
    }

    // Otherwise treat as RSA SPKI blob (host verify hook parses).
    var out: PublicKey = .{ .algo = .rsa_sha256, .key_id = key_id };
    @memcpy(out.bytes[0..der_len], der[0..der_len]);
    out.rsa_len = der_len;
    return out;
}

// ──────────────────────────────────────────────────────────────────────
// RSA verify hook (host-injected, BoringSSL in real builds)
// ──────────────────────────────────────────────────────────────────────

/// Signature verifier for RSA-SHA256 (PKCS1 v1_5). Returns true on a
/// valid signature. The host wires this at boot; null until then.
pub const RsaVerifyFn = *const fn (
    spki_der: []const u8,
    message: []const u8,
    signature: []const u8,
) bool;

var rsa_verify_hook: ?RsaVerifyFn = null;

pub fn setRsaVerifyHook(hook: ?RsaVerifyFn) void {
    rsa_verify_hook = hook;
}

pub fn rsaVerify(spki: []const u8, message: []const u8, sig: []const u8) bool {
    if (rsa_verify_hook) |h| return h(spki, message, sig);
    return false; // host did not wire BoringSSL: refuse
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

pub fn testSeed(salt: u8) [Ed25519.KeyPair.seed_length]u8 {
    var s: [Ed25519.KeyPair.seed_length]u8 = undefined;
    var i: usize = 0;
    while (i < s.len) : (i += 1) s[i] = @intCast((i +% salt) & 0xff);
    return s;
}

test "KeyId round-trips a typical actor URL" {
    const kid = try KeyId.fromSlice("https://example.com/users/alice#main-key");
    try std.testing.expectEqualStrings("https://example.com/users/alice#main-key", kid.slice());
}

test "KeyId rejects empty and oversize" {
    try std.testing.expectError(error.SignatureMalformed, KeyId.fromSlice(""));
    var big: [max_key_id_bytes + 1]u8 = undefined;
    @memset(&big, 'a');
    try std.testing.expectError(error.SignatureMalformed, KeyId.fromSlice(&big));
}

test "Ed25519 PEM round-trip via parsePublicKeyPem" {
    const kid = try KeyId.fromSlice("https://example.com/users/bob#main-key");
    const pair = try generateEd25519FromSeed(kid, testSeed(1));
    var pem_buf: [max_pem_bytes]u8 = undefined;
    const n = try writeEd25519PublicPem(pair.public.ed25519Bytes(), &pem_buf);
    try std.testing.expect(n > 50);

    const parsed = try parsePublicKeyPem(pem_buf[0..n], kid);
    try std.testing.expect(parsed.algo == .ed25519);
    try std.testing.expectEqualSlices(u8, &pair.public.ed25519Bytes(), &parsed.ed25519Bytes());
}

test "parsePublicKeyPem tolerates surrounding whitespace and CRLF" {
    const kid = try KeyId.fromSlice("kid");
    const pair = try generateEd25519FromSeed(kid, testSeed(1));
    var pem_buf: [max_pem_bytes]u8 = undefined;
    const n = try writeEd25519PublicPem(pair.public.ed25519Bytes(), &pem_buf);

    // Splice in CR characters and a trailing space; should still parse.
    var noisy: [max_pem_bytes]u8 = undefined;
    var w: usize = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        noisy[w] = pem_buf[i];
        w += 1;
        if (pem_buf[i] == '\n' and w + 1 < noisy.len) {
            noisy[w] = '\r';
            w += 1;
        }
    }
    const parsed = try parsePublicKeyPem(noisy[0..w], kid);
    try std.testing.expect(parsed.algo == .ed25519);
}

test "parsePublicKeyPem returns rsa for foreign SPKI" {
    // Synthesize a fake-but-DER-shaped SPKI blob: a SEQUENCE wrapper.
    // We only need parsePublicKeyPem to *not* misclassify it as ed25519
    // and to roundtrip the bytes intact.
    var der: [64]u8 = undefined;
    @memset(&der, 0xAB);
    der[0] = 0x30; // SEQUENCE
    der[1] = 0x3e; // length 62
    // Build PEM by hand.
    var b64_buf: [base64.Encoder.calcSize(64)]u8 = undefined;
    const b64 = base64.Encoder.encode(&b64_buf, &der);
    var pem_buf: [max_pem_bytes]u8 = undefined;
    var pos: usize = 0;
    @memcpy(pem_buf[pos .. pos + ed25519_pem_header.len], ed25519_pem_header);
    pos += ed25519_pem_header.len;
    @memcpy(pem_buf[pos .. pos + b64.len], b64);
    pos += b64.len;
    @memcpy(pem_buf[pos .. pos + ed25519_pem_footer.len], ed25519_pem_footer);
    pos += ed25519_pem_footer.len;

    const kid = try KeyId.fromSlice("kid");
    const parsed = try parsePublicKeyPem(pem_buf[0..pos], kid);
    try std.testing.expect(parsed.algo == .rsa_sha256);
    try std.testing.expectEqualSlices(u8, der[0..64], parsed.rsaSpki());
}

test "rsaVerify refuses when no hook is wired" {
    setRsaVerifyHook(null);
    try std.testing.expect(!rsaVerify("spki", "msg", "sig"));
}

test "rsaVerify dispatches to the installed hook" {
    const H = struct {
        fn yes(_: []const u8, _: []const u8, _: []const u8) bool {
            return true;
        }
    };
    setRsaVerifyHook(H.yes);
    defer setRsaVerifyHook(null);
    try std.testing.expect(rsaVerify("spki", "msg", "sig"));
}
