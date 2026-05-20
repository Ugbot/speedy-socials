//! P-256 (NIST secp256r1) ECDSA-SHA256 sign + verify, with low-S
//! normalization.
//!
//! AT Protocol accepts P-256 keys (multicodec 0x1200) alongside
//! secp256k1 (0xe7) and Ed25519 (0xed) for DPoP proofs (ES256) and
//! for `did:key:zDn…` actors. This module mirrors the shape of
//! `core/crypto/secp256k1.zig`.
//!
//! Implementation: layer on `std.crypto.sign.ecdsa.EcdsaP256Sha256`.
//! Stdlib already deterministically signs (RFC 6979). We add the
//! low-S check on emit + verify to match the AT spec's malleability
//! resistance requirement.
//!
//! Tiger Style: no allocator, bounded buffers, no recursion.

const std = @import("std");
const E = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const secret_length: usize = E.SecretKey.encoded_length; // 32
pub const public_compressed_length: usize = E.PublicKey.compressed_sec1_encoded_length; // 33
pub const signature_length: usize = E.Signature.encoded_length; // 64

pub const Error = error{
    BadSecretKey,
    BadPublicKey,
    BadSignature,
    NonLowS,
    VerifyFailed,
};

/// NIST P-256 group order n.
const order_be: [32]u8 = .{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
};

const half_order_be: [32]u8 = blk: {
    @setEvalBranchQuota(10_000);
    var out: [32]u8 = order_be;
    var carry: u8 = 0;
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        const cur: u16 = (@as(u16, carry) << 8) | @as(u16, out[i]);
        out[i] = @intCast(cur >> 1);
        carry = @intCast(cur & 1);
    }
    break :blk out;
};

fn cmpBe32(a: []const u8, b: []const u8) i32 {
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

fn negate(s: []u8) void {
    var borrow: i16 = 0;
    var i: usize = s.len;
    while (i > 0) : (i -= 1) {
        const idx = i - 1;
        const lhs: i16 = @as(i16, order_be[idx]);
        const rhs: i16 = @as(i16, s[idx]) + borrow;
        var diff: i16 = lhs - rhs;
        if (diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        s[idx] = @intCast(diff);
    }
}

/// Sign `message` using a P-256 secret key. Output is the canonical
/// `r || s` form with `s` in low-S form.
pub fn sign(message: []const u8, secret_key: [secret_length]u8) Error![signature_length]u8 {
    const sk = E.SecretKey.fromBytes(secret_key) catch return error.BadSecretKey;
    const kp = E.KeyPair.fromSecretKey(sk) catch return error.BadSecretKey;
    const sig = kp.sign(message, null) catch return error.BadSignature;
    var out: [signature_length]u8 = sig.toBytes();
    // Normalise low-S.
    if (cmpBe32(out[32..64], &half_order_be) > 0) {
        negate(out[32..64]);
    }
    return out;
}

/// Verify a P-256 signature; rejects high-S form.
pub fn verify(message: []const u8, signature: [signature_length]u8, public_key: [public_compressed_length]u8) Error!void {
    if (cmpBe32(signature[32..64], &half_order_be) > 0) return error.NonLowS;
    const pk = E.PublicKey.fromSec1(&public_key) catch return error.BadPublicKey;
    const sig = E.Signature.fromBytes(signature);
    sig.verify(message, pk) catch return error.VerifyFailed;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "AT-25: P-256 round-trip sign + verify" {
    var seed: [secret_length]u8 = .{0} ** secret_length;
    seed[31] = 1; // non-zero scalar
    const sk = try E.SecretKey.fromBytes(seed);
    const kp = try E.KeyPair.fromSecretKey(sk);
    const pk_compressed = kp.public_key.toCompressedSec1();

    const sig_bytes = try sign("hello p256", seed);
    try verify("hello p256", sig_bytes, pk_compressed);
}

test "AT-25: P-256 verify rejects high-S signature" {
    var seed: [secret_length]u8 = .{0} ** secret_length;
    seed[31] = 1;
    const sk = try E.SecretKey.fromBytes(seed);
    const kp = try E.KeyPair.fromSecretKey(sk);
    const pk = kp.public_key.toCompressedSec1();

    var sig_bytes = try sign("hello", seed);
    // Force high-S by negating it.
    negate(sig_bytes[32..64]);
    try testing.expectError(error.NonLowS, verify("hello", sig_bytes, pk));
}

test "AT-25: P-256 verify rejects bad signature" {
    var seed: [secret_length]u8 = .{0} ** secret_length;
    seed[31] = 1;
    const sk = try E.SecretKey.fromBytes(seed);
    const kp = try E.KeyPair.fromSecretKey(sk);
    const pk = kp.public_key.toCompressedSec1();

    var sig_bytes = try sign("hello", seed);
    sig_bytes[0] ^= 0xff;
    // Could fail with NonLowS (if flipping pushed it above half-order)
    // or with VerifyFailed — both are correct.
    const r = verify("hello", sig_bytes, pk);
    try testing.expect(std.meta.isError(r));
}
