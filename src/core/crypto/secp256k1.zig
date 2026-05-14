//! secp256k1 ECDSA-SHA256 sign + verify, with low-S normalization.
//!
//! AT Protocol production accounts use `did:key:zQ3sh…` keys backed by
//! the secp256k1 curve (`multicodec 0xe7`). The spec requires
//! low-S normalization for malleability resistance — a signature with
//! `s > n/2` MUST be rejected (and conversely, signers MUST emit the
//! `s ≤ n/2` form).
//!
//! Implementation: layer on `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256`.
//! Stdlib already deterministically signs (RFC 6979) so all we add is
//! the low-S check on emit + verify.
//!
//! Tiger Style: no allocator, bounded buffers, no recursion.

const std = @import("std");
const E = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

pub const secret_length: usize = E.SecretKey.encoded_length;        // 32
pub const public_compressed_length: usize = E.PublicKey.compressed_sec1_encoded_length; // 33
pub const signature_length: usize = E.Signature.encoded_length;     // 64 (r || s)

pub const Error = error{
    /// Secret key is invalid (zero / out-of-range).
    BadSecretKey,
    /// Public key bytes did not parse.
    BadPublicKey,
    /// Signature could not be deserialized.
    BadSignature,
    /// Signature has high-S form — must be normalized.
    NonLowS,
    /// Cryptographic verification failed.
    VerifyFailed,
};

/// secp256k1 group order n. Constant from SEC 2.
const order_be: [32]u8 = .{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
};

/// n / 2, computed once at comptime.
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

/// Compare two big-endian unsigned 32-byte integers. Returns -1 / 0 / 1.
fn cmpBe32(a: []const u8, b: []const u8) i32 {
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

/// Compute n - s (big-endian) into `out`. Caller guarantees s < n.
fn subFromOrder(s: []const u8, out: []u8) void {
    std.debug.assert(s.len == 32);
    std.debug.assert(out.len == 32);
    var borrow: i32 = 0;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        const diff: i32 = @as(i32, order_be[i]) - @as(i32, s[i]) - borrow;
        if (diff < 0) {
            out[i] = @intCast(diff + 256);
            borrow = 1;
        } else {
            out[i] = @intCast(diff);
            borrow = 0;
        }
    }
}

/// True if `s` (32 bytes, big-endian) is in the low half of the group
/// order — i.e. `s ≤ n/2`.
pub fn isLowS(s: []const u8) bool {
    return cmpBe32(s, &half_order_be) <= 0;
}

/// Normalize a 64-byte (r || s) signature to low-S form, in place.
pub fn normalizeLowS(sig: *[signature_length]u8) void {
    const s_slice = sig[32..64];
    if (isLowS(s_slice)) return;
    var new_s: [32]u8 = undefined;
    subFromOrder(s_slice, &new_s);
    @memcpy(s_slice, &new_s);
}

/// Sign `message` with a 32-byte secret key. Output is 64 bytes
/// (r || s) in low-S canonical form.
pub fn sign(message: []const u8, secret_key: [secret_length]u8) Error![signature_length]u8 {
    const sk = E.SecretKey.fromBytes(secret_key) catch return error.BadSecretKey;
    const kp = E.KeyPair.fromSecretKey(sk) catch return error.BadSecretKey;
    const s = kp.sign(message, null) catch return error.BadSecretKey;
    var out = s.toBytes();
    normalizeLowS(&out);
    return out;
}

/// Derive a compressed-SEC1 public key from a secret key.
pub fn derivePublic(secret_key: [secret_length]u8) Error![public_compressed_length]u8 {
    const sk = E.SecretKey.fromBytes(secret_key) catch return error.BadSecretKey;
    const kp = E.KeyPair.fromSecretKey(sk) catch return error.BadSecretKey;
    return kp.public_key.toCompressedSec1();
}

/// Verify a 64-byte ECDSA signature over `message` against a
/// compressed-SEC1 public key. Rejects high-S signatures.
pub fn verify(
    message: []const u8,
    signature: [signature_length]u8,
    public_key: [public_compressed_length]u8,
) Error!void {
    if (!isLowS(signature[32..])) return error.NonLowS;
    const pk = E.PublicKey.fromSec1(&public_key) catch return error.BadPublicKey;
    const sig = E.Signature.fromBytes(signature);
    sig.verify(message, pk) catch return error.VerifyFailed;
}

// ── Tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "secp256k1: half-order constant is below n" {
    try testing.expectEqual(@as(i32, -1), cmpBe32(&half_order_be, &order_be));
}

test "secp256k1: deterministic sign + verify" {
    var sk: [secret_length]u8 = undefined;
    @memset(&sk, 0x42);
    sk[0] = 0; // ensure < n
    const pk = try derivePublic(sk);
    const msg = "hello bsky";
    const sig = try sign(msg, sk);
    try verify(msg, sig, pk);
    // Tampered message rejected.
    try testing.expectError(error.VerifyFailed, verify("hellO bsky", sig, pk));
}

test "secp256k1: signatures are emitted in low-S form" {
    var sk: [secret_length]u8 = undefined;
    @memset(&sk, 0x13);
    sk[0] = 0;
    var i: u32 = 0;
    // Sign 12 different messages and verify every emitted signature is
    // low-S.
    while (i < 12) : (i += 1) {
        var msg_buf: [16]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "msg-{d}", .{i}) catch unreachable;
        const s = try sign(msg, sk);
        try testing.expect(isLowS(s[32..]));
    }
}

test "secp256k1: verify rejects manually-mauled high-S form" {
    var sk: [secret_length]u8 = undefined;
    @memset(&sk, 0x77);
    sk[0] = 0;
    const pk = try derivePublic(sk);
    const msg = "speedy";
    var s = try sign(msg, sk);
    // Flip s -> n - s. This produces a still-mathematically-valid ECDSA
    // signature but in high-S form (assuming the original was low-S,
    // which our sign() guarantees).
    var new_s: [32]u8 = undefined;
    subFromOrder(s[32..64], &new_s);
    @memcpy(s[32..64], &new_s);
    try testing.expectError(error.NonLowS, verify(msg, s, pk));
}

test "secp256k1: verify rejects bad public key bytes" {
    const msg = "x";
    var sig: [signature_length]u8 = undefined;
    @memset(&sig, 0);
    var bad_pk: [public_compressed_length]u8 = undefined;
    @memset(&bad_pk, 0); // 0x00 prefix is not a valid SEC1 marker
    try testing.expectError(error.BadPublicKey, verify(msg, sig, bad_pk));
}
