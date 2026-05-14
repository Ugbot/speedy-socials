//! Ed25519 + secp256k1 keypair primitives for AT Protocol.
//!
//! AT Protocol production accounts use secp256k1 (ES256K) or P-256
//! (ES256). Bridging deployments (e.g. speedy-socials as an AP↔AT relay)
//! sign their *own* identity with Ed25519, which is the only curve the
//! stdlib gives us for "edd25519" did:key types.
//!
//! Status:
//!   * Ed25519: implemented via `std.crypto.sign.Ed25519`.
//!   * secp256k1: stdlib has `EcdsaSecp256k1Sha256` but the AT Protocol
//!     spec also requires low-S normalization. We expose a stub that
//!     returns `error.NotImplemented` for sign/verify until the
//!     normalization helper from the absorbed `lib/zat/.../jwt.zig`
//!     is rewritten Tiger Style in a later phase.
//!
//! Multibase `did:key:` round-trip is implemented for Ed25519 only
//! (multicodec 0xed). secp256k1 (0xe7) accepts/encodes raw bytes but
//! signing remains a stub.

const std = @import("std");
const core = @import("core");
const AtpError = core.errors.AtpError;
const assertLe = core.assert.assertLe;

pub const KeyAlg = enum { ed25519, secp256k1 };

pub const ed25519_public_len: usize = 32;
pub const ed25519_secret_len: usize = 64; // stdlib stores seed+pk
pub const ed25519_signature_len: usize = 64;
pub const secp256k1_pubkey_compressed_len: usize = 33;

// Multicodec varint prefixes.
const ed25519_multicodec: [2]u8 = .{ 0xed, 0x01 };
const secp256k1_multicodec: [2]u8 = .{ 0xe7, 0x01 };

// did:key: prefix string.
const did_key_prefix = "did:key:";

// Maximum did:key string we will accept (well above worst-case length).
pub const max_did_key_bytes: usize = 128;

// ── Ed25519 ────────────────────────────────────────────────────────

pub const Ed25519KeyPair = struct {
    public_key: [ed25519_public_len]u8,
    secret_key: [ed25519_secret_len]u8,

    /// Generate a new keypair from a 32-byte seed.
    pub fn fromSeed(seed: [32]u8) Ed25519KeyPair {
        const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
        return .{
            .public_key = kp.public_key.bytes,
            .secret_key = kp.secret_key.bytes,
        };
    }

    pub fn sign(self: Ed25519KeyPair, message: []const u8) [ed25519_signature_len]u8 {
        const sk = std.crypto.sign.Ed25519.SecretKey.fromBytes(self.secret_key) catch unreachable;
        const kp = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(sk) catch unreachable;
        const sig = kp.sign(message, null) catch unreachable;
        return sig.toBytes();
    }
};

pub fn verifyEd25519(message: []const u8, signature: [ed25519_signature_len]u8, public_key: [ed25519_public_len]u8) bool {
    const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature);
    sig.verify(message, pk) catch return false;
    return true;
}

// ── secp256k1 (stub) ───────────────────────────────────────────────

/// Sign + verify with secp256k1 require deterministic ECDSA + low-S
/// normalization to be spec-compliant. Until those land Tiger Style in
/// `core/crypto/`, we surface a typed error.
pub fn signSecp256k1(_: []const u8, _: [32]u8) AtpError![64]u8 {
    return error.NotImplemented;
}

pub fn verifySecp256k1(_: []const u8, _: [64]u8, _: [secp256k1_pubkey_compressed_len]u8) AtpError!bool {
    return error.NotImplemented;
}

// ── did:key encoding (Ed25519 + secp256k1 raw) ─────────────────────

/// Build a `did:key:z…` string for an Ed25519 public key. Writes into
/// `out`; returns the slice written.
pub fn formatDidKeyEd25519(public_key: [ed25519_public_len]u8, out: []u8) AtpError![]const u8 {
    var mc: [ed25519_public_len + 2]u8 = undefined;
    mc[0] = ed25519_multicodec[0];
    mc[1] = ed25519_multicodec[1];
    @memcpy(mc[2..], &public_key);
    return formatDidKeyFromMulticodec(&mc, out);
}

pub fn formatDidKeySecp256k1(compressed: [secp256k1_pubkey_compressed_len]u8, out: []u8) AtpError![]const u8 {
    var mc: [secp256k1_pubkey_compressed_len + 2]u8 = undefined;
    mc[0] = secp256k1_multicodec[0];
    mc[1] = secp256k1_multicodec[1];
    @memcpy(mc[2..], &compressed);
    return formatDidKeyFromMulticodec(&mc, out);
}

/// Parsed did:key: yields the algorithm and a borrowed view over the
/// decoded raw public-key bytes inside `scratch`.
pub const ParsedDidKey = struct {
    alg: KeyAlg,
    /// View into the scratch buffer passed to `parseDidKey`.
    public_key: []const u8,
};

/// Parse a `did:key:z…` string. `scratch` holds the decoded multicodec
/// bytes — the returned `public_key` slice points into it.
pub fn parseDidKey(s: []const u8, scratch: []u8) AtpError!ParsedDidKey {
    if (s.len < did_key_prefix.len + 2) return error.BadMultibase;
    if (!std.mem.startsWith(u8, s, did_key_prefix)) return error.BadMultibase;
    const mb = s[did_key_prefix.len..];
    if (mb[0] != 'z') return error.BadMultibase;

    const n = try base58btcDecode(mb[1..], scratch);
    if (n < 2) return error.BadMulticodec;
    const decoded = scratch[0..n];

    if (decoded[0] == ed25519_multicodec[0] and decoded[1] == ed25519_multicodec[1]) {
        if (decoded.len != 2 + ed25519_public_len) return error.BadMulticodec;
        return .{ .alg = .ed25519, .public_key = decoded[2..] };
    }
    if (decoded[0] == secp256k1_multicodec[0] and decoded[1] == secp256k1_multicodec[1]) {
        if (decoded.len != 2 + secp256k1_pubkey_compressed_len) return error.BadMulticodec;
        return .{ .alg = .secp256k1, .public_key = decoded[2..] };
    }
    return error.BadMulticodec;
}

fn formatDidKeyFromMulticodec(mc: []const u8, out: []u8) AtpError![]const u8 {
    // worst-case base58btc expansion: ceil(n * log(256) / log(58)) ≈ 1.4 * n
    // For ed25519 (34 bytes) the encoded length is 47; we add the
    // `did:key:z` prefix (9 bytes) for a 56-byte total. Pre-flight by
    // sizing a stack scratch.
    var b58: [128]u8 = undefined;
    const written = try base58btcEncode(mc, &b58);
    const total = did_key_prefix.len + 1 + written;
    if (out.len < total) return error.BufferTooSmall;
    @memcpy(out[0..did_key_prefix.len], did_key_prefix);
    out[did_key_prefix.len] = 'z';
    @memcpy(out[did_key_prefix.len + 1 ..][0..written], b58[0..written]);
    assertLe(total, out.len);
    return out[0..total];
}

// ── base58btc (allocator-free, bounded) ────────────────────────────

const b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58_decode_table: [256]i8 = blk: {
    var t: [256]i8 = .{-1} ** 256;
    for (b58_alphabet, 0..) |c, i| t[c] = @intCast(i);
    break :blk t;
};

/// Encode bytes to base58 (no multibase prefix). `dst.len` must hold the
/// worst-case output (≈ ceil(src.len * 138 / 100) + 1). Returns bytes
/// written.
fn base58btcEncode(src: []const u8, dst: []u8) AtpError!usize {
    // Buffer-of-base-58-digits, built as we divide. We process via
    // repeated multiply-and-add over `dst` interpreted as a big-endian
    // base-58 accumulator. Pure integer arithmetic, no allocator.
    var size: usize = 0;
    @memset(dst, 0);

    // Skip & count leading zeros — encoded as leading '1'.
    var leading_zeros: usize = 0;
    var i: usize = 0;
    while (i < src.len and src[i] == 0) : (i += 1) leading_zeros += 1;

    var j: usize = leading_zeros;
    while (j < src.len) : (j += 1) {
        assertLe(j, src.len);
        var carry: u32 = src[j];
        var k: usize = 0;
        // Walk current digits, applying carry.
        while (k < size or carry != 0) : (k += 1) {
            if (k >= dst.len) return error.BufferTooSmall;
            const idx = dst.len - 1 - k;
            carry += @as(u32, dst[idx]) * 256;
            dst[idx] = @as(u8, @intCast(carry % 58));
            carry /= 58;
        }
        size = k;
    }

    // Total length = leading zeros + significant digits.
    const total = leading_zeros + size;
    if (total > dst.len) return error.BufferTooSmall;
    // Shift result to front, translating each digit to alphabet.
    // dst currently contains, in the *rightmost* `size` bytes, the
    // significant base-58 digits.
    var out_idx: usize = 0;
    var z: usize = 0;
    while (z < leading_zeros) : (z += 1) {
        dst[out_idx] = '1';
        out_idx += 1;
    }
    var d: usize = 0;
    while (d < size) : (d += 1) {
        const idx = dst.len - size + d;
        dst[out_idx] = b58_alphabet[dst[idx]];
        out_idx += 1;
    }
    // Zero the tail (purely tidy — callers honor the returned length).
    var tail: usize = out_idx;
    while (tail < dst.len) : (tail += 1) dst[tail] = 0;
    return out_idx;
}

/// Decode base58btc into `dst`. Returns bytes written.
fn base58btcDecode(src: []const u8, dst: []u8) AtpError!usize {
    if (src.len == 0) return 0;

    // Count leading '1' (-> leading 0 bytes).
    var leading_zeros: usize = 0;
    var i: usize = 0;
    while (i < src.len and src[i] == '1') : (i += 1) leading_zeros += 1;

    // Big-endian accumulator built in `dst[1..]`, growing toward index 0.
    @memset(dst, 0);
    var size: usize = 0;
    while (i < src.len) : (i += 1) {
        assertLe(i, src.len);
        const c = src[i];
        const v = b58_decode_table[c];
        if (v < 0) return error.BadMultibase;
        var carry: u32 = @intCast(v);
        var k: usize = 0;
        while (k < size or carry != 0) : (k += 1) {
            if (k >= dst.len) return error.BufferTooSmall;
            const idx = dst.len - 1 - k;
            carry += @as(u32, dst[idx]) * 58;
            dst[idx] = @as(u8, @intCast(carry & 0xff));
            carry >>= 8;
        }
        size = k;
    }
    const total = leading_zeros + size;
    if (total > dst.len) return error.BufferTooSmall;
    // Shift significant bytes into prefix.
    var out_idx: usize = 0;
    var z: usize = 0;
    while (z < leading_zeros) : (z += 1) {
        dst[out_idx] = 0;
        out_idx += 1;
    }
    var d: usize = 0;
    while (d < size) : (d += 1) {
        const idx = dst.len - size + d;
        dst[out_idx] = dst[idx];
        out_idx += 1;
    }
    // Zero the tail beyond the answer.
    var tail: usize = out_idx;
    while (tail < dst.len) : (tail += 1) dst[tail] = 0;
    return out_idx;
}

// ── Tests ──────────────────────────────────────────────────────────

test "ed25519: deterministic seed + sign + verify" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = Ed25519KeyPair.fromSeed(seed);
    const msg = "hello speedy";
    const sig = kp.sign(msg);
    try std.testing.expect(verifyEd25519(msg, sig, kp.public_key));
    // tampered message fails
    try std.testing.expect(!verifyEd25519("hello speedY", sig, kp.public_key));
}

test "ed25519: different seeds → different public keys" {
    var s1: [32]u8 = undefined;
    var s2: [32]u8 = undefined;
    @memset(&s1, 0x11);
    @memset(&s2, 0x22);
    const a = Ed25519KeyPair.fromSeed(s1);
    const b = Ed25519KeyPair.fromSeed(s2);
    try std.testing.expect(!std.mem.eql(u8, &a.public_key, &b.public_key));
}

test "did:key: format + parse roundtrip (ed25519)" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x37);
    const kp = Ed25519KeyPair.fromSeed(seed);

    var out: [max_did_key_bytes]u8 = undefined;
    const did = try formatDidKeyEd25519(kp.public_key, &out);
    try std.testing.expect(std.mem.startsWith(u8, did, "did:key:z"));

    var scratch: [128]u8 = undefined;
    const parsed = try parseDidKey(did, &scratch);
    try std.testing.expectEqual(KeyAlg.ed25519, parsed.alg);
    try std.testing.expectEqualSlices(u8, kp.public_key[0..], parsed.public_key);
}

test "did:key: secp256k1 raw bytes roundtrip" {
    var pub_compressed: [secp256k1_pubkey_compressed_len]u8 = undefined;
    pub_compressed[0] = 0x02;
    var i: usize = 1;
    while (i < secp256k1_pubkey_compressed_len) : (i += 1) pub_compressed[i] = @intCast(i);

    var out: [max_did_key_bytes]u8 = undefined;
    const did = try formatDidKeySecp256k1(pub_compressed, &out);

    var scratch: [128]u8 = undefined;
    const parsed = try parseDidKey(did, &scratch);
    try std.testing.expectEqual(KeyAlg.secp256k1, parsed.alg);
    try std.testing.expectEqualSlices(u8, pub_compressed[0..], parsed.public_key);
}

test "secp256k1: sign+verify stubs return NotImplemented" {
    var sk: [32]u8 = undefined;
    @memset(&sk, 1);
    try std.testing.expectError(error.NotImplemented, signSecp256k1("x", sk));

    var pk: [secp256k1_pubkey_compressed_len]u8 = undefined;
    var sig: [64]u8 = undefined;
    @memset(&pk, 0);
    @memset(&sig, 0);
    try std.testing.expectError(error.NotImplemented, verifySecp256k1("x", sig, pk));
}

test "did:key: parseDidKey rejects malformed prefix" {
    var scratch: [64]u8 = undefined;
    try std.testing.expectError(error.BadMultibase, parseDidKey("did:web:example.com", &scratch));
    try std.testing.expectError(error.BadMultibase, parseDidKey("did:key:Aabc", &scratch));
}
