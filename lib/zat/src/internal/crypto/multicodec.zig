//! multicodec key parsing
//!
//! parses multicodec-prefixed public keys from DID documents.
//! extracts key type and raw key bytes.
//!
//! see: https://github.com/multiformats/multicodec

const std = @import("std");

/// supported key types for AT Protocol
pub const KeyType = enum {
    secp256k1, // ES256K - used by most AT Protocol accounts
    p256, // ES256 - also supported
};

/// parsed public key with type and raw bytes
pub const PublicKey = struct {
    key_type: KeyType,
    /// raw compressed public key (33 bytes for secp256k1/p256)
    raw: []const u8,
};

/// multicodec prefixes (unsigned varint encoding)
/// secp256k1-pub: 0xe7 = 231, varint encoded as 0xe7 0x01 (2 bytes)
/// p256-pub: 0x1200 = 4608, varint encoded as 0x80 0x24 (2 bytes)
/// parse a multicodec-prefixed public key
/// returns the key type and a slice pointing to the raw key bytes
pub fn parsePublicKey(data: []const u8) !PublicKey {
    if (data.len < 2) return error.TooShort;

    // check for secp256k1-pub (varint 0xe7 = 231 encoded as 0xe7 0x01)
    if (data.len >= 2 and data[0] == 0xe7 and data[1] == 0x01) {
        const raw = data[2..];
        if (raw.len != 33) return error.InvalidKeyLength;
        return .{
            .key_type = .secp256k1,
            .raw = raw,
        };
    }

    // check for p256-pub (varint 0x1200 = 4608 encoded as 0x80 0x24)
    if (data.len >= 2 and data[0] == 0x80 and data[1] == 0x24) {
        const raw = data[2..];
        if (raw.len != 33) return error.InvalidKeyLength;
        return .{
            .key_type = .p256,
            .raw = raw,
        };
    }

    return error.UnsupportedKeyType;
}

/// encode a raw public key with multicodec prefix
pub fn encodePublicKey(allocator: std.mem.Allocator, key_type: KeyType, raw: []const u8) ![]u8 {
    if (raw.len != 33) return error.InvalidKeyLength;

    const result = try allocator.alloc(u8, 2 + raw.len);
    switch (key_type) {
        .secp256k1 => {
            result[0] = 0xe7;
            result[1] = 0x01;
        },
        .p256 => {
            result[0] = 0x80;
            result[1] = 0x24;
        },
    }
    @memcpy(result[2..], raw);
    return result;
}

/// format a raw public key as a did:key string
pub fn formatDidKey(allocator: std.mem.Allocator, key_type: KeyType, raw: []const u8) ![]u8 {
    const multibase = @import("multibase.zig");

    const mc_bytes = try encodePublicKey(allocator, key_type, raw);
    defer allocator.free(mc_bytes);

    const multibase_str = try multibase.encode(allocator, .base58btc, mc_bytes);
    defer allocator.free(multibase_str);

    // "did:key:" + multibase string (which already has 'z' prefix)
    const result = try allocator.alloc(u8, did_key_prefix.len + multibase_str.len);
    @memcpy(result[0..did_key_prefix.len], did_key_prefix);
    @memcpy(result[did_key_prefix.len..], multibase_str);
    return result;
}

const did_key_prefix = "did:key:";

/// parse a did:key string into key type and raw public key bytes.
/// caller owns the returned slice (raw field).
pub fn parseDidKey(allocator: std.mem.Allocator, did: []const u8) !struct { key_type: KeyType, raw: []u8 } {
    const multibase = @import("multibase.zig");

    if (!std.mem.startsWith(u8, did, did_key_prefix)) return error.InvalidDidKey;
    const multibase_str = did[did_key_prefix.len..];
    if (multibase_str.len == 0) return error.InvalidDidKey;

    const mc_bytes = try multibase.decode(allocator, multibase_str);
    defer allocator.free(mc_bytes);

    const parsed = try parsePublicKey(mc_bytes);
    const raw = try allocator.dupe(u8, parsed.raw);
    return .{ .key_type = parsed.key_type, .raw = raw };
}

/// verify an ECDSA signature given a did:key string.
/// dispatches to the correct curve based on the key type encoded in the did:key.
pub fn verifyDidKeySignature(allocator: std.mem.Allocator, did: []const u8, message: []const u8, sig_bytes: []const u8) !void {
    const jwt = @import("jwt.zig");

    const parsed = try parseDidKey(allocator, did);
    defer allocator.free(parsed.raw);

    switch (parsed.key_type) {
        .secp256k1 => try jwt.verifySecp256k1(message, sig_bytes, parsed.raw),
        .p256 => try jwt.verifyP256(message, sig_bytes, parsed.raw),
    }
}

// === tests ===

test "parse secp256k1 key" {
    // 0xe7 0x01 prefix (varint) + 33-byte compressed key
    var data: [35]u8 = undefined;
    data[0] = 0xe7;
    data[1] = 0x01;
    data[2] = 0x02; // compressed point prefix
    @memset(data[3..], 0xaa);

    const key = try parsePublicKey(&data);
    try std.testing.expectEqual(KeyType.secp256k1, key.key_type);
    try std.testing.expectEqual(@as(usize, 33), key.raw.len);
}

test "parse p256 key" {
    // 0x80 0x24 prefix + 33-byte compressed key
    var data: [35]u8 = undefined;
    data[0] = 0x80;
    data[1] = 0x24;
    data[2] = 0x03; // compressed point prefix
    @memset(data[3..], 0xbb);

    const key = try parsePublicKey(&data);
    try std.testing.expectEqual(KeyType.p256, key.key_type);
    try std.testing.expectEqual(@as(usize, 33), key.raw.len);
}

test "reject unsupported key type" {
    const data = [_]u8{ 0xff, 0x02, 0x00 };
    try std.testing.expectError(error.UnsupportedKeyType, parsePublicKey(&data));
}

test "reject too short" {
    const data = [_]u8{0xe7};
    try std.testing.expectError(error.TooShort, parsePublicKey(&data));
}

test "encode-decode round-trip secp256k1" {
    const alloc = std.testing.allocator;
    var raw: [33]u8 = undefined;
    raw[0] = 0x02;
    @memset(raw[1..], 0xaa);

    const encoded = try encodePublicKey(alloc, .secp256k1, &raw);
    defer alloc.free(encoded);

    const parsed = try parsePublicKey(encoded);
    try std.testing.expectEqual(KeyType.secp256k1, parsed.key_type);
    try std.testing.expectEqualSlices(u8, &raw, parsed.raw);
}

test "did:key round-trip secp256k1" {
    const alloc = std.testing.allocator;
    const multibase = @import("multibase.zig");

    var raw: [33]u8 = undefined;
    raw[0] = 0x02;
    @memset(raw[1..], 0xcc);

    const did_key_str = try formatDidKey(alloc, .secp256k1, &raw);
    defer alloc.free(did_key_str);

    // should start with "did:key:z"
    try std.testing.expect(std.mem.startsWith(u8, did_key_str, "did:key:z"));

    // parse back: strip "did:key:" prefix, decode multibase, parse multicodec
    const multibase_str = did_key_str["did:key:".len..];
    const mc_bytes = try multibase.decode(alloc, multibase_str);
    defer alloc.free(mc_bytes);

    const parsed = try parsePublicKey(mc_bytes);
    try std.testing.expectEqual(KeyType.secp256k1, parsed.key_type);
    try std.testing.expectEqualSlices(u8, &raw, parsed.raw);
}

test "did:key round-trip p256" {
    const alloc = std.testing.allocator;
    const multibase = @import("multibase.zig");

    var raw: [33]u8 = undefined;
    raw[0] = 0x03;
    @memset(raw[1..], 0xdd);

    const did_key_str = try formatDidKey(alloc, .p256, &raw);
    defer alloc.free(did_key_str);

    const multibase_str = did_key_str["did:key:".len..];
    const mc_bytes = try multibase.decode(alloc, multibase_str);
    defer alloc.free(mc_bytes);

    const parsed = try parsePublicKey(mc_bytes);
    try std.testing.expectEqual(KeyType.p256, parsed.key_type);
    try std.testing.expectEqualSlices(u8, &raw, parsed.raw);
}

test "parseDidKey round-trip secp256k1" {
    const alloc = std.testing.allocator;

    var raw: [33]u8 = undefined;
    raw[0] = 0x02;
    @memset(raw[1..], 0xcc);

    const did_str = try formatDidKey(alloc, .secp256k1, &raw);
    defer alloc.free(did_str);

    const parsed = try parseDidKey(alloc, did_str);
    defer alloc.free(parsed.raw);

    try std.testing.expectEqual(KeyType.secp256k1, parsed.key_type);
    try std.testing.expectEqualSlices(u8, &raw, parsed.raw);
}

test "parseDidKey round-trip p256" {
    const alloc = std.testing.allocator;

    var raw: [33]u8 = undefined;
    raw[0] = 0x03;
    @memset(raw[1..], 0xdd);

    const did_str = try formatDidKey(alloc, .p256, &raw);
    defer alloc.free(did_str);

    const parsed = try parseDidKey(alloc, did_str);
    defer alloc.free(parsed.raw);

    try std.testing.expectEqual(KeyType.p256, parsed.key_type);
    try std.testing.expectEqualSlices(u8, &raw, parsed.raw);
}

test "parseDidKey with real indigo test vector" {
    // from bluesky-social/indigo jwt test fixtures
    const alloc = std.testing.allocator;

    const parsed = try parseDidKey(alloc, "did:key:zQ3shscXNYZQZSPwegiv7uQZZV5kzATLBRtgJhs7uRY7pfSk4");
    defer alloc.free(parsed.raw);

    try std.testing.expectEqual(KeyType.secp256k1, parsed.key_type);
    try std.testing.expectEqual(@as(usize, 33), parsed.raw.len);
    try std.testing.expect(parsed.raw[0] == 0x02 or parsed.raw[0] == 0x03);
}

test "parseDidKey rejects invalid prefix" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.InvalidDidKey, parseDidKey(alloc, "did:web:example.com"));
    try std.testing.expectError(error.InvalidDidKey, parseDidKey(alloc, "did:key:"));
    try std.testing.expectError(error.InvalidDidKey, parseDidKey(alloc, ""));
}

test "verifyDidKeySignature secp256k1" {
    const alloc = std.testing.allocator;
    const jwt = @import("jwt.zig");
    const crypto = std.crypto;
    const Scheme = crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

    const sk_bytes = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    const message = "verify via did:key";
    const sig = try jwt.signSecp256k1(message, &sk_bytes);

    // derive public key and format as did:key
    const sk = try Scheme.SecretKey.fromBytes(sk_bytes);
    const kp = try Scheme.KeyPair.fromSecretKey(sk);
    const pk_bytes = kp.public_key.toCompressedSec1();
    const did = try formatDidKey(alloc, .secp256k1, &pk_bytes);
    defer alloc.free(did);

    // should verify
    try verifyDidKeySignature(alloc, did, message, &sig.bytes);

    // should reject wrong message
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        verifyDidKeySignature(alloc, did, "wrong message", &sig.bytes),
    );
}
