//! keypair abstraction for AT Protocol cryptography
//!
//! unified keypair type for secp256k1 (ES256K) and P-256 (ES256).
//! handles signing with low-S normalization, public key derivation,
//! and did:key formatting.
//!
//! see: https://atproto.com/specs/cryptography

const std = @import("std");
const crypto = std.crypto;
const multicodec = @import("multicodec.zig");
const jwt = @import("jwt.zig");

pub const Keypair = struct {
    key_type: multicodec.KeyType,
    secret_key: [32]u8,

    /// create a keypair from raw secret key bytes (32 bytes).
    /// validates the key is on the curve.
    pub fn fromSecretKey(key_type: multicodec.KeyType, secret_key: [32]u8) !Keypair {
        // zero is not a valid scalar for any curve
        if (std.mem.allEqual(u8, &secret_key, 0)) return error.InvalidSecretKey;
        // validate by attempting to construct the stdlib key
        switch (key_type) {
            .secp256k1 => {
                _ = crypto.sign.ecdsa.EcdsaSecp256k1Sha256.SecretKey.fromBytes(secret_key) catch
                    return error.InvalidSecretKey;
            },
            .p256 => {
                _ = crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(secret_key) catch
                    return error.InvalidSecretKey;
            },
        }
        return .{ .key_type = key_type, .secret_key = secret_key };
    }

    /// sign a message with deterministic ECDSA (RFC 6979) and low-S normalization
    pub fn sign(self: *const Keypair, message: []const u8) !jwt.Signature {
        return switch (self.key_type) {
            .secp256k1 => jwt.signSecp256k1(message, &self.secret_key),
            .p256 => jwt.signP256(message, &self.secret_key),
        };
    }

    /// return the compressed SEC1 public key (33 bytes)
    pub fn publicKey(self: *const Keypair) ![33]u8 {
        switch (self.key_type) {
            .secp256k1 => {
                const Scheme = crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
                const sk = Scheme.SecretKey.fromBytes(self.secret_key) catch return error.InvalidSecretKey;
                const kp = Scheme.KeyPair.fromSecretKey(sk) catch return error.InvalidSecretKey;
                return kp.public_key.toCompressedSec1();
            },
            .p256 => {
                const Scheme = crypto.sign.ecdsa.EcdsaP256Sha256;
                const sk = Scheme.SecretKey.fromBytes(self.secret_key) catch return error.InvalidSecretKey;
                const kp = Scheme.KeyPair.fromSecretKey(sk) catch return error.InvalidSecretKey;
                return kp.public_key.toCompressedSec1();
            },
        }
    }

    /// format the public key as a did:key string.
    /// caller owns the returned slice.
    pub fn did(self: *const Keypair, allocator: std.mem.Allocator) ![]u8 {
        const pk = try self.publicKey();
        return multicodec.formatDidKey(allocator, self.key_type, &pk);
    }

    /// return the JWT algorithm identifier
    pub fn algorithm(self: *const Keypair) jwt.Algorithm {
        return switch (self.key_type) {
            .secp256k1 => .ES256K,
            .p256 => .ES256,
        };
    }

    /// return the uncompressed SEC1 public key (65 bytes: 0x04 || x[32] || y[32]).
    pub fn uncompressedPublicKey(self: *const Keypair) ![65]u8 {
        switch (self.key_type) {
            .secp256k1 => {
                const Scheme = crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
                const sk = Scheme.SecretKey.fromBytes(self.secret_key) catch return error.InvalidSecretKey;
                const kp = Scheme.KeyPair.fromSecretKey(sk) catch return error.InvalidSecretKey;
                return kp.public_key.toUncompressedSec1();
            },
            .p256 => {
                const Scheme = crypto.sign.ecdsa.EcdsaP256Sha256;
                const sk = Scheme.SecretKey.fromBytes(self.secret_key) catch return error.InvalidSecretKey;
                const kp = Scheme.KeyPair.fromSecretKey(sk) catch return error.InvalidSecretKey;
                return kp.public_key.toUncompressedSec1();
            },
        }
    }

    /// format the public key as a JWK JSON string.
    /// includes kty, crv, x, y, kid (thumbprint), use, alg.
    /// caller owns the returned slice.
    pub fn jwk(self: *const Keypair, allocator: std.mem.Allocator) ![]u8 {
        const uncompressed = try self.uncompressedPublicKey();
        const x_b64 = try jwt.base64UrlEncode(allocator, uncompressed[1..33]);
        defer allocator.free(x_b64);
        const y_b64 = try jwt.base64UrlEncode(allocator, uncompressed[33..65]);
        defer allocator.free(y_b64);

        const crv = switch (self.key_type) {
            .p256 => "P-256",
            .secp256k1 => "secp256k1",
        };
        const alg = @tagName(self.algorithm());

        // RFC 7638 thumbprint inline — avoids re-deriving the public key
        const canonical = try std.fmt.allocPrint(allocator,
            \\{{"crv":"{s}","kty":"EC","x":"{s}","y":"{s}"}}
        , .{ crv, x_b64, y_b64 });
        defer allocator.free(canonical);

        var hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(canonical, &hash, .{});
        const kid = try jwt.base64UrlEncode(allocator, &hash);
        defer allocator.free(kid);

        return std.fmt.allocPrint(allocator,
            \\{{"kty":"EC","crv":"{s}","x":"{s}","y":"{s}","kid":"{s}","use":"sig","alg":"{s}"}}
        , .{ crv, x_b64, y_b64, kid, alg });
    }

    /// compute the JWK thumbprint (RFC 7638) as a base64url string.
    /// canonical form: {"crv":"...","kty":"EC","x":"...","y":"..."}
    /// caller owns the returned slice.
    pub fn jwkThumbprint(self: *const Keypair, allocator: std.mem.Allocator) ![]u8 {
        const uncompressed = try self.uncompressedPublicKey();
        const x_b64 = try jwt.base64UrlEncode(allocator, uncompressed[1..33]);
        defer allocator.free(x_b64);
        const y_b64 = try jwt.base64UrlEncode(allocator, uncompressed[33..65]);
        defer allocator.free(y_b64);

        const crv = switch (self.key_type) {
            .p256 => "P-256",
            .secp256k1 => "secp256k1",
        };

        // RFC 7638: required members in lexicographic order
        const canonical = try std.fmt.allocPrint(allocator,
            \\{{"crv":"{s}","kty":"EC","x":"{s}","y":"{s}"}}
        , .{ crv, x_b64, y_b64 });
        defer allocator.free(canonical);

        var hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(canonical, &hash, .{});
        return jwt.base64UrlEncode(allocator, &hash);
    }
};

// === tests ===

test "keypair secp256k1 sign and verify round-trip" {
    const alloc = std.testing.allocator;

    const kp = try Keypair.fromSecretKey(.secp256k1, .{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    });

    const message = "keypair round-trip test";
    const sig = try kp.sign(message);

    // verify via did:key
    const did_str = try kp.did(alloc);
    defer alloc.free(did_str);

    try multicodec.verifyDidKeySignature(alloc, did_str, message, &sig.bytes);
}

test "keypair p256 sign and verify round-trip" {
    const alloc = std.testing.allocator;

    const kp = try Keypair.fromSecretKey(.p256, .{
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    });

    const message = "keypair p256 round-trip";
    const sig = try kp.sign(message);

    const did_str = try kp.did(alloc);
    defer alloc.free(did_str);

    try multicodec.verifyDidKeySignature(alloc, did_str, message, &sig.bytes);
}

test "keypair did:key format is correct" {
    const alloc = std.testing.allocator;

    const kp = try Keypair.fromSecretKey(.secp256k1, .{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    });

    const did_str = try kp.did(alloc);
    defer alloc.free(did_str);

    // must start with did:key:z (base58btc multibase prefix)
    try std.testing.expect(std.mem.startsWith(u8, did_str, "did:key:z"));

    // must round-trip back to the same public key
    const parsed = try multicodec.parseDidKey(alloc, did_str);
    defer alloc.free(parsed.raw);

    const pk = try kp.publicKey();
    try std.testing.expectEqual(multicodec.KeyType.secp256k1, parsed.key_type);
    try std.testing.expectEqualSlices(u8, &pk, parsed.raw);
}

test "keypair algorithm matches key type" {
    const secp = try Keypair.fromSecretKey(.secp256k1, .{0x01} ** 32);
    try std.testing.expectEqual(jwt.Algorithm.ES256K, secp.algorithm());

    const p256 = try Keypair.fromSecretKey(.p256, .{0x21} ** 32);
    try std.testing.expectEqual(jwt.Algorithm.ES256, p256.algorithm());
}

test "keypair rejects invalid secret key" {
    // all-zeros is not a valid scalar for either curve
    try std.testing.expectError(error.InvalidSecretKey, Keypair.fromSecretKey(.secp256k1, .{0x00} ** 32));
    try std.testing.expectError(error.InvalidSecretKey, Keypair.fromSecretKey(.p256, .{0x00} ** 32));
}

test "keypair jwk p256 round-trip" {
    const alloc = std.testing.allocator;
    const kp = try Keypair.fromSecretKey(.p256, .{
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    });

    const jwk_json = try kp.jwk(alloc);
    defer alloc.free(jwk_json);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, jwk_json, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("EC", obj.get("kty").?.string);
    try std.testing.expectEqualStrings("P-256", obj.get("crv").?.string);
    try std.testing.expectEqualStrings("ES256", obj.get("alg").?.string);
    try std.testing.expectEqualStrings("sig", obj.get("use").?.string);
    try std.testing.expect(obj.get("x") != null);
    try std.testing.expect(obj.get("y") != null);
    try std.testing.expect(obj.get("kid") != null);
}

test "keypair jwk secp256k1 round-trip" {
    const alloc = std.testing.allocator;
    const kp = try Keypair.fromSecretKey(.secp256k1, .{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    });

    const jwk_json = try kp.jwk(alloc);
    defer alloc.free(jwk_json);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, jwk_json, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("EC", obj.get("kty").?.string);
    try std.testing.expectEqualStrings("secp256k1", obj.get("crv").?.string);
    try std.testing.expectEqualStrings("ES256K", obj.get("alg").?.string);
    try std.testing.expectEqualStrings("sig", obj.get("use").?.string);
}

test "keypair jwk thumbprint matches kid" {
    const alloc = std.testing.allocator;
    const kp = try Keypair.fromSecretKey(.p256, .{
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    });

    // get thumbprint directly
    const thumbprint = try kp.jwkThumbprint(alloc);
    defer alloc.free(thumbprint);

    // get kid from JWK
    const jwk_json = try kp.jwk(alloc);
    defer alloc.free(jwk_json);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, jwk_json, .{});
    defer parsed.deinit();

    const kid = parsed.value.object.get("kid").?.string;
    try std.testing.expectEqualStrings(thumbprint, kid);
}

test "keypair cross-verify: sign with keypair, verify with jwt.verify" {
    // sign with Keypair, verify through the JWT multibase path (existing code)
    const alloc = std.testing.allocator;
    const multibase = @import("multibase.zig");

    const sk_bytes = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    const kp = try Keypair.fromSecretKey(.secp256k1, sk_bytes);
    const message = "cross-verify test";
    const sig = try kp.sign(message);

    // get the multibase-encoded key (as it would appear in a DID document)
    const pk = try kp.publicKey();
    const mc_bytes = try multicodec.encodePublicKey(alloc, .secp256k1, &pk);
    defer alloc.free(mc_bytes);
    const multibase_key = try multibase.encode(alloc, .base58btc, mc_bytes);
    defer alloc.free(multibase_key);

    // verify through the old path
    try jwt.verifySecp256k1(message, &sig.bytes, &pk);
}
