//! Ed25519 keypair for Mastodon OAuth JWT signing.
//!
//! Same shape as `src/protocols/atproto/keypair.zig` (Ed25519 path), kept
//! local so the Mastodon plugin does not depend on the AT Protocol plugin.

const std = @import("std");

pub const ed25519_public_len: usize = 32;
pub const ed25519_secret_len: usize = 64;
pub const ed25519_signature_len: usize = 64;

pub const Ed25519KeyPair = struct {
    public_key: [ed25519_public_len]u8,
    secret_key: [ed25519_secret_len]u8,

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

test "Ed25519 sign/verify roundtrip" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0xA5);
    const kp = Ed25519KeyPair.fromSeed(seed);
    const msg = "hello world";
    const sig = kp.sign(msg);
    try std.testing.expect(verifyEd25519(msg, sig, kp.public_key));
    try std.testing.expect(!verifyEd25519("tampered", sig, kp.public_key));
}
