//! Deterministic synthetic Ed25519 keys for bridge actors.
//!
//! The relay mints synthetic identities on both sides of the bridge
//! (synthetic AT DIDs for AP-origin actors, synthetic AP actors for
//! AT-origin DIDs). Each synthetic identity needs a signing key so
//! the bridge can actually write records (AT side) or sign federation
//! deliveries (AP side).
//!
//! Persisting per-actor secret material in the db is operationally
//! awkward — it expands the disaster-recovery surface and turns the
//! db dump into PII. Instead we derive the seed deterministically
//! from `HMAC-SHA256(pepper, identity)`. The pepper is a process-wide
//! 32-byte value loaded from `RELAY_SYNTHETIC_KEY_PEPPER` env or, if
//! absent, a fixed development constant (with a noisy boot warning
//! and a build-time recommendation to set the env var in production).
//!
//! Result: synthetic keys are stable across process restarts as long
//! as the pepper is stable, and the db never holds secret material.
//! Rotating the pepper rotates every synthetic key in lockstep — the
//! operator's escape hatch.

const std = @import("std");
const core = @import("core");
const atproto = @import("protocol_atproto");

pub const Ed25519KeyPair = atproto.keypair.Ed25519KeyPair;

/// 32-byte pepper. Set once at boot.
var pepper: [32]u8 = blk: {
    // Default development pepper. The boot path overrides via env.
    // Knowingly hard-coded — production deployments MUST set
    // RELAY_SYNTHETIC_KEY_PEPPER. The boot log emits a warning when
    // this default is in use.
    @setEvalBranchQuota(2000);
    var d: [32]u8 = undefined;
    const src = "speedy-socials/dev-pepper/2026-05/relay-synthetic-keys";
    for (&d, 0..) |*b, i| b.* = src[i % src.len] ^ @as(u8, @intCast(i & 0xff));
    break :blk d;
};

var pepper_is_default: bool = true;

pub fn setPepper(bytes: []const u8) void {
    var d: [32]u8 = .{0} ** 32;
    if (bytes.len >= 32) {
        @memcpy(&d, bytes[0..32]);
    } else {
        @memcpy(d[0..bytes.len], bytes);
    }
    pepper = d;
    pepper_is_default = false;
}

pub fn isDefaultPepper() bool {
    return pepper_is_default;
}

/// Derive an Ed25519 keypair seed from `identity` (an AP actor URL
/// or an AT DID — anything stable that names the synthetic entity).
pub fn deriveSeed(identity: []const u8) [32]u8 {
    var seed: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&seed, identity, &pepper);
    return seed;
}

/// Convenience: derive a full keypair from `identity`.
pub fn deriveKeypair(identity: []const u8) Ed25519KeyPair {
    return Ed25519KeyPair.fromSeed(deriveSeed(identity));
}

// ── Tests ─────────────────────────────────────────────────────────

const testing = std.testing;

test "deriveSeed is deterministic for the same identity" {
    const a = deriveSeed("https://mastodon.example/users/alice");
    const b = deriveSeed("https://mastodon.example/users/alice");
    try testing.expectEqualSlices(u8, &a, &b);
}

test "deriveSeed differs for different identities" {
    const a = deriveSeed("did:plc:alice");
    const b = deriveSeed("did:plc:bob");
    try testing.expect(!std.mem.eql(u8, &a, &b));
}

test "setPepper invalidates the default flag and changes the seed" {
    const before = deriveSeed("did:plc:x");
    setPepper("a-strong-32-byte-production-pepper");
    defer {
        // Restore the dev default for the rest of the test run. We
        // don't have direct access to the build-time computation, so
        // re-derive from the same source bytes.
        var dev: [32]u8 = undefined;
        const src = "speedy-socials/dev-pepper/2026-05/relay-synthetic-keys";
        for (&dev, 0..) |*b, i| b.* = src[i % src.len] ^ @as(u8, @intCast(i & 0xff));
        setPepper(&dev);
        pepper_is_default = true;
    }
    try testing.expect(!isDefaultPepper());
    const after = deriveSeed("did:plc:x");
    try testing.expect(!std.mem.eql(u8, &before, &after));
}

test "deriveKeypair signs deterministically" {
    const kp1 = deriveKeypair("did:plc:test");
    const kp2 = deriveKeypair("did:plc:test");
    const msg = "speedy-socials bridge";
    const s1 = kp1.sign(msg);
    const s2 = kp2.sign(msg);
    try testing.expectEqualSlices(u8, &s1, &s2);
}

test "A1: published PEM + sign + verify round-trip" {
    // The acceptance test for A1: a peer fetches the actor doc,
    // pulls the public key PEM, and verifies a signature we made
    // with the matching private key.
    const activitypub = @import("protocol_activitypub");

    const actor_url = "https://relay.example/ap/users/at:plc:alice";
    const kp = deriveKeypair(actor_url);

    var pem_buf: [256]u8 = undefined;
    const pem_len = try activitypub.keys.writeEd25519PublicPem(kp.public_key, &pem_buf);
    const pem = pem_buf[0..pem_len];

    // The peer parses the PEM and extracts the raw public key. We
    // reuse the AP keys' parser surface here.
    const kid = try activitypub.keys.KeyId.fromSlice("https://relay.example/ap/users/at:plc:alice#main-key");
    const parsed = try activitypub.keys.parsePublicKeyPem(pem, kid);
    try testing.expect(parsed.algo == .ed25519);
    try testing.expectEqualSlices(u8, &kp.public_key, &parsed.ed25519Bytes());

    // Sign a payload + verify it parses through the same key the
    // peer extracted. This is what `sig.verify` does internally on
    // an inbound delivery.
    const msg = "POST /inbox\nhost: peer.example\ndigest: sha-256=...";
    const sig = kp.sign(msg);
    try testing.expect(@import("protocol_atproto").keypair.verifyEd25519(msg, sig, parsed.ed25519Bytes()));
}
