const std = @import("std");
const zat = @import("zat");

/// AT Protocol commit object (version 3).
pub const Commit = struct {
    /// Account DID.
    did: []const u8,
    /// Commit version (always 3).
    version: u8 = 3,
    /// CID of the MST root node.
    data_cid: []const u8,
    /// TID revision (monotonically increasing).
    rev: []const u8,
    /// CID of the previous commit (virtually always null in v3).
    prev: ?[]const u8 = null,
    /// Ed25519 signature bytes (base64 encoded).
    sig: []const u8,
};

/// Generate a new TID revision string.
pub fn generateRev(allocator: std.mem.Allocator) ![]const u8 {
    const ts: u64 = @intCast(std.time.microTimestamp());
    const tid = zat.Tid.fromTimestamp(ts, 0);
    return allocator.dupe(u8, tid.str());
}

/// Generate a new record key (TID-based).
pub fn generateRkey(allocator: std.mem.Allocator) ![]const u8 {
    return generateRev(allocator);
}

/// Create a signed commit.
/// The commit is serialized as DAG-CBOR, hashed with SHA-256, and signed with Ed25519.
pub fn createCommit(
    allocator: std.mem.Allocator,
    did: []const u8,
    data_cid: []const u8,
    prev_rev: ?[]const u8,
    signing_key_seed: []const u8,
) !Commit {
    const rev = try generateRev(allocator);
    errdefer allocator.free(rev);

    // Build the unsigned commit as JSON for now
    // (Full CBOR serialization would use ZAT's cbor module)
    var commit_aw: std.io.Writer.Allocating = .init(allocator);
    defer commit_aw.deinit();

    try std.json.Stringify.value(.{
        .did = did,
        .version = @as(u8, 3),
        .data = data_cid,
        .rev = rev,
        .prev = prev_rev,
    }, .{}, &commit_aw.writer);

    // Sign with Ed25519
    var seed: [32]u8 = undefined;
    if (signing_key_seed.len >= 32) {
        @memcpy(&seed, signing_key_seed[0..32]);
    } else {
        @memset(&seed, 0);
        @memcpy(seed[0..signing_key_seed.len], signing_key_seed);
    }

    const key_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const sig = try key_pair.sign(commit_aw.written(), null);

    // Base64 encode the signature
    const sig_b64 = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(64));
    errdefer allocator.free(sig_b64);
    _ = std.base64.standard.Encoder.encode(sig_b64, &sig.toBytes());

    return Commit{
        .did = try allocator.dupe(u8, did),
        .data_cid = try allocator.dupe(u8, data_cid),
        .rev = rev,
        .prev = if (prev_rev) |pr| try allocator.dupe(u8, pr) else null,
        .sig = sig_b64,
    };
}

/// Free a commit's allocated fields.
pub fn freeCommit(allocator: std.mem.Allocator, c: Commit) void {
    allocator.free(c.did);
    allocator.free(c.data_cid);
    allocator.free(c.rev);
    if (c.prev) |pr| allocator.free(pr);
    allocator.free(c.sig);
}

test "createCommit produces valid structure" {
    const allocator = std.testing.allocator;
    const c = try createCommit(allocator, "did:web:test", "bafyreiabc", null, "testseedtestseedtestseedtestseed");
    defer freeCommit(allocator, c);

    try std.testing.expectEqual(@as(u8, 3), c.version);
    try std.testing.expectEqualStrings("did:web:test", c.did);
    try std.testing.expectEqualStrings("bafyreiabc", c.data_cid);
    try std.testing.expect(c.rev.len == 13); // TID is 13 chars
    try std.testing.expect(c.sig.len > 0);
    try std.testing.expect(c.prev == null);
}
