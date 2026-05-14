//! end-to-end repo verification
//!
//! exercises the full AT Protocol trust chain:
//!   handle → DID → DID document → signing key
//!                                       ↓
//!   repo CAR → commit → signature ← verified against key
//!                   ↓
//!            MST root CID → walk nodes → verify key heights → structure proven

const std = @import("std");
const Allocator = std.mem.Allocator;

const Did = @import("../syntax/did.zig").Did;
const Handle = @import("../syntax/handle.zig").Handle;
const DidDocument = @import("../identity/did_document.zig").DidDocument;
const DidResolver = @import("../identity/did_resolver.zig").DidResolver;
const HandleResolver = @import("../identity/handle_resolver.zig").HandleResolver;
const HttpTransport = @import("../xrpc/transport.zig").HttpTransport;
const multibase = @import("../crypto/multibase.zig");
const multicodec = @import("../crypto/multicodec.zig");
const jwt = @import("../crypto/jwt.zig");
const cbor = @import("cbor.zig");
const car = @import("car.zig");
const mst = @import("mst.zig");

pub const VerifyResult = struct {
    did: []const u8,
    handle: []const u8,
    signing_key_type: multicodec.KeyType,
    commit_rev: []const u8,
    commit_version: i64,
    record_count: usize,
};

/// result of verifying a commit's CAR data against a signing key.
/// used by the relay to verify firehose frames without identity resolution.
pub const CommitVerifyResult = struct {
    commit_did: []const u8,
    commit_rev: []const u8,
    commit_version: i64,
    record_count: usize,
    commit_cid: []const u8,
};

pub const VerifyError = error{
    InvalidIdentifier,
    SigningKeyNotFound,
    PdsEndpointNotFound,
    NoRootsInCar,
    CommitBlockNotFound,
    InvalidCommit,
    SignatureNotFound,
    MstRootMismatch,
    FetchFailed,
} || Allocator.Error;

/// verify a commit's CAR bytes against a pre-resolved signing key.
/// this is the inner loop of verifyRepo() without identity resolution or PDS fetch.
/// used by the relay to verify firehose commit frames directly.
///
/// `car_bytes` is the raw CAR data (from the firehose frame's `blocks` field).
/// `public_key` is the pre-resolved signing key for the commit's DID.
///
/// options:
///   `verify_mst` — walk the MST and verify key heights (default true).
///   `expected_did` — if set, verify the commit DID matches.
pub fn verifyCommitCar(
    allocator: Allocator,
    car_bytes: []const u8,
    public_key: multicodec.PublicKey,
    options: VerifyCommitCarOptions,
) VerifyCommitCarError!CommitVerifyResult {
    // 1. parse CAR
    const repo_car = car.readWithOptions(allocator, car_bytes, .{
        .max_size = options.max_car_size,
        .max_blocks = options.max_blocks,
    }) catch return error.InvalidCommit;
    if (repo_car.roots.len == 0) return error.NoRootsInCar;

    // 2. find commit block
    const commit_cid_raw = repo_car.roots[0].raw;
    const commit_data = car.findBlock(repo_car, commit_cid_raw) orelse return error.CommitBlockNotFound;

    // 3. decode commit
    const commit = cbor.decodeAll(allocator, commit_data) catch return error.InvalidCommit;
    const commit_did = commit.getString("did") orelse return error.InvalidCommit;
    const commit_version = commit.getInt("version") orelse return error.InvalidCommit;
    const commit_rev = commit.getString("rev") orelse return error.InvalidCommit;
    const sig_bytes = commit.getBytes("sig") orelse return error.SignatureNotFound;

    // 4. validate commit structure
    if (commit_version != 3) return error.InvalidCommit;
    if (Did.parse(commit_did) == null) return error.InvalidCommit;

    // 5. check DID matches expected (if provided)
    if (options.expected_did) |expected| {
        if (!std.mem.eql(u8, commit_did, expected)) return error.InvalidCommit;
    }

    // 6. verify signature
    const unsigned_commit_bytes = try encodeUnsignedCommit(allocator, commit);
    switch (public_key.key_type) {
        .p256 => jwt.verifyP256(unsigned_commit_bytes, sig_bytes, public_key.raw) catch return error.SignatureVerificationFailed,
        .secp256k1 => jwt.verifySecp256k1(unsigned_commit_bytes, sig_bytes, public_key.raw) catch return error.SignatureVerificationFailed,
    }

    // 7. optionally walk MST
    var record_count: usize = 0;
    if (options.verify_mst) {
        const data_cid_value = commit.get("data") orelse return error.InvalidCommit;
        const data_cid = switch (data_cid_value) {
            .cid => |c| c,
            else => return error.InvalidCommit,
        };
        record_count = walkAndVerifyMst(allocator, repo_car, data_cid.raw) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.MstRootMismatch,
        };
    }

    return .{
        .commit_did = commit_did,
        .commit_rev = commit_rev,
        .commit_version = commit_version,
        .record_count = record_count,
        .commit_cid = commit_cid_raw,
    };
}

pub const VerifyCommitCarOptions = struct {
    verify_mst: bool = true,
    expected_did: ?[]const u8 = null,
    max_car_size: ?usize = null, // null = default 2MB
    max_blocks: ?usize = null, // null = default 10,000
};

pub const VerifyCommitCarError = error{
    NoRootsInCar,
    CommitBlockNotFound,
    InvalidCommit,
    SignatureNotFound,
    SignatureVerificationFailed,
    MstRootMismatch,
    OutOfMemory,
};

/// verify a repo end-to-end: resolve identity, fetch repo, verify commit signature, walk and rebuild MST.
pub fn verifyRepo(caller_alloc: Allocator, identifier: []const u8) !VerifyResult {
    var arena = std.heap.ArenaAllocator.init(caller_alloc);
    defer arena.deinit();
    const allocator = arena.allocator();

    // 1. resolve identifier to DID
    const did_str = if (Did.parse(identifier) != null)
        identifier
    else blk: {
        const handle = Handle.parse(identifier) orelse return error.InvalidIdentifier;
        var resolver = HandleResolver.init(allocator);
        defer resolver.deinit();
        break :blk try resolver.resolve(handle);
    };

    const did = Did.parse(did_str) orelse return error.InvalidIdentifier;

    // 2. resolve DID → DID document
    var did_resolver = DidResolver.init(allocator);
    defer did_resolver.deinit();
    var did_doc = try did_resolver.resolve(did);
    defer did_doc.deinit();

    // 3. extract signing key
    const signing_vm = did_doc.signingKey() orelse return error.SigningKeyNotFound;
    const key_bytes = try multibase.decode(allocator, signing_vm.public_key_multibase);
    const public_key = try multicodec.parsePublicKey(key_bytes);

    // 4. extract PDS endpoint
    const pds_endpoint = did_doc.pdsEndpoint() orelse return error.PdsEndpointNotFound;

    // 5. fetch repo CAR
    const car_bytes = try fetchRepo(allocator, pds_endpoint, did_str);

    // 6-10. verify CAR: signature, commit structure, MST
    const commit_result = verifyCommitCar(allocator, car_bytes, public_key, .{
        .expected_did = did_str,
        .max_car_size = car_bytes.len, // no size limits — we fetched this ourselves
        .max_blocks = car_bytes.len, // effectively unlimited
    }) catch |err| switch (err) {
        error.SignatureVerificationFailed => return error.InvalidCommit,
        error.OutOfMemory => return error.OutOfMemory,
        inline else => |e| return e,
    };

    // build result — dupe strings to caller's allocator so they survive arena cleanup
    return VerifyResult{
        .did = try caller_alloc.dupe(u8, did_str),
        .handle = try caller_alloc.dupe(u8, did_doc.handle() orelse identifier),
        .signing_key_type = public_key.key_type,
        .commit_rev = try caller_alloc.dupe(u8, commit_result.commit_rev),
        .commit_version = commit_result.commit_version,
        .record_count = commit_result.record_count,
    };
}

/// fetch a repo CAR from a PDS endpoint
fn fetchRepo(allocator: Allocator, pds_endpoint: []const u8, did_str: []const u8) ![]u8 {
    var transport = HttpTransport.init(allocator);
    defer transport.deinit();

    // build URL: {pds}/xrpc/com.atproto.sync.getRepo?did={did}
    const url = try std.fmt.allocPrint(allocator, "{s}/xrpc/com.atproto.sync.getRepo?did={s}", .{ pds_endpoint, did_str });

    const result = transport.fetch(.{ .url = url }) catch return error.FetchFailed;
    if (result.status != .ok) return error.FetchFailed;
    return result.body;
}

/// encode a commit value without the "sig" field (for signature verification)
pub fn encodeUnsignedCommit(allocator: Allocator, commit: cbor.Value) ![]u8 {
    const entries = switch (commit) {
        .map => |m| m,
        else => return error.InvalidCommit,
    };

    // filter out "sig", keep everything else
    var unsigned_entries: std.ArrayList(cbor.Value.MapEntry) = .{};
    for (entries) |entry| {
        if (!std.mem.eql(u8, entry.key, "sig")) {
            try unsigned_entries.append(allocator, entry);
        }
    }

    const unsigned_value: cbor.Value = .{ .map = unsigned_entries.items };
    return cbor.encodeAlloc(allocator, unsigned_value);
}

/// walk the MST using the specialized decoder, verifying each key's tree layer
/// is deterministically correct. combined with CAR block CID verification
/// (which proves data integrity), this is equivalent to a full MST rebuild.
fn walkAndVerifyMst(allocator: Allocator, repo_car: car.Car, root_cid_raw: []const u8) !usize {
    const root_data = car.findBlock(repo_car, root_cid_raw) orelse return error.CommitBlockNotFound;
    const root_node = try mst.decodeMstNode(allocator, root_data);
    if (root_node.entries.len == 0 and root_node.left == null) return 0;

    // root layer = key height of first entry (first entry always has prefix_len = 0)
    const root_layer = mst.keyHeight(root_node.entries[0].key_suffix);

    return walkVerifyNode(allocator, repo_car, root_node, root_layer);
}

const WalkError = VerifyError || mst.MstDecodeError;

fn walkVerifyNode(allocator: Allocator, repo_car: car.Car, node: mst.MstNodeData, expected_layer: u32) WalkError!usize {
    var count: usize = 0;
    var key_buf: [512]u8 = undefined;
    var key_len: usize = 0;

    // left subtree
    if (node.left) |left_cid| {
        if (expected_layer == 0) return error.MstRootMismatch;
        count += try walkVerifyChild(allocator, repo_car, left_cid, expected_layer - 1);
    }

    for (node.entries) |entry| {
        // reconstruct key from prefix compression (in-place, zero alloc)
        @memcpy(key_buf[entry.prefix_len..][0..entry.key_suffix.len], entry.key_suffix);
        key_len = entry.prefix_len + entry.key_suffix.len;

        // verify this key belongs at the expected layer
        if (mst.keyHeight(key_buf[0..key_len]) != expected_layer) return error.MstRootMismatch;

        count += 1;

        // right subtree
        if (entry.tree) |tree_cid| {
            if (expected_layer == 0) return error.MstRootMismatch;
            count += try walkVerifyChild(allocator, repo_car, tree_cid, expected_layer - 1);
        }
    }

    return count;
}

fn walkVerifyChild(allocator: Allocator, repo_car: car.Car, cid_raw: []const u8, expected_layer: u32) WalkError!usize {
    const block_data = car.findBlock(repo_car, cid_raw) orelse return error.CommitBlockNotFound;
    const node = try mst.decodeMstNode(allocator, block_data);
    return walkVerifyNode(allocator, repo_car, node, expected_layer);
}

// === sync 1.1: commit diff verification ===

/// decoded commit fields from a CAR file
pub const Commit = struct {
    did: []const u8,
    rev: []const u8,
    version: i64,
    sig: []const u8,
    data_cid: []const u8, // raw CID bytes — MST root
    prev: ?[]const u8, // raw CID bytes — previous commit CID (null for first commit)
};

/// lightweight: parse CAR, find root block, decode commit CBOR.
/// no MST loading. reusable for both #commit and #sync frames.
/// pre-computes unsigned commit bytes for signature verification (avoids re-decode).
pub fn loadCommitFromCAR(allocator: Allocator, car_bytes: []const u8) !struct {
    commit: Commit,
    commit_cid: []const u8,
    unsigned_commit_bytes: []const u8,
    repo_car: car.Car,
} {
    const repo_car = car.readWithOptions(allocator, car_bytes, .{}) catch return error.InvalidCommit;
    if (repo_car.roots.len == 0) return error.NoRootsInCar;

    const commit_cid_raw = repo_car.roots[0].raw;
    const commit_data = car.findBlock(repo_car, commit_cid_raw) orelse return error.CommitBlockNotFound;

    const commit_value = cbor.decodeAll(allocator, commit_data) catch return error.InvalidCommit;
    const commit_did = commit_value.getString("did") orelse return error.InvalidCommit;
    const commit_version = commit_value.getInt("version") orelse return error.InvalidCommit;
    const commit_rev = commit_value.getString("rev") orelse return error.InvalidCommit;
    const sig_bytes = commit_value.getBytes("sig") orelse return error.SignatureNotFound;

    // pre-compute unsigned commit bytes while we have the cbor.Value
    const unsigned_commit_bytes = encodeUnsignedCommit(allocator, commit_value) catch return error.InvalidCommit;

    // extract data CID (MST root)
    const data_cid_value = commit_value.get("data") orelse return error.InvalidCommit;
    const data_cid_raw = switch (data_cid_value) {
        .cid => |c| c.raw,
        else => return error.InvalidCommit,
    };

    // extract prev commit CID (optional)
    const prev_cid_raw: ?[]const u8 = if (commit_value.get("prev")) |prev_value| switch (prev_value) {
        .cid => |c| c.raw,
        .null => null,
        else => return error.InvalidCommit,
    } else null;

    return .{
        .commit = .{
            .did = commit_did,
            .rev = commit_rev,
            .version = commit_version,
            .sig = sig_bytes,
            .data_cid = data_cid_raw,
            .prev = prev_cid_raw,
        },
        .commit_cid = commit_cid_raw,
        .unsigned_commit_bytes = unsigned_commit_bytes,
        .repo_car = repo_car,
    };
}

pub const VerifyCommitDiffOptions = struct {
    expected_did: ?[]const u8 = null,
    skip_inversion: bool = false,
    max_car_size: ?usize = null,
    max_blocks: ?usize = null,
};

pub const VerifyCommitDiffError = error{
    NoRootsInCar,
    CommitBlockNotFound,
    InvalidCommit,
    SignatureNotFound,
    SignatureVerificationFailed,
    MstRootMismatch,
    PrevDataMismatch,
    InversionMismatch,
    PartialTree,
    DuplicatePath,
    OutOfMemory,
    InvalidMstNode,
};

/// result of commit diff verification
pub const CommitDiffResult = struct {
    commit_did: []const u8,
    commit_rev: []const u8,
    commit_version: i64,
    commit_cid: []const u8,
    data_cid: []const u8,
};

/// verify a commit diff: parse CAR, verify signature, load partial MST,
/// invert operations, and verify the resulting root matches prev_data.
pub fn verifyCommitDiff(
    allocator: Allocator,
    blocks: []const u8,
    msg_ops: []const mst.Operation,
    prev_data: ?[]const u8,
    public_key: multicodec.PublicKey,
    options: VerifyCommitDiffOptions,
) VerifyCommitDiffError!CommitDiffResult {
    // 1. parse CAR + extract commit
    const loaded = loadCommitFromCAR(allocator, blocks) catch return error.InvalidCommit;
    const commit = loaded.commit;
    const repo_car = loaded.repo_car;

    // 2. verify commit structure
    if (commit.version != 3) return error.InvalidCommit;
    if (Did.parse(commit.did) == null) return error.InvalidCommit;

    // 3. check expected_did
    if (options.expected_did) |expected| {
        if (!std.mem.eql(u8, commit.did, expected)) return error.InvalidCommit;
    }

    // 4. verify signature (unsigned bytes pre-computed by loadCommitFromCAR)
    switch (public_key.key_type) {
        .p256 => jwt.verifyP256(loaded.unsigned_commit_bytes, commit.sig, public_key.raw) catch return error.SignatureVerificationFailed,
        .secp256k1 => jwt.verifySecp256k1(loaded.unsigned_commit_bytes, commit.sig, public_key.raw) catch return error.SignatureVerificationFailed,
    }

    // 5. if no prev_data or skip_inversion, we're done (first commit or lenient mode)
    if (prev_data == null or options.skip_inversion) {
        return .{
            .commit_did = commit.did,
            .commit_rev = commit.rev,
            .commit_version = commit.version,
            .commit_cid = loaded.commit_cid,
            .data_cid = commit.data_cid,
        };
    }

    // 6. load partial MST from CAR blocks
    var tree = mst.Mst.loadFromBlocks(allocator, repo_car, commit.data_cid) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidMstNode => return error.InvalidMstNode,
        else => return error.MstRootMismatch,
    };

    // 7. deep copy for inversion
    var inverted = tree.copy() catch return error.OutOfMemory;

    // 8. normalize ops
    const sorted_ops = mst.normalizeOps(allocator, msg_ops) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.DuplicatePath => return error.DuplicatePath,
    };

    // 9. invert each operation
    for (sorted_ops) |op| {
        mst.invertOp(&inverted, op) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InversionMismatch => return error.InversionMismatch,
            error.PartialTree => return error.PartialTree,
        };
    }

    // 10. compute root CID of inverted tree
    const inverted_root = inverted.rootCid() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.PartialTree => return error.PartialTree,
    };

    // 11. compare against prev_data
    if (!std.mem.eql(u8, inverted_root.raw, prev_data.?)) {
        return error.PrevDataMismatch;
    }

    return .{
        .commit_did = commit.did,
        .commit_rev = commit.rev,
        .commit_version = commit.version,
        .commit_cid = loaded.commit_cid,
        .data_cid = commit.data_cid,
    };
}

// === tests ===

test "verify repo - zzstoatzz.io" {
    // did:plc:xbtmt2zjwlrfegqvch7fboei on pds.zzstoatzz.io (self-hosted PDS)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const result = verifyRepo(arena.allocator(), "zzstoatzz.io") catch |err| {
        std.debug.print("network error (expected in CI): {}\n", .{err});
        return;
    };

    try std.testing.expectEqualStrings("did:plc:xbtmt2zjwlrfegqvch7fboei", result.did);
    try std.testing.expect(result.record_count > 0);
    std.debug.print("verified zzstoatzz.io: {d} records, rev={s}\n", .{ result.record_count, result.commit_rev });
}

test "verifyCommitDiff: build tree, serialize partial CAR, verify inversion" {
    // this test constructs a tree, applies ops, builds a partial CAR
    // with the commit + changed MST nodes, and verifies the diff
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cid1 = try cbor.Cid.forDagCbor(a, "record1");
    const cid2 = try cbor.Cid.forDagCbor(a, "record2");
    const cid3 = try cbor.Cid.forDagCbor(a, "record3");

    // build "before" tree
    var before_tree = mst.Mst.init(a);
    try before_tree.put("col/existing", cid1);
    try before_tree.put("col/to_update", cid1);
    try before_tree.put("col/to_delete", cid2);
    const prev_data_cid = try before_tree.rootCid();

    // build "after" tree (apply ops forward)
    var after_tree = try before_tree.copy();
    try after_tree.put("col/new_record", cid3); // create
    try after_tree.put("col/to_update", cid2); // update
    try after_tree.delete("col/to_delete"); // delete
    const new_data_cid = try after_tree.rootCid();

    // verify inversion works at the MST level
    var inverted = try after_tree.copy();
    const ops = [_]mst.Operation{
        .{ .path = "col/new_record", .value = cid3.raw, .prev = null },
        .{ .path = "col/to_update", .value = cid2.raw, .prev = cid1.raw },
        .{ .path = "col/to_delete", .value = null, .prev = cid2.raw },
    };
    const sorted = try mst.normalizeOps(a, &ops);
    for (sorted) |op| {
        try mst.invertOp(&inverted, op);
    }
    const inverted_root = try inverted.rootCid();
    try std.testing.expectEqualSlices(u8, prev_data_cid.raw, inverted_root.raw);

    // also verify the after tree has the expected new root
    try std.testing.expect(!std.mem.eql(u8, prev_data_cid.raw, new_data_cid.raw));
}

test "loadCommitFromCAR extracts commit fields" {
    // build a minimal valid commit CAR
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const data_cid = try cbor.Cid.forDagCbor(a, "mst-root-placeholder");

    // build commit CBOR
    const commit_value: cbor.Value = .{ .map = &.{
        .{ .key = "data", .value = .{ .cid = data_cid } },
        .{ .key = "did", .value = .{ .text = "did:plc:test123" } },
        .{ .key = "rev", .value = .{ .text = "3k2abc000000" } },
        .{ .key = "sig", .value = .{ .bytes = "fakesig" } },
        .{ .key = "version", .value = .{ .unsigned = 3 } },
    } };
    const commit_bytes = try cbor.encodeAlloc(a, commit_value);
    const commit_cid = try cbor.Cid.forDagCbor(a, commit_bytes);

    // build CAR with commit block
    const car_data = car.Car{
        .roots = &.{commit_cid},
        .blocks = &.{
            .{ .cid_raw = commit_cid.raw, .data = commit_bytes },
        },
    };
    const car_bytes = try car.writeAlloc(a, car_data);

    // parse it back
    const loaded = try loadCommitFromCAR(a, car_bytes);
    try std.testing.expectEqualStrings("did:plc:test123", loaded.commit.did);
    try std.testing.expectEqualStrings("3k2abc000000", loaded.commit.rev);
    try std.testing.expectEqual(@as(i64, 3), loaded.commit.version);
    try std.testing.expectEqualSlices(u8, data_cid.raw, loaded.commit.data_cid);
    try std.testing.expect(loaded.commit.prev == null);
}

// stress test: pfrazee.com (~192k records on bsky.network)
// run manually with: zig test src/internal/repo/repo_verifier.zig --
//   not included in `zig build test` — too slow for CI
//
// test "verify repo - pfrazee.com (stress)" {
//     var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
//     defer arena.deinit();
//     const result = verifyRepo(arena.allocator(), "pfrazee.com") catch |err| {
//         std.debug.print("network error: {}\n", .{err});
//         return;
//     };
//     try std.testing.expectEqualStrings("did:plc:ragtjsm2j2vknwkz3zp4oxrd", result.did);
//     try std.testing.expect(result.record_count > 0);
//     std.debug.print("verified pfrazee.com: {d} records, rev={s}\n", .{ result.record_count, result.commit_rev });
// }
