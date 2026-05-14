//! CAR v1 codec (Content Addressable aRchive)
//!
//! read and write CAR v1 files used in AT Protocol firehose commit events.
//! the `blocks` field of a #commit payload is a CAR file containing
//! the signed commit, MST nodes, and record data.
//!
//! format: [varint header_len] [DAG-CBOR header] [varint block_len] [CID] [data] ...
//!
//! see: https://ipld.io/specs/transport/car/carv1/

const std = @import("std");
const cbor = @import("cbor.zig");

const Allocator = std.mem.Allocator;

/// a single block from a CAR file
pub const Block = struct {
    cid_raw: []const u8, // raw CID bytes (for matching against op CIDs)
    data: []const u8, // block content (DAG-CBOR encoded)
};

/// parsed CAR file
pub const Car = struct {
    roots: []const cbor.Cid,
    blocks: []const Block,
    /// CID bytes → block data for O(1) lookup. built by read/readWithOptions.
    /// empty for manually-constructed Cars (findBlock falls back to linear scan).
    block_index: std.StringHashMapUnmanaged([]const u8) = .empty,
};

pub const CarError = error{
    InvalidHeader,
    InvalidVarint,
    InvalidCid,
    UnexpectedEof,
    OutOfMemory,
    BadBlockHash,
    BlocksTooLarge,
    TooManyBlocks,
};

/// match indigo's safety limits
const max_blocks_size: usize = 2 * 1024 * 1024; // 2 MB
const max_block_count: usize = 10_000;

pub const ReadOptions = struct {
    /// verify that each block's content hashes to its CID.
    /// this is the correct behavior for untrusted data (e.g. from the network).
    /// set to false only for trusted local data where you want raw decode speed.
    verify_block_hashes: bool = true,
    /// max total CAR size in bytes. null = use default (2 MB).
    max_size: ?usize = null,
    /// max number of blocks. null = use default (10,000).
    max_blocks: ?usize = null,
};

/// parse a CAR v1 file from raw bytes
pub fn read(allocator: Allocator, data: []const u8) CarError!Car {
    return readWithOptions(allocator, data, .{});
}

/// parse a CAR v1 file from raw bytes with options
pub fn readWithOptions(allocator: Allocator, data: []const u8, options: ReadOptions) CarError!Car {
    if (data.len > (options.max_size orelse max_blocks_size)) return error.BlocksTooLarge;

    var pos: usize = 0;

    // read header length (unsigned varint)
    const header_len = cbor.readUvarint(data, &pos) orelse return error.InvalidVarint;
    const header_len_usize = std.math.cast(usize, header_len) orelse return error.InvalidHeader;
    const header_end = pos + header_len_usize;
    if (header_end > data.len) return error.UnexpectedEof;

    // decode header (DAG-CBOR map with "version" and "roots")
    const header_bytes = data[pos..header_end];
    const header = cbor.decodeAll(allocator, header_bytes) catch return error.InvalidHeader;

    // extract roots (array of CID links)
    var roots: std.ArrayList(cbor.Cid) = .{};
    if (header.getArray("roots")) |root_values| {
        for (root_values) |root_val| {
            switch (root_val) {
                .cid => |c| try roots.append(allocator, c),
                else => {},
            }
        }
    }

    pos = header_end;

    // read blocks
    var blocks: std.ArrayList(Block) = .{};
    var block_index: std.StringHashMapUnmanaged([]const u8) = .empty;

    while (pos < data.len) {
        // block: [varint total_len] [CID bytes] [data bytes]
        // total_len includes both CID and data
        const block_len = cbor.readUvarint(data, &pos) orelse return error.InvalidVarint;
        const block_len_usize = std.math.cast(usize, block_len) orelse return error.InvalidHeader;
        const block_end = pos + block_len_usize;
        if (block_end > data.len) return error.UnexpectedEof;

        const block_data = data[pos..block_end];

        // parse CID to determine its length, then the rest is block content
        const cid_len = cidLength(block_data) orelse return error.InvalidCid;
        if (cid_len > block_data.len) return error.InvalidCid;

        const cid_bytes = block_data[0..cid_len];
        const content = block_data[cid_len..];

        if (options.verify_block_hashes) {
            try verifyBlockHash(cid_bytes, content);
        }

        if (blocks.items.len >= (options.max_blocks orelse max_block_count)) return error.TooManyBlocks;

        try blocks.append(allocator, .{
            .cid_raw = cid_bytes,
            .data = content,
        });
        try block_index.put(allocator, cid_bytes, content);

        pos = block_end;
    }

    return .{
        .roots = try roots.toOwnedSlice(allocator),
        .blocks = try blocks.toOwnedSlice(allocator),
        .block_index = block_index,
    };
}

/// verify that block content hashes to the digest in its CID
fn verifyBlockHash(cid_bytes: []const u8, content: []const u8) CarError!void {
    const cid = cbor.Cid{ .raw = cid_bytes };
    const hash_fn = cid.hashFn() orelse return error.InvalidCid;

    // identity hash (0x00) — digest IS the content, no hashing needed
    if (hash_fn == cbor.HashFn.identity) return;

    // only SHA-256 supported
    if (hash_fn != cbor.HashFn.sha2_256) return error.BadBlockHash;

    const expected = cid.digest() orelse return error.InvalidCid;
    if (expected.len != 32) return error.BadBlockHash;

    const Sha256 = std.crypto.hash.sha2.Sha256;
    var computed: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(content, &computed, .{});

    if (!std.mem.eql(u8, &computed, expected)) return error.BadBlockHash;
}

/// determine the byte length of a CID at the start of data
fn cidLength(data: []const u8) ?usize {
    if (data.len < 2) return null;

    // CIDv0: starts with 0x12 0x20 (sha2-256 multihash, 32 byte digest)
    if (data[0] == 0x12 and data[1] == 0x20) {
        return 34; // 1 + 1 + 32
    }

    // CIDv1: version varint + codec varint + multihash (hash_fn varint + digest_len varint + digest)
    var pos: usize = 0;
    _ = cbor.readUvarint(data, &pos) orelse return null; // version
    _ = cbor.readUvarint(data, &pos) orelse return null; // codec
    _ = cbor.readUvarint(data, &pos) orelse return null; // hash function
    const digest_len = cbor.readUvarint(data, &pos) orelse return null;

    const digest_len_usize = std.math.cast(usize, digest_len) orelse return null;
    return pos + digest_len_usize;
}

/// find a block by matching CID bytes.
/// uses the hash index when available (O(1)), falls back to linear scan for
/// manually-constructed Cars without an index.
pub fn findBlock(c: Car, cid_raw: []const u8) ?[]const u8 {
    if (c.block_index.count() > 0) return c.block_index.get(cid_raw);
    for (c.blocks) |block| {
        if (std.mem.eql(u8, block.cid_raw, cid_raw)) return block.data;
    }
    return null;
}

// === writer ===

/// write a CAR v1 file to the given writer.
/// produces: [varint header_len] [DAG-CBOR header] [blocks...]
/// where each block is: [varint block_len] [CID bytes] [data bytes]
pub fn write(allocator: Allocator, writer: anytype, c: Car) !void {
    // build header: {"roots": [...CID links...], "version": 1}
    var root_values: std.ArrayList(cbor.Value) = .{};
    defer root_values.deinit(allocator);
    for (c.roots) |root| {
        try root_values.append(allocator, .{ .cid = root });
    }

    const header_value: cbor.Value = .{ .map = &.{
        .{ .key = "roots", .value = .{ .array = root_values.items } },
        .{ .key = "version", .value = .{ .unsigned = 1 } },
    } };

    // encode header to bytes
    const header_bytes = try cbor.encodeAlloc(allocator, header_value);
    defer allocator.free(header_bytes);

    // write header length + header
    try cbor.writeUvarint(writer, header_bytes.len);
    try writer.writeAll(header_bytes);

    // write blocks
    for (c.blocks) |block| {
        const block_len = block.cid_raw.len + block.data.len;
        try cbor.writeUvarint(writer, block_len);
        try writer.writeAll(block.cid_raw);
        try writer.writeAll(block.data);
    }
}

/// write a CAR v1 file to a freshly allocated byte slice
pub fn writeAlloc(allocator: Allocator, c: Car) ![]u8 {
    var list: std.ArrayList(u8) = .{};
    errdefer list.deinit(allocator);
    try write(allocator, list.writer(allocator), c);
    return try list.toOwnedSlice(allocator);
}

// === tests ===

test "cidLength CIDv0" {
    // sha2-256 multihash: 0x12 0x20 + 32 bytes
    var data: [34]u8 = undefined;
    data[0] = 0x12;
    data[1] = 0x20;
    @memset(data[2..], 0xaa);

    try std.testing.expectEqual(@as(?usize, 34), cidLength(&data));
}

test "cidLength CIDv1" {
    // CIDv1: version=1, codec=0x71 (dag-cbor), sha2-256 (0x12), 32-byte digest
    const data = [_]u8{
        0x01, // version varint
        0x71, // codec varint (dag-cbor)
        0x12, // hash fn varint (sha2-256)
        0x20, // digest len varint (32)
    } ++ [_]u8{0xaa} ** 32;

    try std.testing.expectEqual(@as(?usize, 36), cidLength(&data));
}

test "read minimal CAR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // construct a minimal CAR v1 file:
    // header: DAG-CBOR {"version": 1, "roots": []}
    const header_cbor = [_]u8{
        0xa2, // map(2)
        0x67, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x01, // "version": 1
        0x65, 'r', 'o', 'o', 't', 's', 0x80, // "roots": []
    };

    // one block: CIDv1 (dag-cbor, sha2-256) + CBOR data
    const cid_prefix = [_]u8{
        0x01, // version
        0x71, // dag-cbor
        0x12, // sha2-256
        0x20, // 32-byte digest
    };
    const digest = [_]u8{0xaa} ** 32;
    const block_content = [_]u8{
        0xa1, // map(1)
        0x64, 't', 'e', 'x', 't', // "text"
        0x62, 'h', 'i', // "hi"
    };

    // assemble the CAR file
    var car_buf: [256]u8 = undefined;
    var car_pos: usize = 0;

    // header length varint
    car_buf[car_pos] = @intCast(header_cbor.len);
    car_pos += 1;

    // header
    @memcpy(car_buf[car_pos..][0..header_cbor.len], &header_cbor);
    car_pos += header_cbor.len;

    // block length varint (CID + content)
    const block_total_len = cid_prefix.len + digest.len + block_content.len;
    car_buf[car_pos] = @intCast(block_total_len);
    car_pos += 1;

    // CID
    @memcpy(car_buf[car_pos..][0..cid_prefix.len], &cid_prefix);
    car_pos += cid_prefix.len;
    @memcpy(car_buf[car_pos..][0..digest.len], &digest);
    car_pos += digest.len;

    // block content
    @memcpy(car_buf[car_pos..][0..block_content.len], &block_content);
    car_pos += block_content.len;

    // this test uses a fake digest, so skip verification
    const car_file = try readWithOptions(alloc, car_buf[0..car_pos], .{ .verify_block_hashes = false });

    try std.testing.expectEqual(@as(usize, 1), car_file.blocks.len);
    try std.testing.expectEqual(@as(usize, block_content.len), car_file.blocks[0].data.len);

    // decode the block content as CBOR
    const val = try cbor.decodeAll(alloc, car_file.blocks[0].data);
    try std.testing.expectEqualStrings("hi", val.getString("text").?);
}

test "read CAR with roots" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // create a CID to use as a root
    const root_cid = try cbor.Cid.forDagCbor(alloc, "root block data");

    // build header with a root: {"roots": [CID], "version": 1}
    const header_value: cbor.Value = .{ .map = &.{
        .{ .key = "roots", .value = .{ .array = &.{.{ .cid = root_cid }} } },
        .{ .key = "version", .value = .{ .unsigned = 1 } },
    } };
    const header_bytes = try cbor.encodeAlloc(alloc, header_value);

    // assemble minimal CAR: header only, no blocks
    var car_buf: std.ArrayList(u8) = .{};
    defer car_buf.deinit(alloc);
    try cbor.writeUvarint(car_buf.writer(alloc), header_bytes.len);
    try car_buf.appendSlice(alloc, header_bytes);

    const car_file = try read(alloc, car_buf.items);
    try std.testing.expectEqual(@as(usize, 1), car_file.roots.len);
    try std.testing.expectEqual(root_cid.version().?, car_file.roots[0].version().?);
    try std.testing.expectEqual(root_cid.codec().?, car_file.roots[0].codec().?);
    try std.testing.expectEqualSlices(u8, root_cid.digest().?, car_file.roots[0].digest().?);
}

test "write → read round-trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // create some blocks
    const block1_data = "block one data";
    const block2_data = "block two data";
    const cid1 = try cbor.Cid.forDagCbor(alloc, block1_data);
    const cid2 = try cbor.Cid.forDagCbor(alloc, block2_data);

    const original = Car{
        .roots = &.{cid1},
        .blocks = &.{
            .{ .cid_raw = cid1.raw, .data = block1_data },
            .{ .cid_raw = cid2.raw, .data = block2_data },
        },
    };

    // write then read
    const car_bytes = try writeAlloc(alloc, original);
    const parsed = try read(alloc, car_bytes);

    // verify roots
    try std.testing.expectEqual(@as(usize, 1), parsed.roots.len);
    try std.testing.expectEqualSlices(u8, cid1.digest().?, parsed.roots[0].digest().?);

    // verify blocks
    try std.testing.expectEqual(@as(usize, 2), parsed.blocks.len);
    try std.testing.expectEqualSlices(u8, block1_data, parsed.blocks[0].data);
    try std.testing.expectEqualSlices(u8, block2_data, parsed.blocks[1].data);

    // verify CID matching
    try std.testing.expectEqualSlices(u8, cid1.raw, parsed.blocks[0].cid_raw);
    try std.testing.expectEqualSlices(u8, cid2.raw, parsed.blocks[1].cid_raw);
}

test "write → read round-trip with CBOR block content" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // encode a record as DAG-CBOR
    const record: cbor.Value = .{ .map = &.{
        .{ .key = "$type", .value = .{ .text = "app.bsky.feed.post" } },
        .{ .key = "text", .value = .{ .text = "hello from CAR writer" } },
    } };
    const record_bytes = try cbor.encodeAlloc(alloc, record);
    const cid = try cbor.Cid.forDagCbor(alloc, record_bytes);

    const original = Car{
        .roots = &.{cid},
        .blocks = &.{
            .{ .cid_raw = cid.raw, .data = record_bytes },
        },
    };

    const car_bytes = try writeAlloc(alloc, original);
    const parsed = try read(alloc, car_bytes);

    // find the block by CID and decode it
    const found = findBlock(parsed, cid.raw).?;
    const decoded = try cbor.decodeAll(alloc, found);
    try std.testing.expectEqualStrings("hello from CAR writer", decoded.getString("text").?);
    try std.testing.expectEqualStrings("app.bsky.feed.post", decoded.getString("$type").?);
}

test "read rejects block with bad hash" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // create a valid CAR, then corrupt the block content
    const record_bytes = try cbor.encodeAlloc(alloc, .{ .map = &.{
        .{ .key = "text", .value = .{ .text = "original" } },
    } });
    const cid = try cbor.Cid.forDagCbor(alloc, record_bytes);

    // write a CAR with the correct CID but wrong data
    const tampered_data = "tampered";
    const tampered_car = Car{
        .roots = &.{cid},
        .blocks = &.{
            .{ .cid_raw = cid.raw, .data = tampered_data },
        },
    };
    const car_bytes = try writeAlloc(alloc, tampered_car);

    // should fail with verification on (default)
    try std.testing.expectError(error.BadBlockHash, read(alloc, car_bytes));

    // should succeed with verification off
    const parsed = try readWithOptions(alloc, car_bytes, .{ .verify_block_hashes = false });
    try std.testing.expectEqual(@as(usize, 1), parsed.blocks.len);
}

test "findBlock returns null for missing CID" {
    const c = Car{ .roots = &.{}, .blocks = &.{} };
    try std.testing.expect(findBlock(c, "nonexistent") == null);
}
