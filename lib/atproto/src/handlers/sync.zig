const std = @import("std");
const xrpc_mod = @import("../xrpc.zig");
const storage_mod = @import("../storage.zig");
const config_mod = @import("../config.zig");
const XrpcInput = xrpc_mod.XrpcInput;
const XrpcOutput = xrpc_mod.XrpcOutput;
const Storage = storage_mod.Storage;
const PdsConfig = config_mod.PdsConfig;

/// com.atproto.sync.getLatestCommit
pub fn getLatestCommit(allocator: std.mem.Allocator, store: Storage, _: PdsConfig, input: XrpcInput) !XrpcOutput {
    const did = input.params.get("did") orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing did parameter");
    };

    const entry = try store.getLatestCommit(allocator, did) orelse {
        return XrpcOutput.errResponse(404, "RepoNotFound", "Repository not found");
    };

    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .cid = entry.data_cid,
        .rev = entry.rev,
    }, .{}));
}

/// com.atproto.sync.getRepo
pub fn getRepo(allocator: std.mem.Allocator, store: Storage, _: PdsConfig, input: XrpcInput) !XrpcOutput {
    const did = input.params.get("did") orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing did parameter");
    };

    // Collect all records for this repo
    const records = try store.listRecords(allocator, did, "", 10000, null);
    defer allocator.free(records);

    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .did = did,
        .record_count = records.len,
    }, .{}));
}

/// com.atproto.sync.getBlob
pub fn getBlob(allocator: std.mem.Allocator, store: Storage, _: PdsConfig, input: XrpcInput) !XrpcOutput {
    const cid = input.params.get("cid") orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing cid parameter");
    };

    const blob = try store.getBlob(allocator, cid) orelse {
        return XrpcOutput.errResponse(404, "BlobNotFound", "Blob not found");
    };

    return .{ .blob = .{
        .data = blob.data,
        .content_type = blob.mime_type,
    } };
}

/// com.atproto.sync.listBlobs
pub fn listBlobs(allocator: std.mem.Allocator, store: Storage, _: PdsConfig, input: XrpcInput) !XrpcOutput {
    const did = input.params.get("did") orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing did parameter");
    };

    const limit_str = input.params.get("limit") orelse "500";
    const limit = std.fmt.parseInt(u32, limit_str, 10) catch 500;
    const cursor = input.params.get("cursor");

    const blobs = try store.listBlobs(allocator, did, limit, cursor);
    defer allocator.free(blobs);

    var cids: std.ArrayList([]const u8) = .empty;
    defer cids.deinit(allocator);
    for (blobs) |b| try cids.append(allocator, b.cid);

    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .cids = cids.items,
        .cursor = @as(?[]const u8, null),
    }, .{}));
}
