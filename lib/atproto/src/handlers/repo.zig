const std = @import("std");
const xrpc_mod = @import("../xrpc.zig");
const storage_mod = @import("../storage.zig");
const config_mod = @import("../config.zig");
const repo_mod = @import("../repo.zig");
const session_mod = @import("../auth/session.zig");
const commit_mod = @import("../commit.zig");
const record_mod = @import("../record.zig");
const XrpcInput = xrpc_mod.XrpcInput;
const XrpcOutput = xrpc_mod.XrpcOutput;
const Storage = storage_mod.Storage;
const PdsConfig = config_mod.PdsConfig;

fn requireAuth(allocator: std.mem.Allocator, cfg: PdsConfig, input: XrpcInput) ![]const u8 {
    return try session_mod.validateAuth(allocator, cfg, input.auth_token) orelse {
        return error.AuthenticationRequired;
    };
}

/// com.atproto.repo.createRecord
pub fn createRecord(allocator: std.mem.Allocator, store: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    const auth_did = requireAuth(allocator, cfg, input) catch {
        return XrpcOutput.errResponse(401, "AuthenticationRequired", "Authentication required");
    };
    defer allocator.free(auth_did);

    const body = input.body orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing request body");
    };

    const parsed = std.json.parseFromSlice(struct {
        repo: []const u8,
        collection: []const u8,
        rkey: ?[]const u8 = null,
        record: std.json.Value,
    }, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Invalid JSON body");
    };
    defer parsed.deinit();

    // Get account signing key
    const account = try store.getAccountByDid(allocator, auth_did) orelse {
        return XrpcOutput.errResponse(404, "RepoNotFound", "Repository not found");
    };

    var repo = repo_mod.Repository.init(allocator, auth_did, account.signing_key_seed, store);

    // Serialize the record value back to JSON for storage
    const record_json = try std.json.Stringify.valueAlloc(allocator, parsed.value.record, .{});
    defer allocator.free(record_json);

    const result = try repo.createRecord(parsed.value.collection, parsed.value.rkey, record_json);
    defer {
        allocator.free(result.uri);
        allocator.free(result.cid);
        allocator.free(result.rev);
    }

    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .uri = result.uri,
        .cid = result.cid,
    }, .{}));
}

/// com.atproto.repo.getRecord
pub fn getRecord(allocator: std.mem.Allocator, store: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    _ = cfg;
    const repo_did = input.params.get("repo") orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing repo parameter");
    };
    const collection = input.params.get("collection") orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing collection parameter");
    };
    const rkey = input.params.get("rkey") orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing rkey parameter");
    };

    const entry = try store.getRecord(allocator, repo_did, collection, rkey) orelse {
        return XrpcOutput.errResponse(404, "RecordNotFound", "Record not found");
    };

    const uri = try record_mod.buildAtUri(allocator, repo_did, collection, rkey);
    defer allocator.free(uri);

    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .uri = uri,
        .cid = entry.cid,
        .value = std.json.Value{ .string = entry.value },
    }, .{}));
}

/// com.atproto.repo.listRecords
pub fn listRecords(allocator: std.mem.Allocator, store: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    _ = cfg;
    const repo_did = input.params.get("repo") orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing repo parameter");
    };
    const collection = input.params.get("collection") orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing collection parameter");
    };

    const limit_str = input.params.get("limit") orelse "50";
    const limit = std.fmt.parseInt(u32, limit_str, 10) catch 50;
    const cursor = input.params.get("cursor");

    const entries = try store.listRecords(allocator, repo_did, collection, limit, cursor);
    defer allocator.free(entries);

    var records: std.ArrayList(struct {
        uri: []const u8,
        cid: []const u8,
        value: []const u8,
    }) = .empty;
    defer records.deinit(allocator);

    for (entries) |e| {
        const uri = try record_mod.buildAtUri(allocator, repo_did, e.collection, e.rkey);
        try records.append(allocator, .{ .uri = uri, .cid = e.cid, .value = e.value });
    }
    defer for (records.items) |r| allocator.free(r.uri);

    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .records = records.items,
        .cursor = @as(?[]const u8, null),
    }, .{}));
}

/// com.atproto.repo.deleteRecord
pub fn deleteRecord(allocator: std.mem.Allocator, store: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    const auth_did = requireAuth(allocator, cfg, input) catch {
        return XrpcOutput.errResponse(401, "AuthenticationRequired", "Authentication required");
    };
    defer allocator.free(auth_did);

    const body = input.body orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing request body");
    };

    const parsed = std.json.parseFromSlice(struct {
        repo: []const u8,
        collection: []const u8,
        rkey: []const u8,
    }, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Invalid JSON body");
    };
    defer parsed.deinit();

    try store.deleteRecord(allocator, auth_did, parsed.value.collection, parsed.value.rkey);

    return XrpcOutput.ok(try allocator.dupe(u8, "{}"));
}

/// com.atproto.repo.putRecord
pub fn putRecord(allocator: std.mem.Allocator, store: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    // putRecord has the same flow as createRecord but with a required rkey
    return createRecord(allocator, store, cfg, input);
}

/// com.atproto.repo.describeRepo
pub fn describeRepo(allocator: std.mem.Allocator, store: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    _ = cfg;
    const repo_did = input.params.get("repo") orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing repo parameter");
    };

    const account = try store.getAccountByDid(allocator, repo_did) orelse {
        return XrpcOutput.errResponse(404, "RepoNotFound", "Repository not found");
    };

    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .handle = account.handle,
        .did = account.did,
        .didDoc = .{},
        .collections = &[_][]const u8{},
        .handleIsCorrect = true,
    }, .{}));
}

/// com.atproto.repo.uploadBlob
pub fn uploadBlob(allocator: std.mem.Allocator, store: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    _ = requireAuth(allocator, cfg, input) catch {
        return XrpcOutput.errResponse(401, "AuthenticationRequired", "Authentication required");
    };

    const data = input.body orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing blob data");
    };

    // Generate CID from blob content
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    const cid_hex = std.fmt.bytesToHex(&hash, .lower);
    const cid: []const u8 = &cid_hex;

    try store.putBlob(allocator, .{
        .cid = cid,
        .mime_type = "application/octet-stream",
        .size = data.len,
        .data = data,
    });

    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .blob = .{
            .@"$type" = "blob",
            .ref = .{ .@"$link" = cid },
            .mimeType = "application/octet-stream",
            .size = data.len,
        },
    }, .{}));
}
