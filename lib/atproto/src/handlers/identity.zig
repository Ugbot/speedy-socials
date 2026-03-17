const std = @import("std");
const xrpc_mod = @import("../xrpc.zig");
const storage_mod = @import("../storage.zig");
const config_mod = @import("../config.zig");
const XrpcInput = xrpc_mod.XrpcInput;
const XrpcOutput = xrpc_mod.XrpcOutput;
const Storage = storage_mod.Storage;
const PdsConfig = config_mod.PdsConfig;

/// com.atproto.identity.resolveHandle
pub fn resolveHandle(allocator: std.mem.Allocator, store: Storage, _: PdsConfig, input: XrpcInput) !XrpcOutput {
    const handle = input.params.get("handle") orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing handle parameter");
    };

    const account = try store.getAccountByIdentifier(allocator, handle) orelse {
        return XrpcOutput.errResponse(404, "HandleNotFound", "Handle not found");
    };

    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .did = account.did,
    }, .{}));
}

/// com.atproto.identity.updateHandle
pub fn updateHandle(allocator: std.mem.Allocator, _: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    _ = allocator;
    _ = cfg;
    _ = input;
    return XrpcOutput.errResponse(501, "MethodNotImplemented", "Handle updates not yet implemented");
}
