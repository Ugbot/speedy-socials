const std = @import("std");
const xrpc_mod = @import("../xrpc.zig");
const storage_mod = @import("../storage.zig");
const config_mod = @import("../config.zig");
const XrpcInput = xrpc_mod.XrpcInput;
const XrpcOutput = xrpc_mod.XrpcOutput;
const Storage = storage_mod.Storage;
const PdsConfig = config_mod.PdsConfig;

/// com.atproto.label.queryLabels
pub fn queryLabels(allocator: std.mem.Allocator, _: Storage, _: PdsConfig, _: XrpcInput) !XrpcOutput {
    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .labels = &[_]struct{}{},
        .cursor = @as(?[]const u8, null),
    }, .{}));
}
