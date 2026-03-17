const std = @import("std");
const xrpc_mod = @import("../xrpc.zig");
const storage_mod = @import("../storage.zig");
const config_mod = @import("../config.zig");
const session_mod = @import("../auth/session.zig");
const XrpcInput = xrpc_mod.XrpcInput;
const XrpcOutput = xrpc_mod.XrpcOutput;
const Storage = storage_mod.Storage;
const PdsConfig = config_mod.PdsConfig;

/// com.atproto.moderation.createReport
pub fn createReport(allocator: std.mem.Allocator, _: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    _ = try session_mod.validateAuth(allocator, cfg, input.auth_token) orelse {
        return XrpcOutput.errResponse(401, "AuthenticationRequired", "Authentication required");
    };

    const body = input.body orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing request body");
    };

    const parsed = std.json.parseFromSlice(struct {
        reasonType: []const u8,
        reason: ?[]const u8 = null,
        subject: std.json.Value,
    }, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Invalid JSON body");
    };
    defer parsed.deinit();

    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .id = @as(u64, 1),
        .reasonType = parsed.value.reasonType,
        .reason = parsed.value.reason,
        .subject = parsed.value.subject,
        .reportedBy = "did:web:anonymous",
        .createdAt = "2024-01-01T00:00:00Z",
    }, .{}));
}
