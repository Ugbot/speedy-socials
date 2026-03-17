const std = @import("std");
const xrpc_mod = @import("xrpc.zig");
const storage_mod = @import("storage.zig");
const config_mod = @import("config.zig");
const server_handlers = @import("handlers/server.zig");
const repo_handlers = @import("handlers/repo.zig");
const sync_handlers = @import("handlers/sync.zig");
const identity_handlers = @import("handlers/identity.zig");
const label_handlers = @import("handlers/label.zig");
const moderation_handlers = @import("handlers/moderation.zig");
const XrpcInput = xrpc_mod.XrpcInput;
const XrpcOutput = xrpc_mod.XrpcOutput;
const Storage = storage_mod.Storage;
const PdsConfig = config_mod.PdsConfig;

const HandlerFn = *const fn (std.mem.Allocator, Storage, PdsConfig, XrpcInput) anyerror!XrpcOutput;

const Route = struct {
    method: []const u8,
    handler: HandlerFn,
};

/// Static route table mapping XRPC method names to handlers.
const routes = [_]Route{
    // com.atproto.server
    .{ .method = "com.atproto.server.describeServer", .handler = &describeServerAdapter },
    .{ .method = "com.atproto.server.createSession", .handler = &server_handlers.createSession },
    .{ .method = "com.atproto.server.refreshSession", .handler = &server_handlers.refreshSession },
    .{ .method = "com.atproto.server.deleteSession", .handler = &server_handlers.deleteSession },
    .{ .method = "com.atproto.server.getSession", .handler = &server_handlers.getSession },
    .{ .method = "com.atproto.server.createAccount", .handler = &server_handlers.createAccount },

    // com.atproto.repo
    .{ .method = "com.atproto.repo.createRecord", .handler = &repo_handlers.createRecord },
    .{ .method = "com.atproto.repo.getRecord", .handler = &repo_handlers.getRecord },
    .{ .method = "com.atproto.repo.listRecords", .handler = &repo_handlers.listRecords },
    .{ .method = "com.atproto.repo.deleteRecord", .handler = &repo_handlers.deleteRecord },
    .{ .method = "com.atproto.repo.putRecord", .handler = &repo_handlers.putRecord },
    .{ .method = "com.atproto.repo.describeRepo", .handler = &repo_handlers.describeRepo },
    .{ .method = "com.atproto.repo.uploadBlob", .handler = &repo_handlers.uploadBlob },

    // com.atproto.sync
    .{ .method = "com.atproto.sync.getLatestCommit", .handler = &sync_handlers.getLatestCommit },
    .{ .method = "com.atproto.sync.getRepo", .handler = &sync_handlers.getRepo },
    .{ .method = "com.atproto.sync.getBlob", .handler = &sync_handlers.getBlob },
    .{ .method = "com.atproto.sync.listBlobs", .handler = &sync_handlers.listBlobs },

    // com.atproto.identity
    .{ .method = "com.atproto.identity.resolveHandle", .handler = &identity_handlers.resolveHandle },
    .{ .method = "com.atproto.identity.updateHandle", .handler = &identity_handlers.updateHandle },

    // com.atproto.label
    .{ .method = "com.atproto.label.queryLabels", .handler = &label_handlers.queryLabels },

    // com.atproto.moderation
    .{ .method = "com.atproto.moderation.createReport", .handler = &moderation_handlers.createReport },
};

/// Adapter for describeServer which doesn't take Storage.
fn describeServerAdapter(allocator: std.mem.Allocator, _: Storage, cfg: PdsConfig, input: XrpcInput) anyerror!XrpcOutput {
    return server_handlers.describeServer(allocator, cfg, input);
}

/// Dispatch an XRPC method to the appropriate handler.
/// Returns MethodNotImplemented for unknown methods.
pub fn dispatch(
    method: []const u8,
    allocator: std.mem.Allocator,
    store: Storage,
    cfg: PdsConfig,
    input: XrpcInput,
) !XrpcOutput {
    for (&routes) |*route| {
        if (std.mem.eql(u8, route.method, method)) {
            return route.handler(allocator, store, cfg, input);
        }
    }
    return XrpcOutput.errResponse(501, "MethodNotImplemented", "XRPC method not implemented");
}

/// List all supported XRPC methods.
pub fn listMethods() []const []const u8 {
    comptime {
        var methods: [routes.len][]const u8 = undefined;
        for (&routes, 0..) |*route, i| {
            methods[i] = route.method;
        }
        return &methods;
    }
}

test "dispatch known method" {
    const allocator = std.testing.allocator;
    var mem = storage_mod.MemoryStorage.init(allocator);
    defer mem.deinit();

    const cfg = PdsConfig{
        .did = "did:web:test",
        .hostname = "test",
        .service_endpoint = "https://test",
        .available_user_domains = &.{},
        .jwt_secret = "secret",
    };

    const result = try dispatch("com.atproto.server.describeServer", allocator, mem.storage(), cfg, .{});
    switch (result) {
        .success => |s| {
            defer allocator.free(s.body);
            try std.testing.expect(std.mem.indexOf(u8, s.body, "did:web:test") != null);
        },
        else => return error.UnexpectedResult,
    }
}

test "dispatch unknown method returns 501" {
    const allocator = std.testing.allocator;
    var mem = storage_mod.MemoryStorage.init(allocator);
    defer mem.deinit();

    const cfg = PdsConfig{
        .did = "did:web:test",
        .hostname = "test",
        .service_endpoint = "https://test",
        .available_user_domains = &.{},
        .jwt_secret = "secret",
    };

    const result = try dispatch("com.atproto.nonexistent.method", allocator, mem.storage(), cfg, .{});
    switch (result) {
        .err => |e| try std.testing.expectEqual(@as(u16, 501), e.status),
        else => return error.UnexpectedResult,
    }
}
