const std = @import("std");
const config_mod = @import("../config.zig");
const PdsConfig = config_mod.PdsConfig;

/// Returns the DID string for /.well-known/atproto-did.
/// Per spec, this returns just the DID as text/plain.
pub fn atprotoDid(cfg: PdsConfig) []const u8 {
    return cfg.did;
}

/// Generate the WebFinger response for a user.
pub fn webfingerResponse(
    allocator: std.mem.Allocator,
    handle: []const u8,
    hostname: []const u8,
    actor_url: []const u8,
) ![]const u8 {
    const subject = try std.fmt.allocPrint(allocator, "acct:{s}@{s}", .{ handle, hostname });
    defer allocator.free(subject);

    return std.json.Stringify.valueAlloc(allocator, .{
        .subject = subject,
        .links = &[_]struct {
            rel: []const u8,
            type: []const u8,
            href: []const u8,
        }{.{
            .rel = "self",
            .type = "application/activity+json",
            .href = actor_url,
        }},
    }, .{});
}

test "atprotoDid returns plain DID" {
    const cfg = PdsConfig{
        .did = "did:web:example.com",
        .hostname = "example.com",
        .service_endpoint = "https://example.com",
        .available_user_domains = &.{},
        .jwt_secret = "secret",
    };
    try std.testing.expectEqualStrings("did:web:example.com", atprotoDid(cfg));
}
