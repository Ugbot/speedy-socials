const std = @import("std");
const zat = @import("zat");

/// Validate a collection NSID.
pub fn validateCollection(collection: []const u8) bool {
    const nsid = zat.Nsid.parse(collection) catch return false;
    _ = nsid;
    return true;
}

/// Validate a record key.
pub fn validateRkey(rkey: []const u8) bool {
    const parsed = zat.Rkey.parse(rkey) catch return false;
    _ = parsed;
    return true;
}

/// Build an AT-URI from components.
pub fn buildAtUri(allocator: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "at://{s}/{s}/{s}", .{ did, collection, rkey });
}

test "buildAtUri" {
    const uri = try buildAtUri(std.testing.allocator, "did:web:test", "app.bsky.feed.post", "abc123");
    defer std.testing.allocator.free(uri);
    try std.testing.expectEqualStrings("at://did:web:test/app.bsky.feed.post/abc123", uri);
}
