//! WebFinger (RFC 7033) JRD writer.
//!
//! Serves `/.well-known/webfinger?resource=acct:user@host` with two
//! links:
//!   * `self` → `application/activity+json` actor profile
//!   * `profile-page` → `text/html` actor page (stub for now)
//!
//! Tiger Style: fixed-length writes into caller buffer. The deprecated
//! Atom OStatus link is intentionally omitted (PROTOCOL_AUDIT AP-M1).

const std = @import("std");

pub const WriteError = error{ BufferTooSmall, BadResource };

pub const Config = struct {
    hostname: []const u8,
    username: []const u8,
};

pub fn parseResourceParam(resource: []const u8) WriteError!struct { username: []const u8, host: []const u8 } {
    // Expect `acct:user@host`.
    if (!std.mem.startsWith(u8, resource, "acct:")) return error.BadResource;
    const rest = resource[5..];
    const at = std.mem.indexOfScalar(u8, rest, '@') orelse return error.BadResource;
    const user = rest[0..at];
    const host = rest[at + 1 ..];
    if (user.len == 0 or host.len == 0) return error.BadResource;
    return .{ .username = user, .host = host };
}

pub fn writeJrd(cfg: Config, out: []u8) WriteError![]const u8 {
    const fmt =
        "{{\"subject\":\"acct:{s}@{s}\"," ++
        "\"aliases\":[\"https://{s}/users/{s}\",\"https://{s}/@{s}\"]," ++
        "\"links\":[" ++
        "{{\"rel\":\"self\",\"type\":\"application/activity+json\",\"href\":\"https://{s}/users/{s}\"}}," ++
        "{{\"rel\":\"http://webfinger.net/rel/profile-page\",\"type\":\"text/html\",\"href\":\"https://{s}/@{s}\"}}" ++
        "]}}";
    const result = std.fmt.bufPrint(out, fmt, .{
        cfg.username, cfg.hostname,
        cfg.hostname, cfg.username,
        cfg.hostname, cfg.username,
        cfg.hostname, cfg.username,
        cfg.hostname, cfg.username,
    }) catch return error.BufferTooSmall;
    return result;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseResourceParam strips acct: prefix and splits user@host" {
    const r = try parseResourceParam("acct:alice@example.com");
    try testing.expectEqualStrings("alice", r.username);
    try testing.expectEqualStrings("example.com", r.host);
}

test "parseResourceParam rejects bad input" {
    try testing.expectError(error.BadResource, parseResourceParam("alice@example.com"));
    try testing.expectError(error.BadResource, parseResourceParam("acct:foo"));
    try testing.expectError(error.BadResource, parseResourceParam("acct:@x"));
    try testing.expectError(error.BadResource, parseResourceParam("acct:x@"));
}

test "writeJrd emits all required fields" {
    var buf: [1024]u8 = undefined;
    const out = try writeJrd(.{ .hostname = "example.com", .username = "alice" }, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "\"subject\":\"acct:alice@example.com\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"rel\":\"self\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "application/activity+json") != null);
    try testing.expect(std.mem.indexOf(u8, out, "https://example.com/users/alice") != null);
    try testing.expect(std.mem.indexOf(u8, out, "https://example.com/@alice") != null);
    // Deprecated Atom link should NOT appear (AP-M1).
    try testing.expect(std.mem.indexOf(u8, out, "schemas.google.com") == null);
}

test "writeJrd fails on too-small buffer" {
    var tiny: [16]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, writeJrd(.{ .hostname = "x", .username = "y" }, &tiny));
}
