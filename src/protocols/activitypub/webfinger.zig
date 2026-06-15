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
    // AP-28: accept both `acct:user@host` and direct `https://host/users/name`
    // (or `https://host/@name`) form. The Mastodon API + Pleroma + some
    // crawlers send the URL form to dodge the `acct:` parser.
    if (std.mem.startsWith(u8, resource, "acct:")) {
        const rest = resource[5..];
        const at = std.mem.indexOfScalar(u8, rest, '@') orelse return error.BadResource;
        const user = rest[0..at];
        const host = rest[at + 1 ..];
        if (user.len == 0 or host.len == 0) return error.BadResource;
        return .{ .username = user, .host = host };
    }
    if (std.mem.startsWith(u8, resource, "https://")) {
        const after = resource[8..];
        const slash = std.mem.indexOfScalar(u8, after, '/') orelse return error.BadResource;
        const host = after[0..slash];
        const path = after[slash + 1 ..];
        // Accept both `/users/<name>` and `/@<name>`.
        if (std.mem.startsWith(u8, path, "users/")) {
            const user = path[6..];
            if (user.len == 0 or host.len == 0) return error.BadResource;
            // Trim any trailing `/` or `?...` fragment.
            const trim_end = std.mem.indexOfAny(u8, user, "/?#") orelse user.len;
            return .{ .username = user[0..trim_end], .host = host };
        }
        if (std.mem.startsWith(u8, path, "@")) {
            const user = path[1..];
            if (user.len == 0 or host.len == 0) return error.BadResource;
            const trim_end = std.mem.indexOfAny(u8, user, "/?#") orelse user.len;
            return .{ .username = user[0..trim_end], .host = host };
        }
        return error.BadResource;
    }
    return error.BadResource;
}

pub fn writeJrd(cfg: Config, out: []u8) WriteError![]const u8 {
    // DUAL-4: the `at-uri` link advertises the account's AT Protocol
    // identity so an AppView / crawler discovering us over WebFinger can
    // cross to the at:// side. For unified-signup accounts the AP
    // username is the AT handle, so the URI is `at://<username>`.
    const fmt =
        "{{\"subject\":\"acct:{s}@{s}\"," ++
        "\"aliases\":[\"https://{s}/users/{s}\",\"https://{s}/@{s}\"]," ++
        "\"links\":[" ++
        "{{\"rel\":\"self\",\"type\":\"application/activity+json\",\"href\":\"https://{s}/users/{s}\"}}," ++
        "{{\"rel\":\"http://webfinger.net/rel/profile-page\",\"type\":\"text/html\",\"href\":\"https://{s}/@{s}\"}}," ++
        "{{\"rel\":\"https://atproto.com/spec/at-uri\",\"href\":\"at://{s}\"}}" ++
        "]}}";
    const result = std.fmt.bufPrint(out, fmt, .{
        cfg.username, cfg.hostname,
        cfg.hostname, cfg.username,
        cfg.hostname, cfg.username,
        cfg.hostname, cfg.username,
        cfg.hostname, cfg.username,
        cfg.username,
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

test "DUAL-4: writeJrd advertises the at-uri discovery link" {
    var buf: [1024]u8 = undefined;
    const out = try writeJrd(.{ .hostname = "example.com", .username = "alice.example.com" }, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "\"rel\":\"https://atproto.com/spec/at-uri\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"href\":\"at://alice.example.com\"") != null);
}

test "writeJrd fails on too-small buffer" {
    var tiny: [16]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, writeJrd(.{ .hostname = "x", .username = "y" }, &tiny));
}

test "AP-28: parseResourceParam accepts https URL form (/users/<name>)" {
    const r = try parseResourceParam("https://example.com/users/alice");
    try testing.expectEqualStrings("alice", r.username);
    try testing.expectEqualStrings("example.com", r.host);
}

test "AP-28: parseResourceParam accepts https URL form (/@<name>)" {
    const r = try parseResourceParam("https://example.com/@bob");
    try testing.expectEqualStrings("bob", r.username);
    try testing.expectEqualStrings("example.com", r.host);
}

test "AP-28: parseResourceParam trims trailing fragment from URL form" {
    const r = try parseResourceParam("https://example.com/@bob?foo=bar");
    try testing.expectEqualStrings("bob", r.username);
}

test "AP-28: parseResourceParam still rejects total garbage" {
    try testing.expectError(error.BadResource, parseResourceParam("ftp://x/y"));
    try testing.expectError(error.BadResource, parseResourceParam("https://example.com/random/path"));
}
