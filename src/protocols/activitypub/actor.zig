//! Build the `Person` JSON-LD actor document.
//!
//! Mastodon expects:
//!   * `id`, `type`, `preferredUsername`, `inbox`, `outbox`, `followers`,
//!     `following`, `featured`, `endpoints.sharedInbox`
//!   * `publicKey` object with `id`, `owner`, `publicKeyPem`
//!   * `manuallyApprovesFollowers` (AS extension)
//!   * `discoverable`, `indexable` (toot:)
//!
//! Tiger Style: caller-supplied output buffer.

const std = @import("std");

pub const WriteError = error{BufferTooSmall};

pub const Config = struct {
    hostname: []const u8,
    username: []const u8,
    display_name: []const u8 = "",
    bio: []const u8 = "",
    public_key_pem: []const u8 = "",
    /// True if the account is locked / approves followers manually.
    manually_approves_followers: bool = false,
    discoverable: bool = true,
    indexable: bool = true,
};

pub fn writePerson(cfg: Config, out: []u8) WriteError![]const u8 {
    // Build using bufPrint segments to keep within line-length but
    // produce a single contiguous JSON-LD object.
    var w: usize = 0;
    w += try copy(out[w..],
        "{\"@context\":[\"https://www.w3.org/ns/activitystreams\"," ++
        "{\"toot\":\"http://joinmastodon.org/ns#\"," ++
        "\"discoverable\":\"toot:discoverable\"," ++
        "\"indexable\":\"toot:indexable\"," ++
        "\"featured\":{\"@id\":\"toot:featured\",\"@type\":\"@id\"}," ++
        "\"manuallyApprovesFollowers\":\"as:manuallyApprovesFollowers\"}],");
    w += try fmtInto(out[w..], "\"id\":\"https://{s}/users/{s}\",", .{ cfg.hostname, cfg.username });
    w += try copy(out[w..], "\"type\":\"Person\",");
    w += try fmtInto(out[w..], "\"preferredUsername\":\"{s}\",", .{cfg.username});
    if (cfg.display_name.len > 0) {
        w += try fmtInto(out[w..], "\"name\":\"{s}\",", .{cfg.display_name});
    }
    if (cfg.bio.len > 0) {
        w += try fmtInto(out[w..], "\"summary\":\"{s}\",", .{cfg.bio});
    }
    w += try fmtInto(out[w..],
        "\"inbox\":\"https://{s}/users/{s}/inbox\"," ++
        "\"outbox\":\"https://{s}/users/{s}/outbox\"," ++
        "\"followers\":\"https://{s}/users/{s}/followers\"," ++
        "\"following\":\"https://{s}/users/{s}/following\"," ++
        "\"featured\":\"https://{s}/users/{s}/collections/featured\"," ++
        "\"endpoints\":{{\"sharedInbox\":\"https://{s}/inbox\"}},",
        .{
            cfg.hostname, cfg.username,
            cfg.hostname, cfg.username,
            cfg.hostname, cfg.username,
            cfg.hostname, cfg.username,
            cfg.hostname, cfg.username,
            cfg.hostname,
        });
    w += try fmtInto(out[w..], "\"manuallyApprovesFollowers\":{s},", .{
        if (cfg.manually_approves_followers) "true" else "false",
    });
    w += try fmtInto(out[w..], "\"discoverable\":{s},", .{
        if (cfg.discoverable) "true" else "false",
    });
    w += try fmtInto(out[w..], "\"indexable\":{s},", .{
        if (cfg.indexable) "true" else "false",
    });
    // publicKey
    w += try fmtInto(out[w..],
        "\"publicKey\":{{\"id\":\"https://{s}/users/{s}#main-key\"," ++
        "\"owner\":\"https://{s}/users/{s}\",\"publicKeyPem\":\"",
        .{ cfg.hostname, cfg.username, cfg.hostname, cfg.username });
    // PEM contains newlines — JSON-escape them to `\n`.
    w += try escapePem(out[w..], cfg.public_key_pem);
    w += try copy(out[w..], "\"}}");
    return out[0..w];
}

fn copy(dest: []u8, src: []const u8) WriteError!usize {
    if (src.len > dest.len) return error.BufferTooSmall;
    @memcpy(dest[0..src.len], src);
    return src.len;
}

fn fmtInto(dest: []u8, comptime fmt: []const u8, args: anytype) WriteError!usize {
    const got = std.fmt.bufPrint(dest, fmt, args) catch return error.BufferTooSmall;
    return got.len;
}

fn escapePem(dest: []u8, pem: []const u8) WriteError!usize {
    var w: usize = 0;
    for (pem) |ch| {
        if (ch == '\n') {
            if (w + 2 > dest.len) return error.BufferTooSmall;
            dest[w] = '\\';
            dest[w + 1] = 'n';
            w += 2;
        } else if (ch == '"') {
            if (w + 2 > dest.len) return error.BufferTooSmall;
            dest[w] = '\\';
            dest[w + 1] = '"';
            w += 2;
        } else if (ch == '\\') {
            if (w + 2 > dest.len) return error.BufferTooSmall;
            dest[w] = '\\';
            dest[w + 1] = '\\';
            w += 2;
        } else {
            if (w + 1 > dest.len) return error.BufferTooSmall;
            dest[w] = ch;
            w += 1;
        }
    }
    return w;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "writePerson includes Mastodon-extension fields" {
    var buf: [4096]u8 = undefined;
    const out = try writePerson(.{
        .hostname = "example.com",
        .username = "alice",
        .display_name = "Alice",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----",
        .manually_approves_followers = true,
    }, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "\"type\":\"Person\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"preferredUsername\":\"alice\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"name\":\"Alice\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "https://example.com/users/alice/inbox") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"sharedInbox\":\"https://example.com/inbox\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"manuallyApprovesFollowers\":true") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"discoverable\":true") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"indexable\":true") != null);
    try testing.expect(std.mem.indexOf(u8, out, "publicKey") != null);
    // PEM newlines are escaped.
    try testing.expect(std.mem.indexOf(u8, out, "BEGIN PUBLIC KEY-----\\nABC") != null);
}

test "writePerson with empty optional fields" {
    var buf: [4096]u8 = undefined;
    const out = try writePerson(.{ .hostname = "h", .username = "u" }, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "\"name\"") == null);
    try testing.expect(std.mem.indexOf(u8, out, "\"summary\"") == null);
    try testing.expect(std.mem.indexOf(u8, out, "\"manuallyApprovesFollowers\":false") != null);
}

test "writePerson fails when buffer too small" {
    var tiny: [16]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, writePerson(.{ .hostname = "h", .username = "u" }, &tiny));
}
