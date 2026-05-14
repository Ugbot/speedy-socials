//! NodeInfo 2.1 + JRD discovery responses.
//!
//! Two endpoints will be served when the plugin wires routes in Phase 3
//! integration:
//!
//!   GET /.well-known/nodeinfo          → JRD pointing at the doc
//!   GET /nodeinfo/2.1                  → the NodeInfo 2.1 document
//!
//! Both responses are deterministic strings derived from a `Config`
//! supplied at startup (no allocator). Stats live in storage and will be
//! merged in by the route handler once Phase 2 lands.

const std = @import("std");

pub const Config = struct {
    /// The instance hostname, e.g. `social.example.com`.
    hostname: []const u8,
    /// Software version string published by NodeInfo (`software.version`).
    software_version: []const u8 = "0.1.0",
    /// Whether registration is open. NodeInfo `openRegistrations`.
    open_registrations: bool = false,
};

pub const max_jrd_bytes: usize = 512;
pub const max_nodeinfo_bytes: usize = 2048;

pub const WriteError = error{BufferTooSmall};

const W = struct {
    buf: []u8,
    pos: usize = 0,

    fn writeAll(self: *W, s: []const u8) WriteError!void {
        if (self.pos + s.len > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos .. self.pos + s.len], s);
        self.pos += s.len;
    }

    fn print(self: *W, comptime fmt: []const u8, args: anytype) WriteError!void {
        const rem = self.buf[self.pos..];
        const got = std.fmt.bufPrint(rem, fmt, args) catch return error.BufferTooSmall;
        self.pos += got.len;
    }

    fn slice(self: *W) []const u8 {
        return self.buf[0..self.pos];
    }
};

/// Write the `/.well-known/nodeinfo` JRD response into `out`.
pub fn writeJrd(cfg: Config, out: []u8) WriteError![]const u8 {
    var w = W{ .buf = out };
    try w.writeAll("{\"links\":[{\"rel\":\"http://nodeinfo.diaspora.software/ns/schema/2.1\",\"href\":\"https://");
    try w.writeAll(cfg.hostname);
    try w.writeAll("/nodeinfo/2.1\"}]}");
    return w.slice();
}

/// Stats payload patched in by the route handler at request time.
pub const Stats = struct {
    total_users: u64 = 0,
    active_month: u64 = 0,
    active_halfyear: u64 = 0,
    local_posts: u64 = 0,
};

/// Write the NodeInfo 2.1 document.
pub fn writeNodeInfo(cfg: Config, stats: Stats, out: []u8) WriteError![]const u8 {
    var w = W{ .buf = out };
    try w.writeAll(
        "{\"version\":\"2.1\",\"software\":{\"name\":\"speedy-socials\",\"version\":\"",
    );
    try w.writeAll(cfg.software_version);
    try w.writeAll(
        "\",\"repository\":\"https://github.com/anthropics/speedy-socials\"},\"protocols\":[\"activitypub\"]," ++
            "\"services\":{\"inbound\":[],\"outbound\":[]},\"openRegistrations\":",
    );
    try w.writeAll(if (cfg.open_registrations) "true" else "false");
    try w.writeAll(",\"usage\":{\"users\":{\"total\":");
    try w.print("{d},\"activeMonth\":{d},\"activeHalfyear\":{d}", .{
        stats.total_users, stats.active_month, stats.active_halfyear,
    });
    try w.writeAll("},\"localPosts\":");
    try w.print("{d}", .{stats.local_posts});
    try w.writeAll("},\"metadata\":{\"hostname\":\"");
    try w.writeAll(cfg.hostname);
    try w.writeAll("\"}}");
    return w.slice();
}

test "JRD includes nodeinfo 2.1 link" {
    var buf: [max_jrd_bytes]u8 = undefined;
    const out = try writeJrd(.{ .hostname = "example.com" }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "nodeinfo/2.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "example.com") != null);
    try std.testing.expect(std.mem.startsWith(u8, out, "{\"links\""));
}

test "NodeInfo 2.1 document includes required fields" {
    var buf: [max_nodeinfo_bytes]u8 = undefined;
    const out = try writeNodeInfo(.{ .hostname = "x" }, .{
        .total_users = 42,
        .local_posts = 99,
    }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"version\":\"2.1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"activitypub\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"total\":42") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"localPosts\":99") != null);
}

test "openRegistrations toggles correctly" {
    var buf: [max_nodeinfo_bytes]u8 = undefined;
    const open = try writeNodeInfo(.{ .hostname = "x", .open_registrations = true }, .{}, &buf);
    try std.testing.expect(std.mem.indexOf(u8, open, "\"openRegistrations\":true") != null);
    var buf2: [max_nodeinfo_bytes]u8 = undefined;
    const closed = try writeNodeInfo(.{ .hostname = "x", .open_registrations = false }, .{}, &buf2);
    try std.testing.expect(std.mem.indexOf(u8, closed, "\"openRegistrations\":false") != null);
}

test "writeJrd refuses too-small buffer" {
    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, writeJrd(.{ .hostname = "x" }, &tiny));
}
