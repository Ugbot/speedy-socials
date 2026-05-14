//! Parsed HTTP/1.1 request (read-only view over the connection's read
//! buffer).
//!
//! No allocations: method, target, headers all reference slices of the
//! source bytes. The request lives only as long as the connection's
//! request arena.

const std = @import("std");
const limits = @import("../limits.zig");
const HttpError = @import("../errors.zig").HttpError;
const assert_mod = @import("../assert.zig");
const assertLe = assert_mod.assertLe;

pub const Method = enum {
    get,
    head,
    post,
    put,
    delete,
    patch,
    options,
    other,

    pub fn parse(text: []const u8) Method {
        if (std.ascii.eqlIgnoreCase(text, "GET")) return .get;
        if (std.ascii.eqlIgnoreCase(text, "HEAD")) return .head;
        if (std.ascii.eqlIgnoreCase(text, "POST")) return .post;
        if (std.ascii.eqlIgnoreCase(text, "PUT")) return .put;
        if (std.ascii.eqlIgnoreCase(text, "DELETE")) return .delete;
        if (std.ascii.eqlIgnoreCase(text, "PATCH")) return .patch;
        if (std.ascii.eqlIgnoreCase(text, "OPTIONS")) return .options;
        return .other;
    }
};

pub const Header = struct {
    name: []const u8, // not lowercased; compare case-insensitively
    value: []const u8,
};

pub const Request = struct {
    method: Method,
    method_raw: []const u8,
    target: []const u8, // path?query, undecoded
    version: []const u8, // e.g. "HTTP/1.1"
    headers: []const Header,
    body: []const u8,

    pub fn header(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    /// Split target into path and query (raw — caller decodes as needed).
    pub fn pathAndQuery(self: *const Request) struct { path: []const u8, query: []const u8 } {
        const t = self.target;
        if (std.mem.indexOfScalar(u8, t, '?')) |q| {
            return .{ .path = t[0..q], .query = t[q + 1 ..] };
        }
        return .{ .path = t, .query = "" };
    }
};
