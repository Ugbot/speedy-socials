//! HTTP/1.1 response builder writing into a fixed buffer.
//!
//! Tiger Style: bounded. Overflow returns HttpError.ResponseBufferFull
//! rather than reallocating.

const std = @import("std");
const HttpError = @import("../errors.zig").HttpError;

pub const Status = enum(u16) {
    ok = 200,
    created = 201,
    no_content = 204,
    moved_permanently = 301,
    found = 302,
    not_modified = 304,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    conflict = 409,
    gone = 410,
    payload_too_large = 413,
    unsupported_media = 415,
    too_many_requests = 429,
    internal = 500,
    not_implemented = 501,
    service_unavailable = 503,

    pub fn reason(self: Status) []const u8 {
        return switch (self) {
            .ok => "OK",
            .created => "Created",
            .no_content => "No Content",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .not_modified => "Not Modified",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .conflict => "Conflict",
            .gone => "Gone",
            .payload_too_large => "Payload Too Large",
            .unsupported_media => "Unsupported Media Type",
            .too_many_requests => "Too Many Requests",
            .internal => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .service_unavailable => "Service Unavailable",
        };
    }
};

pub const Builder = struct {
    buffer: []u8,
    pos: usize,
    headers_finalized: bool,

    pub fn init(buffer: []u8) Builder {
        return .{ .buffer = buffer, .pos = 0, .headers_finalized = false };
    }

    fn writeAll(self: *Builder, payload_bytes: []const u8) HttpError!void {
        if (self.pos + payload_bytes.len > self.buffer.len) return error.ResponseBufferFull;
        @memcpy(self.buffer[self.pos..][0..payload_bytes.len], payload_bytes);
        self.pos += payload_bytes.len;
    }

    fn writeFmt(self: *Builder, comptime fmt: []const u8, args: anytype) HttpError!void {
        const remaining = self.buffer[self.pos..];
        const written = std.fmt.bufPrint(remaining, fmt, args) catch return error.ResponseBufferFull;
        self.pos += written.len;
    }

    pub fn startStatus(self: *Builder, status: Status) HttpError!void {
        try self.writeFmt("HTTP/1.1 {d} {s}\r\n", .{ @intFromEnum(status), status.reason() });
    }

    pub fn header(self: *Builder, name: []const u8, value: []const u8) HttpError!void {
        try self.writeAll(name);
        try self.writeAll(": ");
        try self.writeAll(value);
        try self.writeAll("\r\n");
    }

    pub fn headerFmt(self: *Builder, name: []const u8, comptime fmt: []const u8, args: anytype) HttpError!void {
        try self.writeAll(name);
        try self.writeAll(": ");
        try self.writeFmt(fmt, args);
        try self.writeAll("\r\n");
    }

    pub fn finishHeaders(self: *Builder) HttpError!void {
        try self.writeAll("\r\n");
        self.headers_finalized = true;
    }

    pub fn body(self: *Builder, payload_bytes: []const u8) HttpError!void {
        try self.writeAll(payload_bytes);
    }

    /// Convenience: write a complete response with content-type and body
    /// known up front.
    pub fn simple(self: *Builder, status: Status, content_type: []const u8, payload: []const u8) HttpError!void {
        try self.startStatus(status);
        try self.header("Content-Type", content_type);
        try self.headerFmt("Content-Length", "{d}", .{payload.len});
        try self.header("Connection", "close");
        try self.finishHeaders();
        try self.body(payload);
    }

    pub fn bytes(self: *const Builder) []const u8 {
        return self.buffer[0..self.pos];
    }
};

test "Builder simple 200" {
    var buf: [256]u8 = undefined;
    var b = Builder.init(&buf);
    try b.simple(.ok, "text/plain", "hello");
    const out = b.bytes();
    try std.testing.expect(std.mem.startsWith(u8, out, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, out, "\r\n\r\nhello"));
}

test "Builder rejects overflow" {
    var buf: [32]u8 = undefined;
    var b = Builder.init(&buf);
    try std.testing.expectError(error.ResponseBufferFull, b.simple(.ok, "text/plain", "a very long body that does not fit"));
}
