//! HTTP Transport - isolates HTTP client for 0.16 migration
//!
//! wraps std.http.Client to provide a single point of change
//! when zig 0.16 moves HTTP to std.Io interface.
//!
//! 0.16 migration plan:
//! - add `io: std.Io` field
//! - add `initWithIo(io: std.Io, allocator: Allocator)` constructor
//! - update fetch() to use io.http or equivalent

const std = @import("std");

pub const HttpTransport = struct {
    allocator: std.mem.Allocator,
    http_client: std.http.Client,
    keep_alive: bool = true,

    // 0.16: will add
    // io: ?std.Io = null,

    pub fn init(allocator: std.mem.Allocator) HttpTransport {
        return .{
            .allocator = allocator,
            .http_client = .{ .allocator = allocator },
        };
    }

    // 0.16: will add
    // pub fn initWithIo(io: std.Io, allocator: std.mem.Allocator) HttpTransport {
    //     return .{
    //         .allocator = allocator,
    //         .http_client = .{ .allocator = allocator },
    //         .io = io,
    //     };
    // }

    pub fn deinit(self: *HttpTransport) void {
        self.http_client.deinit();
    }

    /// fetch a URL and write response to provided writer
    pub fn fetch(self: *HttpTransport, options: FetchOptions) !FetchResult {
        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        var headers: std.http.Client.Request.Headers = .{
            .accept_encoding = .{ .override = "identity" }, // disable gzip - zig stdlib issue
            .content_type = if (options.payload != null) .{ .override = "application/json" } else .default,
        };

        // apply custom headers
        if (options.authorization) |auth| {
            headers.authorization = .{ .override = auth };
        }
        if (options.content_type) |ct| {
            headers.content_type = .{ .override = ct };
        }

        // build extra headers array for accept and any custom headers
        var extra_buf: [8]std.http.Header = undefined;
        var extra_count: usize = 0;

        if (options.accept) |accept| {
            extra_buf[extra_count] = .{ .name = "accept", .value = accept };
            extra_count += 1;
        }

        if (options.extra_headers) |hdrs| {
            for (hdrs) |h| {
                if (extra_count < extra_buf.len) {
                    extra_buf[extra_count] = h;
                    extra_count += 1;
                }
            }
        }

        const result = self.http_client.fetch(.{
            .location = .{ .url = options.url },
            .response_writer = &aw.writer,
            .method = options.method,
            .payload = options.payload,
            .headers = headers,
            .extra_headers = extra_buf[0..extra_count],
            .keep_alive = self.keep_alive,
        }) catch return error.RequestFailed;

        return .{
            .status = result.status,
            .body = try self.allocator.dupe(u8, aw.written()),
        };
    }

    pub const FetchOptions = struct {
        url: []const u8,
        method: std.http.Method = .GET,
        payload: ?[]const u8 = null,
        authorization: ?[]const u8 = null,
        accept: ?[]const u8 = null,
        content_type: ?[]const u8 = null,
        extra_headers: ?[]const std.http.Header = null,
    };

    pub const FetchResult = struct {
        status: std.http.Status,
        body: []u8,
    };
};

// === tests ===

test "transport init/deinit" {
    var transport = HttpTransport.init(std.testing.allocator);
    defer transport.deinit();
}
