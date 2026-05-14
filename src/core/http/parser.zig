//! HTTP/1.1 request parser.
//!
//! Single pass over the connection's read buffer. Headers stored in a
//! fixed-capacity array provided by the caller — no heap.
//!
//! Tiger Style: bounded everything. A malformed or oversized request
//! returns a specific error, never panics.

const std = @import("std");
const limits = @import("../limits.zig");
const errors = @import("../errors.zig");
const HttpError = errors.HttpError;
const req_mod = @import("request.zig");
const assert_mod = @import("../assert.zig");
const assertLe = assert_mod.assertLe;

pub const HeaderArray = [limits.max_http_headers]req_mod.Header;

/// Parse result. `consumed` is the number of bytes from the start of
/// `bytes` that contained the head (request line + headers + CRLFCRLF).
/// `body` is whatever bytes remained after the head, up to Content-Length.
pub const Parsed = struct {
    request: req_mod.Request,
    consumed: usize,
};

/// Parse an HTTP request from `bytes`. `headers_out` is a caller-provided
/// fixed array; the request's `headers` slice points into it.
///
/// Returns `HttpError.UnexpectedEof` if the buffer does not yet contain
/// a full head (caller should read more bytes and retry).
pub fn parse(bytes: []const u8, headers_out: *HeaderArray) HttpError!Parsed {
    var p: usize = 0;

    // Request line: METHOD SP TARGET SP VERSION CRLF
    const sp1 = std.mem.indexOfScalar(u8, bytes[p..], ' ') orelse return error.UnexpectedEof;
    const method_raw = bytes[p .. p + sp1];
    if (method_raw.len == 0) return error.MalformedRequestLine;
    if (method_raw.len > limits.max_http_method_bytes) return error.MethodTooLong;
    p += sp1 + 1;

    const sp2_rel = std.mem.indexOfScalar(u8, bytes[p..], ' ') orelse return error.UnexpectedEof;
    const target = bytes[p .. p + sp2_rel];
    if (target.len == 0) return error.MalformedRequestLine;
    if (target.len > limits.max_http_target_bytes) return error.TargetTooLong;
    p += sp2_rel + 1;

    const crlf1_rel = std.mem.indexOf(u8, bytes[p..], "\r\n") orelse return error.UnexpectedEof;
    const version = bytes[p .. p + crlf1_rel];
    if (!std.mem.startsWith(u8, version, "HTTP/")) return error.MalformedRequestLine;
    p += crlf1_rel + 2;

    // Headers until empty line.
    var header_count: u32 = 0;
    while (true) {
        if (p + 1 >= bytes.len) return error.UnexpectedEof;
        if (bytes[p] == '\r' and bytes[p + 1] == '\n') {
            p += 2;
            break;
        }
        const crlf_rel = std.mem.indexOf(u8, bytes[p..], "\r\n") orelse return error.UnexpectedEof;
        const line = bytes[p .. p + crlf_rel];
        if (line.len > limits.max_http_header_bytes) return error.HeaderTooLarge;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHeader;
        const name = line[0..colon];
        if (name.len == 0) return error.MalformedHeader;
        var v_start: usize = colon + 1;
        while (v_start < line.len and (line[v_start] == ' ' or line[v_start] == '\t')) v_start += 1;
        var v_end: usize = line.len;
        while (v_end > v_start and (line[v_end - 1] == ' ' or line[v_end - 1] == '\t')) v_end -= 1;
        const value = line[v_start..v_end];

        if (header_count >= limits.max_http_headers) return error.TooManyHeaders;
        headers_out[header_count] = .{ .name = name, .value = value };
        header_count += 1;
        p += crlf_rel + 2;
    }

    const headers_slice = headers_out[0..header_count];

    // Body — bounded by Content-Length, if present.
    var body_len: usize = 0;
    for (headers_slice) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "content-length")) {
            body_len = std.fmt.parseInt(usize, h.value, 10) catch return error.BadRequest;
            break;
        }
    }
    if (body_len > limits.conn_read_buffer_bytes) return error.PayloadTooLarge;
    if (p + body_len > bytes.len) return error.UnexpectedEof;
    const body = bytes[p .. p + body_len];

    return .{
        .request = .{
            .method = req_mod.Method.parse(method_raw),
            .method_raw = method_raw,
            .target = target,
            .version = version,
            .headers = headers_slice,
            .body = body,
        },
        .consumed = p + body_len,
    };
}

test "parse simple GET" {
    const raw = "GET /hello HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n";
    var hdrs: HeaderArray = undefined;
    const p = try parse(raw, &hdrs);
    try std.testing.expectEqual(req_mod.Method.get, p.request.method);
    try std.testing.expectEqualStrings("/hello", p.request.target);
    try std.testing.expectEqualStrings("example.com", p.request.header("host").?);
    try std.testing.expectEqual(@as(usize, raw.len), p.consumed);
}

test "parse POST with body" {
    const raw = "POST /post HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
    var hdrs: HeaderArray = undefined;
    const p = try parse(raw, &hdrs);
    try std.testing.expectEqual(req_mod.Method.post, p.request.method);
    try std.testing.expectEqualStrings("hello", p.request.body);
}

test "parse rejects truncated head" {
    const raw = "GET /x HTTP/1.1\r\nHost: x";
    var hdrs: HeaderArray = undefined;
    try std.testing.expectError(error.UnexpectedEof, parse(raw, &hdrs));
}

test "parse rejects too many headers" {
    var buf: [8192]u8 = undefined;
    var pos: usize = 0;
    {
        const line = "GET / HTTP/1.1\r\n";
        @memcpy(buf[pos..][0..line.len], line);
        pos += line.len;
    }
    var i: u32 = 0;
    while (i < limits.max_http_headers + 4) : (i += 1) {
        const written = try std.fmt.bufPrint(buf[pos..], "X-H{d}: v\r\n", .{i});
        pos += written.len;
    }
    @memcpy(buf[pos..][0..2], "\r\n");
    pos += 2;
    var hdrs: HeaderArray = undefined;
    try std.testing.expectError(error.TooManyHeaders, parse(buf[0..pos], &hdrs));
}
