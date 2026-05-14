//! RFC 7578 `multipart/form-data` parser, bounded.
//!
//! Operates over a single contiguous byte slice (the request body, as
//! the HTTP layer delivers it). Each iteration returns one part with
//! its headers and body slice into the source buffer — zero copies, no
//! allocation.
//!
//! Tiger Style bounds:
//!   * boundary length ≤ `limits.max_multipart_boundary_bytes`
//!   * parts per request ≤ `limits.max_multipart_parts`
//!   * headers per part ≤ `limits.max_multipart_headers_per_part`
//!   * per-part body ≤ `limits.max_upload_bytes` (caller cap)
//!
//! Anything that exceeds these returns `error.PayloadTooLarge` or a
//! more specific malformed-input error; the caller maps it to 413/400.

const std = @import("std");
const limits = @import("core").limits;

pub const Error = error{
    MissingBoundary,
    BoundaryTooLong,
    Malformed,
    TooManyParts,
    TooManyHeaders,
    PayloadTooLarge,
    UnexpectedEnd,
};

pub const Header = struct {
    name: []const u8, // case-insensitive compare; not lowercased in place
    value: []const u8,
};

pub const Part = struct {
    headers: [limits.max_multipart_headers_per_part]Header = undefined,
    header_count: u32 = 0,
    /// Inclusive body slice (without trailing CRLF or boundary).
    body: []const u8 = &.{},

    pub fn header(self: *const Part, name: []const u8) ?[]const u8 {
        var i: u32 = 0;
        while (i < self.header_count) : (i += 1) {
            if (std.ascii.eqlIgnoreCase(self.headers[i].name, name)) {
                return self.headers[i].value;
            }
        }
        return null;
    }

    /// Extract `name="..."` from a Content-Disposition header. Returns
    /// null when absent.
    pub fn dispositionName(self: *const Part) ?[]const u8 {
        return parseDispositionParam(self.header("Content-Disposition") orelse return null, "name");
    }

    /// Extract `filename="..."` from a Content-Disposition header.
    pub fn dispositionFilename(self: *const Part) ?[]const u8 {
        return parseDispositionParam(self.header("Content-Disposition") orelse return null, "filename");
    }

    pub fn contentType(self: *const Part) ?[]const u8 {
        return self.header("Content-Type");
    }
};

/// Parse `Content-Type: multipart/form-data; boundary=...` and return
/// the boundary value (no surrounding quotes). The slice points into
/// `content_type`.
pub fn parseBoundary(content_type: []const u8) Error![]const u8 {
    // Find "boundary=" (case-insensitive) followed by a token or quoted-string.
    var i: usize = 0;
    while (i + 9 <= content_type.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(content_type[i .. i + 9], "boundary=")) {
            var s = content_type[i + 9 ..];
            // Strip surrounding quotes if present.
            if (s.len >= 2 and s[0] == '"') {
                const end = std.mem.indexOfScalar(u8, s[1..], '"') orelse return error.Malformed;
                s = s[1 .. 1 + end];
            } else {
                // Stop at the next ';' or whitespace.
                var j: usize = 0;
                while (j < s.len) : (j += 1) {
                    const ch = s[j];
                    if (ch == ';' or ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n') break;
                }
                s = s[0..j];
            }
            if (s.len == 0) return error.MissingBoundary;
            if (s.len > limits.max_multipart_boundary_bytes) return error.BoundaryTooLong;
            return s;
        }
    }
    return error.MissingBoundary;
}

/// Iterate over parts in `body`, given the boundary from the
/// Content-Type. Returns the count of parts written to `out` and asserts
/// `out.len >= limits.max_multipart_parts`. Anything over the cap →
/// `error.TooManyParts`.
pub fn parseAll(
    body: []const u8,
    boundary: []const u8,
    out: []Part,
) Error!u32 {
    std.debug.assert(out.len >= limits.max_multipart_parts);
    if (boundary.len == 0) return error.MissingBoundary;
    if (boundary.len > limits.max_multipart_boundary_bytes) return error.BoundaryTooLong;

    // Build "--<boundary>" prefix on the stack.
    var prefix_buf: [limits.max_multipart_boundary_bytes + 4]u8 = undefined;
    prefix_buf[0] = '-';
    prefix_buf[1] = '-';
    @memcpy(prefix_buf[2 .. 2 + boundary.len], boundary);
    const prefix = prefix_buf[0 .. 2 + boundary.len];

    // Find first delimiter.
    var pos = std.mem.indexOf(u8, body, prefix) orelse return error.Malformed;
    pos += prefix.len;

    var count: u32 = 0;
    while (true) {
        // After a delimiter we expect either "--" (final marker) or CRLF.
        if (pos + 2 <= body.len and body[pos] == '-' and body[pos + 1] == '-') {
            // Final boundary. Anything after (epilogue) is ignored.
            return count;
        }
        if (pos + 2 > body.len) return error.UnexpectedEnd;
        if (body[pos] != '\r' or body[pos + 1] != '\n') return error.Malformed;
        pos += 2;

        if (count >= limits.max_multipart_parts) return error.TooManyParts;

        // Parse headers until blank line.
        var part: Part = .{};
        while (true) {
            const line_end = std.mem.indexOfPos(u8, body, pos, "\r\n") orelse return error.UnexpectedEnd;
            const line = body[pos..line_end];
            pos = line_end + 2;
            if (line.len == 0) break; // end of headers

            if (part.header_count >= limits.max_multipart_headers_per_part) {
                return error.TooManyHeaders;
            }
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.Malformed;
            const name = line[0..colon];
            // Trim leading whitespace from value.
            var v_start: usize = colon + 1;
            while (v_start < line.len and (line[v_start] == ' ' or line[v_start] == '\t')) v_start += 1;
            part.headers[part.header_count] = .{ .name = name, .value = line[v_start..] };
            part.header_count += 1;
        }

        // Body runs up to "\r\n--<boundary>".
        // Build the in-body delimiter: CRLF + prefix.
        var delim_buf: [2 + limits.max_multipart_boundary_bytes + 2]u8 = undefined;
        delim_buf[0] = '\r';
        delim_buf[1] = '\n';
        @memcpy(delim_buf[2 .. 2 + prefix.len], prefix);
        const delim = delim_buf[0 .. 2 + prefix.len];

        const next = std.mem.indexOfPos(u8, body, pos, delim) orelse return error.UnexpectedEnd;
        part.body = body[pos..next];
        if (part.body.len > limits.max_upload_bytes) return error.PayloadTooLarge;
        pos = next + delim.len;

        out[count] = part;
        count += 1;
    }
}

/// Locate `param="..."` (RFC 7578 §4.2 only handles the quoted form
/// reliably). Returns the unquoted value on success.
fn parseDispositionParam(header: []const u8, param: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < header.len) : (i += 1) {
        // Find the parameter name preceded by ';' or start.
        if (i + param.len + 2 > header.len) break;
        const ok_pos = (i == 0) or (header[i - 1] == ';' or header[i - 1] == ' ' or header[i - 1] == '\t');
        if (!ok_pos) continue;
        if (!std.ascii.eqlIgnoreCase(header[i .. i + param.len], param)) continue;
        const after = i + param.len;
        if (after >= header.len or header[after] != '=') continue;
        var s = header[after + 1 ..];
        if (s.len >= 2 and s[0] == '"') {
            const end = std.mem.indexOfScalar(u8, s[1..], '"') orelse return null;
            return s[1 .. 1 + end];
        }
        var j: usize = 0;
        while (j < s.len and s[j] != ';' and s[j] != ' ' and s[j] != '\t') : (j += 1) {}
        return s[0..j];
    }
    return null;
}

// ── tests ──────────────────────────────────────────────────────────

test "parseBoundary: simple token" {
    const ct = "multipart/form-data; boundary=----WebKitFormBoundary7MA4";
    const b = try parseBoundary(ct);
    try std.testing.expectEqualStrings("----WebKitFormBoundary7MA4", b);
}

test "parseBoundary: quoted" {
    const ct = "multipart/form-data; boundary=\"abc; xyz\"";
    const b = try parseBoundary(ct);
    try std.testing.expectEqualStrings("abc; xyz", b);
}

test "parseBoundary: missing returns error" {
    const ct = "multipart/form-data";
    try std.testing.expectError(error.MissingBoundary, parseBoundary(ct));
}

test "parseAll: single text field" {
    const boundary = "X";
    const body =
        "--X\r\n" ++
        "Content-Disposition: form-data; name=\"hello\"\r\n" ++
        "\r\n" ++
        "world" ++
        "\r\n--X--\r\n";
    var parts: [limits.max_multipart_parts]Part = undefined;
    const n = try parseAll(body, boundary, &parts);
    try std.testing.expectEqual(@as(u32, 1), n);
    try std.testing.expectEqualStrings("world", parts[0].body);
    try std.testing.expectEqualStrings("hello", parts[0].dispositionName().?);
}

test "parseAll: single file part" {
    const boundary = "B";
    const body =
        "--B\r\n" ++
        "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "\r\n" ++
        "abc" ++
        "\r\n--B--\r\n";
    var parts: [limits.max_multipart_parts]Part = undefined;
    const n = try parseAll(body, boundary, &parts);
    try std.testing.expectEqual(@as(u32, 1), n);
    try std.testing.expectEqualStrings("abc", parts[0].body);
    try std.testing.expectEqualStrings("file", parts[0].dispositionName().?);
    try std.testing.expectEqualStrings("a.txt", parts[0].dispositionFilename().?);
    try std.testing.expectEqualStrings("text/plain", parts[0].contentType().?);
}

test "parseAll: mixed parts" {
    const boundary = "Z";
    const body =
        "--Z\r\n" ++
        "Content-Disposition: form-data; name=\"description\"\r\n" ++
        "\r\n" ++
        "an image" ++
        "\r\n--Z\r\n" ++
        "Content-Disposition: form-data; name=\"file\"; filename=\"img.png\"\r\n" ++
        "Content-Type: image/png\r\n" ++
        "\r\n" ++
        "BIN" ++
        "\r\n--Z--\r\n";
    var parts: [limits.max_multipart_parts]Part = undefined;
    const n = try parseAll(body, boundary, &parts);
    try std.testing.expectEqual(@as(u32, 2), n);
    try std.testing.expectEqualStrings("an image", parts[0].body);
    try std.testing.expectEqualStrings("BIN", parts[1].body);
    try std.testing.expectEqualStrings("image/png", parts[1].contentType().?);
}

test "parseAll: malformed without delimiter is rejected" {
    const boundary = "Q";
    const body = "no boundary here";
    var parts: [limits.max_multipart_parts]Part = undefined;
    try std.testing.expectError(error.Malformed, parseAll(body, boundary, &parts));
}

test "parseAll: rejects too-long boundary at parse time" {
    var huge: [limits.max_multipart_boundary_bytes + 8]u8 = undefined;
    @memset(&huge, 'A');
    var parts: [limits.max_multipart_parts]Part = undefined;
    try std.testing.expectError(error.BoundaryTooLong, parseAll("--AAA--", &huge, &parts));
}

test "parseAll: rejects oversize part body" {
    // Build a part whose body exceeds max_upload_bytes by 1.
    const boundary = "P";
    const head = "--P\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n";
    const tail = "\r\n--P--\r\n";
    const big = limits.max_upload_bytes + 1;
    const total = head.len + big + tail.len;
    const buf = try std.testing.allocator.alloc(u8, total);
    defer std.testing.allocator.free(buf);
    @memcpy(buf[0..head.len], head);
    @memset(buf[head.len .. head.len + big], 'x');
    @memcpy(buf[head.len + big ..], tail);

    var parts: [limits.max_multipart_parts]Part = undefined;
    try std.testing.expectError(error.PayloadTooLarge, parseAll(buf, boundary, &parts));
}
