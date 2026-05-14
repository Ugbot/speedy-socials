//! Shared HTTP helpers for the Mastodon plugin.
//!
//! Mirrors `xrpc.zig` from the AT Protocol plugin: a handful of
//! allocation-free helpers for writing JSON bodies, parsing query
//! parameters, and looking up bearer tokens.

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;
const Status = core.http.response.Status;

pub fn writeJsonBody(hc: *HandlerContext, status: Status, body: []const u8) !void {
    try hc.response.startStatus(status);
    try hc.response.header("Content-Type", "application/json; charset=utf-8");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

pub fn writeError(hc: *HandlerContext, status: Status, message: []const u8) !void {
    var buf: [512]u8 = undefined;
    const body = std.fmt.bufPrint(&buf, "{{\"error\":\"{s}\"}}", .{message}) catch return error.ResponseBufferFull;
    try writeJsonBody(hc, status, body);
}

pub fn writeHtmlBody(hc: *HandlerContext, status: Status, body: []const u8) !void {
    try hc.response.startStatus(status);
    try hc.response.header("Content-Type", "text/html; charset=utf-8");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

pub fn queryParam(query: []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    var guard: u32 = 0;
    while (i < query.len) {
        guard += 1;
        if (guard > 64) return null;
        const seg_end = std.mem.indexOfScalarPos(u8, query, i, '&') orelse query.len;
        const seg = query[i..seg_end];
        const eq = std.mem.indexOfScalar(u8, seg, '=');
        if (eq) |eq_idx| {
            const k = seg[0..eq_idx];
            const v = seg[eq_idx + 1 ..];
            if (std.mem.eql(u8, k, name)) return v;
        } else if (std.mem.eql(u8, seg, name)) {
            return "";
        }
        i = seg_end + 1;
    }
    return null;
}

/// Extract a JSON string field (no escape/nesting support). Mirrors the
/// xrpc helper.
pub fn jsonString(body: []const u8, name: []const u8) ?[]const u8 {
    var needle_buf: [96]u8 = undefined;
    if (name.len + 4 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..name.len], name);
    needle_buf[1 + name.len] = '"';
    needle_buf[2 + name.len] = ':';
    needle_buf[3 + name.len] = '"';
    const needle = needle_buf[0 .. 4 + name.len];
    const start = std.mem.indexOf(u8, body, needle) orelse return null;
    const val_start = start + needle.len;
    const end_rel = std.mem.indexOfScalar(u8, body[val_start..], '"') orelse return null;
    return body[val_start .. val_start + end_rel];
}

/// Extract a JSON integer field. Returns null if not found or malformed.
pub fn jsonInt(body: []const u8, name: []const u8) ?i64 {
    var needle_buf: [96]u8 = undefined;
    if (name.len + 3 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..name.len], name);
    needle_buf[1 + name.len] = '"';
    needle_buf[2 + name.len] = ':';
    const needle = needle_buf[0 .. 3 + name.len];
    const start = std.mem.indexOf(u8, body, needle) orelse return null;
    var i: usize = start + needle.len;
    while (i < body.len and (body[i] == ' ' or body[i] == '\t')) : (i += 1) {}
    var sign_mul: i64 = 1;
    if (i < body.len and body[i] == '-') {
        sign_mul = -1;
        i += 1;
    }
    var val: i64 = 0;
    var digits: u32 = 0;
    while (i < body.len and body[i] >= '0' and body[i] <= '9') : (i += 1) {
        val = val * 10 + @as(i64, body[i] - '0');
        digits += 1;
    }
    if (digits == 0) return null;
    return val * sign_mul;
}

/// Parse `application/x-www-form-urlencoded` body for a named field.
/// Returns the raw (not percent-decoded) value. Mastodon clients send
/// short ASCII tokens here so decoding is rarely required.
pub fn formField(body: []const u8, name: []const u8) ?[]const u8 {
    return queryParam(body, name);
}

/// Pull the bearer token out of the `Authorization: Bearer <jwt>` header.
pub fn bearerToken(hc: *const HandlerContext) ?[]const u8 {
    const hdr = hc.request.header("Authorization") orelse return null;
    if (!std.mem.startsWith(u8, hdr, "Bearer ")) return null;
    return hdr["Bearer ".len..];
}

const testing = std.testing;

test "queryParam parses key=value pairs" {
    try testing.expectEqualStrings("hello", queryParam("a=hello&b=world", "a").?);
    try testing.expectEqualStrings("world", queryParam("a=hello&b=world", "b").?);
    try testing.expect(queryParam("a=hello", "missing") == null);
}

test "jsonString + jsonInt" {
    const body = "{\"name\":\"alice\",\"age\":30}";
    try testing.expectEqualStrings("alice", jsonString(body, "name").?);
    try testing.expectEqual(@as(i64, 30), jsonInt(body, "age").?);
    try testing.expect(jsonInt(body, "missing") == null);
}

test "formField is a queryParam alias" {
    const body = "client_id=abc&client_secret=xyz";
    try testing.expectEqualStrings("abc", formField(body, "client_id").?);
}
