//! XRPC helpers — query param parsing, error response shapes.
//!
//! Tiger Style: pure, allocator-free, bounded.

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;
const Status = core.http.response.Status;

/// Look up a query parameter by name. Returns null if missing.
pub fn queryParam(query: []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < query.len) {
        const seg_end = std.mem.indexOfScalarPos(u8, query, i, '&') orelse query.len;
        const seg = query[i..seg_end];
        const eq = std.mem.indexOfScalar(u8, seg, '=');
        if (eq) |eq_idx| {
            const k = seg[0..eq_idx];
            const v = seg[eq_idx + 1 ..];
            if (std.mem.eql(u8, k, name)) return v;
        } else {
            if (std.mem.eql(u8, seg, name)) return "";
        }
        i = seg_end + 1;
    }
    return null;
}

pub fn writeJsonBody(hc: *HandlerContext, status: Status, body: []const u8) !void {
    try hc.response.startStatus(status);
    try hc.response.header("Content-Type", "application/json");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

pub fn writeError(hc: *HandlerContext, status: Status, err_name: []const u8, message: []const u8) !void {
    var buf: [512]u8 = undefined;
    const body = std.fmt.bufPrint(&buf, "{{\"error\":\"{s}\",\"message\":\"{s}\"}}", .{ err_name, message }) catch return error.ResponseBufferFull;
    try writeJsonBody(hc, status, body);
}

/// Extract a JSON string field (very small parser — no nesting, no
/// escapes). Returns null when not found.
pub fn jsonStringField(body: []const u8, name: []const u8) ?[]const u8 {
    var needle_buf: [128]u8 = undefined;
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

const testing = std.testing;

test "xrpc: queryParam basic" {
    try testing.expectEqualStrings("alice", queryParam("repo=alice&collection=x", "repo").?);
    try testing.expectEqualStrings("x", queryParam("repo=alice&collection=x", "collection").?);
    try testing.expect(queryParam("a=b", "c") == null);
}

test "xrpc: jsonStringField" {
    const body = "{\"identifier\":\"alice\",\"password\":\"hunter2\"}";
    try testing.expectEqualStrings("alice", jsonStringField(body, "identifier").?);
    try testing.expectEqualStrings("hunter2", jsonStringField(body, "password").?);
    try testing.expect(jsonStringField(body, "missing") == null);
}
