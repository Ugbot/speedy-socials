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

/// AT-12 helper: locate the inner JSON of an array-valued field.
/// Returns the slice between `[` and the matching `]` (exclusive).
/// Brace-balanced — handles nested objects.
pub fn jsonArrayField(body: []const u8, name: []const u8) ?[]const u8 {
    var needle_buf: [128]u8 = undefined;
    if (name.len + 4 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..name.len], name);
    needle_buf[1 + name.len] = '"';
    needle_buf[2 + name.len] = ':';
    needle_buf[3 + name.len] = '[';
    const needle = needle_buf[0 .. 4 + name.len];
    const start = std.mem.indexOf(u8, body, needle) orelse return null;
    const arr_start = start + needle.len;
    // Walk forward, tracking nested structures and strings.
    var i = arr_start;
    var depth: u32 = 1;
    var in_string = false;
    var escape = false;
    while (i < body.len) : (i += 1) {
        const ch = body[i];
        if (escape) {
            escape = false;
            continue;
        }
        if (in_string) {
            if (ch == '\\') escape = true;
            if (ch == '"') in_string = false;
            continue;
        }
        switch (ch) {
            '"' => in_string = true,
            '[', '{' => depth += 1,
            ']' => {
                depth -= 1;
                if (depth == 0) return body[arr_start..i];
            },
            '}' => depth -= 1,
            else => {},
        }
    }
    return null;
}

/// AT-12 helper: walk top-level objects within an array slice
/// (one returned by `jsonArrayField`). Each iteration returns the
/// slice between matching braces, including them.
pub const ObjectArrayIter = struct {
    rem: []const u8,

    pub fn init(arr: []const u8) ObjectArrayIter {
        return .{ .rem = arr };
    }

    pub fn next(self: *ObjectArrayIter) ?[]const u8 {
        // Skip whitespace + commas.
        var i: usize = 0;
        while (i < self.rem.len) : (i += 1) {
            const c = self.rem[i];
            if (c == ' ' or c == '\n' or c == '\t' or c == ',' or c == '\r') continue;
            break;
        }
        if (i >= self.rem.len) return null;
        if (self.rem[i] != '{') return null;
        const start = i;
        var depth: u32 = 1;
        var in_string = false;
        var escape = false;
        i += 1;
        while (i < self.rem.len) : (i += 1) {
            const ch = self.rem[i];
            if (escape) {
                escape = false;
                continue;
            }
            if (in_string) {
                if (ch == '\\') escape = true;
                if (ch == '"') in_string = false;
                continue;
            }
            switch (ch) {
                '"' => in_string = true,
                '{', '[' => depth += 1,
                '}', ']' => {
                    depth -= 1;
                    if (depth == 0 and ch == '}') {
                        const out = self.rem[start .. i + 1];
                        self.rem = self.rem[i + 1 ..];
                        return out;
                    }
                },
                else => {},
            }
        }
        return null;
    }
};

/// AT-12 helper: extract a nested JSON object (`{...}`) by field name.
/// Returns the slice including the braces, or null if not found.
pub fn jsonObjectField(body: []const u8, name: []const u8) ?[]const u8 {
    var needle_buf: [128]u8 = undefined;
    if (name.len + 4 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..name.len], name);
    needle_buf[1 + name.len] = '"';
    needle_buf[2 + name.len] = ':';
    needle_buf[3 + name.len] = '{';
    const needle = needle_buf[0 .. 4 + name.len];
    const start = std.mem.indexOf(u8, body, needle) orelse return null;
    const obj_start = start + needle.len - 1; // include the `{`
    var i = obj_start + 1;
    var depth: u32 = 1;
    var in_string = false;
    var escape = false;
    while (i < body.len) : (i += 1) {
        const ch = body[i];
        if (escape) {
            escape = false;
            continue;
        }
        if (in_string) {
            if (ch == '\\') escape = true;
            if (ch == '"') in_string = false;
            continue;
        }
        switch (ch) {
            '"' => in_string = true,
            '{', '[' => depth += 1,
            '}', ']' => {
                depth -= 1;
                if (depth == 0) return body[obj_start .. i + 1];
            },
            else => {},
        }
    }
    return null;
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

test "AT-12: jsonArrayField extracts balanced array body" {
    const body = "{\"writes\":[{\"a\":1},{\"b\":[2,3]}],\"x\":1}";
    const arr = jsonArrayField(body, "writes").?;
    try testing.expectEqualStrings("{\"a\":1},{\"b\":[2,3]}", arr);
}

test "AT-12: ObjectArrayIter walks each object" {
    const arr = "{\"a\":1},{\"b\":[2,3]},{\"c\":\"x\"}";
    var iter = ObjectArrayIter.init(arr);
    try testing.expectEqualStrings("{\"a\":1}", iter.next().?);
    try testing.expectEqualStrings("{\"b\":[2,3]}", iter.next().?);
    try testing.expectEqualStrings("{\"c\":\"x\"}", iter.next().?);
    try testing.expect(iter.next() == null);
}

test "AT-12: jsonObjectField extracts nested value" {
    const body = "{\"k\":1,\"value\":{\"inner\":\"x\"},\"end\":1}";
    try testing.expectEqualStrings("{\"inner\":\"x\"}", jsonObjectField(body, "value").?);
}
