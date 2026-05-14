//! JSON path helpers
//!
//! simplifies navigating nested json structures.
//! eliminates the verbose nested if-checks.
//!
//! two approaches:
//! - runtime paths: getString(value, "embed.external.uri") - for dynamic paths
//! - comptime paths: extractAt(T, alloc, value, .{"embed", "external"}) - for static paths with type safety
//!
//! debug logging:
//! enable with `pub const std_options = .{ .log_scope_levels = &.{.{ .scope = .zat, .level = .debug }} };`

const std = @import("std");
const log = std.log.scoped(.zat);

/// navigate a json value by dot-separated path
/// returns null if any segment is missing or wrong type
pub fn getPath(value: std.json.Value, path: []const u8) ?std.json.Value {
    var current = value;
    var it = std.mem.splitScalar(u8, path, '.');

    while (it.next()) |segment| {
        switch (current) {
            .object => |obj| {
                current = obj.get(segment) orelse return null;
            },
            .array => |arr| {
                const idx = std.fmt.parseInt(usize, segment, 10) catch return null;
                if (idx >= arr.items.len) return null;
                current = arr.items[idx];
            },
            else => return null,
        }
    }

    return current;
}

/// get a string at path
pub fn getString(value: std.json.Value, path: []const u8) ?[]const u8 {
    const v = getPath(value, path) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

/// get an integer at path
pub fn getInt(value: std.json.Value, path: []const u8) ?i64 {
    const v = getPath(value, path) orelse return null;
    return switch (v) {
        .integer => |i| i,
        else => null,
    };
}

/// get a float at path
pub fn getFloat(value: std.json.Value, path: []const u8) ?f64 {
    const v = getPath(value, path) orelse return null;
    return switch (v) {
        .float => |f| f,
        .integer => |i| @floatFromInt(i),
        else => null,
    };
}

/// get a bool at path
pub fn getBool(value: std.json.Value, path: []const u8) ?bool {
    const v = getPath(value, path) orelse return null;
    return switch (v) {
        .bool => |b| b,
        else => null,
    };
}

/// get an array at path
pub fn getArray(value: std.json.Value, path: []const u8) ?[]std.json.Value {
    const v = getPath(value, path) orelse return null;
    return switch (v) {
        .array => |a| a.items,
        else => null,
    };
}

/// get an object at path
pub fn getObject(value: std.json.Value, path: []const u8) ?std.json.ObjectMap {
    const v = getPath(value, path) orelse return null;
    return switch (v) {
        .object => |o| o,
        else => null,
    };
}

// === comptime path extraction ===

/// extract a typed struct from a nested path
/// uses comptime tuple for path segments - no runtime string parsing
/// leverages std.json.parseFromValueLeaky for type-safe extraction
///
/// on failure, logs diagnostic info when debug logging is enabled for .zat scope
pub fn extractAt(
    comptime T: type,
    allocator: std.mem.Allocator,
    value: std.json.Value,
    comptime path: anytype,
) std.json.ParseFromValueError!T {
    var current = value;
    inline for (path) |segment| {
        current = switch (current) {
            .object => |obj| obj.get(segment) orelse {
                log.debug("extractAt: missing field \"{s}\" in path {any}, expected {s}", .{
                    segment,
                    path,
                    @typeName(T),
                });
                return error.MissingField;
            },
            else => {
                log.debug("extractAt: expected object at \"{s}\" in path {any}, got {s}", .{
                    segment,
                    path,
                    @tagName(current),
                });
                return error.UnexpectedToken;
            },
        };
    }
    return std.json.parseFromValueLeaky(T, allocator, current, .{ .ignore_unknown_fields = true }) catch |err| {
        log.debug("extractAt: parse failed for {s} at path {any}: {s} (json type: {s})", .{
            @typeName(T),
            path,
            @errorName(err),
            @tagName(current),
        });
        return err;
    };
}

/// extract a typed value, returning null if path doesn't exist
pub fn extractAtOptional(
    comptime T: type,
    allocator: std.mem.Allocator,
    value: std.json.Value,
    comptime path: anytype,
) ?T {
    return extractAt(T, allocator, value, path) catch null;
}

// === tests ===

test "getPath simple" {
    const json_str =
        \\{"name": "alice", "age": 30}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("alice", getString(parsed.value, "name").?);
    try std.testing.expectEqual(@as(i64, 30), getInt(parsed.value, "age").?);
}

test "getPath nested" {
    const json_str =
        \\{"embed": {"external": {"uri": "https://example.com"}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("https://example.com", getString(parsed.value, "embed.external.uri").?);
}

test "getPath array index" {
    const json_str =
        \\{"items": ["a", "b", "c"]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("b", getString(parsed.value, "items.1").?);
}

test "getPath missing returns null" {
    const json_str =
        \\{"name": "alice"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expect(getString(parsed.value, "missing") == null);
    try std.testing.expect(getString(parsed.value, "name.nested") == null);
}

test "getPath deeply nested real-world example" {
    // the exact painful example from user feedback
    const json_str =
        \\{
        \\  "embed": {
        \\    "$type": "app.bsky.embed.external",
        \\    "external": {
        \\      "uri": "https://tangled.sh",
        \\      "title": "Tangled",
        \\      "description": "Git hosting on AT Protocol"
        \\    }
        \\  }
        \\}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_str, .{});
    defer parsed.deinit();

    // instead of 6 nested if-checks:
    const uri = getString(parsed.value, "embed.external.uri");
    try std.testing.expectEqualStrings("https://tangled.sh", uri.?);

    const title = getString(parsed.value, "embed.external.title");
    try std.testing.expectEqualStrings("Tangled", title.?);
}

// === comptime extraction tests ===

test "extractAt struct" {
    const json_str =
        \\{
        \\  "embed": {
        \\    "external": {
        \\      "uri": "https://tangled.sh",
        \\      "title": "Tangled"
        \\    }
        \\  }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), json_str, .{});

    const External = struct {
        uri: []const u8,
        title: []const u8,
    };

    const ext = try extractAt(External, arena.allocator(), parsed.value, .{ "embed", "external" });
    try std.testing.expectEqualStrings("https://tangled.sh", ext.uri);
    try std.testing.expectEqualStrings("Tangled", ext.title);
}

test "extractAt with optional fields" {
    const json_str =
        \\{
        \\  "user": {
        \\    "name": "alice",
        \\    "age": 30
        \\  }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), json_str, .{});

    const User = struct {
        name: []const u8,
        age: i64,
        bio: ?[]const u8 = null,
    };

    const user = try extractAt(User, arena.allocator(), parsed.value, .{"user"});
    try std.testing.expectEqualStrings("alice", user.name);
    try std.testing.expectEqual(@as(i64, 30), user.age);
    try std.testing.expect(user.bio == null);
}

test "extractAt empty path extracts root" {
    const json_str =
        \\{"name": "root", "value": 42}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), json_str, .{});

    const Root = struct {
        name: []const u8,
        value: i64,
    };

    const root = try extractAt(Root, arena.allocator(), parsed.value, .{});
    try std.testing.expectEqualStrings("root", root.name);
    try std.testing.expectEqual(@as(i64, 42), root.value);
}

test "extractAtOptional returns null on missing path" {
    const json_str =
        \\{"exists": {"value": 1}}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), json_str, .{});

    const Thing = struct { value: i64 };

    const exists = extractAtOptional(Thing, arena.allocator(), parsed.value, .{"exists"});
    try std.testing.expect(exists != null);
    try std.testing.expectEqual(@as(i64, 1), exists.?.value);

    const missing = extractAtOptional(Thing, arena.allocator(), parsed.value, .{"missing"});
    try std.testing.expect(missing == null);
}

test "extractAt logs diagnostic on enum parse failure" {
    // simulates the issue: unknown enum value from external API
    const json_str =
        \\{"op": {"action": "archive", "path": "app.bsky.feed.post/abc"}}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), json_str, .{});

    const Action = enum { create, update, delete };
    const Op = struct {
        action: Action,
        path: []const u8,
    };

    // "archive" is not a valid Action variant - this should fail
    // with debug logging enabled, you'd see:
    //   debug(zat): extractAt: parse failed for json.Op at path { "op" }: InvalidEnumTag (json type: object)
    const result = extractAtOptional(Op, arena.allocator(), parsed.value, .{"op"});
    try std.testing.expect(result == null);
}

test "extractAt logs diagnostic on missing field" {
    const json_str =
        \\{"data": {"name": "test"}}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), json_str, .{});

    const Thing = struct { value: i64 };

    // path "data.missing" doesn't exist
    // with debug logging enabled, you'd see:
    //   debug(zat): extractAt: missing field "missing" in path { "data", "missing" }, expected json.Thing
    const result = extractAtOptional(Thing, arena.allocator(), parsed.value, .{ "data", "missing" });
    try std.testing.expect(result == null);
}

test "extractAt ignores unknown fields" {
    // real-world case: TAP messages have extra fields (live, rev, cid) that we don't need
    const json_str =
        \\{
        \\  "record": {
        \\    "live": true,
        \\    "did": "did:plc:abc123",
        \\    "rev": "3mbspmpaidl2a",
        \\    "collection": "pub.leaflet.document",
        \\    "rkey": "xyz789",
        \\    "action": "create",
        \\    "cid": "bafyreitest"
        \\  }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), json_str, .{});

    // only extract the fields we care about
    const Record = struct {
        collection: []const u8,
        action: []const u8,
        did: []const u8,
        rkey: []const u8,
    };

    const rec = try extractAt(Record, arena.allocator(), parsed.value, .{"record"});
    try std.testing.expectEqualStrings("pub.leaflet.document", rec.collection);
    try std.testing.expectEqualStrings("create", rec.action);
    try std.testing.expectEqualStrings("did:plc:abc123", rec.did);
    try std.testing.expectEqualStrings("xyz789", rec.rkey);
}
