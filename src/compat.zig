// Compatibility layer for Zig 0.15 API changes.
// Provides wrappers for APIs that changed between 0.13/0.14 and 0.15.

const std = @import("std");

/// Replacement for std.json.stringify which was removed in Zig 0.15.
/// Serializes a value to JSON and writes it to an ArrayList writer.
pub fn jsonStringify(value: anytype, options: std.json.Stringify.Options, writer: anytype) !void {
    _ = options;
    // Use std.fmt with the json formatter
    try writer.print("{f}", .{std.json.fmt(value, .{})});
}

/// Replacement for std.json.stringifyAlloc which was removed in Zig 0.15.
pub fn jsonStringifyAlloc(allocator: std.mem.Allocator, value: anytype, options: std.json.Stringify.Options) ![]u8 {
    _ = options;
    return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(value, .{})});
}
