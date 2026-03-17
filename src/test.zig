const std = @import("std");

pub fn main() !void {
    std.debug.print("Test program running!\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Allocator created\n", .{});

    // Test basic string allocation
    const test_str = try allocator.dupe(u8, "Hello World!");
    defer allocator.free(test_str);
    std.debug.print("String allocated: {s}\n", .{test_str});

    std.debug.print("Test completed successfully!\n", .{});
}
