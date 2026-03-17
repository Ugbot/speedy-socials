const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Get ZAT dependency (vendored submodule)
    const zat_dep = b.dependency("zat", .{
        .target = target,
        .optimize = optimize,
    });
    const zat_mod = zat_dep.module("zat");

    // Expose the atproto module
    const mod = b.addModule("atproto", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zat", .module = zat_mod },
        },
    });

    // Tests
    const tests = b.addTest(.{ .root_module = mod });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run atproto library tests");
    test_step.dependOn(&run_tests.step);
}
