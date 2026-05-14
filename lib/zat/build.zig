const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const websocket = b.dependency("websocket", .{
        .target = target,
        .optimize = optimize,
    });

    const mod = b.addModule("zat", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "websocket", .module = websocket.module("websocket") },
        },
    });

    const tests = b.addTest(.{ .root_module = mod });

    // add interop test fixtures (lazy — only fetched when running tests)
    if (b.lazyDependency("atproto-interop-tests", .{})) |interop| {
        const interop_files = .{
            // syntax fixtures
            .{ "tid_syntax_valid", "syntax/tid_syntax_valid.txt" },
            .{ "tid_syntax_invalid", "syntax/tid_syntax_invalid.txt" },
            .{ "did_syntax_valid", "syntax/did_syntax_valid.txt" },
            .{ "did_syntax_invalid", "syntax/did_syntax_invalid.txt" },
            .{ "handle_syntax_valid", "syntax/handle_syntax_valid.txt" },
            .{ "handle_syntax_invalid", "syntax/handle_syntax_invalid.txt" },
            .{ "nsid_syntax_valid", "syntax/nsid_syntax_valid.txt" },
            .{ "nsid_syntax_invalid", "syntax/nsid_syntax_invalid.txt" },
            .{ "recordkey_syntax_valid", "syntax/recordkey_syntax_valid.txt" },
            .{ "recordkey_syntax_invalid", "syntax/recordkey_syntax_invalid.txt" },
            .{ "aturi_syntax_valid", "syntax/aturi_syntax_valid.txt" },
            .{ "aturi_syntax_invalid", "syntax/aturi_syntax_invalid.txt" },
            // crypto fixtures
            .{ "signature_fixtures", "crypto/signature-fixtures.json" },
            .{ "w3c_didkey_K256", "crypto/w3c_didkey_K256.json" },
            .{ "w3c_didkey_P256", "crypto/w3c_didkey_P256.json" },
            // data model fixtures
            .{ "data_model_fixtures", "data-model/data-model-fixtures.json" },
            // mst fixtures
            .{ "mst_key_heights", "mst/key_heights.json" },
            .{ "common_prefix", "mst/common_prefix.json" },
            .{ "commit_proofs", "firehose/commit-proof-fixtures.json" },
        };
        inline for (interop_files) |entry| {
            tests.root_module.addAnonymousImport(entry[0], .{
                .root_source_file = interop.path(entry[1]),
            });
        }
    }

    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "run unit tests");
    test_step.dependOn(&run_tests.step);

    // publish-docs script (uses zat to publish docs to ATProto)
    const publish_docs = b.addExecutable(.{
        .name = "publish-docs",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/publish-docs.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zat", .module = mod }},
        }),
    });
    b.installArtifact(publish_docs);
}
