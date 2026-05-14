const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── sqlite (vendored) ──────────────────────────────────────────
    const sqlite_dep = b.dependency("sqlite", .{ .target = target, .optimize = optimize });
    const sqlite_mod = sqlite_dep.module("sqlite");

    // ── third-party: TigerBeetle vendored utilities ────────────────
    // We vendor selected files from TigerBeetle (Apache-2.0) under
    // `src/third_party/tigerbeetle/`. Each sub-area is exposed as a
    // separate module so `core` can re-export specific pieces without
    // pulling in unrelated TB code. See `docs/adr/004-vendor-tigerbeetle.md`.
    const tb_static_alloc_mod = b.addModule("tigerbeetle_static_allocator", .{
        .root_source_file = b.path("src/third_party/tigerbeetle/alloc/static_allocator.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tb_counting_alloc_mod = b.addModule("tigerbeetle_counting_allocator", .{
        .root_source_file = b.path("src/third_party/tigerbeetle/alloc/counting_allocator.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tb_prng_mod = b.addModule("tb_prng", .{
        .root_source_file = b.path("src/third_party/tigerbeetle/prng/prng.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── core module ────────────────────────────────────────────────
    const core_mod = b.addModule("core", .{
        .root_source_file = b.path("src/core/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sqlite", .module = sqlite_mod },
            .{ .name = "tigerbeetle_static_allocator", .module = tb_static_alloc_mod },
            .{ .name = "tigerbeetle_counting_allocator", .module = tb_counting_alloc_mod },
            .{ .name = "tb_prng", .module = tb_prng_mod },
        },
    });

    // ── plugin modules ─────────────────────────────────────────────
    const plugin_modules = [_]struct { name: []const u8, path: []const u8 }{
        .{ .name = "protocol_echo", .path = "src/protocols/echo/plugin.zig" },
        .{ .name = "protocol_atproto", .path = "src/protocols/atproto/plugin.zig" },
        .{ .name = "protocol_activitypub", .path = "src/protocols/activitypub/plugin.zig" },
        .{ .name = "protocol_relay", .path = "src/protocols/relay/plugin.zig" },
    };

    var plugin_imports_list: std.ArrayList(std.Build.Module.Import) = .empty;
    defer plugin_imports_list.deinit(b.allocator);
    plugin_imports_list.append(b.allocator, .{ .name = "core", .module = core_mod }) catch @panic("OOM");

    // Build the non-relay plugin modules first so that the relay can
    // import them. The relay is the only plugin that explicitly depends
    // on sibling plugins (see ADR-002 + the sibling-lookup carve-out in
    // src/protocols/relay/plugin.zig).
    const atproto_mod = b.addModule("protocol_atproto", .{
        .root_source_file = b.path("src/protocols/atproto/plugin.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "core", .module = core_mod },
            .{ .name = "sqlite", .module = sqlite_mod },
        },
    });
    const ap_mod = b.addModule("protocol_activitypub", .{
        .root_source_file = b.path("src/protocols/activitypub/plugin.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "core", .module = core_mod },
            .{ .name = "sqlite", .module = sqlite_mod },
        },
    });
    const echo_mod = b.addModule("protocol_echo", .{
        .root_source_file = b.path("src/protocols/echo/plugin.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "core", .module = core_mod }},
    });
    const relay_mod = b.addModule("protocol_relay", .{
        .root_source_file = b.path("src/protocols/relay/plugin.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "core", .module = core_mod },
            .{ .name = "sqlite", .module = sqlite_mod },
            .{ .name = "protocol_atproto", .module = atproto_mod },
            .{ .name = "protocol_activitypub", .module = ap_mod },
        },
    });

    plugin_imports_list.append(b.allocator, .{ .name = "protocol_echo", .module = echo_mod }) catch @panic("OOM");
    plugin_imports_list.append(b.allocator, .{ .name = "protocol_atproto", .module = atproto_mod }) catch @panic("OOM");
    plugin_imports_list.append(b.allocator, .{ .name = "protocol_activitypub", .module = ap_mod }) catch @panic("OOM");
    plugin_imports_list.append(b.allocator, .{ .name = "protocol_relay", .module = relay_mod }) catch @panic("OOM");

    const plugin_imports = plugin_imports_list.items;

    // ── executable ─────────────────────────────────────────────────
    const exe = b.addExecutable(.{
        .name = "speedy-socials",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/app/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = plugin_imports,
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the speedy-socials server");
    run_step.dependOn(&run_cmd.step);

    // ── tests ──────────────────────────────────────────────────────
    const core_tests = b.addTest(.{ .root_module = core_mod });
    const run_core_tests = b.addRunArtifact(core_tests);

    const app_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/app/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = plugin_imports,
        }),
    });
    const run_app_tests = b.addRunArtifact(app_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_core_tests.step);
    test_step.dependOn(&run_app_tests.step);

    // Per-plugin test step. Each plugin module's tests run independently
    // so that referenced symbols (cid, mst, dag_cbor, …) get pulled in
    // and their `test` blocks execute. The relay is the only plugin
    // that needs its siblings + sqlite available at test time.
    for (plugin_modules) |pm| {
        const is_relay = std.mem.eql(u8, pm.name, "protocol_relay");
        const is_ap = std.mem.eql(u8, pm.name, "protocol_activitypub");
        const is_atproto = std.mem.eql(u8, pm.name, "protocol_atproto");
        const needs_sqlite = is_ap or is_atproto;
        const mod = if (is_relay) b.createModule(.{
            .root_source_file = b.path(pm.path),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "core", .module = core_mod },
                .{ .name = "sqlite", .module = sqlite_mod },
                .{ .name = "protocol_atproto", .module = atproto_mod },
                .{ .name = "protocol_activitypub", .module = ap_mod },
            },
        }) else if (needs_sqlite) b.createModule(.{
            .root_source_file = b.path(pm.path),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "core", .module = core_mod },
                .{ .name = "sqlite", .module = sqlite_mod },
            },
        }) else b.createModule(.{
            .root_source_file = b.path(pm.path),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "core", .module = core_mod },
            },
        });
        const t = b.addTest(.{ .root_module = mod });
        const run_t = b.addRunArtifact(t);
        test_step.dependOn(&run_t.step);
    }

    // ── benchmarks ─────────────────────────────────────────────────
    const bench_storage = b.addExecutable(.{
        .name = "storage-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/storage_bench.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "core", .module = core_mod },
                .{ .name = "sqlite", .module = sqlite_mod },
            },
        }),
    });
    const run_bench_storage = b.addRunArtifact(bench_storage);
    const bench_step = b.step("bench-storage", "Run the storage layer benchmark");
    bench_step.dependOn(&run_bench_storage.step);
}
