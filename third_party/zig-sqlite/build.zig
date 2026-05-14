const std = @import("std");
const debug = std.debug;
const heap = std.heap;
const mem = std.mem;
const ResolvedTarget = std.Build.ResolvedTarget;
const Query = std.Target.Query;
const builtin = @import("builtin");

// Preprocessor step removed for Zig 0.16 build compatibility — only used to
// regenerate loadable-ext headers, which are vendored in c/.

fn getTarget(original_target: ResolvedTarget) ResolvedTarget {
    var tmp = original_target;

    if (tmp.result.isGnuLibC()) {
        const min_glibc_version = std.SemanticVersion{
            .major = 2,
            .minor = 28,
            .patch = 0,
        };
        const ver = tmp.result.os.version_range.linux.glibc;
        if (ver.order(min_glibc_version) == .lt) {
            std.debug.panic("sqlite requires glibc version >= 2.28", .{});
        }
    }

    return tmp;
}

const TestTarget = struct {
    query: Query,
    single_threaded: bool = false,
};

const ci_targets = switch (builtin.target.cpu.arch) {
    .x86_64 => switch (builtin.target.os.tag) {
        .linux => [_]TestTarget{
            TestTarget{ .query = .{ .cpu_arch = .x86_64, .abi = .musl } },
            TestTarget{ .query = .{ .cpu_arch = .x86, .abi = .musl } },
            TestTarget{ .query = .{ .cpu_arch = .aarch64, .abi = .musl } },
        },
        .windows => [_]TestTarget{
            TestTarget{ .query = .{ .cpu_arch = .x86_64, .abi = .gnu } },
            // Disabled due to https://github.com/ziglang/zig/issues/20047
            // TestTarget{ .query = .{ .cpu_arch = .x86, .abi = .gnu } },
        },
        .macos => [_]TestTarget{
            TestTarget{ .query = .{ .cpu_arch = .x86_64 } },
        },
        else => [_]TestTarget{},
    },
    else => [_]TestTarget{},
};

const all_test_targets = switch (builtin.target.cpu.arch) {
    .x86_64 => switch (builtin.target.os.tag) {
        .linux => [_]TestTarget{
            TestTarget{ .query = .{} },
            TestTarget{ .query = .{ .cpu_arch = .x86_64, .abi = .musl } },
            TestTarget{ .query = .{ .cpu_arch = .x86, .abi = .musl } },
            TestTarget{ .query = .{ .cpu_arch = .aarch64, .abi = .musl } },
            TestTarget{ .query = .{ .cpu_arch = .riscv64, .abi = .musl } },
            // Disabled because it fails for some unknown reason
            // TestTarget{ .query = .{ .cpu_arch = .mips, .abi = .musl } },
            TestTarget{ .query = .{ .cpu_arch = .x86_64, .os_tag = .windows } },
            // Disabled due to https://github.com/ziglang/zig/issues/20047
            // TestTarget{ .query = .{ .cpu_arch = .x86, .os_tag = .windows } },
            TestTarget{ .query = .{ .cpu_arch = .x86_64, .os_tag = .macos } },
            TestTarget{ .query = .{ .cpu_arch = .aarch64, .os_tag = .macos } },
        },
        .windows => [_]TestTarget{
            TestTarget{ .query = .{ .cpu_arch = .x86_64, .abi = .gnu } },
            // Disabled due to https://github.com/ziglang/zig/issues/20047
            // TestTarget{ .query = .{ .cpu_arch = .x86, .abi = .gnu } },
        },
        .freebsd => [_]TestTarget{
            TestTarget{ .query = .{} },
            TestTarget{ .query = .{ .cpu_arch = .x86_64 } },
        },
        .macos => [_]TestTarget{
            TestTarget{ .query = .{ .cpu_arch = .x86_64 } },
        },
        else => [_]TestTarget{
            TestTarget{ .query = .{} },
        },
    },
    .aarch64 => switch (builtin.target.os.tag) {
        .linux, .windows, .freebsd, .macos => [_]TestTarget{
            TestTarget{ .query = .{} },
        },
        else => [_]TestTarget{
            TestTarget{ .query = .{} },
        },
    },
    else => [_]TestTarget{
        TestTarget{ .query = .{} },
    },
};

fn computeTestTargets(isNative: bool, ci: ?bool) ?[]const TestTarget {
    if (ci != null and ci.?) return &ci_targets;

    if (isNative) {
        // If the target is native we assume the user didn't change it with -Dtarget and run all test targets.
        return &all_test_targets;
    }

    // Otherwise we run a single test target.
    return null;
}

// This creates a SQLite static library from the SQLite dependency code.
fn makeSQLiteLib(b: *std.Build, dep: *std.Build.Dependency, c_flags: []const []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, sqlite_c: enum { with, without }) *std.Build.Step.Compile {
    const mod = b.addModule("lib-sqlite", .{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const lib = b.addLibrary(.{
        .name = "sqlite",
        .linkage = .static,
        .root_module = mod,
    });

    mod.addIncludePath(dep.path("."));
    mod.addIncludePath(b.path("c"));
    if (sqlite_c == .with) {
        mod.addCSourceFile(.{
            .file = dep.path("sqlite3.c"),
            .flags = c_flags,
        });
    }
    mod.addCSourceFile(.{
        .file = b.path("c/workaround.c"),
        .flags = c_flags,
    });

    return lib;
}

pub fn build(b: *std.Build) !void {
    const in_memory = b.option(bool, "in_memory", "Should the tests run with sqlite in memory (default true)") orelse true;
    const dbfile = b.option([]const u8, "dbfile", "Always use this database file instead of a temporary one");
    const ci = b.option(bool, "ci", "Build and test in the CI on GitHub");

    const query = b.standardTargetOptionsQueryOnly(.{});
    const target = b.resolveTargetQuery(query);
    const optimize = b.standardOptimizeOption(.{});

    // Upstream dependency
    const sqlite_dep = b.dependency("sqlite", .{
        .target = target,
        .optimize = optimize,
    });

    // Define C flags to use

    var flags: std.ArrayList([]const u8) = .empty;
    defer flags.deinit(b.allocator);
    try flags.append(b.allocator, "-std=c99");

    inline for (std.meta.fields(EnableOptions)) |field| {
        const opt = b.option(bool, field.name, "Enable " ++ field.name) orelse field.defaultValue().?;

        if (opt) {
            var buf: [field.name.len]u8 = undefined;
            const name = std.ascii.upperString(&buf, field.name);
            const flag = try std.fmt.allocPrint(b.allocator, "-DSQLITE_ENABLE_{s}", .{name});

            try flags.append(b.allocator, flag);
        }
    }

    const c_flags = flags.items;

    //
    // Main library and module
    //

    // const sqlite_lib, const sqlite_mod = blk: {
    const sqlite_lib, _ = blk: {
        const lib = makeSQLiteLib(b, sqlite_dep, c_flags, target, optimize, .with);

        const mod = b.addModule("sqlite", .{
            .root_source_file = b.path("sqlite.zig"),
            .link_libc = true,
        });
        mod.addIncludePath(b.path("c"));
        mod.addIncludePath(sqlite_dep.path("."));
        mod.linkLibrary(lib);

        break :blk .{ lib, mod };
    };
    b.installArtifact(sqlite_lib);

    // const sqliteext_mod = blk: {
    _ = blk: {
        const lib = makeSQLiteLib(b, sqlite_dep, c_flags, target, optimize, .without);

        const mod = b.addModule("sqliteext", .{
            .root_source_file = b.path("sqlite.zig"),
            .link_libc = true,
        });
        mod.addIncludePath(b.path("c"));
        mod.linkLibrary(lib);

        break :blk mod;
    };

    //
    // Tests
    //

    const test_targets = computeTestTargets(query.isNative(), ci) orelse &[_]TestTarget{.{
        .query = query,
    }};
    const test_step = b.step("test", "Run library tests");

    // By default the tests will only be execute for native test targets, however they will be compiled
    // for _all_ targets defined in `test_targets`.
    //
    // If you want to execute tests for other targets you can pass -fqemu, -fdarling, -fwine, -frosetta.

    for (test_targets) |test_target| {
        const cross_target = getTarget(b.resolveTargetQuery(test_target.query));
        const single_threaded_txt = if (test_target.single_threaded) "single" else "multi";
        const test_name = b.fmt("{s}-{s}-{s}", .{
            try cross_target.result.zigTriple(b.allocator),
            @tagName(optimize),
            single_threaded_txt,
        });

        const test_sqlite_lib = makeSQLiteLib(b, sqlite_dep, c_flags, cross_target, optimize, .with);

        const mod = b.addModule(test_name, .{
            .target = cross_target,
            .optimize = optimize,
            .root_source_file = b.path("sqlite.zig"),
            .single_threaded = test_target.single_threaded,
        });

        const tests = b.addTest(.{
            .name = test_name,
            .root_module = mod,
        });
        mod.addIncludePath(b.path("c"));
        mod.addIncludePath(sqlite_dep.path("."));
        mod.linkLibrary(test_sqlite_lib);

        const tests_options = b.addOptions();
        tests.root_module.addImport("build_options", tests_options.createModule());

        tests_options.addOption(bool, "in_memory", in_memory);
        tests_options.addOption(?[]const u8, "dbfile", dbfile);

        const run_tests = b.addRunArtifact(tests);
        test_step.dependOn(&run_tests.step);
    }

    // This builds an example shared library with the extension and a binary that tests it.

    //\ const zigcrypto_install_artifact = addZigcrypto(b, sqliteext_mod, target, optimize);
    //\ test_step.dependOn(&zigcrypto_install_artifact.step);
    //\ const zigcrypto_test_run = addZigcryptoTestRun(b, sqlite_mod, target, optimize);
    //\ zigcrypto_test_run.step.dependOn(&zigcrypto_install_artifact.step);
    //\ test_step.dependOn(&zigcrypto_test_run.step);

    //
    // Tools
    //
}

// See https://www.sqlite.org/compile.html for flags
const EnableOptions = struct {
    // https://www.sqlite.org/fts5.html
    fts5: bool = true,
};
