const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── optional feature flags ─────────────────────────────────────
    // The streaming backends (kafka/redis/nats) are now PURE-ZIG vendored
    // modules wired unconditionally (no flag) — see below. `-Dpostgres`
    // remains only until the pg.zig provider lands. `-Dtrace` compiles in
    // Chrome-format span tracing.
    const enable_postgres = b.option(bool, "postgres", "Compile + link the libpq storage backend") orelse false;
    const enable_trace = b.option(bool, "trace", "Compile in Chrome-format span tracing (off = zero hot-path cost)") orelse false;

    const build_opts = b.addOptions();
    build_opts.addOption(bool, "postgres", enable_postgres);
    build_opts.addOption(bool, "trace", enable_trace);
    const build_options_mod = build_opts.createModule();

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
    const tb_intrusive_mod = b.addModule("tb_intrusive", .{
        .root_source_file = b.path("src/third_party/tigerbeetle/intrusive/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            // The previously-gated PRNG-driven fuzz tests on Stack/List/Queue
            // need the vendored TB PRNG. Production code paths in the
            // intrusive collections never reach for it.
            .{ .name = "tb_prng", .module = tb_prng_mod },
        },
    });
    const tb_testing_mod = b.addModule("tb_testing", .{
        .root_source_file = b.path("src/third_party/tigerbeetle/testing/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    // W4: TigerBeetle stdx — BoundedArrayType, RingBufferType, IOPSType,
    // BitSetType. The shim re-exports them plus the local `copy_*`
    // helpers and our existing `tb_prng` so the borrow is one import.
    // See `src/third_party/tigerbeetle/stdx/stdx.zig`.
    const tb_stdx_mod = b.addModule("tb_stdx", .{
        .root_source_file = b.path("src/third_party/tigerbeetle/stdx/stdx.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "tb_prng", .module = tb_prng_mod },
        },
    });

    // ── third-party: ianic/tls.zig (vendored submodule) ───────────
    // Pure-Zig TLS 1.2/1.3 client + TLS 1.3 server. Replaces the
    // system OpenSSL link for *server-side* TLS (`core.tls.ianic_inbound`).
    // The OpenSSL link is retained narrowly for RSA-PKCS1v15-SHA256
    // signing (used by AP federation outbound delivery for Mastodon's
    // default rsa-sha256 actors). See `third_party/ianic-tls/`.
    const ianic_tls_mod = b.addModule("tls", .{
        .root_source_file = b.path("third_party/ianic-tls/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── third-party: streaming sink drivers (vendored submodules) ──
    // Pure-Zig (std.Io-based, no system libs), wired as plain modules +
    // imported into `core` UNCONDITIONALLY — no `-D` gate. They back the
    // runtime-selected STREAM_BACKEND={kafka,redis,nats} options.
    const redis_mod = b.addModule("redis", .{
        .root_source_file = b.path("third_party/redis.zig/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const nats_options = b.addOptions();
    nats_options.addOption(bool, "enable_debug", false);
    nats_options.addOption([]const u8, "io_backend", "threaded");
    const nats_mod = b.addModule("nats", .{
        .root_source_file = b.path("third_party/nats.zig/src/nats.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = nats_options.createModule() },
        },
    });
    // Kafka: Ugbot/zig-kafka (branch zig-0.16, ported to this std). The
    // SDK module depends on `kafka_generated` + the `ztime` 0.16 shim.
    const kafka_generated_mod = b.addModule("kafka_generated", .{
        .root_source_file = b.path("third_party/zig-kafka/sdk/src/generated_index.zig"),
        .target = target,
        .optimize = optimize,
    });
    const kafka_ztime_mod = b.addModule("ztime", .{
        .root_source_file = b.path("third_party/zig-kafka/sdk/src/compat.zig"),
        .target = target,
        .optimize = optimize,
    });
    const kafka_mod = b.addModule("kafka", .{
        .root_source_file = b.path("third_party/zig-kafka/sdk/src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "kafka_generated", .module = kafka_generated_mod },
            .{ .name = "ztime", .module = kafka_ztime_mod },
        },
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
            .{ .name = "tb_intrusive", .module = tb_intrusive_mod },
            .{ .name = "tb_testing", .module = tb_testing_mod },
            .{ .name = "tb_stdx", .module = tb_stdx_mod },
            .{ .name = "tls", .module = ianic_tls_mod },
            .{ .name = "build_options", .module = build_options_mod },
            .{ .name = "redis", .module = redis_mod },
            .{ .name = "nats", .module = nats_mod },
            .{ .name = "kafka", .module = kafka_mod },
        },
    });

    // Optional native lib for the Postgres backend (until pg.zig lands).
    // The cImport in `storage/postgres_backend.zig` is comptime-gated
    // behind `-Dpostgres` so the default build needs no libpq headers.
    if (enable_postgres) linkLibpq(b, core_mod);

    // ── system OpenSSL link (W3.1) ─────────────────────────────────
    // Wired via Homebrew on macOS aarch64, system pkg-config on Linux.
    // Used by `core.crypto.openssl` for RSA-PKCS1v15-SHA256 sign and by
    // `core.tls.boring_inbound.BoringInboundBackend` for server TLS.
    // See `third_party/boringssl/README.md` for the rationale on system
    // linking vs source vendor.
    linkSystemOpenSsl(b, core_mod, target);

    // ── plugin modules ─────────────────────────────────────────────
    const plugin_modules = [_]struct { name: []const u8, path: []const u8 }{
        .{ .name = "protocol_echo", .path = "src/protocols/echo/plugin.zig" },
        .{ .name = "protocol_atproto", .path = "src/protocols/atproto/plugin.zig" },
        .{ .name = "protocol_activitypub", .path = "src/protocols/activitypub/plugin.zig" },
        .{ .name = "protocol_mastodon", .path = "src/protocols/mastodon/plugin.zig" },
        .{ .name = "protocol_relay", .path = "src/protocols/relay/plugin.zig" },
        .{ .name = "protocol_media", .path = "src/protocols/media/plugin.zig" },
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
    const media_mod = b.addModule("protocol_media", .{
        .root_source_file = b.path("src/protocols/media/plugin.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "core", .module = core_mod },
            .{ .name = "sqlite", .module = sqlite_mod },
        },
    });
    // The Mastodon plugin delegates uploads to the media plugin's
    // public `api`, so it must see the media module at build time. The
    // dependency is strictly one-way (mastodon → media); media never
    // reaches back, mirroring the relay's sibling-lookup carve-out.
    const mastodon_mod = b.addModule("protocol_mastodon", .{
        .root_source_file = b.path("src/protocols/mastodon/plugin.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "core", .module = core_mod },
            .{ .name = "sqlite", .module = sqlite_mod },
            .{ .name = "protocol_media", .module = media_mod },
        },
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
    plugin_imports_list.append(b.allocator, .{ .name = "protocol_mastodon", .module = mastodon_mod }) catch @panic("OOM");
    plugin_imports_list.append(b.allocator, .{ .name = "protocol_relay", .module = relay_mod }) catch @panic("OOM");
    plugin_imports_list.append(b.allocator, .{ .name = "protocol_media", .module = media_mod }) catch @panic("OOM");

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

    // Tests for the vendored TB simulation primitives must run against
    // the tb_testing module directly — `zig test` only executes test
    // blocks in the module being compiled, so referencing them from
    // core's root.zig is not enough.
    const tb_testing_tests = b.addTest(.{ .root_module = tb_testing_mod });
    const run_tb_testing_tests = b.addRunArtifact(tb_testing_tests);

    // The vendored intrusive Stack/List/Queue have PRNG-driven fuzz tests
    // that were gated until `tb_prng` landed. They live in the
    // tb_intrusive module's own test blocks, so we must run that module
    // directly.
    const tb_intrusive_tests = b.addTest(.{ .root_module = tb_intrusive_mod });
    const run_tb_intrusive_tests = b.addRunArtifact(tb_intrusive_tests);

    // W4: the vendored stdx module has its own test blocks plus the
    // upstream-TB `test` blocks inside bounded_array / ring_buffer /
    // iops / bit_set that we pull in via the shim's `test {}`. Running
    // the module directly executes all of them.
    const tb_stdx_tests = b.addTest(.{ .root_module = tb_stdx_mod });
    const run_tb_stdx_tests = b.addRunArtifact(tb_stdx_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_core_tests.step);
    test_step.dependOn(&run_app_tests.step);
    test_step.dependOn(&run_tb_testing_tests.step);
    test_step.dependOn(&run_tb_intrusive_tests.step);
    test_step.dependOn(&run_tb_stdx_tests.step);

    // Per-plugin test step. Each plugin module's tests run independently
    // so that referenced symbols (cid, mst, dag_cbor, …) get pulled in
    // and their `test` blocks execute. The relay is the only plugin
    // that needs its siblings + sqlite available at test time.
    for (plugin_modules) |pm| {
        const is_relay = std.mem.eql(u8, pm.name, "protocol_relay");
        const is_ap = std.mem.eql(u8, pm.name, "protocol_activitypub");
        const is_atproto = std.mem.eql(u8, pm.name, "protocol_atproto");
        const is_media = std.mem.eql(u8, pm.name, "protocol_media");
        const is_mastodon = std.mem.eql(u8, pm.name, "protocol_mastodon");
        const needs_sqlite = is_ap or is_atproto or is_media or is_mastodon;
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
        }) else if (is_mastodon) b.createModule(.{
            .root_source_file = b.path(pm.path),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "core", .module = core_mod },
                .{ .name = "sqlite", .module = sqlite_mod },
                .{ .name = "protocol_media", .module = media_mod },
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
    // Benches inherit the top-level optimize mode. For production-shape
    // numbers run `zig build bench -Doptimize=ReleaseFast`. Debug mode
    // numbers will not meet baseline.json thresholds — that's
    // intentional, the thresholds are recorded against ReleaseFast.
    const bench_optimize = optimize;
    const bench_storage = b.addExecutable(.{
        .name = "storage-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/storage_bench.zig"),
            .target = target,
            .optimize = bench_optimize,
            .imports = &.{
                .{ .name = "core", .module = core_mod },
                .{ .name = "sqlite", .module = sqlite_mod },
            },
        }),
    });
    const run_bench_storage = b.addRunArtifact(bench_storage);
    const bench_step = b.step("bench-storage", "Run the storage layer benchmark");
    bench_step.dependOn(&run_bench_storage.step);

    // D3: firehose throughput — direct insert vs ring+batched drain.
    const bench_firehose = b.addExecutable(.{
        .name = "firehose-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/firehose_bench.zig"),
            .target = target,
            .optimize = bench_optimize,
            .imports = &.{
                .{ .name = "core", .module = core_mod },
                .{ .name = "sqlite", .module = sqlite_mod },
                .{ .name = "protocol_atproto", .module = atproto_mod },
            },
        }),
    });
    const run_bench_firehose = b.addRunArtifact(bench_firehose);
    const bench_fh_step = b.step("bench-firehose", "Run the firehose throughput benchmark (D3)");
    bench_fh_step.dependOn(&run_bench_firehose.step);

    // ── simulation harness ─────────────────────────────────────────
    // `zig build sim` runs the federation scenario(s) in tests/sim/.
    // They link against `core` (which re-exports the TB-derived TimeSim /
    // SimIo / PacketSimulator under `core.sim`) plus the fuzz helpers
    // under `core.testing.fuzz`.
    const sim_imports = [_]std.Build.Module.Import{
        .{ .name = "core", .module = core_mod },
        .{ .name = "protocol_activitypub", .module = ap_mod },
        .{ .name = "protocol_atproto", .module = atproto_mod },
        .{ .name = "protocol_relay", .module = relay_mod },
        .{ .name = "sqlite", .module = sqlite_mod },
    };

    const sim_fed_exe = b.addExecutable(.{
        .name = "sim-federate-with-mastodon",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sim/federate_with_mastodon.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &sim_imports,
        }),
    });
    const run_sim_fed = b.addRunArtifact(sim_fed_exe);

    const sim_fh_exe = b.addExecutable(.{
        .name = "sim-firehose-subscriber",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sim/firehose_subscriber.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &sim_imports,
        }),
    });
    const run_sim_fh = b.addRunArtifact(sim_fh_exe);

    const sim_relay_exe = b.addExecutable(.{
        .name = "sim-relay-bridge",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sim/relay_bridge_scenario.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &sim_imports,
        }),
    });
    const run_sim_relay = b.addRunArtifact(sim_relay_exe);

    const sim_chaos_exe = b.addExecutable(.{
        .name = "sim-relay-chaos",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sim/relay_chaos_overflow.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &sim_imports,
        }),
    });
    const run_sim_chaos = b.addRunArtifact(sim_chaos_exe);

    const sim_replay_exe = b.addExecutable(.{
        .name = "sim-deterministic-replay",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sim/deterministic_replay.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &sim_imports,
        }),
    });
    const run_sim_replay = b.addRunArtifact(sim_replay_exe);

    const sim_step = b.step("sim", "Run simulation tests");
    sim_step.dependOn(&run_sim_fed.step);
    sim_step.dependOn(&run_sim_fh.step);
    sim_step.dependOn(&run_sim_relay.step);
    sim_step.dependOn(&run_sim_chaos.step);
    sim_step.dependOn(&run_sim_replay.step);

    // The simulation scenarios also run as regular `zig build test` tests.
    const sim_fed_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sim/federate_with_mastodon.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &sim_imports,
        }),
    });
    const sim_fh_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sim/firehose_subscriber.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &sim_imports,
        }),
    });
    test_step.dependOn(&b.addRunArtifact(sim_fed_tests).step);
    test_step.dependOn(&b.addRunArtifact(sim_fh_tests).step);

    const sim_relay_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sim/relay_bridge_scenario.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &sim_imports,
        }),
    });
    test_step.dependOn(&b.addRunArtifact(sim_relay_tests).step);

    // ── benchmarks (continued) ─────────────────────────────────────
    const echo_bench = b.addExecutable(.{
        .name = "echo-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/echo_bench.zig"),
            .target = target,
            .optimize = bench_optimize,
            .imports = &.{
                .{ .name = "core", .module = core_mod },
            },
        }),
    });
    const run_echo_bench = b.addRunArtifact(echo_bench);

    const bench_runner = b.addExecutable(.{
        .name = "bench-runner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/bench_runner.zig"),
            .target = target,
            .optimize = bench_optimize,
            .imports = &.{
                .{ .name = "core", .module = core_mod },
                .{ .name = "sqlite", .module = sqlite_mod },
            },
        }),
    });
    const run_bench_runner = b.addRunArtifact(bench_runner);
    // Echo bench must finish FIRST so the runner can splice its results.
    run_bench_runner.step.dependOn(&run_echo_bench.step);

    const all_bench_step = b.step("bench", "Run all benchmarks and write bench/results.json");
    all_bench_step.dependOn(&run_bench_runner.step);
}

/// Link the system OpenSSL (`libssl` + `libcrypto`) into the given
/// module. Used by `core` so that `core.crypto.openssl` (RSA sign +
/// inbound TLS) can `@cImport` the headers and resolve at link time.
///
/// macOS aarch64/x86_64: prefer Homebrew OpenSSL 3 because Apple's
/// system libssl is a wrapped LibreSSL that third-party code is not
/// supposed to link.
/// Linux: rely on pkg-config-discoverable system headers + libraries.
fn linkSystemOpenSsl(b: *std.Build, mod: *std.Build.Module, target: std.Build.ResolvedTarget) void {
    _ = b;
    const os_tag = target.result.os.tag;
    const arch = target.result.cpu.arch;
    if (os_tag == .macos) {
        // Homebrew install paths differ by arch.
        const inc_path: []const u8 = if (arch == .aarch64)
            "/opt/homebrew/opt/openssl@3/include"
        else
            "/usr/local/opt/openssl@3/include";
        const lib_path: []const u8 = if (arch == .aarch64)
            "/opt/homebrew/opt/openssl@3/lib"
        else
            "/usr/local/opt/openssl@3/lib";
        mod.addIncludePath(.{ .cwd_relative = inc_path });
        mod.addLibraryPath(.{ .cwd_relative = lib_path });
    }
    mod.linkSystemLibrary("ssl", .{});
    mod.linkSystemLibrary("crypto", .{});
}

/// Link an optional Homebrew-installed library (librdkafka, libpq, …)
/// into `mod`. `brew_formula` is the Homebrew cellar name used to locate
/// headers/libs on macOS; `lib_name` is the linker name (`-l<lib_name>`).
/// On Linux we rely on system/pkg-config-discoverable paths.
fn linkSystemLibByPrefix(
    mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    brew_formula: []const u8,
    lib_name: []const u8,
) void {
    const os_tag = target.result.os.tag;
    const arch = target.result.cpu.arch;
    if (os_tag == .macos) {
        const brew_root: []const u8 = if (arch == .aarch64) "/opt/homebrew/opt" else "/usr/local/opt";
        const inc = std.fmt.allocPrint(std.heap.page_allocator, "{s}/{s}/include", .{ brew_root, brew_formula }) catch @panic("OOM");
        const lib = std.fmt.allocPrint(std.heap.page_allocator, "{s}/{s}/lib", .{ brew_root, brew_formula }) catch @panic("OOM");
        mod.addIncludePath(.{ .cwd_relative = inc });
        mod.addLibraryPath(.{ .cwd_relative = lib });
    }
    mod.linkSystemLibrary(lib_name, .{});
}

/// Link libpq (Postgres client). Homebrew installs the headers/libs under
/// a versioned `postgresql@NN` prefix rather than a bare `libpq/` dir, so
/// we ask `pg_config` for the exact paths (the canonical, portable way).
/// If `pg_config` isn't on PATH we fall back to the system search path.
fn linkLibpq(b: *std.Build, mod: *std.Build.Module) void {
    if (pgConfig(b, "--includedir")) |inc| mod.addIncludePath(.{ .cwd_relative = inc });
    if (pgConfig(b, "--libdir")) |lib| mod.addLibraryPath(.{ .cwd_relative = lib });
    mod.linkSystemLibrary("pq", .{});
}

/// Run `pg_config <flag>` and return the trimmed first line, or null if
/// pg_config is unavailable / fails.
fn pgConfig(b: *std.Build, flag: []const u8) ?[]const u8 {
    var code: u8 = 0;
    const stdout = b.runAllowFail(&.{ "pg_config", flag }, &code, .ignore) catch return null;
    if (code != 0) return null;
    const trimmed = std.mem.trim(u8, stdout, " \t\r\n");
    if (trimmed.len == 0) return null;
    return b.allocator.dupe(u8, trimmed) catch null;
}
