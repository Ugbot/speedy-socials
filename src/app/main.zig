//! Composition root: build core, register plugins, run server.
//!
//! This is the *only* place the GeneralPurposeAllocator and the plugin
//! list are mentioned. Everything below `server.run()` operates on
//! statically-sized buffers handed in here.

const std = @import("std");
const Io = std.Io;
const core = @import("core");
const echo = @import("protocol_echo");

const limits = core.limits;
const Connection = core.connection.Connection;
const StaticPool = core.static.StaticPool;

/// Liveness hook: process is up. Always ready. Plugins will add more
/// substantive hooks (storage, etc.) in later phases.
fn alwaysReadyHook(_: ?*anyopaque) core.health.Status {
    return .ready;
}

/// Shutdown phase: drain the log ring before we close storage. Wired
/// here so the phase order is owned by the composition root.
fn flushLogsPhase(ud: ?*anyopaque) anyerror!void {
    const log_ptr: *core.log.Log = @ptrCast(@alignCast(ud.?));
    try core.log.flushToStderr(log_ptr);
}

pub fn main() !void {
    // GPA only exists during boot, for the big static pool allocation.
    // After `serve()` starts, no further allocations occur on the hot
    // path. We do not pass `allocator` past this function.
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Threaded Io backend. In Phase 6 we'll swap in a simulation backing
    // for deterministic replay tests.
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Connection pool sits on the heap (too big for the stack) but is
    // created once and never resized.
    const pool = try allocator.create(StaticPool(Connection, limits.max_connections));
    defer allocator.destroy(pool);
    pool.initInPlace();

    var real_clock = try core.clock.RealClock.init();
    var rng = core.rng.Rng.initFromOs();

    // ── Observability (Phase 7) ────────────────────────────────────
    // Heap-allocate the log so its ~2 MiB ring isn't on the stack.
    const log_ptr = try allocator.create(core.log.Log);
    defer allocator.destroy(log_ptr);
    log_ptr.* = core.log.Log.init(real_clock.clock());

    // Seed + build hash + start time go in as the first entries.
    {
        var seed_buf: [32]u8 = undefined;
        const seed_str = std.fmt.bufPrint(&seed_buf, "0x{x}", .{rng.seed}) catch unreachable;
        var ts_buf: [32]u8 = undefined;
        const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{real_clock.clock().wallUnix()}) catch unreachable;
        log_ptr.record(.info, "boot", "starting", &.{
            .{ .k = "seed", .v = seed_str },
            .{ .k = "start_unix", .v = ts_str },
        });
    }

    var drainer = core.log.Drainer.init(log_ptr, 100 * std.time.ns_per_ms);
    try drainer.start();
    defer drainer.stopAndJoin();

    var shutdown = core.shutdown.Shutdown.init();
    try core.shutdown.installSignalHandlers(&shutdown);
    defer core.shutdown.uninstallSignalHandlers();

    var health = core.health.Health.init(&shutdown);
    try health.addHook("process", alwaysReadyHook, null);

    // Register the shutdown phases in canonical order. Server stop is
    // wired below once `server` exists.
    try shutdown.addPhase("flush_logs", flushLogsPhase, log_ptr);

    var ctx: core.plugin.Context = .{
        .clock = real_clock.clock(),
        .rng = &rng,
        .userdata = &health,
    };

    // Register plugins. New protocol → new entry here. Core unchanged.
    var registry = core.plugin.Registry.init();
    _ = try registry.register(echo.plugin);

    try registry.initAll(&ctx);
    defer registry.deinitAll(&ctx);

    var router = core.http.router.Router.init();
    // Health routes use plugin slot u16::MAX as a sentinel — they
    // don't belong to any registered plugin.
    try core.health.registerRoutes(&router, std.math.maxInt(u16));
    try registry.registerAllRoutes(&ctx, &router);

    var server = try core.server.Server.init(
        .{ .bind_addr = "127.0.0.1", .port = 8080 },
        io,
        &ctx,
        &router,
        pool,
    );
    defer server.deinit();

    log_ptr.info("boot", "listening on 127.0.0.1:8080");

    // Run the server; on signal, the handler flips shutdown.requested
    // which Server.run() polls and drops out of accept loop.
    serve_loop: while (true) {
        server.run() catch |err| {
            log_ptr.record(.err, "server", "accept loop ended with error", &.{
                .{ .k = "err", .v = @errorName(err) },
            });
            break :serve_loop;
        };
        if (shutdown.isRequested()) {
            server.requestShutdown();
            break :serve_loop;
        }
        break :serve_loop;
    }

    log_ptr.info("shutdown", "running phases");
    if (shutdown.runPhases()) |first_err| {
        log_ptr.record(.err, "shutdown", "phase reported error", &.{
            .{ .k = "err", .v = @errorName(first_err) },
        });
    }
}

test {
    _ = echo;
}
