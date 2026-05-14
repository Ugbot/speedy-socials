//! Composition root: build core, register plugins, run server.
//!
//! This is the *only* place the GeneralPurposeAllocator and the plugin
//! list are mentioned. Everything below `server.run()` operates on
//! statically-sized buffers handed in here.

const std = @import("std");
const Io = std.Io;
const core = @import("core");
const echo = @import("protocol_echo");
const atproto = @import("protocol_atproto");
const activitypub = @import("protocol_activitypub");
const relay = @import("protocol_relay");

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

    // ── storage subsystem ──────────────────────────────────────────
    // Open the SQLite writer connection + spin up the writer thread.
    // Plugins push queries onto `channel`; the writer drains them.
    const db_path: [:0]const u8 = "./speedy_socials.db";
    const db = try core.storage.sqlite.openWriter(db_path);
    defer core.storage.sqlite.closeDb(db);

    var stmt_table = core.storage.StmtTable.init();
    defer stmt_table.finalizeAll();

    var channel = core.storage.Channel.init();
    var writer = core.storage.Writer.init(db, &stmt_table, &channel);

    var handle = core.storage.Handle.init(&channel, &stmt_table);

    var ctx: core.plugin.Context = .{
        .clock = real_clock.clock(),
        .rng = &rng,
        .storage = &handle,
        .userdata = &health,
    };

    // Register plugins. New protocol → new entry here. Core unchanged.
    var registry = core.plugin.Registry.init();
    _ = try registry.register(echo.plugin);
    _ = try registry.register(atproto.plugin);
    _ = try registry.register(activitypub.plugin);
    // Relay registers AFTER its siblings — its `init` calls
    // `Registry.find` for "atproto" and "activitypub" (the sole
    // sibling-lookup carve-out; see src/protocols/relay/plugin.zig).
    _ = try registry.register(relay.plugin);

    // Hand the relay the registry pointer so it can do its one-time
    // sibling lookup during `initAll`.
    relay.attachRegistry(&registry);

    try registry.initAll(&ctx);
    defer registry.deinitAll(&ctx);

    // ── schema migrations ──────────────────────────────────────────
    var schema = core.storage.Schema.init();
    try schema.register(core.storage.bootstrap_migration);
    try registry.registerAllSchemas(&ctx, &schema);
    try schema.applyAll(db);

    // ── prepared statements + writer thread ────────────────────────
    try stmt_table.prepareAll(db);
    try writer.start();
    defer writer.stop();

    // Relay's admin queries reuse the writer connection — they are
    // rare, admin-bound, and synchronous (good enough for Phase 5).
    relay.state.attachDb(db);

    // ── HTTP server ────────────────────────────────────────────────
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
    _ = atproto;
    _ = activitypub;
    _ = relay;
}
