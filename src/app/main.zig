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

/// Shutdown phase: signal the AP outbox worker to drain before we
/// close storage.
fn flushApOutboxPhase(_: ?*anyopaque) anyerror!void {
    activitypub.state.get().outbox.signalStop();
}

pub fn main() !void {
    // GPA only exists during boot, for the big static pool allocation.
    // After `serve()` starts, no further allocations occur on the hot
    // path. We do not pass `allocator` past this function.
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const gpa_allocator = gpa.allocator();

    // Wrap the GPA in a TigerBeetle StaticAllocator. While in `.init`
    // state, allocations pass through. After the boot sequence we flip
    // to `.static`, after which any allocation panics — guaranteeing
    // the hot path is allocation-free. The wrapper is heap-allocated so
    // its address (used as the vtable `ptr`) is stable across the boot
    // function frame.
    const static_alloc = try gpa_allocator.create(core.alloc.StaticAllocator);
    defer gpa_allocator.destroy(static_alloc);
    static_alloc.* = core.alloc.StaticAllocator.init(gpa_allocator);
    defer static_alloc.deinit();
    const allocator = static_alloc.allocator();

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

    // ── ActivityPub worker pool + state wiring (Phase 3b) ──────────
    const ap_workers = try allocator.create(activitypub.state.PoolType);
    defer allocator.destroy(ap_workers);
    ap_workers.initInPlace();
    try ap_workers.start();
    defer ap_workers.stop();

    activitypub.attachDb(db);
    activitypub.attachWorkers(ap_workers);
    activitypub.setHostname("speedy-socials.local");

    // Wire the RSA verify hook so ActivityPub HTTP signatures with
    // `alg=rsa-sha256` actually verify (Mastodon's default). The hook
    // lives in `core.crypto.rsa`; until W1.2 it was a stub that returned
    // `SignatureInvalid` for every RSA-signed inbox payload.
    activitypub.keys.setRsaVerifyHook(core.crypto.rsa.verifyPkcs1v15Sha256);
    log_ptr.info("boot", "rsa verify hook wired (core.crypto.rsa.verifyPkcs1v15Sha256)");

    // Build the outbound HTTPS client. It shares a dedicated 4-thread
    // pool so federation fetches don't contend with inbox workers.
    // Until a TLS backend is wired in, `https://` requests fail with
    // `error.TlsUnavailable`; plaintext `http://` works in full.
    const http_workers = try allocator.create(core.workers.Pool(4));
    defer allocator.destroy(http_workers);
    http_workers.initInPlace();
    try http_workers.start();
    defer http_workers.stop();

    var http_client = core.http_client.Client.init(io);
    _ = &http_client;
    log_ptr.info("boot", "outbound http client + worker pool ready");

    // Start the AP outbox worker by re-running init paths now that the
    // db is attached. The plugin's init has already run with db=null;
    // since the worker thread is idempotent we kick it now.
    {
        const st = activitypub.state.get();
        if (!st.outbox.running.load(.acquire)) {
            st.outbox.start(db, real_clock.clock(), &rng) catch {};
        }
    }

    try shutdown.addPhase("flush_ap_outbox", flushApOutboxPhase, null);

    // ── AT Protocol PDS wiring (Phase 4b) ──────────────────────────
    var atp_workers: core.workers.Pool(8) = undefined;
    atp_workers.initInPlace();
    try atp_workers.start();
    defer atp_workers.stop();

    atproto.attachDb(db);
    atproto.attachWorkers(&atp_workers);

    // ── HTTP server ────────────────────────────────────────────────
    var router = core.http.router.Router.init();
    // Health routes use plugin slot u16::MAX as a sentinel — they
    // don't belong to any registered plugin.
    try core.health.registerRoutes(&router, std.math.maxInt(u16));
    try registry.registerAllRoutes(&ctx, &router);

    // ── Lock down the boot allocator ───────────────────────────────
    // From here on, the static allocator panics on any `alloc`/`resize`
    // call. The hot path is required to be allocation-free; this is the
    // tripwire that proves it. See `src/third_party/tigerbeetle/alloc/`.
    static_alloc.transition_from_init_to_static();
    log_ptr.info("boot", "static allocator transitioned: hot path is now alloc-free");
    // Flip back to `.deinit` at scope exit so all preceding
    // `defer allocator.destroy(...)` calls can free their slots. Defers
    // run LIFO, so registering this AFTER every destroy-defer means it
    // runs FIRST on the way out.
    defer static_alloc.transition_from_static_to_deinit();

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
