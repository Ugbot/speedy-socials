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
    std.debug.print("rng seed: 0x{x}\n", .{rng.seed});

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
    };

    // Register plugins. New protocol → new entry here. Core unchanged.
    var registry = core.plugin.Registry.init();
    _ = try registry.register(echo.plugin);

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

    // ── HTTP server ────────────────────────────────────────────────
    var router = core.http.router.Router.init();
    try registry.registerAllRoutes(&ctx, &router);

    var server = try core.server.Server.init(
        .{ .bind_addr = "127.0.0.1", .port = 8080 },
        io,
        &ctx,
        &router,
        pool,
    );
    defer server.deinit();

    std.debug.print("speedy-socials listening on 127.0.0.1:8080\n", .{});
    try server.run();
}

test {
    _ = echo;
}
