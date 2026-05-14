//! ActivityPub plugin — Phase 3b integration.
//!
//! Submodules:
//!   * `sig`            — HTTP Signature parse/verify (cavage + RFC 9421)
//!   * `keys`           — public/private keys + PEM + RSA hook
//!   * `activity`       — minimal JSON view parser
//!   * `inbox`          — eight deterministic state machines
//!   * `nodeinfo`       — NodeInfo 2.1 + JRD writers
//!   * `collections`    — OrderedCollection writers
//!   * `schema`         — migration registration (Phase 3b)
//!   * `state`          — module-level state singleton (Phase 3b)
//!   * `routes`         — HTTP route handlers (Phase 3b)
//!   * `webfinger`      — JRD writer (Phase 3b)
//!   * `actor`          — Person JSON-LD writer (Phase 3b)
//!   * `key_cache`      — bounded LRU + worker-pool fetch (Phase 3b)
//!   * `delivery`       — recipient dedup, bto/bcc strip, outbox enqueue
//!   * `outbox_worker`  — federation delivery polling thread
//!
//! Integration seams the composition root drives:
//!   * `attachDb(db)`       — wire the writer DB connection
//!   * `attachWorkers(p)`   — wire the worker pool for key fetches
//!   * `setHostname(...)`   — set the instance hostname
//!
//! On `init` the plugin starts the outbox worker thread. On `deinit`
//! it signals it to stop and joins it.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;

const Plugin = core.plugin.Plugin;
const Context = core.plugin.Context;
const Router = core.http.router.Router;
const Schema = core.storage.Schema;

pub const sig = @import("sig.zig");
pub const keys = @import("keys.zig");
pub const activity = @import("activity.zig");
pub const inbox = @import("inbox.zig");
pub const nodeinfo = @import("nodeinfo.zig");
pub const collections = @import("collections.zig");
pub const schema = @import("schema.zig");
pub const state = @import("state.zig");
pub const routes = @import("routes.zig");
pub const webfinger = @import("webfinger.zig");
pub const actor = @import("actor.zig");
pub const key_cache = @import("key_cache.zig");
pub const delivery = @import("delivery.zig");
pub const outbox_worker = @import("outbox_worker.zig");
pub const key_fetcher_http = @import("key_fetcher_http.zig");
pub const http_delivery = @import("http_delivery.zig");

// ──────────────────────────────────────────────────────────────────────
// Public composition-root API
// ──────────────────────────────────────────────────────────────────────

pub fn attachDb(db: *c.sqlite3) void {
    state.attachDb(db);
}

pub fn attachWorkers(pool: *state.PoolType) void {
    state.attachWorkers(pool);
}

pub fn setHostname(name: []const u8) void {
    state.setHostname(name);
}

/// Bind the outbound HTTP client used by the federation hooks (key
/// cache fetch + outbox delivery). Stored in module-level state so the
/// hook trampolines — which the existing hook ABI does not let us
/// extend with a context pointer — can find it.
pub fn attachHttpClient(client: *core.http_client.Client) void {
    state.attachHttpClient(client);
}

// ──────────────────────────────────────────────────────────────────────
// Plugin contract hooks
// ──────────────────────────────────────────────────────────────────────

fn init(_: ?*anyopaque, ctx: *Context) anyerror!void {
    state.setClockAndRng(ctx.clock, ctx.rng);
    // Outbox worker starts only if a db was attached. In test harnesses
    // that skip the integration step it is a no-op.
    const st = state.get();
    if (st.db) |db| {
        st.outbox.start(db, ctx.clock, ctx.rng) catch |err| {
            std.debug.print("activitypub: outbox worker failed to start: {s}\n", .{@errorName(err)});
        };
    }
}

fn deinit(_: ?*anyopaque, _: *Context) void {
    state.get().outbox.joinAndDrain();
    state.reset();
}

fn registerSchema(_: ?*anyopaque, _: *Context, sch: *Schema) anyerror!void {
    try schema.register(sch);
}

fn registerRoutes(_: ?*anyopaque, _: *Context, router: *Router, plugin_index: u16) anyerror!void {
    try routes.register(router, plugin_index);
}

pub const plugin: Plugin = .{
    .name = "activitypub",
    .version = 2,
    .init = init,
    .deinit = deinit,
    .register_schema = registerSchema,
    .register_routes = registerRoutes,
};

test {
    _ = sig;
    _ = keys;
    _ = activity;
    _ = inbox;
    _ = nodeinfo;
    _ = collections;
    _ = schema;
    _ = state;
    _ = routes;
    _ = webfinger;
    _ = actor;
    _ = key_cache;
    _ = delivery;
    _ = outbox_worker;
    _ = key_fetcher_http;
    _ = http_delivery;
}

test "activitypub plugin registers" {
    var rng = core.rng.Rng.init(0x42);
    var sc = core.clock.SimClock.init(0);
    var ctx: Context = .{ .clock = sc.clock(), .rng = &rng };

    var reg = core.plugin.Registry.init();
    _ = try reg.register(plugin);
    try reg.initAll(&ctx);
    defer reg.deinitAll(&ctx);

    try std.testing.expect(reg.find("activitypub") != null);
}
