//! Mastodon API plugin — W1.3.
//!
//! Mirrors the AP plugin's structure. The plugin owns three private
//! tables (`mastodon_apps`, `mastodon_tokens`, `mastodon_notifications`,
//! plus `mastodon_favourites` and `mastodon_reblogs` for count
//! materialization) and shares `ap_users`, `ap_activities`, `ap_follows`,
//! `ap_actor_keys` with the AP plugin by querying directly against the
//! writer connection (no sibling plugin lookup).
//!
//! OAuth flow chosen: `password` + `client_credentials` grants. See
//! `oauth.zig` for the rationale.
//!
//! Composition-root API:
//!   * `attachDb(db)`        — supply the writer DB.
//!   * `setHostname(...)`    — instance hostname.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;

const Plugin = core.plugin.Plugin;
const Context = core.plugin.Context;
const Router = core.http.router.Router;
const Schema = core.storage.Schema;

pub const schema = @import("schema.zig");
pub const state = @import("state.zig");
pub const jwt = @import("jwt.zig");
pub const oauth = @import("oauth.zig");
pub const auth = @import("auth.zig");
pub const routes = @import("routes.zig");
pub const http_util = @import("http_util.zig");
pub const serialize = @import("serialize.zig");
pub const db = @import("db.zig");
pub const users = @import("users.zig");
pub const keypair_ed25519 = @import("keypair_ed25519.zig");
pub const streaming_ws = @import("routes/streaming_ws.zig");

const WsUpgradeRouter = core.ws.upgrade_router.WsUpgradeRouter;

// Public composition-root API.

pub fn attachDb(database: *c.sqlite3) void {
    state.attachDb(database);
}

pub fn setHostname(name: []const u8) void {
    state.setHostname(name);
}

pub fn attachWsRegistry(reg: *core.ws.registry.Registry) void {
    state.attachWsRegistry(reg);
}

// Plugin contract hooks.

fn init(_: ?*anyopaque, ctx: *Context) anyerror!void {
    state.setClockAndRng(ctx.clock, ctx.rng);
}

fn deinit(_: ?*anyopaque, _: *Context) void {
    state.reset();
}

fn registerSchema(_: ?*anyopaque, _: *Context, sch: *Schema) anyerror!void {
    try schema.register(sch);
}

fn registerRoutes(_: ?*anyopaque, _: *Context, router: *Router, plugin_index: u16) anyerror!void {
    try routes.register(router, plugin_index);
}

fn registerWs(_: ?*anyopaque, _: *Context, router: *WsUpgradeRouter, plugin_index: u16) anyerror!void {
    try streaming_ws.registerRoutes(router, plugin_index);
}

pub const plugin: Plugin = .{
    .name = "mastodon",
    .version = 1,
    .init = init,
    .deinit = deinit,
    .register_schema = registerSchema,
    .register_routes = registerRoutes,
    .register_ws_upgrade = registerWs,
};

test {
    _ = schema;
    _ = state;
    _ = jwt;
    _ = oauth;
    _ = auth;
    _ = routes;
    _ = http_util;
    _ = serialize;
    _ = db;
    _ = users;
    _ = keypair_ed25519;
    _ = @import("tests.zig");
    _ = @import("routes/accounts.zig");
    _ = @import("routes/statuses.zig");
    _ = @import("routes/timelines.zig");
    _ = @import("routes/notifications.zig");
    _ = @import("routes/instance.zig");
    _ = @import("routes/apps.zig");
    _ = @import("routes/media.zig");
    _ = @import("routes/streaming.zig");
    _ = streaming_ws;
}

test "mastodon plugin registers" {
    var rng = core.rng.Rng.init(0xDEAD);
    var sc = core.clock.SimClock.init(0);
    var ctx: Context = .{ .clock = sc.clock(), .rng = &rng };

    var reg = core.plugin.Registry.init();
    _ = try reg.register(plugin);
    try reg.initAll(&ctx);
    defer reg.deinitAll(&ctx);

    try std.testing.expect(reg.find("mastodon") != null);
}
