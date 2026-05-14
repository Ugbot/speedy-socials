//! ActivityPub plugin — Phase 3a (signatures + state machines).
//!
//! This is the pure-logic core. Routes are not registered yet; that
//! lands when the storage layer (Phase 2) and HTTP delivery worker
//! (Phase 3b) are wired in. The plugin still registers cleanly so
//! `main.zig` can refer to it.
//!
//! Submodules:
//!   * `sig`        — HTTP Signature parse/verify (cavage + RFC 9421)
//!   * `keys`       — public/private keys, PEM serialization, RSA hook
//!   * `activity`   — minimal JSON view parser
//!   * `inbox`      — eight deterministic state machines
//!   * `nodeinfo`   — NodeInfo 2.1 + JRD writers
//!   * `collections`— OrderedCollection writers
//!
//! The plugin's `state` will grow to hold the per-instance host config
//! and a small key cache. For Phase 3a it is `null`.

const std = @import("std");
const core = @import("core");

const Plugin = core.plugin.Plugin;
const Context = core.plugin.Context;
const Router = core.http.router.Router;

pub const sig = @import("sig.zig");
pub const keys = @import("keys.zig");
pub const activity = @import("activity.zig");
pub const inbox = @import("inbox.zig");
pub const nodeinfo = @import("nodeinfo.zig");
pub const collections = @import("collections.zig");

fn init(_: ?*anyopaque, _: *Context) anyerror!void {}

fn deinit(_: ?*anyopaque, _: *Context) void {}

// register_routes is intentionally null: storage integration comes next.
// When it lands, this function will register:
//   GET  /.well-known/nodeinfo
//   GET  /nodeinfo/2.1
//   GET  /users/{u}                  (with Accept negotiation)
//   POST /users/{u}/inbox
//   GET  /users/{u}/outbox
//   GET  /users/{u}/followers
//   GET  /users/{u}/following
//   GET  /users/{u}/collections/featured

pub const plugin: Plugin = .{
    .name = "activitypub",
    .version = 1,
    .init = init,
    .deinit = deinit,
    .register_routes = null,
};

test {
    _ = sig;
    _ = keys;
    _ = activity;
    _ = inbox;
    _ = nodeinfo;
    _ = collections;
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
