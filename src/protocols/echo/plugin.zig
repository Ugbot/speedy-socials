//! Echo plugin — the toy plugin that proves the plugin contract works.
//!
//! Registers two routes:
//!   GET  /echo           → "echo\n"
//!   POST /echo           → returns the request body verbatim
//!
//! Kept in-tree forever. Phase 1's exit criterion is "this plugin
//! compiles + serves with zero edits to core/".

const std = @import("std");
const core = @import("core");

const Plugin = core.plugin.Plugin;
const Context = core.plugin.Context;
const Router = core.http.router.Router;
const HandlerContext = core.http.router.HandlerContext;
const Method = core.http.request.Method;

fn echoGet(hc: *HandlerContext) anyerror!void {
    try hc.response.simple(.ok, "text/plain", "echo\n");
}

fn echoPost(hc: *HandlerContext) anyerror!void {
    const body = hc.request.body;
    try hc.response.startStatus(.ok);
    try hc.response.header("Content-Type", "application/octet-stream");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

fn init(_: ?*anyopaque, _: *Context) anyerror!void {}

fn deinit(_: ?*anyopaque, _: *Context) void {}

fn registerRoutes(_: ?*anyopaque, _: *Context, router: *Router, plugin_index: u16) anyerror!void {
    try router.register(.get, "/echo", echoGet, plugin_index);
    try router.register(.post, "/echo", echoPost, plugin_index);
}

pub const plugin: Plugin = .{
    .name = "echo",
    .version = 1,
    .init = init,
    .deinit = deinit,
    .register_routes = registerRoutes,
};

test "echo plugin registers and dispatches" {
    var rng = core.rng.Rng.init(0x42);
    var sc = core.clock.SimClock.init(0);
    var ctx: Context = .{ .clock = sc.clock(), .rng = &rng };

    var reg = core.plugin.Registry.init();
    _ = try reg.register(plugin);
    try reg.initAll(&ctx);
    defer reg.deinitAll(&ctx);

    var router = Router.init();
    try reg.registerAllRoutes(&ctx, &router);

    var params: core.http.router.PathParams = .{};
    const match = router.matchOrCode(.get, "/echo", &params);
    switch (match) {
        .ok => {},
        else => return error.TestExpectedOk,
    }
}
