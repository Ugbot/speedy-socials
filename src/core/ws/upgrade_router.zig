//! Static-capacity WebSocket upgrade router.
//!
//! Mirrors `core/http/router.zig` but the matched handler takes
//! ownership of the connection after the 101 Switching Protocols
//! response is written. The frame codec, ping/pong, close handshake —
//! everything beyond the handshake — is the plugin's responsibility.
//!
//! Pattern syntax is identical to the HTTP router: literal segments
//! and `:name` placeholders; trailing `*` captures the rest of the
//! path. Method is always GET (RFC 6455 §4.1), so it is implicit.
//!
//! Tiger Style:
//!   - fixed capacity (`limits.max_ws_routes`)
//!   - no allocation at lookup time
//!   - duplicate pattern → DuplicateRoute at register time
//!   - frozen before serve loop begins

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const limits = @import("../limits.zig");
const errors = @import("../errors.zig");
const RouterError = errors.RouterError;
const WsError = errors.WsError;
const Request = @import("../http/request.zig").Request;
const Context = @import("../plugin.zig").Context;
const router_mod = @import("../http/router.zig");
const PathParams = router_mod.PathParams;
const Arena = @import("../arena.zig").Arena;
const assert_mod = @import("../assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

/// Per-upgrade context handed to the matched plugin handler. After the
/// server has written the 101 response on `stream`, the handler owns
/// the stream until it returns. The server then closes the socket and
/// releases the connection slot.
pub const WsUpgradeContext = struct {
    plugin_ctx: *Context,
    request: *const Request,
    params: PathParams,
    /// Underlying TCP stream (or TLS-wrapped stream). The plugin reads
    /// and writes frames directly on this.
    stream: net.Stream,
    io: Io,
    /// Per-connection arena for any scratch the plugin needs during
    /// the upgrade-dispatch call frame. The slot is released when the
    /// handler returns; do not retain pointers into this arena past
    /// that point unless they reference plugin-owned long-lived state.
    arena: *Arena,
};

pub const WsHandler = *const fn (ctx: *WsUpgradeContext) anyerror!void;

pub const UpgradeRoute = struct {
    pattern: []const u8,
    handler: WsHandler,
    plugin_index: u16,
};

pub const WsUpgradeRouter = struct {
    routes: [limits.max_ws_routes]UpgradeRoute = undefined,
    count: u32 = 0,
    frozen: bool = false,

    pub fn init() WsUpgradeRouter {
        return .{};
    }

    pub fn register(
        self: *WsUpgradeRouter,
        pattern: []const u8,
        handler: WsHandler,
        plugin_index: u16,
    ) RouterError!void {
        if (self.frozen) return error.DuplicateRoute;
        if (self.count >= limits.max_ws_routes) return error.TooManyRoutes;
        if (pattern.len == 0 or pattern[0] != '/') return error.PatternTooLong;
        if (pattern.len > limits.max_route_pattern_bytes) return error.PatternTooLong;

        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.routes[i].pattern, pattern)) {
                return error.DuplicateRoute;
            }
        }
        self.routes[self.count] = .{
            .pattern = pattern,
            .handler = handler,
            .plugin_index = plugin_index,
        };
        self.count += 1;
        assertLe(self.count, limits.max_ws_routes);
    }

    pub fn freeze(self: *WsUpgradeRouter) void {
        self.frozen = true;
    }

    /// Linear scan for a pattern matching `path`. Returns null if no
    /// pattern matches; caller is expected to respond 400 Bad Request
    /// when the inbound request was an Upgrade request but had no
    /// matching WS route.
    pub fn match(
        self: *const WsUpgradeRouter,
        path: []const u8,
        params: *PathParams,
    ) ?WsHandler {
        params.* = .{};
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            var tmp: PathParams = .{};
            if (matchPattern(self.routes[i].pattern, path, &tmp)) {
                params.* = tmp;
                return self.routes[i].handler;
            }
        }
        return null;
    }
};

fn matchPattern(pattern: []const u8, path: []const u8, params: *PathParams) bool {
    var pi: usize = 0;
    var ti: usize = 0;
    while (pi < pattern.len and ti < path.len) {
        if (pattern[pi] == '*' and pi == pattern.len - 1) {
            return true;
        }
        const p_seg_end = nextSegEnd(pattern, pi);
        const t_seg_end = nextSegEnd(path, ti);
        const p_seg = pattern[pi..p_seg_end];
        const t_seg = path[ti..t_seg_end];

        if (p_seg.len > 0 and p_seg[0] == ':') {
            if (params.count >= params.keys.len) return false;
            params.keys[params.count] = p_seg[1..];
            params.values[params.count] = t_seg;
            params.count += 1;
        } else if (!std.mem.eql(u8, p_seg, t_seg)) {
            return false;
        }

        pi = p_seg_end;
        ti = t_seg_end;
        if (pi < pattern.len and pattern[pi] == '/') pi += 1;
        if (ti < path.len and path[ti] == '/') ti += 1;
    }
    return pi >= pattern.len and ti >= path.len;
}

fn nextSegEnd(s: []const u8, start: usize) usize {
    var i = start;
    while (i < s.len and s[i] != '/') i += 1;
    return i;
}

// ── tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

fn dummyHandler(_: *WsUpgradeContext) anyerror!void {}
fn otherHandler(_: *WsUpgradeContext) anyerror!void {}

test "WsUpgradeRouter registers and matches literal" {
    var r = WsUpgradeRouter.init();
    try r.register("/xrpc/com.atproto.sync.subscribeRepos", dummyHandler, 7);
    r.freeze();
    var p: PathParams = .{};
    const h = r.match("/xrpc/com.atproto.sync.subscribeRepos", &p);
    try testing.expect(h != null);
    try testing.expectEqual(@intFromPtr(&dummyHandler), @intFromPtr(h.?));
}

test "WsUpgradeRouter captures path params" {
    var r = WsUpgradeRouter.init();
    try r.register("/streaming/:topic/:user", dummyHandler, 0);
    r.freeze();
    var p: PathParams = .{};
    const h = r.match("/streaming/public/alice", &p);
    try testing.expect(h != null);
    try testing.expectEqualStrings("public", p.get("topic").?);
    try testing.expectEqualStrings("alice", p.get("user").?);
}

test "WsUpgradeRouter returns null on miss" {
    var r = WsUpgradeRouter.init();
    try r.register("/ws/echo", dummyHandler, 0);
    r.freeze();
    var p: PathParams = .{};
    try testing.expect(r.match("/no/such/route", &p) == null);
}

test "WsUpgradeRouter rejects duplicate pattern" {
    var r = WsUpgradeRouter.init();
    try r.register("/x", dummyHandler, 0);
    try testing.expectError(error.DuplicateRoute, r.register("/x", otherHandler, 0));
}

test "WsUpgradeRouter rejects pattern after freeze" {
    var r = WsUpgradeRouter.init();
    try r.register("/x", dummyHandler, 0);
    r.freeze();
    try testing.expectError(error.DuplicateRoute, r.register("/y", dummyHandler, 0));
}

test "WsUpgradeRouter wildcard tail" {
    var r = WsUpgradeRouter.init();
    try r.register("/ws/*", dummyHandler, 0);
    r.freeze();
    var p: PathParams = .{};
    try testing.expect(r.match("/ws/anything/here", &p) != null);
}
