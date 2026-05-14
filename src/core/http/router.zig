//! Static-capacity HTTP router.
//!
//! Routes are registered at startup (during plugin `register_routes`)
//! and frozen before the loop begins. Lookup is linear over registered
//! patterns — at small N (≤ max_routes = 256) this is faster than
//! hashing and avoids any allocator.
//!
//! Pattern syntax: literal segments and `:name` placeholders. Trailing
//! `*` captures the rest of the path. Examples:
//!   /healthz
//!   /users/:username/inbox
//!   /api/v1/timelines/:kind
//!   /xrpc/*
//!
//! Tiger Style:
//!  * fixed capacity (limits.max_routes)
//!  * no allocation at lookup time
//!  * duplicate route → error at register time, not silent override
//!  * unknown route → HttpError.NotFound, handler decides response

const std = @import("std");
const limits = @import("../limits.zig");
const errors = @import("../errors.zig");
const RouterError = errors.RouterError;
const Request = @import("request.zig").Request;
const Method = @import("request.zig").Method;
const Response = @import("response.zig");
const Plugin = @import("../plugin.zig");
const Context = @import("../plugin.zig").Context;
const assert_mod = @import("../assert.zig");
const assertLe = assert_mod.assertLe;

pub const PathParams = struct {
    keys: [4][]const u8 = .{ "", "", "", "" },
    values: [4][]const u8 = .{ "", "", "", "" },
    count: u8 = 0,

    pub fn get(self: *const PathParams, key: []const u8) ?[]const u8 {
        var i: u8 = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.keys[i], key)) return self.values[i];
        }
        return null;
    }
};

pub const HandlerContext = struct {
    plugin_ctx: *Context,
    request: *const Request,
    response: *Response.Builder,
    params: PathParams,
};

pub const Handler = *const fn (hc: *HandlerContext) anyerror!void;

pub const Route = struct {
    method: Method,
    pattern: []const u8, // borrowed; lifetime ≥ Router
    handler: Handler,
    plugin_index: u16, // bookkeeping
};

pub const Router = struct {
    routes: [limits.max_routes]Route = undefined,
    count: u32 = 0,
    frozen: bool = false,

    pub fn init() Router {
        return .{};
    }

    pub fn register(self: *Router, method: Method, pattern: []const u8, handler: Handler, plugin_index: u16) RouterError!void {
        if (self.frozen) return error.DuplicateRoute; // wrong error but expresses "too late"
        if (self.count >= limits.max_routes) return error.TooManyRoutes;
        if (pattern.len > limits.max_route_pattern_bytes) return error.PatternTooLong;
        if (pattern.len == 0 or pattern[0] != '/') return error.PatternTooLong;

        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            const r = self.routes[i];
            if (r.method == method and std.mem.eql(u8, r.pattern, pattern)) {
                return error.DuplicateRoute;
            }
        }

        self.routes[self.count] = .{
            .method = method,
            .pattern = pattern,
            .handler = handler,
            .plugin_index = plugin_index,
        };
        self.count += 1;
        assertLe(self.count, limits.max_routes);
    }

    pub fn freeze(self: *Router) void {
        self.frozen = true;
    }

    pub fn match(self: *const Router, method: Method, path: []const u8, params: *PathParams) ?Handler {
        params.* = .{};
        var i: u32 = 0;
        var method_matched = false;
        while (i < self.count) : (i += 1) {
            const r = self.routes[i];
            if (matchPattern(r.pattern, path, params)) {
                if (r.method == method) return r.handler;
                method_matched = true;
                params.* = .{};
            }
        }
        if (method_matched) {
            // signal "path matched but method didn't" by returning null;
            // caller distinguishes via the dedicated `matchOrCode` helper.
        }
        return null;
    }

    pub const MatchResult = union(enum) {
        ok: Handler,
        not_found,
        method_not_allowed,
    };

    pub fn matchOrCode(self: *const Router, method: Method, path: []const u8, params: *PathParams) MatchResult {
        params.* = .{};
        var i: u32 = 0;
        var any_path_match = false;
        while (i < self.count) : (i += 1) {
            const r = self.routes[i];
            var tmp: PathParams = .{};
            if (matchPattern(r.pattern, path, &tmp)) {
                if (r.method == method) {
                    params.* = tmp;
                    return .{ .ok = r.handler };
                }
                any_path_match = true;
            }
        }
        return if (any_path_match) .method_not_allowed else .not_found;
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

test "Router static + param + method routing" {
    const TestH = struct {
        fn root(_: *HandlerContext) anyerror!void {}
        fn user(_: *HandlerContext) anyerror!void {}
        fn inbox(_: *HandlerContext) anyerror!void {}
    };

    var r = Router.init();
    try r.register(.get, "/healthz", TestH.root, 0);
    try r.register(.get, "/users/:u", TestH.user, 0);
    try r.register(.post, "/users/:u/inbox", TestH.inbox, 0);

    var params: PathParams = .{};
    switch (r.matchOrCode(.get, "/healthz", &params)) {
        .ok => |h| try std.testing.expectEqual(@intFromPtr(&TestH.root), @intFromPtr(h)),
        else => return error.TestExpectedOk,
    }

    switch (r.matchOrCode(.get, "/users/alice", &params)) {
        .ok => |h| {
            try std.testing.expectEqual(@intFromPtr(&TestH.user), @intFromPtr(h));
            try std.testing.expectEqualStrings("alice", params.get("u").?);
        },
        else => return error.TestExpectedOk,
    }

    switch (r.matchOrCode(.get, "/users/alice/inbox", &params)) {
        .method_not_allowed => {},
        else => return error.TestExpectedMethodNotAllowed,
    }

    switch (r.matchOrCode(.get, "/nope", &params)) {
        .not_found => {},
        else => return error.TestExpectedNotFound,
    }
}

test "Router duplicate route rejected" {
    const TestH = struct {
        fn h(_: *HandlerContext) anyerror!void {}
    };
    var r = Router.init();
    try r.register(.get, "/x", TestH.h, 0);
    try std.testing.expectError(error.DuplicateRoute, r.register(.get, "/x", TestH.h, 0));
}

test "Router wildcard tail" {
    const TestH = struct {
        fn h(_: *HandlerContext) anyerror!void {}
    };
    var r = Router.init();
    try r.register(.get, "/xrpc/*", TestH.h, 0);
    var p: PathParams = .{};
    switch (r.matchOrCode(.get, "/xrpc/com.atproto.server.describeServer", &p)) {
        .ok => {},
        else => return error.TestExpectedOk,
    }
}
