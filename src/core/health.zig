//! /healthz (liveness) + /readyz (readiness) endpoints.
//!
//! Liveness — `/healthz`: always returns 200 as long as the process is
//! up and the HTTP loop is serving. Used by container orchestrators
//! to decide "kill and restart".
//!
//! Readiness — `/readyz`: returns 200 only if
//!  (a) `Shutdown.requested` is false, AND
//!  (b) every registered ready-hook returns `.ready`.
//! Used by load balancers to decide "send traffic". On shutdown
//! request we immediately fail `/readyz` so the LB drains us before
//! the accept loop closes.
//!
//! Ready hooks are an array of callbacks. Plugins register their own
//! hooks via `Health.addHook` (in Phase 7 the plugin contract has no
//! ready capability yet — `src/app/main.zig` wires one for storage
//! and `Shutdown`; the plugin contract gains a `ready` field in a
//! later phase).

const std = @import("std");
const limits = @import("limits.zig");
const errors = @import("errors.zig");
const ObsError = errors.ObsError;
const Shutdown = @import("shutdown.zig").Shutdown;
const Router = @import("http/router.zig").Router;
const HandlerContext = @import("http/router.zig").HandlerContext;
const Response = @import("http/response.zig");
const assert_mod = @import("assert.zig");
const assertLe = assert_mod.assertLe;

pub const Status = enum { ready, not_ready };

pub const HookFn = *const fn (userdata: ?*anyopaque) Status;

pub const Hook = struct {
    name_len: u8 = 0,
    name_buf: [limits.max_phase_name_bytes]u8 = undefined,
    func: HookFn,
    userdata: ?*anyopaque = null,

    pub fn name(self: *const Hook) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const Health = struct {
    shutdown: *Shutdown,
    hooks: [limits.max_health_hooks]Hook = undefined,
    hook_count: u8 = 0,

    pub fn init(s: *Shutdown) Health {
        return .{ .shutdown = s };
    }

    pub fn addHook(
        self: *Health,
        name: []const u8,
        func: HookFn,
        userdata: ?*anyopaque,
    ) ObsError!void {
        if (self.hook_count >= limits.max_health_hooks) return error.TooManyHooks;
        if (name.len > limits.max_phase_name_bytes) return error.LabelTooLong;
        var h: *Hook = &self.hooks[self.hook_count];
        h.* = .{ .func = func, .userdata = userdata };
        @memcpy(h.name_buf[0..name.len], name);
        h.name_len = @intCast(name.len);
        self.hook_count += 1;
        assertLe(@as(u32, self.hook_count), limits.max_health_hooks);
    }

    /// Run all hooks; returns the first one that reports not_ready, or
    /// null if all are ready and shutdown is not requested.
    pub fn firstNotReady(self: *Health) ?*const Hook {
        if (self.shutdown.isRequested()) return null; // distinguished case below
        var i: u8 = 0;
        while (i < self.hook_count) : (i += 1) {
            const h: *const Hook = &self.hooks[i];
            if (h.func(h.userdata) == .not_ready) return h;
        }
        return null;
    }

    pub fn isReady(self: *Health) bool {
        if (self.shutdown.isRequested()) return false;
        var i: u8 = 0;
        while (i < self.hook_count) : (i += 1) {
            const h: *const Hook = &self.hooks[i];
            if (h.func(h.userdata) == .not_ready) return false;
        }
        return true;
    }
};

// ── HTTP handlers ──────────────────────────────────────────────────

fn healthzHandler(hc: *HandlerContext) anyerror!void {
    try hc.response.simple(.ok, "text/plain", "ok\n");
}

fn readyzHandler(hc: *HandlerContext) anyerror!void {
    const ud = hc.plugin_ctx.userdata orelse {
        try hc.response.simple(.service_unavailable, "text/plain", "no health module\n");
        return;
    };
    const health: *Health = @ptrCast(@alignCast(ud));
    if (health.isReady()) {
        try hc.response.simple(.ok, "text/plain", "ready\n");
    } else {
        try hc.response.simple(.service_unavailable, "text/plain", "not ready\n");
    }
}

/// Register /healthz and /readyz on the router. The Health pointer
/// is supplied via `Context.userdata` by the composition root.
pub fn registerRoutes(router: *Router, plugin_index: u16) !void {
    try router.register(.get, "/healthz", healthzHandler, plugin_index);
    try router.register(.get, "/readyz", readyzHandler, plugin_index);
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

const Probe = struct {
    var ready_flag: bool = true;
    fn rdy(_: ?*anyopaque) Status {
        return if (ready_flag) .ready else .not_ready;
    }
};

test "Health: ready when all hooks ready and not shutting down" {
    var s = Shutdown.init();
    var h = Health.init(&s);
    Probe.ready_flag = true;
    try h.addHook("storage", Probe.rdy, null);
    try testing.expect(h.isReady());
}

test "Health: not ready when any hook fails" {
    var s = Shutdown.init();
    var h = Health.init(&s);
    Probe.ready_flag = false;
    try h.addHook("storage", Probe.rdy, null);
    try testing.expect(!h.isReady());
    try testing.expect(h.firstNotReady() != null);
}

test "Health: not ready while shutdown requested" {
    var s = Shutdown.init();
    var h = Health.init(&s);
    Probe.ready_flag = true;
    try h.addHook("storage", Probe.rdy, null);
    s.request();
    try testing.expect(!h.isReady());
}

test "Health: TooManyHooks on overflow" {
    var s = Shutdown.init();
    var h = Health.init(&s);
    var i: u32 = 0;
    while (i < limits.max_health_hooks) : (i += 1) {
        try h.addHook("x", Probe.rdy, null);
    }
    try testing.expectError(error.TooManyHooks, h.addHook("y", Probe.rdy, null));
}
