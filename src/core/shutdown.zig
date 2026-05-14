//! Graceful shutdown coordinator.
//!
//! Phases run sequentially in registration order on a single thread
//! (the one that calls `runPhases`). Each phase is an idempotent
//! callback returning `!void`; failures are logged but do not abort
//! the sequence — a failure in `flush_outbox` must not stop us from
//! still calling `close_storage`.
//!
//! Canonical phase order for speedy-socials:
//!   1. accept_drained   — stop accepting new TCP connections
//!   2. inflight_drained — let in-flight HTTP requests complete
//!   3. flush_outbox     — push pending federation deliveries
//!   4. flush_logs       — drain the log ring to stderr
//!   5. close_storage    — close SQLite (last; everything above logs)
//!
//! Signal handling: `installSignalHandlers()` wires SIGTERM and SIGINT
//! to set `requested = true`. The accept loop polls `requested` each
//! tick and exits cleanly; the composition root then calls
//! `runPhases`.

const std = @import("std");
const builtin = @import("builtin");
const limits = @import("limits.zig");
const errors = @import("errors.zig");
const ObsError = errors.ObsError;
const assert_mod = @import("assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

pub const PhaseFn = *const fn (userdata: ?*anyopaque) anyerror!void;

pub const Phase = struct {
    name_len: u8 = 0,
    name_buf: [limits.max_phase_name_bytes]u8 = undefined,
    func: PhaseFn,
    userdata: ?*anyopaque = null,
    /// Last error from running this phase, or null on success / not run.
    last_err: ?anyerror = null,

    pub fn name(self: *const Phase) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// Process-global pointer used by C-ABI signal handlers. Set by
/// `installSignalHandlers`. Reset to null by `uninstallSignalHandlers`.
var g_shutdown: ?*Shutdown = null;

pub const Shutdown = struct {
    requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    phases: [limits.max_shutdown_phases]Phase = undefined,
    phase_count: u8 = 0,
    ran: bool = false,

    pub fn init() Shutdown {
        return .{};
    }

    /// Register a phase. Phases run in registration order on
    /// `runPhases`.
    pub fn addPhase(
        self: *Shutdown,
        name: []const u8,
        func: PhaseFn,
        userdata: ?*anyopaque,
    ) ObsError!void {
        if (self.phase_count >= limits.max_shutdown_phases) return error.TooManyPhases;
        if (name.len > limits.max_phase_name_bytes) return error.LabelTooLong;
        var p: *Phase = &self.phases[self.phase_count];
        p.* = .{ .func = func, .userdata = userdata };
        @memcpy(p.name_buf[0..name.len], name);
        p.name_len = @intCast(name.len);
        self.phase_count += 1;
        assertLe(@as(u32, self.phase_count), limits.max_shutdown_phases);
    }

    /// Idempotent flag-flip. Safe to call from signal handlers and
    /// from any thread.
    pub fn request(self: *Shutdown) void {
        self.requested.store(true, .release);
    }

    pub fn isRequested(self: *Shutdown) bool {
        return self.requested.load(.acquire);
    }

    /// Run all phases sequentially in registration order. Returns the
    /// first error seen (still runs remaining phases). Re-entry is
    /// disallowed via the `ran` flag.
    pub fn runPhases(self: *Shutdown) ?anyerror {
        assert(!self.ran);
        self.ran = true;
        var first_err: ?anyerror = null;
        var i: u8 = 0;
        while (i < self.phase_count) : (i += 1) {
            var p: *Phase = &self.phases[i];
            p.last_err = null;
            p.func(p.userdata) catch |e| {
                p.last_err = e;
                if (first_err == null) first_err = e;
            };
        }
        return first_err;
    }

    pub fn phaseAt(self: *Shutdown, idx: u8) ?*Phase {
        if (idx >= self.phase_count) return null;
        return &self.phases[idx];
    }
};

// ── Signal handlers ────────────────────────────────────────────────

fn signalHandler(_: std.c.SIG) callconv(.c) void {
    if (g_shutdown) |s| s.request();
}

/// Install SIGTERM and SIGINT handlers that flip the shutdown flag.
/// Idempotent: calling twice with the same Shutdown is safe.
pub fn installSignalHandlers(s: *Shutdown) ObsError!void {
    g_shutdown = s;
    if (builtin.os.tag == .windows) return; // SIG semantics differ.

    var act = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.c.SIG.TERM, &act, null);
    std.posix.sigaction(std.c.SIG.INT, &act, null);
}

pub fn uninstallSignalHandlers() void {
    g_shutdown = null;
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

const Counter = struct {
    var order: [16]u8 = .{0} ** 16;
    var n: usize = 0;

    fn reset() void {
        n = 0;
        var i: usize = 0;
        while (i < order.len) : (i += 1) order[i] = 0;
    }

    fn step(label: u8) anyerror!void {
        order[n] = label;
        n += 1;
    }

    fn phaseA(_: ?*anyopaque) anyerror!void {
        return step('A');
    }
    fn phaseB(_: ?*anyopaque) anyerror!void {
        return step('B');
    }
    fn phaseC(_: ?*anyopaque) anyerror!void {
        return step('C');
    }
    fn phaseFails(_: ?*anyopaque) anyerror!void {
        _ = try step('F');
        return error.PhaseFailed;
    }
};

test "Shutdown: request() flips flag, phases run in order" {
    Counter.reset();
    var s = Shutdown.init();
    try s.addPhase("A", Counter.phaseA, null);
    try s.addPhase("B", Counter.phaseB, null);
    try s.addPhase("C", Counter.phaseC, null);

    try testing.expect(!s.isRequested());
    s.request();
    try testing.expect(s.isRequested());

    try testing.expectEqual(@as(?anyerror, null), s.runPhases());
    try testing.expectEqual(@as(usize, 3), Counter.n);
    try testing.expectEqual(@as(u8, 'A'), Counter.order[0]);
    try testing.expectEqual(@as(u8, 'B'), Counter.order[1]);
    try testing.expectEqual(@as(u8, 'C'), Counter.order[2]);
}

test "Shutdown: failing phase does not stop later phases" {
    Counter.reset();
    var s = Shutdown.init();
    try s.addPhase("F", Counter.phaseFails, null);
    try s.addPhase("A", Counter.phaseA, null);

    const err = s.runPhases();
    try testing.expect(err != null);
    try testing.expectEqual(@as(usize, 2), Counter.n);
    try testing.expectEqual(@as(u8, 'F'), Counter.order[0]);
    try testing.expectEqual(@as(u8, 'A'), Counter.order[1]);
    try testing.expect(s.phaseAt(0).?.last_err != null);
    try testing.expect(s.phaseAt(1).?.last_err == null);
}

test "Shutdown: TooManyPhases on overflow" {
    var s = Shutdown.init();
    var i: u32 = 0;
    while (i < limits.max_shutdown_phases) : (i += 1) {
        try s.addPhase("x", Counter.phaseA, null);
    }
    try testing.expectError(error.TooManyPhases, s.addPhase("y", Counter.phaseA, null));
}

test "Shutdown: signal-handler arming sets global pointer" {
    var s = Shutdown.init();
    try installSignalHandlers(&s);
    defer uninstallSignalHandlers();
    try testing.expect(g_shutdown == &s);
    // Don't actually raise a signal — exercise the API directly.
    s.request();
    try testing.expect(s.isRequested());
}
