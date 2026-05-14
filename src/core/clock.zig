//! Clock abstraction: real wall + monotonic clock in production, a
//! simulated clock under test.
//!
//! Tiger Style: time must be injected so deterministic replay works.
//! Nothing in `core/` or `protocols/` calls `std.time.timestamp()`
//! directly — everything goes through a `*Clock`.

const std = @import("std");
const builtin = @import("builtin");

/// Monotonic nanoseconds since process start (or any fixed epoch — the
/// only contract is that it never goes backwards).
pub const MonoNanos = u64;

/// Wall clock in nanoseconds since the Unix epoch.
pub const WallNanos = i128;

fn osMonotonicNs() MonoNanos {
    // std.time.Timer was removed in Zig 0.16; we call clock_gettime
    // directly (CLOCK_MONOTONIC on Linux, CLOCK_UPTIME_RAW on Darwin).
    var ts: std.c.timespec = undefined;
    const clk: i32 = if (builtin.target.os.tag.isDarwin())
        @intFromEnum(std.c.CLOCK.UPTIME_RAW)
    else
        @intFromEnum(std.c.CLOCK.MONOTONIC);
    _ = std.c.clock_gettime(@enumFromInt(clk), &ts);
    return @as(MonoNanos, @intCast(ts.sec)) * std.time.ns_per_s + @as(MonoNanos, @intCast(ts.nsec));
}

fn osWallNs() WallNanos {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    return @as(WallNanos, ts.sec) * std.time.ns_per_s + @as(WallNanos, ts.nsec);
}

pub const Clock = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        monotonic_ns: *const fn (ptr: *anyopaque) MonoNanos,
        wall_ns: *const fn (ptr: *anyopaque) WallNanos,
    };

    pub fn monotonicNs(self: Clock) MonoNanos {
        return self.vtable.monotonic_ns(self.ptr);
    }

    pub fn wallNs(self: Clock) WallNanos {
        return self.vtable.wall_ns(self.ptr);
    }

    /// Convenience: wall time as a Unix timestamp in seconds.
    pub fn wallUnix(self: Clock) i64 {
        return @intCast(@divTrunc(self.wallNs(), std.time.ns_per_s));
    }
};

pub const RealClock = struct {
    start_ns: MonoNanos,

    pub fn init() !RealClock {
        return .{ .start_ns = osMonotonicNs() };
    }

    fn monotonic(ptr: *anyopaque) MonoNanos {
        const self: *RealClock = @ptrCast(@alignCast(ptr));
        const now = osMonotonicNs();
        return now -% self.start_ns;
    }

    fn wall(_: *anyopaque) WallNanos {
        return osWallNs();
    }

    pub fn clock(self: *RealClock) Clock {
        return .{
            .ptr = self,
            .vtable = &.{
                .monotonic_ns = monotonic,
                .wall_ns = wall,
            },
        };
    }
};

/// Simulated clock for deterministic tests. Time only advances on
/// explicit `advance` calls.
pub const SimClock = struct {
    mono: MonoNanos = 0,
    wall_base_ns: WallNanos = 0,

    pub fn init(wall_base_unix_seconds: i64) SimClock {
        return .{
            .wall_base_ns = @as(WallNanos, wall_base_unix_seconds) * std.time.ns_per_s,
        };
    }

    pub fn advance(self: *SimClock, ns: u64) void {
        self.mono += ns;
        self.wall_base_ns += @as(WallNanos, ns);
    }

    fn monotonic(ptr: *anyopaque) MonoNanos {
        const self: *SimClock = @ptrCast(@alignCast(ptr));
        return self.mono;
    }

    fn wall(ptr: *anyopaque) WallNanos {
        const self: *SimClock = @ptrCast(@alignCast(ptr));
        return self.wall_base_ns;
    }

    pub fn clock(self: *SimClock) Clock {
        return .{
            .ptr = self,
            .vtable = &.{
                .monotonic_ns = monotonic,
                .wall_ns = wall,
            },
        };
    }
};

/// Adapter from the vendored `TimeSim` (TigerBeetle simulation harness) to
/// the local `Clock` vtable, so federation backoff / retry timers can be
/// exercised against realistic drift (linear, periodic, step, non-ideal)
/// without leaving the `Clock` abstraction.
pub const TimeSimClock = struct {
    sim: *@import("tb_testing").time.TimeSim,

    pub fn init(sim: *@import("tb_testing").time.TimeSim) TimeSimClock {
        return .{ .sim = sim };
    }

    fn monotonic(ptr: *anyopaque) MonoNanos {
        const self: *TimeSimClock = @ptrCast(@alignCast(ptr));
        return self.sim.monotonic();
    }

    fn wall(ptr: *anyopaque) WallNanos {
        const self: *TimeSimClock = @ptrCast(@alignCast(ptr));
        return @as(WallNanos, self.sim.realtime());
    }

    pub fn clock(self: *TimeSimClock) Clock {
        return .{
            .ptr = self,
            .vtable = &.{
                .monotonic_ns = monotonic,
                .wall_ns = wall,
            },
        };
    }
};

test "TimeSimClock proxies TimeSim through Clock vtable" {
    const time_sim_mod = @import("tb_testing").time;
    var ts = time_sim_mod.TimeSim.init(.{
        .resolution = std.time.ns_per_ms,
        .offset_type = .linear,
        .offset_coefficient_A = 0,
        .offset_coefficient_B = 0,
        .epoch = 1_700_000_000 * std.time.ns_per_s,
    });
    var tsc = TimeSimClock.init(&ts);
    const c = tsc.clock();
    try std.testing.expectEqual(@as(MonoNanos, 0), c.monotonicNs());
    ts.tick();
    try std.testing.expectEqual(@as(MonoNanos, std.time.ns_per_ms), c.monotonicNs());
    try std.testing.expectEqual(@as(i64, 1_700_000_000), c.wallUnix());
}

test "SimClock advances deterministically" {
    var sc = SimClock.init(1_700_000_000);
    const c = sc.clock();
    try std.testing.expectEqual(@as(MonoNanos, 0), c.monotonicNs());
    sc.advance(500);
    try std.testing.expectEqual(@as(MonoNanos, 500), c.monotonicNs());
    sc.advance(1_500);
    try std.testing.expectEqual(@as(MonoNanos, 2_000), c.monotonicNs());
    try std.testing.expectEqual(@as(i64, 1_700_000_000), c.wallUnix());
}

test "RealClock monotonic non-decreasing" {
    var rc = try RealClock.init();
    const c = rc.clock();
    const t1 = c.monotonicNs();
    const t2 = c.monotonicNs();
    try std.testing.expect(t2 >= t1);
}
