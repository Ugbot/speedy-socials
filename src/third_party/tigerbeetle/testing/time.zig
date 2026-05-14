// Vendored from tigerbeetle/src/testing/time.zig @ 44544ee11057bbc8fe826cb7f93e8e00a57f2fc1.
// Modifications:
//   * Removed dependency on `../time.zig` (TB's Time vtable). TimeSim is now
//     standalone; speedy-socials wraps it via `core.clock.TimeSimClock` to
//     adapt it to the local `core.clock.Clock` vtable.
//   * Replaced stdx.PRNG with std.Random.Xoshiro256 (already used by
//     speedy-socials' `core.rng.Rng`).
//   * `offset()` reads PRNG floats via the standard library directly.
// TigerBeetle is licensed under Apache 2.0; see src/third_party/tigerbeetle/LICENSE.

const std = @import("std");
const assert = std.debug.assert;

pub const OffsetType = enum {
    linear,
    periodic,
    step,
    non_ideal,
};

/// Simulated time source: each `tick()` advances by `resolution` nanoseconds.
/// `realtime()` adds an offset shaped by `offset_type` to model wall-clock
/// drift relative to monotonic time. Used by the simulation harness so that
/// federation backoff, retry timers, and signature freshness windows can be
/// tested without sleeping.
pub const TimeSim = struct {
    /// The duration of a single tick in nanoseconds.
    resolution: u64,

    offset_type: OffsetType,

    /// Co-efficients to scale the offset according to the `offset_type`.
    /// Linear offset is described as A * x + B: A is the drift per tick and B the initial offset.
    /// Periodic is described as A * sin(x * pi / B): A controls the amplitude and B the period in
    /// terms of ticks.
    /// Step function represents a discontinuous jump in the wall-clock time. B is the period in
    /// which the jumps occur. A is the amplitude of the step.
    /// Non-ideal is similar to periodic except the phase is adjusted using a random number taken
    /// from a normal distribution with mean=0, stddev=10. Finally, a random offset (up to
    /// offset_coefficient_C) is added to the result.
    offset_coefficient_A: i64,
    offset_coefficient_B: i64,
    offset_coefficient_C: u32 = 0,

    prng: std.Random.Xoshiro256 = std.Random.Xoshiro256.init(0),

    /// The number of ticks elapsed since initialization.
    ticks: u64 = 0,

    /// The instant in time chosen as the origin of this time source (ns since Unix epoch).
    epoch: i64 = 0,

    pub fn init(opts: struct {
        resolution: u64,
        offset_type: OffsetType,
        offset_coefficient_A: i64,
        offset_coefficient_B: i64,
        offset_coefficient_C: u32 = 0,
        seed: u64 = 0,
        epoch: i64 = 0,
    }) TimeSim {
        assert(opts.resolution > 0);
        return .{
            .resolution = opts.resolution,
            .offset_type = opts.offset_type,
            .offset_coefficient_A = opts.offset_coefficient_A,
            .offset_coefficient_B = opts.offset_coefficient_B,
            .offset_coefficient_C = opts.offset_coefficient_C,
            .prng = std.Random.Xoshiro256.init(opts.seed),
            .epoch = opts.epoch,
        };
    }

    pub fn monotonic(self: *TimeSim) u64 {
        return self.ticks * self.resolution;
    }

    pub fn realtime(self: *TimeSim) i64 {
        return self.epoch + @as(i64, @intCast(self.monotonic())) - self.offset(self.ticks);
    }

    pub fn tick(self: *TimeSim) void {
        self.ticks += 1;
    }

    pub fn offset(self: *TimeSim, ticks: u64) i64 {
        switch (self.offset_type) {
            .linear => {
                const drift_per_tick = self.offset_coefficient_A;
                return @as(i64, @intCast(ticks)) * drift_per_tick + self.offset_coefficient_B;
            },
            .periodic => {
                const unscaled = std.math.sin(@as(f64, @floatFromInt(ticks)) * 2 * std.math.pi /
                    @as(f64, @floatFromInt(self.offset_coefficient_B)));
                const scaled = @as(f64, @floatFromInt(self.offset_coefficient_A)) * unscaled;
                return @as(i64, @intFromFloat(std.math.floor(scaled)));
            },
            .step => {
                return if (ticks > @as(u64, @intCast(self.offset_coefficient_B))) self.offset_coefficient_A else 0;
            },
            .non_ideal => {
                const rand = self.prng.random();
                const phase: f64 = @as(f64, @floatFromInt(ticks)) * 2 * std.math.pi /
                    (@as(f64, @floatFromInt(self.offset_coefficient_B)) +
                        rand.floatNorm(f64) * 10);
                const unscaled = std.math.sin(phase);
                const scaled = @as(f64, @floatFromInt(self.offset_coefficient_A)) * unscaled;
                const c = self.offset_coefficient_C;
                const random_off: i64 = if (c == 0) 0 else blk: {
                    const r = rand.intRangeAtMost(u64, 0, 2 * @as(u64, c));
                    break :blk -@as(i64, @intCast(c)) + @as(i64, @intCast(r));
                };
                return @as(i64, @intFromFloat(std.math.floor(scaled))) + random_off;
            },
        }
    }
};

test "TimeSim linear drift" {
    var t = TimeSim.init(.{
        .resolution = std.time.ns_per_ms,
        .offset_type = .linear,
        .offset_coefficient_A = 7,
        .offset_coefficient_B = 100,
    });
    try std.testing.expectEqual(@as(u64, 0), t.monotonic());
    try std.testing.expectEqual(@as(i64, 100), t.offset(0));
    t.tick();
    try std.testing.expectEqual(@as(u64, std.time.ns_per_ms), t.monotonic());
    try std.testing.expectEqual(@as(i64, 107), t.offset(1));
    var i: u32 = 0;
    while (i < 100) : (i += 1) t.tick();
    try std.testing.expectEqual(@as(i64, 7 * 101 + 100), t.offset(101));
}

test "TimeSim periodic returns bounded values" {
    var t = TimeSim.init(.{
        .resolution = 1,
        .offset_type = .periodic,
        .offset_coefficient_A = 1_000,
        .offset_coefficient_B = 100,
    });
    var max_obs: i64 = std.math.minInt(i64);
    var min_obs: i64 = std.math.maxInt(i64);
    var i: u32 = 0;
    while (i < 1_000) : (i += 1) {
        const o = t.offset(i);
        if (o > max_obs) max_obs = o;
        if (o < min_obs) min_obs = o;
    }
    try std.testing.expect(max_obs <= 1_000 and max_obs >= 900);
    try std.testing.expect(min_obs >= -1_000 and min_obs <= -900);
}

test "TimeSim step jumps once" {
    var t = TimeSim.init(.{
        .resolution = 1,
        .offset_type = .step,
        .offset_coefficient_A = 5_000,
        .offset_coefficient_B = 10,
    });
    try std.testing.expectEqual(@as(i64, 0), t.offset(5));
    try std.testing.expectEqual(@as(i64, 0), t.offset(10));
    try std.testing.expectEqual(@as(i64, 5_000), t.offset(11));
}

test "TimeSim non_ideal stays within bounded random envelope" {
    var t = TimeSim.init(.{
        .resolution = 1,
        .offset_type = .non_ideal,
        .offset_coefficient_A = 100,
        .offset_coefficient_B = 50,
        .offset_coefficient_C = 25,
        .seed = 0xC0FFEE,
    });
    var sum: i64 = 0;
    const N: u32 = 5_000;
    var i: u32 = 0;
    while (i < N) : (i += 1) {
        const o = t.offset(i);
        // Bounded: |sin|*A=100 plus +/-C=25.
        try std.testing.expect(o >= -125 and o <= 125);
        sum += o;
    }
    // Mean should be roughly zero; with N=5000 expect |mean| < ~5.
    const mean = @divTrunc(sum, @as(i64, @intCast(N)));
    try std.testing.expect(mean > -10 and mean < 10);
}
