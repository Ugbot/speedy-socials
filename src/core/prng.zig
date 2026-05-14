//! Full TigerBeetle PRNG surface (Xoshiro256 + enum_weighted + Ratio +
//! Combination + Reservoir + swarm utilities). Re-exported as a separate
//! namespace so callers can use the rich helpers without paying for them
//! on the hot path.
//!
//! TB's `prng.zig` is *itself* a struct — the file declares
//! `s: [4]u64; const PRNG = @This();`. Importing it therefore yields the
//! PRNG *type*, not a namespace. We expose the type as `PRNG` and
//! additionally surface a few convenience aliases.
//!
//! Note: the upstream API deliberately avoids floating point on the
//! PRNG itself (so the underlying generator stays bit-deterministic).
//! The `exponential` and `gaussian` helpers below are speedy-socials
//! additions, built on top of the integer-only API; they live here
//! rather than in the vendored file so that file remains verbatim
//! (modulo the documented shim swap).

const std = @import("std");

pub const PRNG = @import("tb_prng");

/// Less-than-one rational probability. Re-exported for ergonomics so
/// callers can write `core.prng.Ratio` instead of `core.prng.PRNG.Ratio`.
pub const Ratio = PRNG.Ratio;

/// Canonical Ratio constructor.
pub const ratio = PRNG.ratio;

/// Iterator-style API for sampling a combination.
pub const Combination = PRNG.Combination;

/// Iterator-style API for weighted reservoir sampling.
pub const Reservoir = PRNG.Reservoir;

/// Type of the weights argument to `enum_weighted`.
pub const EnumWeightsType = PRNG.EnumWeightsType;

/// Constructor — seed a new PRNG from a u64.
pub fn from_seed(seed: u64) PRNG {
    return PRNG.from_seed(seed);
}

// ─── Distribution helpers (additive — not in TB) ──────────────────────
//
// These build a floating-point distribution out of the PRNG's
// integer-only output. They are intended for use cases where the
// distribution shape matters more than bit-exact determinism (e.g.
// retry-backoff jitter, simulated latency draws). Two PRNGs with the
// same seed will still produce identical f64 sequences because the
// underlying `next()` call sequence is identical.

/// Returns a uniformly distributed f64 in [0, 1). Built from 53 bits of
/// PRNG output (the f64 mantissa) so the gap between consecutive values
/// is uniform.
pub fn uniform01(prng: *PRNG) f64 {
    // Take the high 53 bits to fill the mantissa exactly.
    const bits: u64 = prng.int(u64) >> 11;
    return @as(f64, @floatFromInt(bits)) * (1.0 / @as(f64, @floatFromInt(@as(u64, 1) << 53)));
}

/// Returns a sample from an exponential distribution with the given
/// mean. Uses inverse-CDF sampling: `-mean * ln(1 - U)` where `U` is
/// uniform on [0, 1). The output is always strictly positive.
pub fn exponential(prng: *PRNG, mean: f64) f64 {
    std.debug.assert(mean > 0.0);
    // Use `1 - U` to keep the argument to `log` strictly positive.
    var u: f64 = uniform01(prng);
    // Reject the boundary case `u == 0` (would yield `-ln(1) = 0`,
    // which is fine, but we also want to avoid `u == 1` producing
    // `-ln(0)`; uniform01 already excludes 1, so the only thing we
    // skip is the trivial `u == 0` to keep the output non-zero).
    if (u == 0.0) u = 1.0 / @as(f64, @floatFromInt(@as(u64, 1) << 53));
    return -mean * std.math.log(f64, std.math.e, 1.0 - u);
}

/// Returns a sample from a normal (Gaussian) distribution with the
/// given mean and standard deviation. Uses the Box-Muller transform.
/// Two independent uniform draws are consumed per call (the second
/// transform output is discarded, so determinism is preserved without
/// needing per-PRNG state for caching).
pub fn gaussian(prng: *PRNG, mean: f64, stddev: f64) f64 {
    std.debug.assert(stddev >= 0.0);
    // Avoid `a == 0` (log(0) is -inf).
    var a: f64 = uniform01(prng);
    const b: f64 = uniform01(prng);
    if (a == 0.0) a = 1.0 / @as(f64, @floatFromInt(@as(u64, 1) << 53));
    const r = std.math.sqrt(-2.0 * std.math.log(f64, std.math.e, a));
    const theta = 2.0 * std.math.pi * b;
    return mean + stddev * r * std.math.cos(theta);
}

// ─── Tests ────────────────────────────────────────────────────────────

const testing = std.testing;

test "PRNG re-export round-trips through Ratio" {
    const r = ratio(3, 4);
    try testing.expectEqual(@as(u64, 3), r.numerator);
    try testing.expectEqual(@as(u64, 4), r.denominator);
    var prng = from_seed(0xC0FFEE);
    var hits: u32 = 0;
    var i: u32 = 0;
    while (i < 10_000) : (i += 1) {
        if (prng.chance(r)) hits += 1;
    }
    // Expect ~7500 hits ± a generous statistical band.
    try testing.expect(hits > 7000 and hits < 8000);
}

test "enum_weighted respects weights over 10k samples" {
    const E = enum { a, b, c, d };
    var prng = from_seed(42);
    var counts = [_]u32{ 0, 0, 0, 0 };
    var i: u32 = 0;
    while (i < 10_000) : (i += 1) {
        const e = prng.enum_weighted(E, .{ .a = 1, .b = 1, .c = 4, .d = 4 });
        counts[@intFromEnum(e)] += 1;
    }
    // Total weight = 10, so a≈1000, b≈1000, c≈4000, d≈4000 — ±20%.
    try testing.expect(counts[0] > 800 and counts[0] < 1200);
    try testing.expect(counts[1] > 800 and counts[1] < 1200);
    try testing.expect(counts[2] > 3500 and counts[2] < 4500);
    try testing.expect(counts[3] > 3500 and counts[3] < 4500);
}

test "exponential sample mean within 5% of declared mean" {
    var prng = from_seed(0xBADF00D);
    const declared_mean: f64 = 2.0;
    var sum: f64 = 0.0;
    const n: usize = 20_000;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const x = exponential(&prng, declared_mean);
        try testing.expect(x > 0.0);
        sum += x;
    }
    const observed = sum / @as(f64, @floatFromInt(n));
    const rel_err = @abs(observed - declared_mean) / declared_mean;
    try testing.expect(rel_err < 0.05);
}

test "gaussian sample mean and stddev are well-behaved" {
    var prng = from_seed(0xFACADE);
    const mean: f64 = 5.0;
    const stddev: f64 = 1.5;
    var sum: f64 = 0.0;
    var sq: f64 = 0.0;
    const n: usize = 20_000;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const x = gaussian(&prng, mean, stddev);
        sum += x;
        sq += (x - mean) * (x - mean);
    }
    const observed_mean = sum / @as(f64, @floatFromInt(n));
    const observed_var = sq / @as(f64, @floatFromInt(n));
    const observed_stddev = std.math.sqrt(observed_var);
    try testing.expect(@abs(observed_mean - mean) < 0.05);
    try testing.expect(@abs(observed_stddev - stddev) < 0.05);
}

test "Determinism: same seed yields identical enum_weighted / exponential / gaussian sequences" {
    var a = from_seed(0xABCD_1234);
    var b = from_seed(0xABCD_1234);
    const E = enum { x, y, z };
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        try testing.expectEqual(
            a.enum_weighted(E, .{ .x = 1, .y = 2, .z = 3 }),
            b.enum_weighted(E, .{ .x = 1, .y = 2, .z = 3 }),
        );
    }
    i = 0;
    while (i < 200) : (i += 1) {
        try testing.expectEqual(exponential(&a, 3.0), exponential(&b, 3.0));
    }
    i = 0;
    while (i < 200) : (i += 1) {
        try testing.expectEqual(gaussian(&a, 0.0, 1.0), gaussian(&b, 0.0, 1.0));
    }
}

test "uniform01 stays in [0, 1)" {
    var prng = from_seed(0xDEADBEEF);
    var i: u32 = 0;
    while (i < 10_000) : (i += 1) {
        const u = uniform01(&prng);
        try testing.expect(u >= 0.0 and u < 1.0);
    }
}

test {
    // Pull in the vendored file's own test suite.
    _ = PRNG;
}
