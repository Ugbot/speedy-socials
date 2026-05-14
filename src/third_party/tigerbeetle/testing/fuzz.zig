// Vendored from tigerbeetle/src/testing/fuzz.zig @ 44544ee11057bbc8fe826cb7f93e8e00a57f2fc1.
// Modifications:
//   * Replaced stdx.PRNG with std.Random (callers pass a *std.Random.Xoshiro256
//     from `core.rng.Rng`).
//   * Removed `random_id` / `random_enum_weights` / `DeclEnumExcludingType` /
//     `limit_ram` (require stdx.PRNG.Combination / GiB / setrlimit conveniences
//     not yet vendored — keep the harness minimal for now).
//   * Kept `random_int_exponential`, `range_inclusive_ms`, `parse_seed`,
//     `FuzzArgs` which are exactly what the simulation harness needs.
// TigerBeetle is licensed under Apache 2.0; see src/third_party/tigerbeetle/LICENSE.

const std = @import("std");
const assert = std.debug.assert;

/// Returns an integer of type `T` with an exponential distribution of rate `avg`.
/// Note: If you specify a very high rate then `std.math.maxInt(T)` may be over-represented.
pub fn random_int_exponential(prng: *std.Random.Xoshiro256, comptime T: type, avg: T) T {
    comptime {
        const info = @typeInfo(T);
        assert(info == .int);
        assert(info.int.signedness == .unsigned);
    }
    const random = prng.random();
    const exp = random.floatExp(f64) * @as(f64, @floatFromInt(avg));
    return std.math.lossyCast(T, exp);
}

/// Return a uniformly random duration in nanoseconds in `[min_ms, max_ms]`.
pub fn range_inclusive_ms(prng: *std.Random.Xoshiro256, min_ms: u64, max_ms: u64) u64 {
    assert(min_ms <= max_ms);
    const min_ns = min_ms * std.time.ns_per_ms;
    const max_ns = max_ms * std.time.ns_per_ms;
    return prng.random().intRangeAtMost(u64, min_ns, max_ns);
}

pub const FuzzArgs = struct {
    seed: u64,
    events_max: ?usize,
};

/// Parse a fuzz seed. Accepts:
///   * base-10 unsigned integer (typical).
///   * a 40-char hex string (a Git commit SHA — CI uses this so that runs
///     remain reproducible from the commit hash alone).
pub fn parse_seed(bytes: []const u8) u64 {
    if (bytes.len == 40) {
        const commit_hash = std.fmt.parseUnsigned(u160, bytes, 16) catch |err| switch (err) {
            error.Overflow => unreachable,
            error.InvalidCharacter => @panic("commit hash seed contains an invalid character"),
        };
        return @truncate(commit_hash);
    }

    return std.fmt.parseUnsigned(u64, bytes, 10) catch |err| switch (err) {
        error.Overflow => @panic("seed exceeds a 64-bit unsigned integer"),
        error.InvalidCharacter => @panic("seed contains an invalid character"),
    };
}

test "parse_seed base10" {
    try std.testing.expectEqual(@as(u64, 0), parse_seed("0"));
    try std.testing.expectEqual(@as(u64, 42), parse_seed("42"));
    try std.testing.expectEqual(@as(u64, 18446744073709551615), parse_seed("18446744073709551615"));
}

test "parse_seed git sha (40 hex chars)" {
    // SHA-1 hash, truncated to low 64 bits.
    const sha = "44544ee11057bbc8fe826cb7f93e8e00a57f2fc1";
    const seed = parse_seed(sha);
    // Low 64 bits of 0x44544ee1...a57f2fc1 — compute reference.
    const full = try std.fmt.parseUnsigned(u160, sha, 16);
    const expected: u64 = @truncate(full);
    try std.testing.expectEqual(expected, seed);
}

test "random_int_exponential mean approximates avg" {
    var prng = std.Random.Xoshiro256.init(0xBADF00D);
    const N: u32 = 20_000;
    const target_avg: u64 = 1_000;
    var sum: u128 = 0;
    var i: u32 = 0;
    while (i < N) : (i += 1) {
        sum += random_int_exponential(&prng, u64, target_avg);
    }
    const mean = @as(u64, @intCast(sum / N));
    // Expect within +/- 15% — exponential variance is high but N is large.
    try std.testing.expect(mean > target_avg - target_avg / 6);
    try std.testing.expect(mean < target_avg + target_avg / 6);
}

test "range_inclusive_ms stays within bounds" {
    var prng = std.Random.Xoshiro256.init(7);
    var i: u32 = 0;
    while (i < 1_000) : (i += 1) {
        const ns = range_inclusive_ms(&prng, 5, 20);
        try std.testing.expect(ns >= 5 * std.time.ns_per_ms);
        try std.testing.expect(ns <= 20 * std.time.ns_per_ms);
    }
}
