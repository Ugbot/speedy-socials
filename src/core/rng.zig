//! Seeded RNG behind an interface, for deterministic simulation.
//!
//! Production: seeded from `std.crypto.random` at boot, seed printed
//! to stderr so a failing run can be reproduced by re-seeding.
//! Test/sim: caller supplies the seed.
//!
//! Use cases:
//!  * federation exponential-backoff jitter
//!  * inbox state-machine random tie-breaks
//!  * deterministic test fuzzing
//!
//! Do NOT use this RNG for cryptographic key generation — use
//! `std.crypto.random` directly (or BoringSSL via `core/crypto/`).

const std = @import("std");

/// Full TigerBeetle PRNG surface, re-exported. Callers wanting the
/// rich API (`Ratio`, `Combination`, `Reservoir`, `enum_weighted`,
/// distribution helpers, …) can reach for `core.rng.tb.<thing>` without
/// constructing a TB PRNG separately — methods on `Rng` below also
/// expose the most-needed helpers directly.
pub const tb = @import("prng.zig");

/// Convenience alias matching the upstream type name.
pub const TbPrng = tb.PRNG;

/// Re-export of the rational-probability type.
pub const Ratio = tb.Ratio;

/// Re-export of the canonical Ratio constructor.
pub const ratio = tb.ratio;

pub const Rng = struct {
    state: std.Random.Xoshiro256,
    seed: u64,
    /// TigerBeetle PRNG seeded from the same `seed`. Stored alongside
    /// `state` so the TB helpers below (`chance`, `enumWeighted`,
    /// `exponential`, `gaussian`, …) can be called without re-seeding
    /// (preserves bit-determinism across replays of a given seed).
    /// The two generators are *independent* streams — sampling from
    /// `tb_state` does not perturb `state`, and vice versa.
    tb_state: tb.PRNG,

    pub fn init(seed: u64) Rng {
        return .{
            .state = std.Random.Xoshiro256.init(seed),
            .seed = seed,
            .tb_state = tb.PRNG.from_seed(seed),
        };
    }

    /// Seed from OS state (monotonic time XOR pid). Suitable for
    /// non-cryptographic uses: jitter, fuzz seed, tie-breaks. For key
    /// generation use OS CSPRNG directly via `core/crypto/`.
    pub fn initFromOs() Rng {
        const builtin = @import("builtin");
        const clock_mod = @import("clock.zig");
        var ts: std.c.timespec = undefined;
        const clk: i32 = if (builtin.target.os.tag.isDarwin())
            @intFromEnum(std.c.CLOCK.UPTIME_RAW)
        else
            @intFromEnum(std.c.CLOCK.MONOTONIC);
        _ = std.c.clock_gettime(@enumFromInt(clk), &ts);
        const sec_u: u64 = @intCast(ts.sec);
        const nsec_u: u64 = @intCast(ts.nsec);
        const pid_u: u64 = @intCast(std.c.getpid());
        const seed: u64 = (sec_u *% 1_000_000_000) +% nsec_u ^ (pid_u << 32);
        _ = clock_mod; // silence unused
        return init(seed);
    }

    pub fn random(self: *Rng) std.Random {
        return self.state.random();
    }

    pub fn u64Range(self: *Rng, lo_inclusive: u64, hi_exclusive: u64) u64 {
        return self.random().intRangeLessThan(u64, lo_inclusive, hi_exclusive);
    }

    // ─── TB-helper passthroughs ──────────────────────────────────────
    //
    // These wrap the most-needed TigerBeetle PRNG helpers so callers
    // don't have to reach for `core.rng.tb` directly. They all draw
    // from the independent `tb_state` stream so they don't disturb the
    // existing `state` sequence (preserves bit-compat with code that
    // pre-dates this addition).

    /// Returns true with the given rational probability.
    pub fn chance(self: *Rng, probability: Ratio) bool {
        return self.tb_state.chance(probability);
    }

    /// Returns a random value of an enum, with probability proportional
    /// to the corresponding weight. `weights` is a struct whose field
    /// names match `Enum` (use `tb.EnumWeightsType(Enum)` for the
    /// canonical type).
    pub fn enumWeighted(
        self: *Rng,
        comptime Enum: type,
        weights: tb.EnumWeightsType(Enum),
    ) Enum {
        return self.tb_state.enum_weighted(Enum, weights);
    }

    /// Sample from an exponential distribution with the given mean.
    /// See `core.prng.exponential` for the underlying implementation.
    pub fn exponential(self: *Rng, mean: f64) f64 {
        return tb.exponential(&self.tb_state, mean);
    }

    /// Sample from a normal (Gaussian) distribution with the given
    /// mean and standard deviation. See `core.prng.gaussian` for the
    /// underlying implementation.
    pub fn gaussian(self: *Rng, mean_value: f64, stddev: f64) f64 {
        return tb.gaussian(&self.tb_state, mean_value, stddev);
    }
};

test "Rng deterministic given seed" {
    var a = Rng.init(0xdead_beef);
    var b = Rng.init(0xdead_beef);
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        try std.testing.expectEqual(a.random().int(u64), b.random().int(u64));
    }
}
