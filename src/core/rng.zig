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

pub const Rng = struct {
    state: std.Random.Xoshiro256,
    seed: u64,

    pub fn init(seed: u64) Rng {
        return .{
            .state = std.Random.Xoshiro256.init(seed),
            .seed = seed,
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
};

test "Rng deterministic given seed" {
    var a = Rng.init(0xdead_beef);
    var b = Rng.init(0xdead_beef);
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        try std.testing.expectEqual(a.random().int(u64), b.random().int(u64));
    }
}
