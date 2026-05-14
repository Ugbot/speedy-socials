//! Module-level state for the Mastodon plugin.
//!
//! Mirrors the AP plugin's pattern: a single process-wide struct holding
//! the writer DB handle, hostname, JWT signing key, and clock/RNG. All
//! persistent data lives in SQLite — this struct is purely a handle
//! cache.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const Clock = core.clock.Clock;
const Rng = core.rng.Rng;
const Ed25519KeyPair = @import("keypair_ed25519.zig").Ed25519KeyPair;

pub const State = struct {
    /// Direct SQLite writer connection (same pattern as AP/relay).
    db: ?*c.sqlite3 = null,
    clock: Clock = undefined,
    rng: ?*Rng = null,
    initialized: bool = false,

    /// Instance hostname. Defaults to "speedy-socials.local".
    hostname_buf: [128]u8 = [_]u8{0} ** 128,
    hostname_len: usize = 0,

    /// JWT signing key for OAuth bearer tokens. Generated deterministically
    /// from the process RNG at init.
    jwt_key: Ed25519KeyPair = .{
        .public_key = [_]u8{0} ** 32,
        .secret_key = [_]u8{0} ** 64,
    },

    /// WS subscription registry, wired by the composition root. Null
    /// until attached. See `src/protocols/mastodon/routes/streaming_ws.zig`.
    ws_registry: ?*core.ws.registry.Registry = null,

    pub fn hostname(self: *const State) []const u8 {
        if (self.hostname_len == 0) return "speedy-socials.local";
        return self.hostname_buf[0..self.hostname_len];
    }
};

var instance: State = .{};

pub fn get() *State {
    return &instance;
}

pub fn reset() void {
    instance = .{};
}

pub fn attachDb(db: *c.sqlite3) void {
    instance.db = db;
}

pub fn attachWsRegistry(reg: *core.ws.registry.Registry) void {
    instance.ws_registry = reg;
}

pub fn setClockAndRng(clock: Clock, rng: *Rng) void {
    instance.clock = clock;
    instance.rng = rng;

    // Derive a stable JWT signing seed from the RNG. We pull 32 bytes
    // through the RNG so every boot produces a fresh key — clients must
    // re-authenticate after a restart, which is the desired property for
    // a single-instance server.
    var seed: [32]u8 = undefined;
    rng.random().bytes(&seed);
    instance.jwt_key = Ed25519KeyPair.fromSeed(seed);
    instance.initialized = true;
}

pub fn setHostname(name: []const u8) void {
    const n = @min(name.len, instance.hostname_buf.len);
    @memcpy(instance.hostname_buf[0..n], name[0..n]);
    instance.hostname_len = n;
}

pub fn isInitialized() bool {
    return instance.initialized;
}

const testing = std.testing;

test "state hostname default + override" {
    reset();
    try testing.expectEqualStrings("speedy-socials.local", get().hostname());
    setHostname("example.org");
    try testing.expectEqualStrings("example.org", get().hostname());
    reset();
}

test "setClockAndRng generates a non-zero JWT key" {
    reset();
    var rng = core.rng.Rng.init(0xC0FFEE);
    var sc = core.clock.SimClock.init(1234);
    setClockAndRng(sc.clock(), &rng);
    try testing.expect(isInitialized());
    var any_nonzero = false;
    for (get().jwt_key.public_key) |b| {
        if (b != 0) any_nonzero = true;
    }
    try testing.expect(any_nonzero);
    reset();
}
