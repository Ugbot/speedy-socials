//! Module-level state for the ActivityPub plugin.
//!
//! Mirrors the relay's pattern (`relay/state.zig`): route handlers
//! receive a `HandlerContext` carrying a `*Context` (plugin context) —
//! but not a plugin-private pointer. Storing typed handles in a
//! process-wide struct keeps the route signature unchanged.
//!
//! Tiger Style: this is the only mutable global the activitypub plugin
//! owns. All persistent state lives in SQLite.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const Clock = core.clock.Clock;
const Rng = core.rng.Rng;

const key_cache = @import("key_cache.zig");
const outbox_worker = @import("outbox_worker.zig");

/// Default size of the per-app worker pool used for HTTP key fetches +
/// blocking RSA verification offload. Heap-allocated by main.zig.
pub const default_pool_size: u32 = 8;
pub const PoolType = core.workers.Pool(default_pool_size);

pub const State = struct {
    /// Direct SQLite connection used for synchronous reads + writes off
    /// the request hot path. Same pattern as relay/state.zig: admin/AP
    /// federation traffic is rare enough that one shared connection
    /// (the writer) is fine for now.
    db: ?*c.sqlite3 = null,

    /// Worker pool for HTTP key fetches and blocking RSA verify offload.
    /// Attached by main.zig before `initAll`; may be null in tests that
    /// bypass the pool by setting a synchronous fetch hook.
    workers: ?*PoolType = null,

    /// Wall clock.
    clock: Clock = undefined,

    /// Deterministic RNG (for jitter on retry backoff).
    rng: ?*Rng = null,

    /// Instance hostname (e.g. "speedy.example"). Configurable via
    /// `setHostname`; defaults to the value below.
    hostname_buf: [128]u8 = [_]u8{0} ** 128,
    hostname_len: usize = 0,

    /// Public key cache (LRU keyed on key_id).
    keys: key_cache.Cache = .{},

    /// Outbox worker handle. Spawned in `plugin.init`, signalled to
    /// drain in `plugin.deinit`.
    outbox: outbox_worker.Worker = .{},

    /// Outbound HTTP client wired by the composition root. Null until
    /// `attachHttpClient` is called. The federation hook trampolines
    /// dereference this; they fail closed (KeyFetchFailed /
    /// transient_failure) when it is null.
    http_client: ?*core.http_client.Client = null,

    /// Optional log handle. When wired, the inbox emits decline records
    /// here on strict-mode signature rejection. May be null in tests.
    log: ?*core.log.Log = null,

    /// W3.2 ── strict HTTP-signature verification mode. When true
    /// (default), inbound activities without a verifiable signature are
    /// rejected with 401. Soft-accept can be re-enabled at boot via
    /// `AP_SOFT_ACCEPT=1` in the environment, which flips this flag to
    /// `false`. Tests toggle it directly via `setStrictMode`.
    strict_mode: bool = true,

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

pub fn attachWorkers(pool: *PoolType) void {
    instance.workers = pool;
}

pub fn attachHttpClient(client: *core.http_client.Client) void {
    instance.http_client = client;
}

pub fn setClockAndRng(clock: Clock, rng: *Rng) void {
    instance.clock = clock;
    instance.rng = rng;
}

pub fn attachLog(log: *core.log.Log) void {
    instance.log = log;
}

pub fn setStrictMode(strict: bool) void {
    instance.strict_mode = strict;
}

/// Read `AP_SOFT_ACCEPT=1` once at boot. When present and equal to "1",
/// drops the strict-mode flag so staging deployments can accept
/// unverifiable signatures (with a logged decline).
pub fn configureFromEnv() void {
    const val = std.posix.getenv("AP_SOFT_ACCEPT") orelse return;
    if (std.mem.eql(u8, val, "1")) {
        instance.strict_mode = false;
    }
}

pub fn setHostname(name: []const u8) void {
    const n = @min(name.len, instance.hostname_buf.len);
    @memcpy(instance.hostname_buf[0..n], name[0..n]);
    instance.hostname_len = n;
}

test "State get/reset cycle" {
    reset();
    const s = get();
    try std.testing.expect(s.db == null);
    try std.testing.expect(s.workers == null);
    try std.testing.expectEqualStrings("speedy-socials.local", s.hostname());

    setHostname("example.com");
    try std.testing.expectEqualStrings("example.com", get().hostname());
    reset();
    try std.testing.expectEqualStrings("speedy-socials.local", get().hostname());
}
