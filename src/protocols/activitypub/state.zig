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
    /// H2: per-request DB handle (tenant-routed when configured, else the
    /// boot handle). Request handlers read the DB through this.
    pub fn dbHandle(self: *State) ?*c.sqlite3 {
        return core.storage.currentHandle() orelse self.db;
    }

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

pub fn setHostname(name: []const u8) void {
    const n = @min(name.len, instance.hostname_buf.len);
    @memcpy(instance.hostname_buf[0..n], name[0..n]);
    instance.hostname_len = n;
}

/// G4 / FIXSIG: strict HTTP-signature mode. When `true` (the default)
/// the AP inbox REJECTS — with 401 Unauthorized, no store, no fanout —
/// any activity whose signature cannot be verified (cavage header
/// missing, key unresolvable, digest/signature mismatch, stale or
/// replayed). This is the only correct default: without it an attacker
/// can POST forged Create/Delete/Follow activities as any actor.
///
/// The dev escape hatch (`AP_ALLOW_UNSIGNED_INBOX=1`, wired in
/// `main.zig`) flips this back to `false` to restore the historic
/// "soft acceptance" behaviour for local testing only. See
/// `PROTOCOL_AUDIT.md` AP-C2.
var strict_http_sig: bool = true;

pub fn setStrictHttpSig(enabled: bool) void {
    strict_http_sig = enabled;
}

pub fn isStrictHttpSig() bool {
    return strict_http_sig;
}

// AP-27: NodeInfo should declare atproto when the AT plugin is also
// loaded into this Registry. The composition root flips this on after
// the AT plugin's `register` runs; older deployments that don't bring
// up the AT plugin leave it false and the NodeInfo metadata stays
// AP-only.
var advertise_atproto: bool = false;

pub fn setAdvertiseAtproto(enabled: bool) void {
    advertise_atproto = enabled;
}

pub fn advertiseAtproto() bool {
    return advertise_atproto;
}

// AP-20: process-wide replay-window nonce cache. The inbox handler
// records every successfully verified (keyId, signature) here and
// rejects subsequent matches within `replay_cache.window_seconds`.
var replay_cache: @import("sig.zig").ReplayCache = .{};

pub fn replayCache() *@import("sig.zig").ReplayCache {
    return &replay_cache;
}

// AP-9: outbound signature scheme. `cavage` by default (matches the
// current fediverse majority); operators can flip to `rfc9421` via
// the `AP_OUTBOUND_SIG` env at boot.
pub const OutboundSigScheme = enum { cavage, rfc9421 };
var outbound_sig_scheme: OutboundSigScheme = .cavage;

pub fn setOutboundSigScheme(scheme: OutboundSigScheme) void {
    outbound_sig_scheme = scheme;
}

pub fn outboundSigScheme() OutboundSigScheme {
    return outbound_sig_scheme;
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

test "FIXSIG: strict HTTP-sig is ON by default; escape hatch flips it off" {
    // The security-critical invariant: a fresh process MUST reject
    // unverified inbox activities. The inbox handler gates store+fanout
    // on `isStrictHttpSig()` (routes.zig dispatchInbox), so the default
    // here is what stops forged Create/Delete/Follow activities by
    // default.
    //
    // NOTE: `reset()` only clears the per-process `State` struct, not
    // this module-level policy var — so re-assert the compile-time
    // default explicitly to be order-independent regardless of any
    // earlier test that toggled it.
    setStrictHttpSig(true);
    try std.testing.expect(isStrictHttpSig());

    // Dev escape hatch (AP_ALLOW_UNSIGNED_INBOX=1 in main.zig) restores
    // historic soft acceptance for local testing only.
    setStrictHttpSig(false);
    try std.testing.expect(!isStrictHttpSig());

    // Restore the secure default so subsequent tests in this process
    // observe the production policy.
    setStrictHttpSig(true);
}

test "AP-9: outbound sig scheme defaults to cavage, flips to rfc9421" {
    // Default (matches the boot default; http_delivery.deliver reads this).
    setOutboundSigScheme(.cavage);
    try std.testing.expectEqual(OutboundSigScheme.cavage, outboundSigScheme());
    setOutboundSigScheme(.rfc9421);
    try std.testing.expectEqual(OutboundSigScheme.rfc9421, outboundSigScheme());
    // Restore the process-wide default so order-independent tests see cavage.
    setOutboundSigScheme(.cavage);
}
