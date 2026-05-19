//! G3 — per-IP token bucket rate limiting.
//!
//! Bounded in-memory table of buckets keyed by IPv4/IPv6 remote
//! address. When a request arrives we look up (or LRU-evict +
//! create) the bucket, refill tokens based on elapsed time, and
//! decrement one. If the bucket is empty the request is rejected
//! with 429.
//!
//! Tiger Style: fixed-size table, no allocator on the hot path.
//! Collisions on the linear scan are rare at typical N (≤ 4096
//! distinct source IPs in flight); a hash map would be faster but
//! pulls in allocation churn.
//!
//! Tuning: the default is configured for a small public instance
//! (60 req/s burst per IP). Tune via env at boot.

const std = @import("std");

pub const max_buckets: usize = 4096;

/// One bucket per remote IPv4/IPv6 address.
pub const Bucket = struct {
    /// Packed (family, addr) — `0` if slot is free. We collapse v4
    /// + v6 into a single 128-bit field; v4 maps into the low 32
    /// bits with the high bits set to a v4 marker.
    key: u128 = 0,
    /// Tokens currently available; cap = capacity.
    tokens_x1000: i64 = 0,
    /// Last refill time (monotonic ns).
    last_refill_ns: i64 = 0,
};

pub const Config = struct {
    /// Bucket size — burst capacity per source IP.
    capacity: u32 = 60,
    /// Tokens refilled per second.
    refill_per_sec: u32 = 30,
};

/// Process-wide singleton. Set up once at boot; defaults are inert
/// (`enabled = false`) until configured.
pub const Limiter = struct {
    buckets: [max_buckets]Bucket = [_]Bucket{.{}} ** max_buckets,
    cfg: Config = .{},
    enabled: bool = false,
    lock: std.atomic.Value(bool) = .init(false),
    /// LRU eviction cursor — wraps on overflow.
    next_evict: u32 = 0,

    pub fn init() Limiter {
        return .{};
    }

    pub fn configure(self: *Limiter, cfg: Config) void {
        self.cfg = cfg;
        self.enabled = true;
    }

    /// Decide whether `addr` is allowed to make one more request.
    /// `now_ns` is a monotonic clock reading. Returns `true` if
    /// the bucket had a token to spend (and decrements it).
    pub fn allow(self: *Limiter, key: u128, now_ns: i64) bool {
        if (!self.enabled) return true;
        if (key == 0) return true; // unknown caller — let it through, but log via caller

        while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
        defer self.lock.store(false, .release);

        const slot = self.findOrAlloc(key, now_ns);

        // Refill.
        const dt_ns = now_ns - slot.last_refill_ns;
        if (dt_ns > 0) {
            const refill_x1000 = @divTrunc(dt_ns * @as(i64, self.cfg.refill_per_sec), 1_000_000); // per-ms → per-ns scaled by 1000
            const max_x1000 = @as(i64, self.cfg.capacity) * 1000;
            slot.tokens_x1000 = @min(slot.tokens_x1000 + refill_x1000, max_x1000);
            slot.last_refill_ns = now_ns;
        }
        if (slot.tokens_x1000 < 1000) return false;
        slot.tokens_x1000 -= 1000;
        return true;
    }

    fn findOrAlloc(self: *Limiter, key: u128, now_ns: i64) *Bucket {
        // Look for existing.
        var i: u32 = 0;
        while (i < self.buckets.len) : (i += 1) {
            if (self.buckets[i].key == key) return &self.buckets[i];
        }
        // Look for free slot.
        i = 0;
        while (i < self.buckets.len) : (i += 1) {
            if (self.buckets[i].key == 0) {
                self.buckets[i] = .{
                    .key = key,
                    .tokens_x1000 = @as(i64, self.cfg.capacity) * 1000,
                    .last_refill_ns = now_ns,
                };
                return &self.buckets[i];
            }
        }
        // Evict via wrap-around cursor — bounded, no allocator.
        const idx = self.next_evict % @as(u32, max_buckets);
        self.next_evict +%= 1;
        self.buckets[idx] = .{
            .key = key,
            .tokens_x1000 = @as(i64, self.cfg.capacity) * 1000,
            .last_refill_ns = now_ns,
        };
        return &self.buckets[idx];
    }
};

// ── Global ─────────────────────────────────────────────────────────

var global_limiter: Limiter = .{};

pub fn global() *Limiter {
    return &global_limiter;
}

pub fn configureGlobal(cfg: Config) void {
    global_limiter.configure(cfg);
}

/// Pack an IPv4 address into the bucket key space. Used by callers
/// that have a raw u32 (e.g. `addr.in.sa_addr`).
pub fn keyForIpv4(addr: u32) u128 {
    return (@as(u128, 1) << 96) | @as(u128, addr);
}

/// Pack an IPv6 address (16 bytes, network byte order) into the
/// bucket key space.
pub fn keyForIpv6(bytes: [16]u8) u128 {
    var k: u128 = (@as(u128, 2) << 96);
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        k |= @as(u128, bytes[i]) << @intCast((15 - i) * 8);
    }
    return k;
}

// ── Tests ─────────────────────────────────────────────────────────

const testing = std.testing;

test "Limiter: disabled by default — always allow" {
    var l: Limiter = .{};
    try testing.expect(l.allow(keyForIpv4(0x7f000001), 0));
    try testing.expect(l.allow(keyForIpv4(0x7f000001), 1_000_000_000));
}

test "Limiter: burst capacity then 429" {
    var l: Limiter = .{};
    l.configure(.{ .capacity = 3, .refill_per_sec = 1 });
    const key = keyForIpv4(0x7f000001);
    // Three back-to-back at t=0 should pass; fourth fails.
    try testing.expect(l.allow(key, 0));
    try testing.expect(l.allow(key, 0));
    try testing.expect(l.allow(key, 0));
    try testing.expect(!l.allow(key, 0));
}

test "Limiter: refill over time" {
    var l: Limiter = .{};
    l.configure(.{ .capacity = 2, .refill_per_sec = 1 });
    const key = keyForIpv4(0x7f000001);
    try testing.expect(l.allow(key, 0));
    try testing.expect(l.allow(key, 0));
    try testing.expect(!l.allow(key, 0));
    // 1.5 s later — 1 token refilled.
    try testing.expect(l.allow(key, 1_500_000_000));
    try testing.expect(!l.allow(key, 1_500_000_000));
}

test "Limiter: independent buckets per IP" {
    var l: Limiter = .{};
    l.configure(.{ .capacity = 1, .refill_per_sec = 1 });
    const k1 = keyForIpv4(0x01010101);
    const k2 = keyForIpv4(0x02020202);
    try testing.expect(l.allow(k1, 0));
    try testing.expect(!l.allow(k1, 0));
    try testing.expect(l.allow(k2, 0));
    try testing.expect(!l.allow(k2, 0));
}
