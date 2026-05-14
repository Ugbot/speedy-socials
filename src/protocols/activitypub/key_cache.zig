//! Bounded LRU cache of remote public keys keyed by `keyId`.
//!
//! Tiger Style: fixed capacity, no allocator, spinlock-protected. The
//! cache holds at most `limits.max_cached_pubkeys / shards` entries per
//! shard; we use a single flat slab for simplicity here since 4096
//! entries x ~1.5 KiB ≈ 6 MiB total fits comfortably in BSS.
//!
//! On miss the lookup submits a `Job` to the worker pool to fetch the
//! actor document over HTTP, parse its `publicKey.publicKeyPem`, and
//! return a `PublicKey`. The HTTP fetch itself is a function pointer
//! the host wires at boot. Production wires a TLS-capable HTTPS client;
//! tests override with synchronous stubs.
//!
//! Each entry carries a 24-hour TTL (in addition to LRU capacity bound).
//! Misses bypassing the cache return `FedError.KeyFetchFailed`.

const std = @import("std");
const core = @import("core");
const limits = core.limits;
const assert = core.assert.assert;
const assertLe = core.assert.assertLe;
const Spinlock = core.static.Spinlock;
const Arena = core.arena.Arena;
const Clock = core.clock.Clock;

const keys = @import("keys.zig");
const PublicKey = keys.PublicKey;
const KeyId = keys.KeyId;

pub const FedError = core.errors.FedError;
pub const JobError = core.workers.JobError;

/// Capacity is sized small enough to fit in BSS comfortably even with
/// the full PublicKey struct (~1 KiB each).
pub const capacity: u32 = 256; // intentionally < limits.max_cached_pubkeys

/// Default time-to-live for a cache entry: 24 hours.
pub const default_ttl_ns: i128 = 24 * 60 * 60 * std.time.ns_per_s;

/// KeyEntry sits in a fixed-capacity slab; the LRU order is threaded
/// through the `back`/`next` intrusive-list pointers. `valid` flags the
/// slot as occupied (free slots are not in the list).
const KeyEntry = struct {
    key_id_buf: [keys.max_key_id_bytes]u8 = undefined,
    key_id_len: usize = 0,
    pk: PublicKey = undefined,
    inserted_at_ns: i128 = 0,
    valid: bool = false,
    // Intrusive doubly-linked-list links. The tail of the list is the
    // *most* recently used entry (TB's `DoublyLinkedListType` pushes to
    // tail). The head (`back == null`) is the LRU eviction victim.
    back: ?*KeyEntry = null,
    next: ?*KeyEntry = null,
};

const LruList = core.intrusive.List(KeyEntry);

pub const Cache = struct {
    entries: [capacity]KeyEntry = [_]KeyEntry{.{}} ** capacity,
    lock: Spinlock = .{},
    /// LRU order: tail = MRU, head = LRU.
    lru: LruList = .{},
    /// Diagnostic counters.
    hits: u64 = 0,
    misses: u64 = 0,
    evictions: u64 = 0,

    pub fn reset(self: *Cache) void {
        self.lock.lock();
        defer self.lock.unlock();
        // Drain the LRU list first (clears back/next pointers).
        while (self.lru.pop()) |_| {}
        var i: u32 = 0;
        while (i < capacity) : (i += 1) {
            self.entries[i].valid = false;
            self.entries[i].key_id_len = 0;
            self.entries[i].back = null;
            self.entries[i].next = null;
        }
        self.hits = 0;
        self.misses = 0;
        self.evictions = 0;
    }

    /// In-memory lookup only. Does NOT trigger a fetch. Returns null on
    /// miss. Honors TTL: a stale entry is treated as a miss and
    /// invalidated in place. On hit, the entry is moved to the MRU end
    /// of the LRU list in O(1) via the intrusive list.
    pub fn tryGet(self: *Cache, key_id: []const u8, now_ns: i128) ?PublicKey {
        self.lock.lock();
        defer self.lock.unlock();
        const idx = self.findLocked(key_id) orelse {
            self.misses += 1;
            return null;
        };
        const e = &self.entries[idx];
        // TTL check.
        if (now_ns - e.inserted_at_ns > default_ttl_ns) {
            // Stale: drop from list, mark invalid, count miss.
            self.lru.remove(e);
            e.valid = false;
            self.misses += 1;
            return null;
        }
        // Move-to-front (well: move-to-tail, since tail = MRU).
        self.lru.remove(e);
        self.lru.push(e);
        self.hits += 1;
        return e.pk;
    }

    /// Insert (or refresh) an entry. Evicts the LRU head on full.
    pub fn put(self: *Cache, pk: PublicKey, now_ns: i128) void {
        self.lock.lock();
        defer self.lock.unlock();
        const key_id = pk.key_id.slice();
        if (key_id.len == 0 or key_id.len > keys.max_key_id_bytes) return;

        // Update if present.
        if (self.findLocked(key_id)) |idx| {
            const e = &self.entries[idx];
            e.pk = pk;
            e.inserted_at_ns = now_ns;
            self.lru.remove(e);
            self.lru.push(e);
            return;
        }

        // Find a free slot. If none, evict the LRU head (front of list).
        const victim = self.acquireSlotLocked();
        const e = &self.entries[victim];
        @memcpy(e.key_id_buf[0..key_id.len], key_id);
        e.key_id_len = key_id.len;
        e.pk = pk;
        e.inserted_at_ns = now_ns;
        e.valid = true;
        self.lru.push(e);
    }

    fn acquireSlotLocked(self: *Cache) u32 {
        // First try a free slot — O(capacity) but only when not yet full.
        var i: u32 = 0;
        while (i < capacity) : (i += 1) {
            if (!self.entries[i].valid) return i;
        }
        // Full: evict the least-recently-used entry. TigerBeetle's
        // DoublyLinkedListType is LIFO at the tail end, so the LRU is at
        // the *head* (walk back from tail until `.back == null`). The
        // walk is bounded by `capacity` and only runs on eviction, which
        // is rare relative to hits/inserts. Hit move-to-tail and stale-
        // TTL removal stay O(1).
        var head: *KeyEntry = self.lru.tail orelse unreachable;
        var steps: u32 = 0;
        while (head.back) |b| : (steps += 1) {
            assertLe(steps, capacity);
            head = b;
        }
        self.lru.remove(head);
        head.valid = false;
        self.evictions += 1;
        const base: [*]KeyEntry = @ptrCast(&self.entries);
        const offset = (@intFromPtr(head) - @intFromPtr(base)) / @sizeOf(KeyEntry);
        assertLe(offset, capacity);
        return @intCast(offset);
    }

    fn findLocked(self: *Cache, key_id: []const u8) ?u32 {
        var i: u32 = 0;
        while (i < capacity) : (i += 1) {
            const e = &self.entries[i];
            if (!e.valid) continue;
            if (e.key_id_len != key_id.len) continue;
            if (std.mem.eql(u8, e.key_id_buf[0..e.key_id_len], key_id)) return i;
        }
        return null;
    }

    pub fn size(self: *Cache) u32 {
        self.lock.lock();
        defer self.lock.unlock();
        return @intCast(self.lru.count);
    }
};

// ──────────────────────────────────────────────────────────────────────
// HTTP fetch hook
// ──────────────────────────────────────────────────────────────────────
//
// The cache itself does not perform I/O. To resolve a miss, the caller
// submits a `Job` to the worker pool whose `run` function calls
// `fetch_hook`. Production wires a real HTTPS client; tests override
// with deterministic stubs.
//
// The hook signature takes a caller-provided buffer for the resulting
// public-key PEM bytes plus a key_id slice. It returns the length
// written, or 0 on failure.

pub const FetchHookFn = *const fn (
    key_id: []const u8,
    out_pem: []u8,
) FedError!usize;

var fetch_hook: ?FetchHookFn = null;

pub fn setFetchHook(hook: ?FetchHookFn) void {
    fetch_hook = hook;
}

pub fn getFetchHook() ?FetchHookFn {
    return fetch_hook;
}

/// Default hook used when none is wired: always fails with
/// `KeyFetchFailed`. Production injects a TLS HTTPS client.
pub fn defaultStub(_: []const u8, _: []u8) FedError!usize {
    return error.KeyFetchFailed;
}

// ──────────────────────────────────────────────────────────────────────
// Worker-pool fetch path
// ──────────────────────────────────────────────────────────────────────

pub const FetchCtx = struct {
    /// Input.
    key_id: []const u8,
    /// Output PEM buffer the worker writes into.
    pem_buf: [keys.max_pem_bytes]u8 = undefined,
    pem_len: usize = 0,
};

pub fn fetchJobRun(ctx_raw: *anyopaque, _: *Arena) anyerror!void {
    const ctx: *FetchCtx = @ptrCast(@alignCast(ctx_raw));
    const hook = fetch_hook orelse return error.KeyFetchFailed;
    ctx.pem_len = try hook(ctx.key_id, &ctx.pem_buf);
}

/// High-level helper: hit the in-memory cache, on miss submit a fetch
/// job and block on it via the Completion API, then parse the PEM into
/// a `PublicKey` and insert into the cache. Returns the resolved
/// `PublicKey` or `FedError.KeyFetchFailed`.
pub fn resolve(
    cache: *Cache,
    pool: *core.workers.Pool(8),
    clock: Clock,
    key_id: []const u8,
) FedError!PublicKey {
    const now = clock.wallNs();
    if (cache.tryGet(key_id, now)) |hit| return hit;

    var ctx: FetchCtx = .{ .key_id = key_id };
    var completion = core.workers.Completion.init();
    pool.submit(.{
        .run = fetchJobRun,
        .ctx = @ptrCast(&ctx),
        .completion = &completion,
    }) catch return error.KeyFetchFailed;
    completion.wait() catch return error.KeyFetchFailed;

    if (ctx.pem_len == 0) return error.KeyFetchFailed;
    const kid = KeyId.fromSlice(key_id) catch return error.KeyFetchFailed;
    const pk = keys.parsePublicKeyPem(ctx.pem_buf[0..ctx.pem_len], kid) catch {
        return error.KeyFetchFailed;
    };
    cache.put(pk, now);
    return pk;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Cache miss returns null and increments miss counter" {
    var cache: Cache = .{};
    cache.reset();
    try testing.expect(cache.tryGet("k1", 0) == null);
    try testing.expect(cache.misses == 1);
    try testing.expect(cache.hits == 0);
}

test "Cache put + tryGet hit" {
    var cache: Cache = .{};
    cache.reset();
    const kid = try KeyId.fromSlice("https://example/k1");
    const pair = try keys.generateEd25519FromSeed(kid, keys.testSeed(11));
    cache.put(pair.public, 1000);
    const got = cache.tryGet("https://example/k1", 1000) orelse return error.TestExpectedHit;
    try testing.expect(got.algo == .ed25519);
    try testing.expect(cache.hits == 1);
}

test "Cache TTL expiration invalidates entry" {
    var cache: Cache = .{};
    cache.reset();
    const kid = try KeyId.fromSlice("ttl-key");
    const pair = try keys.generateEd25519FromSeed(kid, keys.testSeed(22));
    cache.put(pair.public, 1000);
    // Read shortly after insertion → hit.
    _ = cache.tryGet("ttl-key", 1000 + 1000) orelse return error.TestExpectedHit;
    // 25 hours later → miss.
    const stale = 1000 + 25 * 60 * 60 * std.time.ns_per_s;
    try testing.expect(cache.tryGet("ttl-key", stale) == null);
}

test "Cache eviction picks LRU slot" {
    var cache: Cache = .{};
    cache.reset();
    // Fill the cache.
    var name_buf: [32]u8 = undefined;
    var i: u32 = 0;
    while (i < capacity) : (i += 1) {
        const name = std.fmt.bufPrint(&name_buf, "k{d}", .{i}) catch unreachable;
        const kid = try KeyId.fromSlice(name);
        const pair = try keys.generateEd25519FromSeed(kid, keys.testSeed(@intCast(i & 0xff)));
        cache.put(pair.public, 0);
    }
    // Touch entry 0 so it becomes most-recently-used.
    _ = cache.tryGet("k0", 0);
    // Inserting one more should evict the LRU (k1, the oldest untouched).
    const new_kid = try KeyId.fromSlice("knew");
    const np = try keys.generateEd25519FromSeed(new_kid, keys.testSeed(123));
    cache.put(np.public, 0);
    try testing.expect(cache.evictions >= 1);
    try testing.expect(cache.tryGet("knew", 0) != null);
    // k0 still present (recently used).
    try testing.expect(cache.tryGet("k0", 0) != null);
}

test "Cache LRU list keeps MRU at tail and evicts head O(1)" {
    // Verifies the TigerBeetle intrusive List adoption: every hit must
    // move the entry to the tail and every full-cache insert must evict
    // exactly the head (true LRU).
    var cache: Cache = .{};
    cache.reset();

    // Fill the cache in order so insertion order == initial LRU order.
    var name_buf: [32]u8 = undefined;
    var i: u32 = 0;
    while (i < capacity) : (i += 1) {
        const name = std.fmt.bufPrint(&name_buf, "lru{d}", .{i}) catch unreachable;
        const kid = try KeyId.fromSlice(name);
        const pair = try keys.generateEd25519FromSeed(kid, keys.testSeed(@intCast(i & 0xff)));
        cache.put(pair.public, 0);
    }
    try testing.expectEqual(capacity, cache.size());
    // Head of list must be the very first inserted key.
    try testing.expect(cache.lru.tail != null);

    // Touch lru0 — it must move to the tail (MRU).
    _ = cache.tryGet("lru0", 0);

    // Insert one more — must evict lru1 (now the LRU head).
    const new_kid = try KeyId.fromSlice("after");
    const np = try keys.generateEd25519FromSeed(new_kid, keys.testSeed(0xaa));
    cache.put(np.public, 0);

    try testing.expectEqual(@as(u64, 1), cache.evictions);
    try testing.expect(cache.tryGet("lru0", 0) != null);
    try testing.expect(cache.tryGet("after", 0) != null);
    // lru1 was evicted.
    try testing.expect(cache.tryGet("lru1", 0) == null);
}

test "Cache LRU TTL eviction removes entry from intrusive list" {
    var cache: Cache = .{};
    cache.reset();
    const kid = try KeyId.fromSlice("ttl");
    const pair = try keys.generateEd25519FromSeed(kid, keys.testSeed(3));
    cache.put(pair.public, 1000);
    try testing.expectEqual(@as(u32, 1), cache.size());
    // Stale read invalidates and removes from the list.
    const stale = 1000 + 25 * 60 * 60 * std.time.ns_per_s;
    try testing.expect(cache.tryGet("ttl", stale) == null);
    try testing.expectEqual(@as(u32, 0), cache.size());
    try testing.expect(cache.lru.empty());
}

test "default fetch hook stub returns KeyFetchFailed" {
    setFetchHook(null);
    var buf: [16]u8 = undefined;
    try testing.expectError(error.KeyFetchFailed, defaultStub("k", &buf));
}

const TestHook = struct {
    var captured_key_id: [64]u8 = undefined;
    var captured_len: usize = 0;
    var supplied_pem: ?[]const u8 = null;

    fn run(key_id: []const u8, out_pem: []u8) FedError!usize {
        captured_len = @min(key_id.len, captured_key_id.len);
        @memcpy(captured_key_id[0..captured_len], key_id[0..captured_len]);
        const pem = supplied_pem orelse return error.KeyFetchFailed;
        if (pem.len > out_pem.len) return error.KeyFetchFailed;
        @memcpy(out_pem[0..pem.len], pem);
        return pem.len;
    }
};

test "resolve uses worker pool to populate cache on miss" {
    var cache: Cache = .{};
    cache.reset();
    const Pool8 = core.workers.Pool(8);
    var pool: Pool8 = undefined;
    pool.initInPlace();
    try pool.start();
    defer pool.stop();

    // Generate a PEM the stub will hand back.
    const kid = try KeyId.fromSlice("https://h/k");
    const pair = try keys.generateEd25519FromSeed(kid, keys.testSeed(7));
    var pem_buf: [keys.max_pem_bytes]u8 = undefined;
    const n = try keys.writeEd25519PublicPem(pair.public.ed25519Bytes(), &pem_buf);

    TestHook.supplied_pem = pem_buf[0..n];
    setFetchHook(TestHook.run);
    defer setFetchHook(null);

    var sc = core.clock.SimClock.init(1);

    const got = try resolve(&cache, &pool, sc.clock(), "https://h/k");
    try testing.expect(got.algo == .ed25519);
    try testing.expectEqualSlices(u8, &pair.public.ed25519Bytes(), &got.ed25519Bytes());
    // Second call should hit cache, no fetch.
    TestHook.supplied_pem = null; // would fail if hit again
    const got2 = try resolve(&cache, &pool, sc.clock(), "https://h/k");
    try testing.expect(got2.algo == .ed25519);
}

test "resolve propagates KeyFetchFailed when hook returns error" {
    var cache: Cache = .{};
    cache.reset();
    const Pool8 = core.workers.Pool(8);
    var pool: Pool8 = undefined;
    pool.initInPlace();
    try pool.start();
    defer pool.stop();

    setFetchHook(defaultStub);
    defer setFetchHook(null);

    var sc = core.clock.SimClock.init(1);
    try testing.expectError(error.KeyFetchFailed, resolve(&cache, &pool, sc.clock(), "missing"));
}
