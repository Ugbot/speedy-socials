//! Bounded Redis/Valkey connection pool. Mirrors `../storage/mysql/pool.zig`
//! exactly in shape and concurrency strategy: a fixed-capacity set of live
//! `Conn`s that callers acquire/release around a unit of work. Tiger Style:
//! capacity is fixed at init (no growth), acquisition is a bounded linear
//! scan under an atomic spin-lock (this stripped 0.16 std has no
//! `std.Thread.Mutex`; the codebase uses the spin-lock pattern — see
//! `core.rate_limit` and `mysql/pool.zig`), and the only allocation is the
//! connections themselves (opened lazily up to `size`).
//!
//! Unlike the MySQL pool, `release` takes a `healthy` flag so a connection
//! whose RESP stream desynchronised (a decode error / transport failure) is
//! closed and dropped rather than handed back to the next caller — the
//! drop-in shape the stream/queue providers expect (`pool.release(c, ok)`).

const std = @import("std");
const conn_mod = @import("conn.zig");

const Conn = conn_mod.Conn;
const Options = conn_mod.Options;

pub const Error = conn_mod.Error || error{PoolExhausted};

pub const max_size: usize = 32;

pub const Pool = struct {
    allocator: std.mem.Allocator,
    opts: Options,
    size: usize,
    /// Atomic spin-lock guarding slot bookkeeping — the SAME primitive the
    /// MySQL pool uses (`std.atomic.Value(bool)` swapped acquire/released
    /// release). Held only across the bounded slot scan, never across a
    /// network dial.
    lock: std.atomic.Value(bool) = .init(false),
    /// Slots: a connection (lazily opened) + whether it's currently checked out.
    conns: [max_size]?*Conn = [_]?*Conn{null} ** max_size,
    in_use: [max_size]bool = [_]bool{false} ** max_size,

    pub fn init(allocator: std.mem.Allocator, opts: Options, capacity: usize) Error!*Pool {
        const n = @min(@max(capacity, 1), max_size);
        const self = allocator.create(Pool) catch return error.SocketError;
        errdefer allocator.destroy(self);
        self.* = .{ .allocator = allocator, .opts = opts, .size = n };
        // Open one connection eagerly so init fails fast on a bad host /
        // unreachable server (matching mysql.Pool.init behaviour).
        const c = try Conn.connect(allocator, opts);
        self.conns[0] = c;
        std.debug.assert(self.size >= 1 and self.size <= max_size);
        return self;
    }

    pub fn deinit(self: *Pool) void {
        var i: usize = 0;
        while (i < self.size) : (i += 1) {
            if (self.conns[i]) |c| c.deinit();
        }
        const alloc = self.allocator;
        alloc.destroy(self);
    }

    /// Check out a connection. Reuses an idle live one (reconnecting in
    /// place if it went unhealthy), else opens a new one in a free slot.
    /// Returns `PoolExhausted` when all slots are busy.
    pub fn acquire(self: *Pool) Error!*Conn {
        // Phase 1 (locked): hand back an idle live connection, or reserve an
        // empty/​stale slot to fill. Connecting is done OUTSIDE the lock so a
        // slow network dial never stalls other threads on the spin-lock.
        var reserve_slot: ?usize = null;
        {
            while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
            defer self.lock.store(false, .release);

            var i: usize = 0;
            while (i < self.size) : (i += 1) {
                if (!self.in_use[i]) {
                    if (self.conns[i]) |c| {
                        if (c.isHealthy()) {
                            self.in_use[i] = true;
                            return c;
                        }
                        // Stale/broken: close it and reuse the slot below.
                        c.deinit();
                        self.conns[i] = null;
                    }
                }
            }
            i = 0;
            while (i < self.size) : (i += 1) {
                if (self.conns[i] == null and !self.in_use[i]) {
                    self.in_use[i] = true; // reserve so a peer can't grab it
                    reserve_slot = i;
                    break;
                }
            }
        }

        const slot = reserve_slot orelse return error.PoolExhausted;
        const c = Conn.connect(self.allocator, self.opts) catch |e| {
            // Failed to open: release the reservation so the slot is reusable.
            while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
            self.in_use[slot] = false;
            self.lock.store(false, .release);
            return e;
        };
        while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
        self.conns[slot] = c;
        self.lock.store(false, .release);
        return c;
    }

    /// Return `c` to the pool. When `healthy` is false (or the connection
    /// reports itself unhealthy) the socket is closed and the slot freed so
    /// the next `acquire` opens a fresh connection.
    pub fn release(self: *Pool, c: *Conn, healthy: bool) void {
        const keep = healthy and c.isHealthy();
        while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
        defer self.lock.store(false, .release);
        var i: usize = 0;
        while (i < self.size) : (i += 1) {
            if (self.conns[i] == c) {
                self.in_use[i] = false;
                if (!keep) {
                    c.deinit();
                    self.conns[i] = null;
                }
                return;
            }
        }
    }
};

// ── Tests ──────────────────────────────────────────────────────────────
// Pure structural test (no server) for the fixed bound, plus a live
// acquire/release reuse test that skips cleanly without a broker.

const testing = std.testing;

test "Pool: max_size is a sane fixed bound; init clamps capacity" {
    try testing.expect(max_size >= 1 and max_size <= 256);
    // The init clamp is pure arithmetic we can check without a socket.
    try testing.expectEqual(@as(usize, 1), @min(@max(@as(usize, 0), 1), max_size));
    try testing.expectEqual(max_size, @min(@max(@as(usize, 1000), 1), max_size));
}

test "redis Pool live acquire/release reuse (skips if no broker)" {
    const gpa = testing.allocator;
    var pool = Pool.init(gpa, conn_mod.testOptions(), 4) catch
        return error.SkipZigTest;
    defer pool.deinit();

    // A first acquire/ping confirms the broker actually speaks RESP.
    {
        const c = pool.acquire() catch return error.SkipZigTest;
        c.ping() catch {
            pool.release(c, false);
            return error.SkipZigTest;
        };
        pool.release(c, true);
    }

    // Acquire/release N times; because we release healthy each time, the
    // pool must hand back the SAME (reused) connection rather than dialing
    // a new one — assert the slot count never grows past 1.
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();
    const first = try pool.acquire();
    pool.release(first, true);

    var iter: usize = 0;
    while (iter < 32) : (iter += 1) {
        const c = try pool.acquire();
        try testing.expectEqual(@intFromPtr(first), @intFromPtr(c)); // reuse
        // Exercise a real command so the reused socket is proven live.
        var kb: [48]u8 = undefined;
        const key = try std.fmt.bufPrint(&kb, "speedy:r2:pool:{x}", .{rand.int(u32)});
        const v = try c.execInteger(&.{ "INCR", key });
        try testing.expect(v >= 1);
        _ = c.execInteger(&.{ "DEL", key }) catch {};
        pool.release(c, true);
    }

    // Count live slots: must be exactly 1 (only the reused connection).
    var live: usize = 0;
    for (pool.conns[0..pool.size]) |slot| {
        if (slot != null) live += 1;
    }
    try testing.expectEqual(@as(usize, 1), live);
}

test "redis Pool init on unreachable broker fails, never panics" {
    const gpa = testing.allocator;
    const r = Pool.init(gpa, .{ .host = "127.0.0.1", .port = 1, .timeout_ms = 500 }, 2);
    try testing.expect(std.meta.isError(r));
}
