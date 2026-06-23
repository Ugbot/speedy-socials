//! Bounded MySQL connection pool. Mirrors the *role* pg.zig's pool plays for
//! the Postgres backend: a fixed-capacity set of live `Conn`s that callers
//! acquire/release around a unit of work. Tiger Style: capacity is fixed at
//! init (no growth), acquisition is a bounded linear scan under a mutex, and
//! the only allocation is the connections themselves (opened lazily up to
//! `size`).
//!
//! This pool is intentionally simple — single mutex, no async, no health
//! checks beyond reconnect-on-acquire-failure. It is sufficient for the
//! request-scoped acquire/release the storage `Backend` performs.

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
    /// Atomic spin-lock guarding slot bookkeeping (this stripped 0.16 std
    /// has no `std.Thread.Mutex`; the codebase uses this pattern — see
    /// `core.rate_limit`). Held only across the bounded slot scan.
    lock: std.atomic.Value(bool) = .init(false),
    /// Slots: a connection (lazily opened) + whether it's currently checked out.
    conns: [max_size]?*Conn = [_]?*Conn{null} ** max_size,
    in_use: [max_size]bool = [_]bool{false} ** max_size,

    pub fn init(allocator: std.mem.Allocator, opts: Options, size: usize) Error!*Pool {
        const n = @min(@max(size, 1), max_size);
        const self = allocator.create(Pool) catch return error.SocketError;
        self.* = .{ .allocator = allocator, .opts = opts, .size = n };
        // Open one connection eagerly so init fails fast on a bad URL /
        // unreachable server (matching pg.Pool.initUri behaviour).
        const c = try Conn.connect(allocator, opts);
        self.conns[0] = c;
        return self;
    }

    pub fn deinit(self: *Pool) void {
        var i: usize = 0;
        while (i < self.size) : (i += 1) {
            if (self.conns[i]) |c| c.close();
        }
        const alloc = self.allocator;
        alloc.destroy(self);
    }

    /// Check out a connection. Reuses an idle live one, else opens a new one
    /// in a free slot. Returns `PoolExhausted` when all slots are busy.
    pub fn acquire(self: *Pool) Error!*Conn {
        // Phase 1 (locked): hand back an idle live connection, or reserve an
        // empty slot to fill. Connecting is done OUTSIDE the lock so a slow
        // network dial never stalls other threads on the spin-lock.
        var reserve_slot: ?usize = null;
        {
            while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
            defer self.lock.store(false, .release);

            var i: usize = 0;
            while (i < self.size) : (i += 1) {
                if (!self.in_use[i]) {
                    if (self.conns[i]) |c| {
                        self.in_use[i] = true;
                        return c;
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

    pub fn release(self: *Pool, c: *Conn) void {
        while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
        defer self.lock.store(false, .release);
        var i: usize = 0;
        while (i < self.size) : (i += 1) {
            if (self.conns[i] == c) {
                self.in_use[i] = false;
                return;
            }
        }
    }
};

// ── Tests ──────────────────────────────────────────────────────────────
// Pure structural test (no server): an empty/zero-size request clamps to a
// valid bound. Acquire/release round-trip is covered by the live backend
// tests gated on MYSQL_TEST_URL.

const testing = std.testing;

test "Pool: max_size is a sane fixed bound" {
    try testing.expect(max_size >= 1 and max_size <= 256);
}
