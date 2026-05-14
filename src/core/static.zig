//! Compile-time-sized data structures.
//!
//! Tiger Style invariant: every collection has a fixed capacity declared
//! at the type level. Overflow is a hard error, not a silent grow.

const std = @import("std");
const builtin = @import("builtin");
const assert_mod = @import("assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

/// A fixed-capacity object pool. `acquire()` returns a stable index +
/// pointer; `release(index)` returns the slot. Index reuse is allowed —
/// callers responsible for not retaining stale indices across releases.
pub fn StaticPool(comptime T: type, comptime N: u32) type {
    return struct {
        const Self = @This();
        pub const capacity: u32 = N;
        pub const Index = u32;

        items: [N]T = undefined,
        free_stack: [N]Index = undefined,
        free_top: u32 = N,
        in_use: u32 = 0,

        pub fn init() Self {
            var self: Self = .{};
            var i: Index = 0;
            while (i < N) : (i += 1) {
                self.free_stack[i] = N - 1 - i;
            }
            return self;
        }

        /// In-place initializer for large pools that should not be
        /// constructed on the stack and copied.
        pub fn initInPlace(self: *Self) void {
            self.free_top = N;
            self.in_use = 0;
            var i: Index = 0;
            while (i < N) : (i += 1) {
                self.free_stack[i] = N - 1 - i;
            }
        }

        pub const AcquireError = error{Exhausted};

        pub fn acquire(self: *Self) AcquireError!struct { index: Index, ptr: *T } {
            if (self.free_top == 0) return error.Exhausted;
            self.free_top -= 1;
            const idx = self.free_stack[self.free_top];
            self.in_use += 1;
            assertLe(self.in_use, N);
            return .{ .index = idx, .ptr = &self.items[idx] };
        }

        pub fn release(self: *Self, index: Index) void {
            assert(index < N);
            assert(self.in_use > 0);
            self.free_stack[self.free_top] = index;
            self.free_top += 1;
            self.in_use -= 1;
            assertLe(self.free_top, N);
        }

        pub fn get(self: *Self, index: Index) *T {
            assert(index < N);
            return &self.items[index];
        }

        pub fn used(self: *const Self) u32 {
            return self.in_use;
        }
    };
}

/// Fixed-capacity ring buffer (SPSC). For MPSC use BoundedMpsc.
pub fn FixedRingBuffer(comptime T: type, comptime N: u32) type {
    comptime {
        if (N == 0) @compileError("FixedRingBuffer capacity must be > 0");
        // Require power of two for fast modulo.
        if ((N & (N - 1)) != 0) @compileError("FixedRingBuffer capacity must be a power of two");
    }
    return struct {
        const Self = @This();
        pub const capacity: u32 = N;
        const mask: u32 = N - 1;

        items: [N]T = undefined,
        head: u32 = 0, // next read
        tail: u32 = 0, // next write

        pub fn init() Self {
            return .{};
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.head == self.tail;
        }

        pub fn len(self: *const Self) u32 {
            return self.tail -% self.head;
        }

        pub fn isFull(self: *const Self) bool {
            return self.len() == N;
        }

        pub const PushError = error{Full};

        pub fn push(self: *Self, value: T) PushError!void {
            if (self.isFull()) return error.Full;
            self.items[self.tail & mask] = value;
            self.tail +%= 1;
        }

        pub fn pop(self: *Self) ?T {
            if (self.isEmpty()) return null;
            const v = self.items[self.head & mask];
            self.head +%= 1;
            return v;
        }
    };
}

/// Atomic spinlock — Tiger Style: acceptable for short, low-contention
/// critical sections in the worker pool and queue infrastructure. For
/// long waits, the worker pool uses its own condition signaling via the
/// Io interface (added in the storage layer / worker pool phases).
pub const Spinlock = struct {
    state: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

    pub fn lock(self: *Spinlock) void {
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn tryLock(self: *Spinlock) bool {
        return self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null;
    }

    pub fn unlock(self: *Spinlock) void {
        self.state.store(0, .release);
    }
};

/// Bounded multi-producer single-consumer queue, spinlock-protected.
/// For blocking semantics use the worker-pool layer above; this is the
/// raw data structure. Producers push individually; the consumer pulls
/// one at a time.
pub fn BoundedMpsc(comptime T: type, comptime N: u32) type {
    return struct {
        const Self = @This();
        pub const capacity: u32 = N;

        lock: Spinlock = .{},
        ring: FixedRingBuffer(T, N) = .{},
        closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        pub fn init() Self {
            return .{};
        }

        pub const PushError = error{ Full, Closed };

        pub fn push(self: *Self, value: T) PushError!void {
            if (self.closed.load(.acquire)) return error.Closed;
            self.lock.lock();
            defer self.lock.unlock();
            self.ring.push(value) catch return error.Full;
        }

        pub fn tryPop(self: *Self) ?T {
            self.lock.lock();
            defer self.lock.unlock();
            return self.ring.pop();
        }

        pub fn close(self: *Self) void {
            self.closed.store(true, .release);
        }
    };
}

test "StaticPool acquire/release" {
    var pool = StaticPool(u32, 4).init();
    const a = try pool.acquire();
    const b = try pool.acquire();
    a.ptr.* = 100;
    b.ptr.* = 200;
    try std.testing.expectEqual(@as(u32, 2), pool.used());
    pool.release(a.index);
    try std.testing.expectEqual(@as(u32, 1), pool.used());
    const c = try pool.acquire();
    try std.testing.expectEqual(a.index, c.index); // LIFO reuse
}

test "StaticPool exhaustion" {
    var pool = StaticPool(u8, 2).init();
    _ = try pool.acquire();
    _ = try pool.acquire();
    try std.testing.expectError(error.Exhausted, pool.acquire());
}

test "FixedRingBuffer push/pop" {
    var rb = FixedRingBuffer(u32, 4).init();
    try rb.push(1);
    try rb.push(2);
    try rb.push(3);
    try std.testing.expectEqual(@as(?u32, 1), rb.pop());
    try rb.push(4);
    try rb.push(5);
    try std.testing.expectError(error.Full, rb.push(99));
    try std.testing.expectEqual(@as(?u32, 2), rb.pop());
    try std.testing.expectEqual(@as(?u32, 3), rb.pop());
    try std.testing.expectEqual(@as(?u32, 4), rb.pop());
    try std.testing.expectEqual(@as(?u32, 5), rb.pop());
    try std.testing.expectEqual(@as(?u32, null), rb.pop());
}

test "BoundedMpsc basic" {
    var q = BoundedMpsc(u32, 4).init();
    try q.push(10);
    try q.push(20);
    try std.testing.expectEqual(@as(?u32, 10), q.tryPop());
    try std.testing.expectEqual(@as(?u32, 20), q.tryPop());
    try std.testing.expectEqual(@as(?u32, null), q.tryPop());
}
