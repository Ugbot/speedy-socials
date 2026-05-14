//! Per-shard ring buffer of recent broadcast events.
//!
//! Philosophy (from `core/limits.zig`):
//!
//!   Use a ring buffer when "we ran out" has no hard failure mode —
//!   broadcast fan-out where it is acceptable to drop the oldest entry
//!   when a slow consumer falls behind.
//!
//! That is exactly this structure. Producers (broadcast callers) push
//! events without ever being rejected: when the ring is full, the
//! oldest event is overwritten and the read cursor is advanced.
//! Consumers (subscriber iterators) read by sequence number; if their
//! cursor falls behind the oldest available sequence, they observe a
//! "skipped" count and resume from the new oldest.
//!
//! Tiger Style:
//!   * Capacity declared at the type level (compile-time const here).
//!   * No allocations. No recursion. All loops bounded.
//!   * Sequence numbers monotonic u64 — never wrap in any plausible
//!     uptime (256 events/shard × 16 shards × max RPS would take >
//!     5e9 years to overflow).

const std = @import("std");
const assert_mod = @import("../assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

/// Default ring capacity per shard. Sized to absorb short consumer
/// stalls without dropping; long stalls naturally lose oldest data
/// (and the consumer sees a `skipped` count when it reconnects).
pub const default_capacity: u32 = 256;

/// Build an EventRing type holding `T` at compile-time capacity `N`.
/// `N` must be a power of two for fast modulo.
pub fn EventRing(comptime T: type, comptime N: u32) type {
    comptime {
        if (N == 0) @compileError("EventRing capacity must be > 0");
        if ((N & (N - 1)) != 0) @compileError("EventRing capacity must be a power of two");
    }
    return struct {
        const Self = @This();
        pub const capacity: u32 = N;
        const mask: u64 = N - 1;

        items: [N]T = undefined,
        /// Next sequence number to assign on push. Monotonic.
        next_seq: u64 = 0,
        /// Total events ever dropped (overwritten while ring was full).
        /// Diagnostic — exposed via `dropped()`.
        dropped_count: u64 = 0,

        pub fn init() Self {
            return .{};
        }

        /// Push an event. Never fails — when the ring is full, the
        /// oldest entry is overwritten. Returns the sequence number
        /// assigned to the new event.
        pub fn push(self: *Self, value: T) u64 {
            const seq = self.next_seq;
            if (seq >= N) {
                // Overwriting a previously-held slot.
                self.dropped_count += 1;
            }
            self.items[@as(usize, @intCast(seq & mask))] = value;
            self.next_seq = seq + 1;
            return seq;
        }

        /// Sequence number of the oldest event still in the ring.
        /// Equal to `nextSeq()` when the ring is empty.
        pub fn oldestSeq(self: *const Self) u64 {
            if (self.next_seq <= N) return 0;
            return self.next_seq - N;
        }

        pub fn nextSeq(self: *const Self) u64 {
            return self.next_seq;
        }

        pub fn dropped(self: *const Self) u64 {
            return self.dropped_count;
        }

        /// Read result for a consumer at `cursor`.
        pub const Read = struct {
            /// Number of events the consumer missed because they were
            /// overwritten before being read.
            skipped: u64,
            /// Events available since `cursor` (or since the new
            /// oldest if `skipped > 0`).
            events: []const T,
            /// Next sequence the consumer should request after
            /// processing `events`.
            next_cursor: u64,
        };

        /// Drain into `dst` starting at `cursor`. Caller chooses how
        /// many at a time by sizing `dst`. Returns a `Read` describing
        /// the result. Does not mutate the ring.
        ///
        /// When the consumer is behind by more than `N` events, the
        /// oldest `n - N` events are unavailable; `skipped` records
        /// how many were lost and the read resumes from the new
        /// oldest available sequence.
        pub fn drainSince(self: *const Self, cursor: u64, dst: []T) Read {
            const head = self.next_seq;
            if (cursor >= head) {
                return .{ .skipped = 0, .events = dst[0..0], .next_cursor = head };
            }
            const oldest = self.oldestSeq();
            var read_from: u64 = cursor;
            var skipped: u64 = 0;
            if (cursor < oldest) {
                skipped = oldest - cursor;
                read_from = oldest;
            }
            const available: u64 = head - read_from;
            const want: u64 = @min(available, @as(u64, dst.len));
            // Bound: `want` is at most `min(N, dst.len)`.
            assertLe(want, N);
            assertLe(want, dst.len);

            var i: u64 = 0;
            while (i < want) : (i += 1) {
                dst[@as(usize, @intCast(i))] = self.items[@as(usize, @intCast((read_from + i) & mask))];
            }
            return .{
                .skipped = skipped,
                .events = dst[0..@as(usize, @intCast(want))],
                .next_cursor = read_from + want,
            };
        }
    };
}

// ── tests ──────────────────────────────────────────────────────

const testing = std.testing;

test "EventRing push assigns sequential ids" {
    var ring = EventRing(u32, 8).init();
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        const seq = ring.push(i * 10);
        try testing.expectEqual(@as(u64, i), seq);
    }
    try testing.expectEqual(@as(u64, 0), ring.oldestSeq());
    try testing.expectEqual(@as(u64, 5), ring.nextSeq());
    try testing.expectEqual(@as(u64, 0), ring.dropped());
}

test "EventRing overwrites oldest when full" {
    var ring = EventRing(u32, 4).init();
    // Push 10 into a ring of 4 -> last 4 survive.
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        _ = ring.push(i);
    }
    try testing.expectEqual(@as(u64, 10), ring.nextSeq());
    try testing.expectEqual(@as(u64, 6), ring.oldestSeq());
    try testing.expectEqual(@as(u64, 6), ring.dropped());

    var out: [4]u32 = undefined;
    const r = ring.drainSince(0, &out);
    try testing.expectEqual(@as(u64, 6), r.skipped);
    try testing.expectEqual(@as(usize, 4), r.events.len);
    try testing.expectEqual(@as(u32, 6), r.events[0]);
    try testing.expectEqual(@as(u32, 9), r.events[3]);
    try testing.expectEqual(@as(u64, 10), r.next_cursor);
}

test "EventRing drainSince partial drain" {
    var ring = EventRing(u32, 8).init();
    var i: u32 = 0;
    while (i < 6) : (i += 1) _ = ring.push(i);
    var out: [3]u32 = undefined;
    const r = ring.drainSince(0, &out);
    try testing.expectEqual(@as(u64, 0), r.skipped);
    try testing.expectEqual(@as(usize, 3), r.events.len);
    try testing.expectEqual(@as(u32, 0), r.events[0]);
    try testing.expectEqual(@as(u32, 2), r.events[2]);
    try testing.expectEqual(@as(u64, 3), r.next_cursor);

    const r2 = ring.drainSince(r.next_cursor, &out);
    try testing.expectEqual(@as(usize, 3), r2.events.len);
    try testing.expectEqual(@as(u32, 3), r2.events[0]);
    try testing.expectEqual(@as(u64, 6), r2.next_cursor);

    const r3 = ring.drainSince(r2.next_cursor, &out);
    try testing.expectEqual(@as(usize, 0), r3.events.len);
}

test "EventRing cursor in future returns empty" {
    var ring = EventRing(u32, 4).init();
    _ = ring.push(1);
    var out: [4]u32 = undefined;
    const r = ring.drainSince(99, &out);
    try testing.expectEqual(@as(usize, 0), r.events.len);
    try testing.expectEqual(@as(u64, 1), r.next_cursor);
}
