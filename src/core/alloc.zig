//! Allocator wrappers (vendored from TigerBeetle).
//!
//! `StaticAllocator` is the boot-time allocator that panics if any
//! allocation occurs after the composition root flips it to `.static`.
//! `CountingAllocator` is a passthrough that records cumulative
//! alloc/free byte counts; useful for diagnostics and tests.
//!
//! See `src/third_party/tigerbeetle/alloc/` for the vendored sources and
//! `src/third_party/tigerbeetle/LICENSE` for the upstream license
//! (Apache-2.0).

const std = @import("std");

pub const StaticAllocator = @import("tigerbeetle_static_allocator");
pub const CountingAllocator = @import("tigerbeetle_counting_allocator");

// ── Tests ────────────────────────────────────────────────────────────

const testing = std.testing;

test "alloc: StaticAllocator panic-on-alloc after static transition" {
    var sa = StaticAllocator.init(testing.allocator);
    defer sa.deinit();
    const a = sa.allocator();

    // init: allowed
    const buf = try a.alloc(u8, 16);

    // free pre-transition flips to deinit per TB semantics; do it after.
    sa.transition_from_init_to_static();

    // In static state TB's allocator asserts the state == .init.
    // In Debug/ReleaseSafe the assertion panics. We cannot catch a
    // panic, so we only verify the state machine is in `.static` and
    // exercise the free-by-deinit transition next.
    try testing.expectEqual(@as(@TypeOf(sa.state), .static), sa.state);

    sa.transition_from_static_to_deinit();
    a.free(buf);
}

test "alloc: CountingAllocator tracks alloc and free" {
    var ca = CountingAllocator.init(testing.allocator);
    defer ca.deinit();
    const a = ca.allocator();

    const buf = try a.alloc(u8, 128);
    try testing.expectEqual(@as(u64, 128), ca.alloc_size);
    try testing.expectEqual(@as(u64, 0), ca.free_size);
    try testing.expectEqual(@as(u64, 128), ca.live_size());

    a.free(buf);
    try testing.expectEqual(@as(u64, 128), ca.free_size);
    try testing.expectEqual(@as(u64, 0), ca.live_size());
}

test "alloc: StaticAllocator round-trip init→static→deinit allows free" {
    var sa = StaticAllocator.init(testing.allocator);
    defer sa.deinit();
    const a = sa.allocator();

    // Allocate in init phase.
    const a_buf = try a.alloc(u32, 4);
    const b_buf = try a.alloc(u32, 8);

    // Go static. New allocations would panic; we don't attempt any.
    sa.transition_from_init_to_static();
    try testing.expectEqual(@as(@TypeOf(sa.state), .static), sa.state);

    // Transition to deinit and drain.
    sa.transition_from_static_to_deinit();
    a.free(a_buf);
    a.free(b_buf);
}

test "alloc: StaticAllocator early-deinit via free in init phase" {
    // TB allows free in init phase but flips state to deinit afterwards.
    // This guarantees allocations stop early rather than after corruption.
    var sa = StaticAllocator.init(testing.allocator);
    defer sa.deinit();
    const a = sa.allocator();

    const buf = try a.alloc(u8, 8);
    a.free(buf);
    try testing.expectEqual(@as(@TypeOf(sa.state), .deinit), sa.state);
    // Now in deinit; no further alloc should be attempted by callers.
}

test "alloc: CountingAllocator under random sequence" {
    var prng_state = std.Random.DefaultPrng.init(0xDEADBEEF);
    const rng = prng_state.random();

    var ca = CountingAllocator.init(testing.allocator);
    defer ca.deinit();
    const a = ca.allocator();

    var bufs: [16][]u8 = undefined;
    var sizes: [16]usize = undefined;
    var total: u64 = 0;

    for (0..16) |i| {
        const n = rng.intRangeAtMost(usize, 1, 256);
        sizes[i] = n;
        bufs[i] = try a.alloc(u8, n);
        total += n;
    }
    try testing.expectEqual(total, ca.alloc_size);
    try testing.expectEqual(total, ca.live_size());

    for (0..16) |i| a.free(bufs[i]);
    try testing.expectEqual(total, ca.free_size);
    try testing.expectEqual(@as(u64, 0), ca.live_size());
}
