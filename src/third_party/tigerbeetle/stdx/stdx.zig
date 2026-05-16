//! Minimal `stdx` shim — only the surface that the vendored
//! `bounded_array.zig`, `ring_buffer.zig`, `iops.zig`, and
//! `bit_set.zig` actually consume.
//!
//! Vendoring TigerBeetle's full `stdx` pulls in unrelated infrastructure
//! (TB's own IO abstraction, time module, mlock, huge-pages, …) that
//! speedy-socials does not need and that would compete with our own
//! primitives. This shim isolates the borrow.
//!
//! If a future vendor pass needs more `stdx.X` surface, add it here.
//! The intent is to keep this file small and reviewable.
//!
//! Sources (verbatim, MIT/Apache-2.0 from TigerBeetle):
//!   `copy_left` / `copy_right` / `copy_disjoint` / `disjoint_slices` /
//!   `SizePrecision`  — TB `src/stdx/stdx.zig` (commit pinned in
//!                       `src/third_party/tigerbeetle/README.md`).
//!   `PRNG`           — re-exported from speedy-socials' already-vendored
//!                       `tb_prng` module so the borrow does not
//!                       double-include TB's PRNG.
//!   `BoundedArrayType` / `RingBufferType` / `IOPSType` / `BitSetType`
//!                    — re-exported from the sibling vendored files in
//!                       this directory so callers can write
//!                       `const stdx = @import("tb_stdx");` and find
//!                       everything via the single shim.

const std = @import("std");
const assert = std.debug.assert;

// ── verbatim from TB stdx.zig ─────────────────────────────────────────

pub const SizePrecision = enum { exact, inexact };

pub inline fn copy_left(
    comptime precision: SizePrecision,
    comptime T: type,
    target: []T,
    source: []const T,
) void {
    switch (precision) {
        .exact => assert(target.len == source.len),
        .inexact => assert(target.len >= source.len),
    }
    if (!disjoint_slices(T, T, target, source)) {
        assert(@intFromPtr(target.ptr) < @intFromPtr(source.ptr));
    }
    const copyForwards = std.mem.copyForwards;
    copyForwards(T, target, source);
}

pub inline fn copy_right(
    comptime precision: SizePrecision,
    comptime T: type,
    target: []T,
    source: []const T,
) void {
    switch (precision) {
        .exact => assert(target.len == source.len),
        .inexact => assert(target.len >= source.len),
    }
    if (!disjoint_slices(T, T, target, source)) {
        assert(@intFromPtr(target.ptr) > @intFromPtr(source.ptr));
    }
    const copyBackwards = std.mem.copyBackwards;
    copyBackwards(T, target, source);
}

pub inline fn copy_disjoint(
    comptime precision: SizePrecision,
    comptime T: type,
    target: []T,
    source: []const T,
) void {
    switch (precision) {
        .exact => assert(target.len == source.len),
        .inexact => assert(target.len >= source.len),
    }
    assert(!@inComptime());
    assert(disjoint_slices(T, T, target, source));
    @memcpy(target[0..source.len], source);
}

pub inline fn disjoint_slices(comptime A: type, comptime B: type, a: []const A, b: []const B) bool {
    return @intFromPtr(a.ptr) + a.len * @sizeOf(A) <= @intFromPtr(b.ptr) or
        @intFromPtr(b.ptr) + b.len * @sizeOf(B) <= @intFromPtr(a.ptr);
}

// ── re-exports so callers see one module ──────────────────────────────

pub const BoundedArrayType = @import("bounded_array.zig").BoundedArrayType;
pub const RingBufferType = @import("ring_buffer.zig").RingBufferType;
pub const IOPSType = @import("iops.zig").IOPSType;
pub const BitSetType = @import("bit_set.zig").BitSetType;

/// PRNG re-exported from the existing `tb_prng` vendor (see
/// `src/third_party/tigerbeetle/prng/`). TB's `stdx.PRNG` is the same
/// `prng.zig` module; bridging here means the tests in `bounded_array`
/// / `ring_buffer` see the canonical PRNG instead of a parallel copy.
pub const PRNG = @import("tb_prng");

// ── tests ─────────────────────────────────────────────────────────────

test "copy_left" {
    const a = try std.testing.allocator.alloc(usize, 8);
    defer std.testing.allocator.free(a);
    for (a, 0..) |*v, i| v.* = i;
    copy_left(.exact, usize, a[0..6], a[2..]);
    try std.testing.expect(std.mem.eql(usize, a, &.{ 2, 3, 4, 5, 6, 7, 6, 7 }));
}

test "copy_right" {
    const a = try std.testing.allocator.alloc(usize, 8);
    defer std.testing.allocator.free(a);
    for (a, 0..) |*v, i| v.* = i;
    copy_right(.exact, usize, a[2..], a[0..6]);
    try std.testing.expect(std.mem.eql(usize, a, &.{ 0, 1, 0, 1, 2, 3, 4, 5 }));
}

test "disjoint_slices true / false" {
    var buf: [16]u32 = undefined;
    try std.testing.expect(disjoint_slices(u32, u32, buf[0..4], buf[8..12]));
    try std.testing.expect(!disjoint_slices(u32, u32, buf[0..8], buf[4..12]));
}

test {
    // Pull child tests into this module's test binary.
    _ = @import("bounded_array.zig");
    _ = @import("ring_buffer.zig");
    _ = @import("iops.zig");
    _ = @import("bit_set.zig");
}
