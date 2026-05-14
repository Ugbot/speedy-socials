//! Always-on assertions for Tiger Style invariants.
//!
//! Unlike `std.debug.assert`, these never get stripped — not in
//! ReleaseFast, not in ReleaseSmall. Invariant violations should crash
//! the process loudly with a useful message rather than corrupting state.
//!
//! Convention:
//!   `assert(x > 0)`           — precondition / invariant
//!   `assertEq(a, b)`          — equality with both sides printed
//!   `unreachableState(msg)`   — a branch that should not be reachable
//!
//! Assertions are not for handling expected errors from external input
//! (network, file system, user). Use the per-subsystem error sets in
//! `core/errors.zig` for those.

const std = @import("std");
const builtin = @import("builtin");

const SourceLocation = std.builtin.SourceLocation;

/// Hard assertion. Aborts the process with a panic message that includes
/// the source location and the failing expression.
pub inline fn assert(ok: bool) void {
    if (!ok) @panic("assertion failed");
}

/// Hard assertion with a free-form message.
pub inline fn assertMsg(ok: bool, comptime msg: []const u8) void {
    if (!ok) @panic(msg);
}

/// Equality assertion with both operands printed on failure. Works for
/// any type that implements `==` (integers, enums, pointers, bools).
pub inline fn assertEq(actual: anytype, expected: anytype) void {
    if (actual != expected) {
        std.debug.print(
            "assertEq failed: actual={any} expected={any}\n",
            .{ actual, expected },
        );
        @panic("assertEq failed");
    }
}

/// Greater-than assertion with diagnostic.
pub inline fn assertGt(a: anytype, b: anytype) void {
    if (!(a > b)) {
        std.debug.print("assertGt failed: {any} > {any}\n", .{ a, b });
        @panic("assertGt failed");
    }
}

/// Less-than-or-equal assertion (typical bound check: `assertLe(n, MAX)`).
pub inline fn assertLe(a: anytype, b: anytype) void {
    if (!(a <= b)) {
        std.debug.print("assertLe failed: {any} <= {any}\n", .{ a, b });
        @panic("assertLe failed");
    }
}

/// Mark a state-machine branch unreachable. Differs from `unreachable`
/// in that the message survives release builds.
pub inline fn unreachableState(comptime msg: []const u8) noreturn {
    @panic("unreachable state: " ++ msg);
}

test "assert ok" {
    assert(true);
    assertEq(@as(u32, 7), @as(u32, 7));
    assertGt(@as(i32, 2), @as(i32, 1));
    assertLe(@as(u32, 5), @as(u32, 5));
}
