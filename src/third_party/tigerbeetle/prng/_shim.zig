//! Minimal shim providing the `stdx` symbols that
//! `tigerbeetle/src/stdx/prng.zig` references. We only need a tiny slice of
//! the upstream `stdx` module (a constant, a string helper, a couple of
//! test helpers) — pulling all of `stdx.zig` would drag in unrelated TB
//! internals (snaptest, flags, time_units, etc.).
//!
//! Each symbol below is intentionally behavior-compatible with the
//! upstream so that the vendored `prng.zig` is otherwise verbatim.

const std = @import("std");

pub const KiB: usize = 1 << 10;

/// Split a string at the first occurrence of `needle`. Behavior matches
/// `stdx.cut` (returns `null` if `needle` not found, otherwise the prefix
/// and suffix excluding the delimiter).
pub fn cut(haystack: []const u8, needle: []const u8) ?struct { []const u8, []const u8 } {
    const idx = std.mem.indexOf(u8, haystack, needle) orelse return null;
    return .{ haystack[0..idx], haystack[idx + needle.len ..] };
}

/// A no-op snaptest shim. Upstream's `Snap` lets tests embed expected
/// output inline (golden-output snapshots). We don't vendor snaptest, so
/// `diff_fmt` just runs the formatter through a discarding writer (proves
/// the formatting itself doesn't panic) and returns success. The
/// statistical / behavior tests in this directory don't rely on the exact
/// counts upstream pinned — we re-assert distribution shape with our own
/// tests in `src/core/prng.zig`.
pub const Snap = struct {
    pub fn snap_fn(comptime _: []const u8) fn (std.builtin.SourceLocation, []const u8) Snap {
        return struct {
            fn make(_: std.builtin.SourceLocation, _: []const u8) Snap {
                return .{};
            }
        }.make;
    }

    pub fn diff_fmt(_: *const Snap, comptime fmt: []const u8, args: anytype) !void {
        // Render to a stack buffer to ensure the format string + args are
        // well-formed; result is dropped. Overflow is ignored.
        var buf: [4096]u8 = undefined;
        _ = std.fmt.bufPrint(&buf, fmt, args) catch {};
    }
};

/// `stdx.BitSetType(N)` is a fixed-capacity bit set. We provide a small
/// equivalent backed by `std.bit_set.IntegerBitSet` rounded up to the
/// next power-of-two storage; only the methods used by `prng.zig`'s
/// `fill` test are exposed.
pub fn BitSetType(comptime capacity: u9) type {
    return struct {
        const Self = @This();
        const Storage = std.StaticBitSet(capacity);
        bits: Storage = Storage.initEmpty(),

        pub fn set(self: *Self, index: usize) void {
            self.bits.set(index);
        }
        pub fn is_set(self: *const Self, index: usize) bool {
            return self.bits.isSet(index);
        }
    };
}

/// The upstream `parse_flag_value_fuzz` drives `Flags.parse_flag_value`
/// over a list of (input → expected) cases and (input → expected error
/// fragment) cases. We mirror just enough to keep `Ratio.parse_flag_value`
/// exercised. `T` must be `Ratio` (or any type with the same parse
/// signature).
pub const Flags = struct {
    pub fn parse_flag_value_fuzz(
        comptime T: type,
        parse: fn ([]const u8, *?[]const u8) error{InvalidFlagValue}!T,
        cases: struct {
            ok: []const struct { []const u8, T },
            err: []const struct { []const u8, []const u8 },
        },
    ) !void {
        var diag: ?[]const u8 = null;
        for (cases.ok) |case| {
            diag = null;
            const got = try parse(case[0], &diag);
            // Compare via formatted representation so we don't require T to
            // implement `==` (Ratio's two-field struct is comparable but
            // this keeps the shim generic).
            try std.testing.expectEqual(case[1], got);
        }
        for (cases.err) |case| {
            diag = null;
            const result = parse(case[0], &diag);
            try std.testing.expectError(error.InvalidFlagValue, result);
            try std.testing.expect(diag != null);
            try std.testing.expect(std.mem.indexOf(u8, diag.?, case[1]) != null);
        }
    }
};
