//! Fixed-slab arena allocator.
//!
//! Used as the per-request scratch arena. The slab is allocated once at
//! startup (via `init`); `reset()` rewinds the offset so the same memory
//! is reused for the next request. Allocation past the end is a hard
//! error (Tiger Style: bounded, not unbounded).

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert_mod = @import("assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

pub const Arena = struct {
    buffer: []u8,
    offset: usize,
    /// High-water mark — peak usage since last reset(). Diagnostic.
    peak: usize,

    pub const Error = error{OutOfArena};

    pub fn init(buffer: []u8) Arena {
        return .{ .buffer = buffer, .offset = 0, .peak = 0 };
    }

    pub fn allocator(self: *Arena) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = arenaAlloc,
                .resize = arenaResize,
                .remap = arenaRemap,
                .free = arenaFree,
            },
        };
    }

    pub fn reset(self: *Arena) void {
        if (self.offset > self.peak) self.peak = self.offset;
        self.offset = 0;
    }

    pub fn used(self: *const Arena) usize {
        return self.offset;
    }

    pub fn capacity(self: *const Arena) usize {
        return self.buffer.len;
    }

    fn arenaAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
        const self: *Arena = @ptrCast(@alignCast(ctx));
        const align_bytes: usize = alignment.toByteUnits();
        const base = @intFromPtr(self.buffer.ptr) + self.offset;
        const aligned = std.mem.alignForward(usize, base, align_bytes);
        const adjust = aligned - base;
        const new_offset = self.offset + adjust + len;
        if (new_offset > self.buffer.len) return null;
        const ptr = self.buffer.ptr + self.offset + adjust;
        self.offset = new_offset;
        assertLe(self.offset, self.buffer.len);
        return ptr;
    }

    fn arenaResize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        // Arena does not support in-place resize; let the caller allocate
        // a new region and copy.
        return false;
    }

    fn arenaRemap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn arenaFree(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize) void {
        // No-op: arena frees in bulk via reset().
    }
};

test "Arena allocates and resets" {
    var backing: [4096]u8 = undefined;
    var arena = Arena.init(&backing);
    const alloc = arena.allocator();

    const a = try alloc.alloc(u8, 100);
    @memset(a, 0xAA);
    const b = try alloc.alloc(u32, 16);
    b[0] = 0xdeadbeef;
    try std.testing.expect(arena.used() > 100);
    arena.reset();
    try std.testing.expectEqual(@as(usize, 0), arena.used());
}

test "Arena rejects allocation past capacity" {
    var backing: [64]u8 = undefined;
    var arena = Arena.init(&backing);
    const alloc = arena.allocator();
    _ = try alloc.alloc(u8, 32);
    try std.testing.expectError(error.OutOfMemory, alloc.alloc(u8, 64));
}
