//! Connection slot: fixed-size buffers + per-request arena, lives in
//! the connection pool for the process lifetime. Slot identity is
//! stable (returned by acquire) so the I/O layer can refer to it by
//! index.
//!
//! Tiger Style: every byte the connection touches comes from this slot.
//! No per-request heap allocation; the arena resets between requests
//! on the same connection (HTTP keep-alive), or on slot reuse for a
//! new client.

const std = @import("std");
const limits = @import("limits.zig");
const Arena = @import("arena.zig").Arena;

pub const Connection = struct {
    /// Inbound buffer (request bytes accumulate here).
    read_buf: [limits.conn_read_buffer_bytes]u8 = undefined,
    /// Outbound buffer (response head + body written here).
    write_buf: [limits.conn_write_buffer_bytes]u8 = undefined,
    /// Per-request arena (handler scratch).
    arena_buf: [limits.request_arena_bytes]u8 = undefined,

    arena: Arena = undefined,
    read_len: usize = 0,

    /// Initialize the arena view; called once when the pool is built.
    pub fn prime(self: *Connection) void {
        self.arena = Arena.init(&self.arena_buf);
        self.read_len = 0;
    }

    /// Reset between requests on the same TCP connection.
    pub fn reset(self: *Connection) void {
        self.arena.reset();
        self.read_len = 0;
    }
};

test "Connection prime + reset" {
    var c: Connection = .{};
    c.prime();
    const alloc = c.arena.allocator();
    const buf = try alloc.alloc(u8, 64);
    @memset(buf, 0xAA);
    try std.testing.expect(c.arena.used() >= 64);
    c.reset();
    try std.testing.expectEqual(@as(usize, 0), c.arena.used());
}
