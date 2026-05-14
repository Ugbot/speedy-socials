//! Ring-backed streaming response writer.
//!
//! Use this when the body length is not known up front (e.g., NDJSON
//! firehose, server-sent events, large query streams). The body is
//! emitted as HTTP/1.1 chunked transfer encoding. The producer writes
//! into a fixed ring; the I/O writer drains it.
//!
//! Tiger Style: the ring's size is the *commitment* on memory. Writers
//! that need to exceed it must wait (backpressure) until the ring drains
//! — the writer never silently overwrites unsent data. This is the
//! "opt-in overflow" model: arbitrary length, but always with bounded
//! memory in flight at any instant.
//!
//! In contrast, `response.Builder` is the fixed-length path: caller
//! knows Content-Length, single shot, no backpressure dance.

const std = @import("std");
const HttpError = @import("../errors.zig").HttpError;
const assert_mod = @import("../assert.zig");

pub const Status = @import("response.zig").Status;

/// One chunk waiting to be flushed by the I/O layer.
pub const Chunk = struct {
    bytes: []const u8,
    final: bool, // true → close stream after sending this (zero-length chunk follows)
};

/// Ring buffer of pending chunks. Capacity is the *backpressure window*:
/// when full, the producer must wait (or yield) until the consumer
/// drains.
pub fn ChunkRing(comptime capacity: u32) type {
    if ((capacity & (capacity - 1)) != 0) @compileError("capacity must be power of 2");
    return struct {
        const Self = @This();
        const mask: u32 = capacity - 1;

        chunks: [capacity]Chunk = undefined,
        head: u32 = 0,
        tail: u32 = 0,

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
            return self.len() == capacity;
        }

        pub const PushError = error{Full};

        pub fn push(self: *Self, c: Chunk) PushError!void {
            if (self.isFull()) return error.Full;
            self.chunks[self.tail & mask] = c;
            self.tail +%= 1;
        }

        pub fn pop(self: *Self) ?Chunk {
            if (self.isEmpty()) return null;
            const c = self.chunks[self.head & mask];
            self.head +%= 1;
            return c;
        }

        pub fn peek(self: *const Self) ?Chunk {
            if (self.isEmpty()) return null;
            return self.chunks[self.head & mask];
        }
    };
}

/// Write the HTTP response head with Transfer-Encoding: chunked. After
/// this, the producer writes body chunks via the ChunkRing and the I/O
/// layer emits them as proper chunked frames.
pub fn writeChunkedHead(
    buffer: []u8,
    status: Status,
    content_type: []const u8,
) HttpError!usize {
    const written = std.fmt.bufPrint(
        buffer,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        .{ @intFromEnum(status), status.reason(), content_type },
    ) catch return error.ResponseBufferFull;
    return written.len;
}

/// Format one chunk frame (`<hex-size>\r\n<bytes>\r\n`) into `out`.
/// Returns the byte length written.
pub fn writeChunkFrame(out: []u8, payload: []const u8) HttpError!usize {
    const max_hex = 16; // u64 hex max
    if (out.len < payload.len + max_hex + 4) return error.ResponseBufferFull;
    const head = std.fmt.bufPrint(out, "{x}\r\n", .{payload.len}) catch return error.ResponseBufferFull;
    @memcpy(out[head.len..][0..payload.len], payload);
    const tail_start = head.len + payload.len;
    out[tail_start] = '\r';
    out[tail_start + 1] = '\n';
    return tail_start + 2;
}

/// Final zero-length chunk that ends a chunked response.
pub fn writeChunkedEnd(out: []u8) HttpError!usize {
    const s = "0\r\n\r\n";
    if (out.len < s.len) return error.ResponseBufferFull;
    @memcpy(out[0..s.len], s);
    return s.len;
}

test "writeChunkedHead format" {
    var buf: [256]u8 = undefined;
    const n = try writeChunkedHead(&buf, .ok, "application/json");
    const s = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, s, "Transfer-Encoding: chunked\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, s, "\r\n\r\n"));
}

test "writeChunkFrame round trip" {
    var buf: [128]u8 = undefined;
    const n = try writeChunkFrame(&buf, "hello");
    try std.testing.expectEqualStrings("5\r\nhello\r\n", buf[0..n]);
}

test "ChunkRing push/pop and full" {
    var ring = ChunkRing(4).init();
    try ring.push(.{ .bytes = "a", .final = false });
    try ring.push(.{ .bytes = "b", .final = false });
    try std.testing.expectEqualStrings("a", ring.pop().?.bytes);
    try ring.push(.{ .bytes = "c", .final = false });
    try ring.push(.{ .bytes = "d", .final = false });
    try ring.push(.{ .bytes = "e", .final = true });
    try std.testing.expectError(error.Full, ring.push(.{ .bytes = "f", .final = false }));
    try std.testing.expectEqualStrings("b", ring.pop().?.bytes);
    try std.testing.expectEqualStrings("c", ring.pop().?.bytes);
    const last3 = ring.pop().?;
    try std.testing.expectEqualStrings("d", last3.bytes);
    const last2 = ring.pop().?;
    try std.testing.expectEqualStrings("e", last2.bytes);
    try std.testing.expect(last2.final);
    try std.testing.expect(ring.pop() == null);
}
