//! WS-1 / C1: unified WebSocket data-plane stream.
//!
//! WebSocket frame loops need three operations against a connection:
//!   * `readNonblocking(buf) → n` — pull as many plaintext bytes as
//!     are *immediately* available; return 0 when none, distinguish
//!     close/error via error union.
//!   * `writeAll(bytes)` — send a fully-formed frame (already
//!     encoded). Blocks briefly during encryption + socket write.
//!   * `close()` — release the connection.
//!
//! This module owns the abstraction. Two concrete impls:
//!   * `PlainStream` — straight TCP socket; uses poll(2) + read(2).
//!   * `TlsStream` — wraps an ianic-tls Connection; runs a
//!     per-connection reader thread that does blocking decrypts
//!     into a ring buffer so the frame loop sees plaintext through
//!     the same non-blocking API.
//!
//! Tiger Style: fixed-size ring, no allocator on the frame loop,
//! single producer (reader thread or main thread) / single consumer
//! per Stream. Thread-safety only matters for `TlsStream` since
//! `PlainStream` runs entirely on the handler thread.

const std = @import("std");
const builtin_atomic = std.atomic;
const Spinlock = @import("../static.zig").Spinlock;

fn sleepMs(ms: u32) void {
    var req: std.c.timespec = .{
        .sec = 0,
        .nsec = @intCast(@as(i64, ms) * std.time.ns_per_ms),
    };
    _ = std.c.nanosleep(&req, &req);
}

pub const Error = error{
    ReadFailed,
    WriteFailed,
    SocketClosed,
    StreamClosed,
    Backpressure,
};

pub const Stream = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        readNonblocking: *const fn (ptr: *anyopaque, dst: []u8) Error!usize,
        writeAll: *const fn (ptr: *anyopaque, bytes: []const u8) Error!void,
        close: *const fn (ptr: *anyopaque) void,
    };

    pub fn readNonblocking(self: Stream, dst: []u8) Error!usize {
        return self.vtable.readNonblocking(self.ptr, dst);
    }

    pub fn writeAll(self: Stream, bytes: []const u8) Error!void {
        return self.vtable.writeAll(self.ptr, bytes);
    }

    pub fn close(self: Stream) void {
        self.vtable.close(self.ptr);
    }
};

// ──────────────────────────────────────────────────────────────────────
// PlainStream — direct TCP socket.
// ──────────────────────────────────────────────────────────────────────

pub const PlainStream = struct {
    fd: std.posix.fd_t,
    closed: bool = false,

    pub fn init(fd: std.posix.fd_t) PlainStream {
        return .{ .fd = fd };
    }

    fn doRead(ptr: *anyopaque, dst: []u8) Error!usize {
        const self: *PlainStream = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StreamClosed;
        var pfd = [_]std.posix.pollfd{.{
            .fd = self.fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&pfd, 0) catch return error.ReadFailed;
        if (ready == 0) return 0;
        if ((pfd[0].revents & (std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL)) != 0) {
            return error.SocketClosed;
        }
        const n = std.posix.read(self.fd, dst) catch |err| switch (err) {
            error.WouldBlock => return 0,
            else => return error.ReadFailed,
        };
        if (n == 0) return error.SocketClosed;
        return n;
    }

    fn doWrite(ptr: *anyopaque, bytes: []const u8) Error!void {
        const self: *PlainStream = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.StreamClosed;
        var written: usize = 0;
        while (written < bytes.len) {
            const n = std.c.write(self.fd, bytes.ptr + written, bytes.len - written);
            if (n <= 0) return error.WriteFailed;
            written += @intCast(n);
        }
    }

    fn doClose(ptr: *anyopaque) void {
        const self: *PlainStream = @ptrCast(@alignCast(ptr));
        self.closed = true;
        // We don't own the fd's lifecycle — the server's accept loop
        // closes it after the handler returns.
    }

    pub fn stream(self: *PlainStream) Stream {
        return .{
            .ptr = self,
            .vtable = &.{
                .readNonblocking = doRead,
                .writeAll = doWrite,
                .close = doClose,
            },
        };
    }
};

// ──────────────────────────────────────────────────────────────────────
// TlsStream — runs blocking TLS reads on a dedicated thread, feeds a
// per-connection plaintext ring that the frame loop drains.
//
// Threading model:
//   * Frame loop (handler thread) calls `readNonblocking` which
//     copies bytes out of the plaintext ring.
//   * Reader thread loops on `tls_read(cipher_buf) → plain_bytes` and
//     pushes into the ring. Spawned by `init`; joined by `close`.
//   * Writes go directly through the TLS adapter on the handler
//     thread (encryption + socket-write block briefly but bounded).
//
// The ring uses a fixed-size byte buffer with read/write indices
// guarded by a small spinlock. Producer (reader thread) drops oldest
// data on overflow — symmetric to the existing ws.event_ring policy.
// ──────────────────────────────────────────────────────────────────────

pub const TlsAdapter = struct {
    ptr: *anyopaque,
    /// Blocking read: pull plaintext bytes from the TLS layer into
    /// `dst`. Returns 0 on clean close, error on failure.
    read_blocking: *const fn (ptr: *anyopaque, dst: []u8) Error!usize,
    /// Blocking writeAll: encrypt + send `bytes`. Returns on success
    /// or fails.
    write_all: *const fn (ptr: *anyopaque, bytes: []const u8) Error!void,
    /// Free TLS resources. The adapter owns the cipher state +
    /// any background buffers.
    close: *const fn (ptr: *anyopaque) void,
};

pub const TlsStream = struct {
    adapter: TlsAdapter,
    ring_buf: [16 * 1024]u8 = undefined,
    write_idx: usize = 0,
    read_idx: usize = 0,
    used: builtin_atomic.Value(usize) = builtin_atomic.Value(usize).init(0),
    lock: Spinlock = .{},
    closed_flag: builtin_atomic.Value(bool) = builtin_atomic.Value(bool).init(false),
    error_flag: builtin_atomic.Value(bool) = builtin_atomic.Value(bool).init(false),
    reader_thread: ?std.Thread = null,

    pub fn init(adapter: TlsAdapter) TlsStream {
        return .{ .adapter = adapter };
    }

    /// Spawn the reader thread. Caller must call `close` to stop it.
    /// Returns error if thread creation fails.
    pub fn start(self: *TlsStream) !void {
        self.reader_thread = try std.Thread.spawn(.{}, readerLoop, .{self});
    }

    fn readerLoop(self: *TlsStream) void {
        var scratch: [4096]u8 = undefined;
        while (!self.closed_flag.load(.acquire)) {
            const n = self.adapter.read_blocking(self.adapter.ptr, &scratch) catch {
                self.error_flag.store(true, .release);
                return;
            };
            if (n == 0) {
                self.closed_flag.store(true, .release);
                return;
            }
            self.pushPlaintext(scratch[0..n]);
        }
    }

    fn pushPlaintext(self: *TlsStream, plaintext: []const u8) void {
        self.lock.lock();
        defer self.lock.unlock();
        for (plaintext) |b| {
            self.ring_buf[self.write_idx] = b;
            self.write_idx = (self.write_idx + 1) % self.ring_buf.len;
            const cur_used = self.used.load(.monotonic);
            if (cur_used == self.ring_buf.len) {
                // Overflow — drop oldest by advancing read_idx.
                self.read_idx = (self.read_idx + 1) % self.ring_buf.len;
            } else {
                self.used.store(cur_used + 1, .monotonic);
            }
        }
    }

    fn doRead(ptr: *anyopaque, dst: []u8) Error!usize {
        const self: *TlsStream = @ptrCast(@alignCast(ptr));
        if (self.error_flag.load(.acquire)) return error.SocketClosed;
        self.lock.lock();
        defer self.lock.unlock();
        const have = self.used.load(.monotonic);
        if (have == 0) {
            if (self.closed_flag.load(.acquire)) return error.SocketClosed;
            return 0;
        }
        const n = @min(have, dst.len);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            dst[i] = self.ring_buf[self.read_idx];
            self.read_idx = (self.read_idx + 1) % self.ring_buf.len;
        }
        self.used.store(have - n, .monotonic);
        return n;
    }

    fn doWrite(ptr: *anyopaque, bytes: []const u8) Error!void {
        const self: *TlsStream = @ptrCast(@alignCast(ptr));
        if (self.closed_flag.load(.acquire)) return error.StreamClosed;
        return self.adapter.write_all(self.adapter.ptr, bytes);
    }

    fn doClose(ptr: *anyopaque) void {
        const self: *TlsStream = @ptrCast(@alignCast(ptr));
        self.closed_flag.store(true, .release);
        self.adapter.close(self.adapter.ptr);
        if (self.reader_thread) |t| {
            t.join();
            self.reader_thread = null;
        }
    }

    pub fn stream(self: *TlsStream) Stream {
        return .{
            .ptr = self,
            .vtable = &.{
                .readNonblocking = doRead,
                .writeAll = doWrite,
                .close = doClose,
            },
        };
    }
};

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "PlainStream stream vtable connects through" {
    // Use a socketpair so we can drive both ends from the test.
    var pair: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &pair) != 0) return error.SocketpairFailed;
    defer _ = std.c.close(pair[0]);
    defer _ = std.c.close(pair[1]);

    var plain = PlainStream.init(pair[0]);
    const s = plain.stream();

    // Write some bytes via the *other* end of the socketpair.
    _ = std.c.write(pair[1], "hello", 5);

    // Give the kernel a moment to flush. Plain socketpair is
    // synchronous, so the data should already be readable.
    var buf: [16]u8 = undefined;
    const n = try s.readNonblocking(&buf);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualSlices(u8, "hello", buf[0..n]);
}

test "PlainStream readNonblocking returns 0 when no data" {
    var pair: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &pair) != 0) return error.SocketpairFailed;
    defer _ = std.c.close(pair[0]);
    defer _ = std.c.close(pair[1]);

    var plain = PlainStream.init(pair[0]);
    const s = plain.stream();
    var buf: [16]u8 = undefined;
    const n = try s.readNonblocking(&buf);
    try testing.expectEqual(@as(usize, 0), n);
}

test "PlainStream writeAll round-trips" {
    var pair: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &pair) != 0) return error.SocketpairFailed;
    defer _ = std.c.close(pair[0]);
    defer _ = std.c.close(pair[1]);

    var plain = PlainStream.init(pair[0]);
    const s = plain.stream();
    try s.writeAll("ping");

    var buf: [8]u8 = undefined;
    const n = try std.posix.read(pair[1], &buf);
    try testing.expectEqualSlices(u8, "ping", buf[0..n]);
}

// TlsStream test: drive the adapter via a synchronous mock.
const MockAdapter = struct {
    var feed_buf: [256]u8 = undefined;
    var feed_len: usize = 0;
    var feed_pos: usize = 0;
    var closed: bool = false;
    var writes_buf: [256]u8 = undefined;
    var writes_len: usize = 0;

    fn read(_: *anyopaque, dst: []u8) Error!usize {
        // Wait until we either have data or are closed.
        var waited: u32 = 0;
        while (feed_pos >= feed_len) {
            if (closed) return 0;
            sleepMs(1);
            waited += 1;
            if (waited > 1000) return error.ReadFailed;
        }
        const n = @min(dst.len, feed_len - feed_pos);
        @memcpy(dst[0..n], feed_buf[feed_pos .. feed_pos + n]);
        feed_pos += n;
        return n;
    }

    fn write(_: *anyopaque, bytes: []const u8) Error!void {
        const cap = @min(bytes.len, writes_buf.len - writes_len);
        @memcpy(writes_buf[writes_len .. writes_len + cap], bytes[0..cap]);
        writes_len += cap;
    }

    fn closeFn(_: *anyopaque) void {
        closed = true;
    }
};

test "WS-3 loopback: PlainStream carries ws frame end-to-end" {
    const ws_frame = @import("frame.zig");

    var pair: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &pair) != 0) return error.SocketpairFailed;
    defer _ = std.c.close(pair[0]);
    defer _ = std.c.close(pair[1]);

    var server_plain = PlainStream.init(pair[0]);
    const server = server_plain.stream();

    var client_plain = PlainStream.init(pair[1]);
    const client = client_plain.stream();

    // Server-side encode + send a binary frame.
    const payload = "ws-payload-hello";
    var encode_buf: [64]u8 = undefined;
    // server → client uses unmasked frames (mask is client→server only).
    const n = try ws_frame.encode(.binary, payload, false, &encode_buf);
    try server.writeAll(encode_buf[0..n]);

    // Client receives the frame bytes via readNonblocking.
    var recv_buf: [64]u8 = undefined;
    // Wait a bit for the kernel to deliver — socketpair is usually
    // immediate but be defensive.
    var got: usize = 0;
    var waited: u32 = 0;
    while (got < n) {
        const m = try client.readNonblocking(recv_buf[got..]);
        if (m > 0) {
            got += m;
            continue;
        }
        sleepMs(1);
        waited += 1;
        if (waited > 200) break;
    }
    try testing.expectEqual(@as(usize, n), got);

    // Decode the frame on the client side (server→client frames
    // are unmasked per RFC 6455).
    const decoded = try ws_frame.decode(recv_buf[0..got], false);
    switch (decoded) {
        .ok => |ok| try testing.expectEqualSlices(u8, payload, ok.frame.payload),
        .need_more => return error.UnexpectedNeedMore,
    }
}

// C1: socketpair-backed adapter — exercises the EXACT path the server's
// WS upgrade dispatcher uses for TLS: a reader thread doing blocking
// reads, handler-thread writes, and a `close` that shuts the fd down to
// unblock the blocked reader so the join completes (no hang).
const SockAdapter = struct {
    fd: std.posix.fd_t,

    fn read(ptr: *anyopaque, dst: []u8) Error!usize {
        const self: *SockAdapter = @ptrCast(@alignCast(ptr));
        // Blocking read; EOF (after shutdown) and errors both map to a
        // clean 0 so the reader loop exits and `close` can join.
        const n = std.posix.read(self.fd, dst) catch return 0;
        return n;
    }
    fn write(ptr: *anyopaque, bytes: []const u8) Error!void {
        const self: *SockAdapter = @ptrCast(@alignCast(ptr));
        var off: usize = 0;
        while (off < bytes.len) {
            const n = std.c.write(self.fd, bytes.ptr + off, bytes.len - off);
            if (n <= 0) return error.WriteFailed;
            off += @intCast(n);
        }
    }
    fn closeFn(ptr: *anyopaque) void {
        const self: *SockAdapter = @ptrCast(@alignCast(ptr));
        _ = std.c.shutdown(self.fd, std.c.SHUT.RDWR);
    }
};

test "C1: TlsStream over a socketpair carries ws frames and close joins" {
    const ws_frame = @import("frame.zig");
    var pair: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &pair) != 0) return error.SocketpairFailed;
    defer _ = std.c.close(pair[0]);
    defer _ = std.c.close(pair[1]);

    // Server side drives a TlsStream over pair[0]; the test peer is pair[1].
    var ad = SockAdapter{ .fd = pair[0] };
    var tls = TlsStream.init(.{
        .ptr = &ad,
        .read_blocking = SockAdapter.read,
        .write_all = SockAdapter.write,
        .close = SockAdapter.closeFn,
    });
    try tls.start();
    const s = tls.stream();

    const payload = "wss-frame-hello";
    var enc: [64]u8 = undefined;
    const n = try ws_frame.encode(.binary, payload, false, &enc);

    // Peer → server: the reader thread decrypts (here: plain copies)
    // into the ring; readNonblocking surfaces it on the handler thread.
    _ = std.c.write(pair[1], enc[0..n].ptr, n);
    var recv: [64]u8 = undefined;
    var got: usize = 0;
    var waited: u32 = 0;
    while (got < n) {
        const m = s.readNonblocking(recv[got..]) catch break;
        if (m > 0) {
            got += m;
            continue;
        }
        sleepMs(1);
        waited += 1;
        if (waited > 500) break;
    }
    try testing.expectEqual(@as(usize, n), got);
    switch (try ws_frame.decode(recv[0..got], false)) {
        .ok => |ok| try testing.expectEqualSlices(u8, payload, ok.frame.payload),
        .need_more => return error.UnexpectedNeedMore,
    }

    // Server → peer: write a frame through the TlsStream write path.
    try s.writeAll(enc[0..n]);
    var back: [64]u8 = undefined;
    const bn = try std.posix.read(pair[1], &back);
    switch (try ws_frame.decode(back[0..bn], false)) {
        .ok => |ok| try testing.expectEqualSlices(u8, payload, ok.frame.payload),
        .need_more => return error.UnexpectedNeedMore,
    }

    // close() must join the blocked reader thread without hanging —
    // SockAdapter.closeFn shuts the fd down to unblock the read.
    s.close();
}

test "TlsStream reader thread drains adapter into ring" {
    MockAdapter.feed_buf[0..5].* = "hello".*;
    MockAdapter.feed_len = 5;
    MockAdapter.feed_pos = 0;
    MockAdapter.closed = false;
    MockAdapter.writes_len = 0;

    var dummy: u8 = 0;
    const adapter: TlsAdapter = .{
        .ptr = &dummy,
        .read_blocking = MockAdapter.read,
        .write_all = MockAdapter.write,
        .close = MockAdapter.closeFn,
    };
    var tls = TlsStream.init(adapter);
    try tls.start();
    const s = tls.stream();

    // Poll readNonblocking until we see the data.
    var buf: [16]u8 = undefined;
    var total: usize = 0;
    var waited: u32 = 0;
    while (total < 5) {
        const got = s.readNonblocking(buf[total..]) catch break;
        if (got > 0) {
            total += got;
            continue;
        }
        sleepMs(1);
        waited += 1;
        if (waited > 500) break;
    }
    try testing.expectEqual(@as(usize, 5), total);
    try testing.expectEqualSlices(u8, "hello", buf[0..5]);

    // Write goes straight through.
    try s.writeAll("pong");
    try testing.expectEqualSlices(u8, "pong", MockAdapter.writes_buf[0..MockAdapter.writes_len]);

    // Close joins the reader thread.
    s.close();
}
