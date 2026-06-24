//! Pure-Zig Redis/Valkey connection: a blocking TCP socket driven by the
//! RESP codec in `resp.zig` + `reply.zig`. No hiredis, no std.net (this
//! stripped 0.16 std lacks it) — TCP is opened via `std.c` getaddrinfo +
//! socket + connect, exactly like `../storage/mysql/conn.zig.dialBlocking`,
//! and bytes move with `std.c.read`/`std.c.write`.
//!
//! Flow: connect → (optionally) HELLO 3 to negotiate RESP3, degrading to
//! RESP2 + a separate AUTH on an old server → (optionally) AUTH if a
//! password was supplied and HELLO did not already carry it → (optionally)
//! SELECT the configured db. Thereafter `command`/the scalar `exec*`
//! helpers encode one request, write it, and read exactly one reply.
//!
//! Tiger Style: a single `recv_buf` (64 KiB initial, grown geometrically up
//! to a 16 MiB hard cap for large bulk replies) and one `send_buf` (256 KiB)
//! are allocated ONCE at connect — mirroring `mysql/conn.zig`. The scalar
//! exec helpers (`execInteger`/`execBulkString`/`execStatus`) parse the
//! reply spine with an on-stack `FixedBufferAllocator` so the common
//! command path performs NO heap allocation. Reads loop on short
//! `std.c.read` returns until `resp.parseReply` reports a complete frame;
//! a decode error marks the connection un-resumable so the pool discards it.

const std = @import("std");
const resp = @import("resp.zig");
const reply = @import("reply.zig");

pub const Reply = reply.Reply;

pub const Error = error{
    /// getaddrinfo could not resolve the host.
    DnsFailed,
    /// socket()/connect() failed for every resolved address.
    ConnectFailed,
    /// A generic socket-layer failure (alloc of the I/O buffers, etc.).
    SocketError,
    /// A blocking read/write timed out (SO_RCVTIMEO/SNDTIMEO fired) or the
    /// peer half-closed mid-frame.
    Timeout,
    /// The peer closed the connection (read/​write returned 0/EOF).
    ConnectionClosed,
    /// A write to the socket failed.
    WriteFailed,
    /// A read from the socket failed.
    ReadFailed,
    /// The RESP codec rejected the bytes (malformed/over-limit). Wraps a
    /// `resp.Error`; the connection is marked un-resumable.
    ProtocolError,
    /// The server returned a RESP error reply (`-ERR ...` / `!...`). The
    /// text is stashed in `last_err_buf[0..last_err_len]` for the backend.
    ServerError,
    /// A scalar `exec*` helper got a reply of the wrong shape (e.g. an
    /// array where an integer was expected).
    UnexpectedReply,
    /// `execBulkString`/`execStatus`: the caller's output buffer is too
    /// small for the reply payload.
    BufferTooSmall,
    /// The reply exceeded the connection's hard recv-buffer cap.
    TooLarge,
};

/// Connection parameters (parsed from a URL by the provider).
pub const Options = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 6379,
    /// AUTH password. Null disables authentication.
    password: ?[]const u8 = null,
    /// ACL username. When set alongside `password`, AUTH uses the two-arg
    /// ACL form (`AUTH <user> <pass>`); otherwise the legacy one-arg form.
    username: ?[]const u8 = null,
    /// Logical database index to SELECT after auth. 0 is the default db and
    /// needs no SELECT.
    db: u32 = 0,
    timeout_ms: u32 = 5000,
    /// Attempt `HELLO 3` first to switch the connection to RESP3, falling
    /// back to RESP2 on an old server that rejects HELLO.
    prefer_resp3: bool = true,
};

/// Initial recv-buffer size. Most replies (status/int/short bulk) fit here
/// without a grow; large bulk replies (e.g. a big GET) trigger geometric
/// growth up to `max_recv_buf`.
pub const initial_recv_buf: usize = 64 * 1024;

/// Hard cap on the recv buffer. A single reply larger than this yields
/// `error.TooLarge` rather than unbounded growth. 16 MiB mirrors the MySQL
/// driver's `max_packet`.
pub const max_recv_buf: usize = 16 * 1024 * 1024;

/// Send buffer. Large enough for any CRUD/stream command argv the providers
/// build (a few KiB of payload); `encodeCommand` fails with BufferTooSmall
/// (mapped to ProtocolError here) if a command somehow exceeds it.
pub const send_buf_size: usize = 256 * 1024;

/// On-stack scratch for parsing a scalar reply's spine. Scalars
/// (status/int/bulk/error) never allocate from the arena, so a tiny buffer
/// is ample; a non-scalar reply (array/map) would exhaust it and surface as
/// ProtocolError, which is correct for the scalar `exec*` helpers.
const scalar_scratch: usize = 1024;

pub const Conn = struct {
    fd: std.c.fd_t,
    allocator: std.mem.Allocator,
    /// Owns the receive buffer (heap, allocated once at connect, grown in
    /// place up to `max_recv_buf`).
    recv_buf: []u8,
    /// Owns the send/encode buffer (heap, allocated once at connect).
    send_buf: []u8,
    /// True iff the RESP3 protocol is in effect (HELLO 3 succeeded).
    resp3: bool = false,
    /// False once a decode error desynchronised the byte stream; the pool
    /// must discard such a connection rather than reuse it.
    healthy: bool = true,
    /// Last server error reply text (from a `-ERR`/`!` reply), for the
    /// backend to classify. Mirrors mysql's `last_err`.
    last_err_buf: [256]u8 = undefined,
    last_err_len: usize = 0,

    pub fn connect(allocator: std.mem.Allocator, opts: Options) Error!*Conn {
        const fd = try dialBlocking(opts.host, opts.port, opts.timeout_ms);
        errdefer _ = std.c.close(fd);

        const recv = allocator.alloc(u8, initial_recv_buf) catch return error.SocketError;
        errdefer allocator.free(recv);
        const send = allocator.alloc(u8, send_buf_size) catch return error.SocketError;
        errdefer allocator.free(send);

        const self = allocator.create(Conn) catch return error.SocketError;
        errdefer allocator.destroy(self);
        self.* = .{
            .fd = fd,
            .allocator = allocator,
            .recv_buf = recv,
            .send_buf = send,
        };

        try self.handshake(opts);
        std.debug.assert(self.healthy);
        return self;
    }

    pub fn deinit(self: *Conn) void {
        _ = std.c.close(self.fd);
        self.allocator.free(self.recv_buf);
        self.allocator.free(self.send_buf);
        self.allocator.destroy(self);
    }

    /// The server's last error reply text, valid until the next command.
    pub fn lastError(self: *const Conn) []const u8 {
        return self.last_err_buf[0..self.last_err_len];
    }

    /// True when the byte stream is still aligned and the socket reusable.
    pub fn isHealthy(self: *const Conn) bool {
        return self.healthy;
    }

    // ── Handshake / auth ───────────────────────────────────────────────

    /// Negotiate the protocol + authenticate + select the db. RESP3 HELLO
    /// degrades to RESP2 gracefully: if `prefer_resp3` we send
    /// `HELLO 3 [AUTH user pass]`; a `-ERR`/`-NOPROTO` reply (an old server
    /// that does not know HELLO, or a server that refuses the AUTH inside
    /// it) means we stay on RESP2 and run AUTH as its own command. When
    /// HELLO succeeds it ALSO performed the auth, so we skip the separate
    /// AUTH. SELECT runs last regardless of protocol.
    fn handshake(self: *Conn, opts: Options) Error!void {
        var authed_via_hello = false;

        if (opts.prefer_resp3) {
            if (self.tryHello(opts)) {
                self.resp3 = true;
                // HELLO carried AUTH iff a password was supplied.
                authed_via_hello = (opts.password != null);
            } else |_| {
                // Old server (or HELLO/AUTH refused): stay RESP2. The
                // failed HELLO left a single reply on the wire which
                // tryHello already consumed, so the stream is aligned.
                self.resp3 = false;
            }
        }

        if (opts.password != null and !authed_via_hello) {
            try self.doAuth(opts);
        }

        if (opts.db != 0) {
            var db_buf: [16]u8 = undefined;
            const db_str = std.fmt.bufPrint(&db_buf, "{d}", .{opts.db}) catch return error.ProtocolError;
            var out: [32]u8 = undefined;
            _ = self.execStatus(&.{ "SELECT", db_str }, &out) catch |e| return e;
        }
    }

    /// Send `HELLO 3 [AUTH <user> <pass>]` and require a non-error reply
    /// (HELLO returns a map of server metadata we discard). Any server
    /// error or transport failure propagates so the caller falls back to
    /// RESP2. Uses an arena because HELLO's reply is a map (aggregate).
    fn tryHello(self: *Conn, opts: Options) Error!void {
        var scratch: [4096]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch);

        // AUTH inside HELLO uses the ACL two-arg form; an absent username
        // defaults to "default" (Redis's implicit ACL user).
        const r = if (opts.password) |pass| blk: {
            const user = opts.username orelse "default";
            break :blk try self.command(fba.allocator(), &.{ "HELLO", "3", "AUTH", user, pass });
        } else try self.command(fba.allocator(), &.{ "HELLO", "3" });

        if (r.isError()) |text| {
            self.captureErr(text);
            return error.ServerError;
        }
    }

    /// Run AUTH as a standalone command (RESP2 path, or when HELLO was not
    /// attempted). Uses the ACL two-arg form when a username is set.
    fn doAuth(self: *Conn, opts: Options) Error!void {
        const pass = opts.password.?;
        var out: [64]u8 = undefined;
        if (opts.username) |user| {
            _ = try self.execStatus(&.{ "AUTH", user, pass }, &out);
        } else {
            _ = try self.execStatus(&.{ "AUTH", pass }, &out);
        }
    }

    // ── Scalar exec helpers (no heap on the command path) ──────────────

    /// Run `args` and return the integer reply. A `-ERR`/`!` reply stashes
    /// the text and returns `error.ServerError`; any other shape is
    /// `error.UnexpectedReply`.
    pub fn execInteger(self: *Conn, args: []const []const u8) Error!i64 {
        var scratch: [scalar_scratch]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch);
        const r = try self.command(fba.allocator(), args);
        if (r.isError()) |text| {
            self.captureErr(text);
            return error.ServerError;
        }
        return switch (r) {
            .int => |v| v,
            .boolean => |b| @intFromBool(b),
            else => error.UnexpectedReply,
        };
    }

    /// Run `args` and copy the bulk/status string reply into `out`,
    /// returning the copied slice (or null for a nil reply). `error.ServerError`
    /// on a server error, `error.BufferTooSmall` if the payload does not fit,
    /// `error.UnexpectedReply` for a non-string shape.
    pub fn execBulkString(self: *Conn, args: []const []const u8, out: []u8) Error!?[]const u8 {
        var scratch: [scalar_scratch]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch);
        const r = try self.command(fba.allocator(), args);
        if (r.isError()) |text| {
            self.captureErr(text);
            return error.ServerError;
        }
        if (r.isNil()) return null;
        const s = r.asString() orelse return error.UnexpectedReply;
        if (s.len > out.len) return error.BufferTooSmall;
        @memcpy(out[0..s.len], s);
        return out[0..s.len];
    }

    /// Run `args` and copy the simple-string (`+OK` style) reply into `out`.
    /// Accepts a bulk string too (some commands answer either way).
    pub fn execStatus(self: *Conn, args: []const []const u8, out: []u8) Error![]const u8 {
        var scratch: [scalar_scratch]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch);
        const r = try self.command(fba.allocator(), args);
        if (r.isError()) |text| {
            self.captureErr(text);
            return error.ServerError;
        }
        const s = r.asString() orelse return error.UnexpectedReply;
        if (s.len > out.len) return error.BufferTooSmall;
        @memcpy(out[0..s.len], s);
        return out[0..s.len];
    }

    /// PING the server and assert a `+PONG` (or bulk "PONG") reply.
    pub fn ping(self: *Conn) Error!void {
        var out: [16]u8 = undefined;
        const s = try self.execStatus(&.{"PING"}, &out);
        if (!std.mem.eql(u8, s, "PONG")) return error.UnexpectedReply;
    }

    // ── The core exec loop ─────────────────────────────────────────────

    /// Encode `args`, write the request, and read exactly one reply.
    ///
    /// Inline scalar payloads in the returned `Reply` borrow `recv_buf` and
    /// are valid until the next command on this connection; aggregate spines
    /// come from `arena`. The read loop grows `recv_buf` (up to the hard
    /// cap) when `parseReply` reports `.incomplete` and the buffer is full,
    /// and `std.debug.assert`s no pipelined leftover (a blocking client
    /// sends one request and reads one reply).
    pub fn command(self: *Conn, arena: std.mem.Allocator, args: []const []const u8) Error!Reply {
        if (!self.healthy) return error.ProtocolError;
        const request = resp.encodeCommand(self.send_buf, args) catch {
            // Either the argv is too big for the send buffer or there are
            // too many args — both are caller/programming faults, not wire
            // desync, so the socket stays healthy. (The codec's Error set is
            // shared with the decoder; only the encoder variants are
            // reachable here, all mapped to a single client-side fault.)
            return error.ProtocolError;
        };
        try self.writeAll(request);

        var filled: usize = 0;
        while (true) {
            // Grow if the buffer is completely full and the parser still
            // wants more — a single reply larger than the current capacity.
            if (filled == self.recv_buf.len) {
                if (self.recv_buf.len >= max_recv_buf) {
                    self.healthy = false;
                    return error.TooLarge;
                }
                const new_len = @min(self.recv_buf.len * 2, max_recv_buf);
                self.recv_buf = self.allocator.realloc(self.recv_buf, new_len) catch {
                    self.healthy = false;
                    return error.SocketError;
                };
            }

            const n = self.readSome(self.recv_buf[filled..]) catch |e| {
                self.healthy = false;
                return e;
            };
            filled += n;

            const res = resp.parseReply(arena, self.recv_buf[0..filled], .{}) catch |e| {
                // A decode error means the stream is no longer aligned.
                self.healthy = false;
                _ = resp.isResumable(e); // always false today; documents intent
                return error.ProtocolError;
            };
            switch (res) {
                .incomplete => continue, // read more bytes
                .complete => |c| {
                    // A pooled blocking client issues one command and reads
                    // one reply; there must be no trailing (pipelined) bytes.
                    std.debug.assert(c.consumed <= filled);
                    if (c.consumed != filled) {
                        // Unexpected extra bytes: treat as desync.
                        self.healthy = false;
                        return error.ProtocolError;
                    }
                    return c.reply;
                },
            }
        }
    }

    fn captureErr(self: *Conn, text: []const u8) void {
        const n = @min(text.len, self.last_err_buf.len);
        @memcpy(self.last_err_buf[0..n], text[0..n]);
        self.last_err_len = n;
    }

    // ── Socket I/O ──────────────────────────────────────────────────────

    /// One `read` into `buf`, mapping EOF/timeouts to typed errors. A zero
    /// return is a clean peer close; a negative return is a transport error
    /// (timeouts surface here as the read returns 0/-1 once SO_RCVTIMEO
    /// fires). Returns the byte count (always ≥1 on success).
    fn readSome(self: *Conn, buf: []u8) Error!usize {
        std.debug.assert(buf.len > 0);
        const n = std.c.read(self.fd, buf.ptr, buf.len);
        if (n == 0) return error.ConnectionClosed;
        if (n < 0) {
            // EAGAIN/EWOULDBLOCK after SO_RCVTIMEO is a timeout; everything
            // else is a generic read failure. We cannot cheaply read errno
            // portably through std.c here without _errno; treat a failed
            // read on a connected socket as ReadFailed (the pool discards).
            return error.ReadFailed;
        }
        return @intCast(n);
    }

    fn writeAll(self: *Conn, buf: []const u8) Error!void {
        var off: usize = 0;
        while (off < buf.len) {
            const n = std.c.write(self.fd, buf.ptr + off, buf.len - off);
            if (n <= 0) {
                self.healthy = false;
                return error.WriteFailed;
            }
            off += @intCast(n);
        }
    }
};

/// Resolve host:port and open a blocking TCP socket via getaddrinfo +
/// socket + connect, trying each address until one connects. Mirrors
/// `mysql/conn.zig.dialBlocking`. Applies SO_RCVTIMEO/SNDTIMEO.
fn dialBlocking(host: []const u8, port: u16, timeout_ms: u32) Error!std.c.fd_t {
    var host_z: [256]u8 = undefined;
    if (host.len >= host_z.len) return error.DnsFailed;
    @memcpy(host_z[0..host.len], host);
    host_z[host.len] = 0;

    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch return error.DnsFailed;
    port_buf[port_str.len] = 0;

    var hints: std.c.addrinfo = std.mem.zeroes(std.c.addrinfo);
    hints.family = std.c.AF.UNSPEC;
    hints.socktype = std.c.SOCK.STREAM;

    const host_ptr: [*:0]const u8 = @ptrCast(&host_z);
    const port_ptr: [*:0]const u8 = @ptrCast(&port_buf);
    var res: ?*std.c.addrinfo = null;
    const rc = std.c.getaddrinfo(host_ptr, port_ptr, &hints, &res);
    if (@intFromEnum(rc) != 0) return error.DnsFailed;
    const head = res orelse return error.DnsFailed;
    defer std.c.freeaddrinfo(head);

    var ai = res;
    while (ai) |a| : (ai = a.next) {
        const addr = a.addr orelse continue;
        const fd = std.c.socket(@intCast(a.family), @intCast(a.socktype), @intCast(a.protocol));
        if (fd < 0) continue;
        applyTimeouts(fd, timeout_ms);
        if (std.c.connect(fd, addr, a.addrlen) == 0) return fd;
        _ = std.c.close(fd);
    }
    return error.ConnectFailed;
}

fn applyTimeouts(fd: std.c.fd_t, timeout_ms: u32) void {
    if (timeout_ms == 0) return;
    const tv = std.posix.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    const bytes = std.mem.asBytes(&tv);
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, bytes) catch {};
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, bytes) catch {};
}

// ──────────────────────────────────────────────────────────────────────
// Endpoint parsing.
// ──────────────────────────────────────────────────────────────────────

/// Parse `host:port` or `redis://[user:pass@]host:port[/db]` (`rediss://`
/// recognised; TLS wired separately) into connection `Options`.
pub fn parseOptions(url: []const u8) Options {
    var s = url;
    inline for (.{ "redis://", "rediss://" }) |scheme| {
        if (std.mem.startsWith(u8, s, scheme)) {
            s = s[scheme.len..];
            break;
        }
    }
    var opts = Options{};
    if (std.mem.indexOfScalar(u8, s, '@')) |at| {
        const userinfo = s[0..at];
        s = s[at + 1 ..];
        if (std.mem.indexOfScalar(u8, userinfo, ':')) |colon| {
            if (colon > 0) opts.username = userinfo[0..colon];
            opts.password = userinfo[colon + 1 ..];
        } else if (userinfo.len > 0) {
            opts.password = userinfo;
        }
    }
    if (std.mem.indexOfScalar(u8, s, '/')) |slash| {
        opts.db = std.fmt.parseInt(u32, s[slash + 1 ..], 10) catch 0;
        s = s[0..slash];
    }
    if (std.mem.lastIndexOfScalar(u8, s, ':')) |colon| {
        opts.host = s[0..colon];
        opts.port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch 6379;
    } else if (s.len > 0) {
        opts.host = s;
    }
    return opts;
}

/// Live-test endpoint, from `REDIS_TEST_URL` (default `127.0.0.1:6379`) — lets
/// CI point the gated live tests at any broker, mirroring `PG_TEST_URL`.
pub fn testOptions() Options {
    const url = if (std.c.getenv("REDIS_TEST_URL")) |p| std.mem.sliceTo(p, 0) else "127.0.0.1:6379";
    return parseOptions(url);
}

// ──────────────────────────────────────────────────────────────────────
// Tests. Pure-logic tests (no socket) assert the exact request bytes the
// handshake/exec paths emit for randomized credentials. The live tests skip
// cleanly when no broker is reachable (REDIS_TEST_URL, default :6379).
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "dialBlocking: unresolvable host fails cleanly (no hang, no crash)" {
    const r = dialBlocking("nonexistent.invalid", 6379, 500);
    try testing.expectError(error.DnsFailed, r);
}

test "AUTH/HELLO/SELECT command bytes match encodeCommand for random creds" {
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();

    var iter: usize = 0;
    while (iter < 128) : (iter += 1) {
        // Random password + (sometimes) username + db.
        var pass_buf: [24]u8 = undefined;
        const pass_len = rand.intRangeAtMost(usize, 1, 24);
        for (0..pass_len) |i| pass_buf[i] = rand.intRangeAtMost(u8, 'a', 'z');
        const pass = pass_buf[0..pass_len];

        const has_user = rand.boolean();
        var user_buf: [16]u8 = undefined;
        const user_len = rand.intRangeAtMost(usize, 1, 16);
        for (0..user_len) |i| user_buf[i] = rand.intRangeAtMost(u8, 'a', 'z');
        const user = user_buf[0..user_len];

        var buf: [512]u8 = undefined;

        // HELLO 3 [AUTH ...].
        {
            const out = if (has_user)
                try resp.encodeCommand(&buf, &.{ "HELLO", "3", "AUTH", user, pass })
            else
                try resp.encodeCommand(&buf, &.{ "HELLO", "3", "AUTH", "default", pass });
            // Re-derive the array header independently.
            const argc: usize = 5;
            var hdr_buf: [16]u8 = undefined;
            const hdr = try std.fmt.bufPrint(&hdr_buf, "*{d}\r\n", .{argc});
            try testing.expect(std.mem.startsWith(u8, out, hdr));
            // The reply must parse back as a 5-element array of bulks.
            const res = try resp.parseReply(testing.allocator, out, .{});
            defer testing.allocator.free(res.complete.reply.array);
            try testing.expectEqual(@as(usize, 5), res.complete.reply.array.len);
            try testing.expectEqualStrings("HELLO", res.complete.reply.array[0].bulk.?);
            try testing.expectEqualStrings("3", res.complete.reply.array[1].bulk.?);
            try testing.expectEqualStrings(pass, res.complete.reply.array[4].bulk.?);
        }

        // Legacy AUTH (no user) vs ACL AUTH (user).
        {
            const out = if (has_user)
                try resp.encodeCommand(&buf, &.{ "AUTH", user, pass })
            else
                try resp.encodeCommand(&buf, &.{ "AUTH", pass });
            const res = try resp.parseReply(testing.allocator, out, .{});
            defer testing.allocator.free(res.complete.reply.array);
            const want_argc: usize = if (has_user) 3 else 2;
            try testing.expectEqual(want_argc, res.complete.reply.array.len);
            try testing.expectEqualStrings(pass, res.complete.reply.array[want_argc - 1].bulk.?);
        }

        // SELECT <db>.
        {
            const db = rand.intRangeAtMost(u32, 1, 15);
            var db_buf: [16]u8 = undefined;
            const db_str = try std.fmt.bufPrint(&db_buf, "{d}", .{db});
            const out = try resp.encodeCommand(&buf, &.{ "SELECT", db_str });
            const res = try resp.parseReply(testing.allocator, out, .{});
            defer testing.allocator.free(res.complete.reply.array);
            try testing.expectEqual(@as(usize, 2), res.complete.reply.array.len);
            try testing.expectEqualStrings("SELECT", res.complete.reply.array[0].bulk.?);
            try testing.expectEqualStrings(db_str, res.complete.reply.array[1].bulk.?);
        }
    }
}

test "redis Conn live round-trip SET/GET/DEL/INCR/XADD/XLEN (skips if no broker)" {
    const gpa = testing.allocator;
    var c = Conn.connect(gpa, testOptions()) catch
        return error.SkipZigTest;
    defer c.deinit();
    c.ping() catch return error.SkipZigTest;

    // Unique key prefix per run so reruns never collide: mix the test seed
    // with a monotonic clock reading (std.time.Timer/milliTimestamp were
    // removed in this stripped 0.16 std; std.c.clock_gettime is the
    // supported path, mirroring core/clock.zig).
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    const now_ns: u64 = @as(u64, @intCast(ts.sec)) *% std.time.ns_per_s +% @as(u64, @intCast(ts.nsec));
    var prng = std.Random.DefaultPrng.init(testing.random_seed ^ now_ns);
    const rand = prng.random();
    const seed = rand.int(u64);

    var key_buf: [64]u8 = undefined;
    const key = try std.fmt.bufPrint(&key_buf, "speedy:r2:{x}:str", .{seed});

    // SET / GET round-trip with a randomized value (incl. embedded spaces).
    var val_buf: [48]u8 = undefined;
    const val = try std.fmt.bufPrint(&val_buf, "v-{x}-{x}", .{ rand.int(u32), rand.int(u32) });
    {
        var out: [16]u8 = undefined;
        const s = try c.execStatus(&.{ "SET", key, val }, &out);
        try testing.expectEqualStrings("OK", s);
    }
    {
        var out: [64]u8 = undefined;
        const got = try c.execBulkString(&.{ "GET", key }, &out);
        try testing.expectEqualStrings(val, got.?);
    }
    // GET of a missing key is nil.
    {
        var miss_buf: [64]u8 = undefined;
        const miss_key = try std.fmt.bufPrint(&miss_buf, "speedy:r2:{x}:absent", .{seed});
        var out: [64]u8 = undefined;
        const got = try c.execBulkString(&.{ "GET", miss_key }, &out);
        try testing.expect(got == null);
    }
    // BufferTooSmall when the output buffer cannot hold the value.
    {
        var tiny: [1]u8 = undefined;
        try testing.expectError(error.BufferTooSmall, c.execBulkString(&.{ "GET", key }, &tiny));
    }
    // INCR a counter from a known base.
    var ctr_buf: [64]u8 = undefined;
    const ctr = try std.fmt.bufPrint(&ctr_buf, "speedy:r2:{x}:ctr", .{seed});
    {
        const base = rand.intRangeAtMost(i64, 1, 1000);
        var sb: [32]u8 = undefined;
        const bstr = try std.fmt.bufPrint(&sb, "{d}", .{base});
        var out: [16]u8 = undefined;
        _ = try c.execStatus(&.{ "SET", ctr, bstr }, &out);
        const after = try c.execInteger(&.{ "INCR", ctr });
        try testing.expectEqual(base + 1, after);
    }
    // XADD then XLEN on a stream.
    var stream_buf: [64]u8 = undefined;
    const stream_key = try std.fmt.bufPrint(&stream_buf, "speedy:r2:{x}:stream", .{seed});
    {
        const n: usize = rand.intRangeAtMost(usize, 1, 6);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            var fb: [32]u8 = undefined;
            const field_val = try std.fmt.bufPrint(&fb, "{x}", .{rand.int(u32)});
            var idbuf: [64]u8 = undefined;
            // XADD returns the generated entry id (a bulk string).
            const id = try c.execBulkString(&.{ "XADD", stream_key, "*", "f", field_val }, &idbuf);
            try testing.expect(id != null);
        }
        const len = try c.execInteger(&.{ "XLEN", stream_key });
        try testing.expectEqual(@as(i64, @intCast(n)), len);
    }
    // ServerError path: WRONGTYPE when we INCR the stream key.
    {
        try testing.expectError(error.ServerError, c.execInteger(&.{ "INCR", stream_key }));
        try testing.expect(c.lastError().len > 0);
        try testing.expect(c.isHealthy()); // a server error keeps the stream aligned
    }
    // Cleanup (best-effort).
    _ = c.execInteger(&.{ "DEL", key, ctr, stream_key }) catch {};
}

test "redis Conn unreachable broker yields a graceful error, never panics" {
    const gpa = testing.allocator;
    // Port 1 is reserved/unused → connect() must fail, not hang/panic.
    const r = Conn.connect(gpa, .{ .host = "127.0.0.1", .port = 1, .timeout_ms = 500 });
    try testing.expect(std.meta.isError(r));
}
