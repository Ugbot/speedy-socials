//! Tiger-style HTTP server (MVP).
//!
//! Uses the Zig 0.16 `std.Io` abstraction: every I/O call goes through
//! an `Io` interface, so the same code runs against `std.Io.Threaded`
//! in production and against a simulated Io in tests. (Phase 1 hooks
//! the real backing only; sim is added in a later phase.)
//!
//! Connection model: each accepted socket is handled inline on the
//! accepting thread (MVP). Connection slot comes from a static pool —
//! no per-connection allocation. The slot's arena resets between
//! requests.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const limits = @import("limits.zig");
const errors = @import("errors.zig");
const HttpError = errors.HttpError;
const StaticPool = @import("static.zig").StaticPool;
const Connection = @import("connection.zig").Connection;
const parser = @import("http/parser.zig");
const request_mod = @import("http/request.zig");
const response = @import("http/response.zig");
const router_mod = @import("http/router.zig");
const Plugin = @import("plugin.zig");
const Registry = @import("plugin.zig").Registry;
const Context = @import("plugin.zig").Context;
const assert_mod = @import("assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

/// Cap on a single underlying read. Small enough that the kernel returns
/// a partial buffer promptly instead of waiting for `read_buf.len`-many
/// bytes, but large enough that one syscall captures a typical HTTP/1.1
/// request head in one go.
const read_chunk_bytes: usize = 1024;

pub const Config = struct {
    bind_addr: []const u8 = "127.0.0.1",
    port: u16 = 8080,
};

pub const Server = struct {
    cfg: Config,
    io: Io,
    ctx: *Context,
    router: *const router_mod.Router,
    pool: *StaticPool(Connection, limits.max_connections),
    inner: net.Server,
    shutting_down: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn init(
        cfg: Config,
        io: Io,
        ctx: *Context,
        router: *const router_mod.Router,
        pool: *StaticPool(Connection, limits.max_connections),
    ) !Server {
        const addr = try net.IpAddress.parse(cfg.bind_addr, cfg.port);
        const inner = try addr.listen(io, .{
            .kernel_backlog = limits.tcp_listen_backlog,
            .reuse_address = true,
            .mode = .stream,
        });
        return .{
            .cfg = cfg,
            .io = io,
            .ctx = ctx,
            .router = router,
            .pool = pool,
            .inner = inner,
        };
    }

    pub fn deinit(self: *Server) void {
        self.inner.deinit(self.io);
    }

    pub fn requestShutdown(self: *Server) void {
        self.shutting_down.store(true, .seq_cst);
    }

    pub fn run(self: *Server) !void {
        while (!self.shutting_down.load(.seq_cst)) {
            const stream = self.inner.accept(self.io) catch |err| switch (err) {
                error.ConnectionAborted, error.WouldBlock => continue,
                else => return err,
            };
            self.handleConnection(stream) catch {};
            stream.close(self.io);
        }
    }

    fn handleConnection(self: *Server, stream: net.Stream) !void {
        const acquired = self.pool.acquire() catch |err| switch (err) {
            error.Exhausted => {
                try writeRaw(stream, self.io, "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 19\r\n\r\nServer Unavailable\n");
                return;
            },
        };
        defer self.pool.release(acquired.index);
        const conn = acquired.ptr;
        conn.prime();

        try self.readRequest(stream, conn);
        try self.dispatchAndRespond(stream, conn);
    }

    fn readRequest(self: *Server, stream: net.Stream, conn: *Connection) !void {
        // Issue: a previous implementation called `readSliceShort(dest)` with
        // the entire remaining read-buffer as `dest`. `readSliceShort` blocks
        // until it has filled `dest` or seen EOF — so curl, which sends a
        // single small HTTP head and waits for a response, would hang here
        // because the kernel had no more bytes to deliver and the reader
        // never returned the partial head to us. nc (which sends + closes)
        // worked because EOF unblocked the read.
        //
        // Fix: read in small chunks via `readVec`, which returns as soon as
        // *any* bytes arrive from the kernel. After each chunk we attempt
        // to parse; if the parser says `UnexpectedEof` we loop, otherwise
        // (success OR any other error) we stop reading and let the dispatch
        // step turn the parse result into a response.
        var read_scratch: [read_chunk_bytes]u8 = undefined;
        var reader = net.Stream.Reader.init(stream, self.io, &read_scratch);
        var hdrs_scratch: parser.HeaderArray = undefined;

        // Bounded outer loop: at most one read per `read_chunk_bytes` until
        // the request buffer is full. Anything beyond that is HeaderTooLarge.
        const max_reads: u32 = @as(u32, @intCast((conn.read_buf.len + read_chunk_bytes - 1) / read_chunk_bytes)) + 1;
        var reads: u32 = 0;
        while (reads < max_reads) : (reads += 1) {
            if (conn.read_len >= conn.read_buf.len) return error.HeaderTooLarge;
            const remain = conn.read_buf.len - conn.read_len;
            const this_chunk = @min(remain, read_chunk_bytes);
            var dest_arr: [1][]u8 = .{conn.read_buf[conn.read_len..][0..this_chunk]};
            const n = reader.interface.readVec(&dest_arr) catch |err| switch (err) {
                error.EndOfStream => return error.UnexpectedEof,
                error.ReadFailed => return error.UnexpectedEof,
            };
            if (n == 0) {
                // No data ready right now; readVec is allowed to return 0
                // without EOF. Try again — but bounded by `max_reads`.
                continue;
            }
            conn.read_len += n;
            _ = parser.parse(conn.read_buf[0..conn.read_len], &hdrs_scratch) catch |err| switch (err) {
                // Need more bytes — loop.
                error.UnexpectedEof => continue,
                // Any other parse error: stop reading. The dispatcher will
                // re-parse, see the same error, and emit a 4xx.
                else => return,
            };
            // Parse succeeded — head is complete.
            return;
        }
        return error.UnexpectedEof;
    }

    fn dispatchAndRespond(self: *Server, stream: net.Stream, conn: *Connection) !void {
        var hdrs_scratch: parser.HeaderArray = undefined;
        const parsed = parser.parse(conn.read_buf[0..conn.read_len], &hdrs_scratch) catch |err| {
            try writeStatusResponse(stream, self.io, conn, errorToStatus(err));
            return;
        };
        const path_query = parsed.request.pathAndQuery();

        var params: router_mod.PathParams = .{};
        const match = self.router.matchOrCode(parsed.request.method, path_query.path, &params);

        var rb = response.Builder.init(&conn.write_buf);

        switch (match) {
            .ok => |handler| {
                var hc = router_mod.HandlerContext{
                    .plugin_ctx = self.ctx,
                    .request = &parsed.request,
                    .response = &rb,
                    .params = params,
                };
                handler(&hc) catch |err| {
                    rb = response.Builder.init(&conn.write_buf);
                    try rb.simple(.internal, "text/plain", @errorName(err));
                };
            },
            .not_found => try rb.simple(.not_found, "text/plain", "not found"),
            .method_not_allowed => try rb.simple(.method_not_allowed, "text/plain", "method not allowed"),
        }

        try writeRaw(stream, self.io, rb.bytes());
    }
};

fn errorToStatus(err: HttpError) response.Status {
    return switch (err) {
        error.PayloadTooLarge => .payload_too_large,
        error.HeaderTooLarge, error.TooManyHeaders, error.MethodTooLong, error.TargetTooLong => .bad_request,
        error.MalformedRequestLine, error.MalformedHeader, error.BadRequest => .bad_request,
        error.UnexpectedEof => .bad_request,
        else => .internal,
    };
}

fn writeStatusResponse(stream: net.Stream, io: Io, conn: *Connection, status: response.Status) !void {
    var rb = response.Builder.init(&conn.write_buf);
    rb.simple(status, "text/plain", status.reason()) catch return;
    try writeRaw(stream, io, rb.bytes());
}

fn writeRaw(stream: net.Stream, io: Io, payload: []const u8) !void {
    var write_scratch: [4096]u8 = undefined;
    var writer = net.Stream.Writer.init(stream, io, &write_scratch);
    writer.interface.writeAll(payload) catch return error.WriteFailed;
    writer.interface.flush() catch return error.WriteFailed;
}

// ──────────────────────────────────────────────────────────────────────
// End-to-end loopback test for the read-loop bugfix.
//
// The test starts a Server bound to 127.0.0.1:0 (kernel-chosen port) with
// a tiny one-route registry, then makes a real TCP connection from a
// helper thread that writes the HTTP head in two segments — exactly how
// curl frames a small GET (request line + headers; client never sends
// FIN until the response is read). Before the fix this hung; now it
// must return within a deterministic bound (we wait at most 2 s).
// ──────────────────────────────────────────────────────────────────────

const std_testing = std.testing;

fn pingHandler(hc: *router_mod.HandlerContext) anyerror!void {
    try hc.response.simple(.ok, "text/plain", "pong");
}

const E2EShared = struct {
    server: *Server,
    port: u16,
    got_response: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    response_buf: [256]u8 = undefined,
    response_len: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

fn serverRunThread(shared: *E2EShared) void {
    shared.server.run() catch {};
}

fn clientThread(shared: *E2EShared) void {
    // Tiny libc-level client so the test does not depend on std.Io's
    // client APIs. AF_INET, SOCK_STREAM, write the request in two
    // segments (the bug only reproduces with chunked sends).
    const c = std.c;
    const fd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    if (fd < 0) return;
    defer _ = c.close(fd);

    var addr: c.sockaddr.in = .{
        .family = c.AF.INET,
        .port = std.mem.nativeToBig(u16, shared.port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001), // 127.0.0.1
        .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    const sa_ptr: *const c.sockaddr = @ptrCast(&addr);
    if (c.connect(fd, sa_ptr, @sizeOf(c.sockaddr.in)) != 0) return;

    // Segment 1: request line + Host header (no terminating CRLF for the
    // headers block — forces the server to wait for more bytes).
    const seg1 = "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\n";
    _ = c.write(fd, seg1.ptr, seg1.len);
    // Small delay so the kernel delivers segment 1 separately. The bug
    // was specifically about the server hanging on the first partial
    // read; this gap reproduces it deterministically.
    var ts: c.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
    _ = c.nanosleep(&ts, &ts);
    // Segment 2: closing CRLF for header block.
    const seg2 = "\r\n";
    _ = c.write(fd, seg2.ptr, seg2.len);

    // Read response (single read; "pong" body is tiny so it fits).
    const n = c.read(fd, &shared.response_buf, shared.response_buf.len);
    if (n > 0) {
        shared.response_len.store(@intCast(n), .release);
        shared.got_response.store(true, .release);
    }
}

test "Server serves a chunked HTTP/1.1 request end-to-end" {
    const allocator = std_testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try allocator.create(StaticPool(Connection, limits.max_connections));
    defer allocator.destroy(pool);
    pool.initInPlace();

    var rng = @import("rng.zig").Rng.init(0x42);
    var sc = @import("clock.zig").SimClock.init(0);
    var ctx: Context = .{ .clock = sc.clock(), .rng = &rng };

    var router: router_mod.Router = router_mod.Router.init();
    try router.register(.get, "/ping", pingHandler, 0);
    router.freeze();

    var server = try Server.init(
        .{ .bind_addr = "127.0.0.1", .port = 0 },
        io,
        &ctx,
        &router,
        pool,
    );
    defer server.deinit();

    // Recover the OS-assigned port from the listening socket. The
    // listener's resolved address is populated by `listen()`.
    const port: u16 = switch (server.inner.socket.address) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };

    var shared: E2EShared = .{ .server = &server, .port = port };
    const srv_t = try std.Thread.spawn(.{}, serverRunThread, .{&shared});
    const cli_t = try std.Thread.spawn(.{}, clientThread, .{&shared});

    // Deterministic upper bound: 2 seconds is generous; before the fix
    // the test hung forever. Poll the atomic flag at 1 ms cadence.
    var waited_ns: u64 = 0;
    const deadline_ns: u64 = 2 * std.time.ns_per_s;
    while (!shared.got_response.load(.acquire) and waited_ns < deadline_ns) {
        var ts: std.c.timespec = .{ .sec = 0, .nsec = 1 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&ts, &ts);
        waited_ns += 1 * std.time.ns_per_ms;
    }

    server.requestShutdown();
    // Poke the accept loop with a dummy connection so it exits.
    {
        const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
        if (fd >= 0) {
            var poke: std.c.sockaddr.in = .{
                .family = std.c.AF.INET,
                .port = std.mem.nativeToBig(u16, port),
                .addr = std.mem.nativeToBig(u32, 0x7f000001),
                .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
            };
            const sap: *const std.c.sockaddr = @ptrCast(&poke);
            _ = std.c.connect(fd, sap, @sizeOf(std.c.sockaddr.in));
            _ = std.c.close(fd);
        }
    }

    cli_t.join();
    srv_t.join();

    try std_testing.expect(shared.got_response.load(.acquire));
    const len = shared.response_len.load(.acquire);
    try std_testing.expect(len > 0);
    const body = shared.response_buf[0..len];
    try std_testing.expect(std.mem.startsWith(u8, body, "HTTP/1.1 200 OK"));
    try std_testing.expect(std.mem.indexOf(u8, body, "pong") != null);
}
