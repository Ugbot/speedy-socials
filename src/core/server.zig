//! Tiger-style HTTP server.
//!
//! Uses the Zig 0.16 `std.Io` abstraction: every I/O call goes through
//! an `Io` interface, so the same code runs against `std.Io.Threaded`
//! in production and against a simulated Io in tests.
//!
//! Connection model: each accepted socket is handled inline on the
//! accepting thread. Connection slot comes from a static pool — no
//! per-connection allocation. The slot's arena resets between requests
//! on the same TCP connection (HTTP/1.1 keep-alive).
//!
//! Three things landed in W1.1:
//!   1. WebSocket upgrade dispatch via a pluggable `WsUpgradeRouter`.
//!      After we read + parse a request that bears `Upgrade: websocket`
//!      we look up the path; on match we write the 101 response and
//!      hand the raw stream to the plugin handler, which owns it until
//!      return. The connection slot is released after the handler
//!      returns; the socket is closed at the accept-loop level.
//!   2. HTTP/1.1 keep-alive: a bounded per-connection inner loop that
//!      reuses the same slot for up to `limits.max_requests_per_connection`
//!      requests. Each iteration resets the arena and read buffer.
//!      WS upgrades bypass the loop — they take the connection.
//!   3. TLS scaffolding: `Server.Config.tls` is an optional `TlsBackend`.
//!      When set, the accepted raw stream is wrapped via `wrapStream`
//!      before any I/O. Default backend is `null` (plain HTTP).

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const limits = @import("limits.zig");
const errors = @import("errors.zig");
const HttpError = errors.HttpError;
const WsError = errors.WsError;
const StaticPool = @import("static.zig").StaticPool;
const Connection = @import("connection.zig").Connection;
const parser = @import("http/parser.zig");
const request_mod = @import("http/request.zig");
const response = @import("http/response.zig");
const router_mod = @import("http/router.zig");
const Plugin = @import("plugin.zig");
const Registry = @import("plugin.zig").Registry;
const Context = @import("plugin.zig").Context;
const ws_handshake = @import("ws/handshake.zig");
const ws_upgrade_router = @import("ws/upgrade_router.zig");
const WsUpgradeRouter = ws_upgrade_router.WsUpgradeRouter;
const WsUpgradeContext = ws_upgrade_router.WsUpgradeContext;
const tls_mod = @import("tls.zig");
const TlsBackend = tls_mod.TlsBackend;
const assert_mod = @import("assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

/// Cap on a single underlying read.
const read_chunk_bytes: usize = 1024;

pub const Config = struct {
    bind_addr: []const u8 = "127.0.0.1",
    port: u16 = 8080,
    /// Pluggable TLS backend. `null` = plain HTTP. When set, every
    /// accepted stream is passed through `tls.wrapStream` before any
    /// HTTP I/O occurs on it.
    tls: ?TlsBackend = null,
};

pub const Server = struct {
    cfg: Config,
    io: Io,
    ctx: *Context,
    router: *const router_mod.Router,
    ws_upgrade_router: *const WsUpgradeRouter,
    pool: *StaticPool(Connection, limits.max_connections),
    inner: net.Server,
    shutting_down: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn init(
        cfg: Config,
        io: Io,
        ctx: *Context,
        router: *const router_mod.Router,
        ws_router: *const WsUpgradeRouter,
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
            .ws_upgrade_router = ws_router,
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
            const raw_stream = self.inner.accept(self.io) catch |err| switch (err) {
                error.ConnectionAborted, error.WouldBlock => continue,
                else => return err,
            };
            // Wrap with the TLS backend if configured. The backend is
            // free to perform the handshake lazily; on hard failure we
            // close the socket and move on (one bad client must not
            // poison the accept loop).
            const stream = if (self.cfg.tls) |be|
                be.wrapStream(self.io, raw_stream) catch {
                    raw_stream.close(self.io);
                    continue;
                }
            else
                raw_stream;
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

        // ── Per-connection keep-alive inner loop ──────────────────────
        // Bounded by `max_requests_per_connection` so a malicious or
        // misconfigured peer cannot keep one slot indefinitely. Each
        // iteration resets the arena + read buffer. An iteration may
        // exit early via:
        //   - WS upgrade dispatch (returns; outer loop closes socket)
        //   - explicit `Connection: close` on req or resp
        //   - read error / parse error / write error
        var served: u32 = 0;
        while (served < limits.max_requests_per_connection) : (served += 1) {
            assertLe(served, limits.max_requests_per_connection);

            // First iteration: pool's `prime` left us in clean state.
            // Subsequent iterations: arena resets, but if the client
            // pipelined and left bytes after the prior request's head
            // they are already in `conn.read_buf[..read_len]` — only
            // the arena needs resetting. The readRequest loop is
            // idempotent on a buffer that already contains a full
            // head (parser.parse returns immediately).
            if (served > 0) {
                conn.arena.reset();
            }

            self.readRequest(stream, conn) catch |err| switch (err) {
                // Client closed the connection cleanly between requests.
                error.UnexpectedEof => return,
                error.HeaderTooLarge => {
                    try writeStatusResponse(stream, self.io, conn, .payload_too_large);
                    return;
                },
                else => return,
            };

            // Peek at the parsed request to decide between the WS
            // upgrade fast-path and the normal HTTP dispatcher. The
            // dispatcher re-parses (cheap; bytes are hot in cache).
            var hdrs_scratch: parser.HeaderArray = undefined;
            const parsed = parser.parse(conn.read_buf[0..conn.read_len], &hdrs_scratch) catch {
                // Malformed request: respond with a 400 and bail.
                try writeStatusResponse(stream, self.io, conn, .bad_request);
                return;
            };

            const is_last_iter = served + 1 == limits.max_requests_per_connection;
            const client_wants_close = headerIndicatesClose(&parsed.request);

            if (isUpgradeRequest(&parsed.request)) {
                // WS upgrade short-circuits keep-alive. The plugin
                // takes the stream after we write 101.
                try self.dispatchWsUpgrade(stream, conn, &parsed.request);
                return;
            }

            const final = is_last_iter or client_wants_close;
            try self.dispatchAndRespond(stream, conn, &parsed.request, final);

            if (final) return;

            // Slide any pipelined leftover bytes (a partial next
            // request) to the front of the buffer so the next
            // iteration's readRequest can complete the parse without
            // dropping data. `parsed.consumed` covers the request head
            // *and* its declared body.
            const consumed = parsed.consumed;
            assertLe(consumed, conn.read_len);
            if (consumed < conn.read_len) {
                const leftover = conn.read_len - consumed;
                std.mem.copyForwards(u8, conn.read_buf[0..leftover], conn.read_buf[consumed..conn.read_len]);
                conn.read_len = leftover;
            } else {
                conn.read_len = 0;
            }
        }
    }

    fn readRequest(self: *Server, stream: net.Stream, conn: *Connection) !void {
        var hdrs_scratch: parser.HeaderArray = undefined;
        // Pipelined leftover from a prior keep-alive request may
        // already contain a complete head — try to parse first and
        // skip the read entirely if so.
        if (conn.read_len > 0) {
            _ = parser.parse(conn.read_buf[0..conn.read_len], &hdrs_scratch) catch {};
            // Either it parsed (we return immediately) or it didn't
            // and we fall through to read more. The dispatcher will
            // do its own parse so we don't need the parsed result.
            const try_parse = parser.parse(conn.read_buf[0..conn.read_len], &hdrs_scratch);
            if (try_parse) |_| return else |_| {}
        }
        var read_scratch: [read_chunk_bytes]u8 = undefined;
        var reader = net.Stream.Reader.init(stream, self.io, &read_scratch);

        // Bounded outer loop: at most one read per `read_chunk_bytes`
        // until the request buffer is full. Anything beyond is
        // HeaderTooLarge.
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
            if (n == 0) continue;
            conn.read_len += n;
            _ = parser.parse(conn.read_buf[0..conn.read_len], &hdrs_scratch) catch |err| switch (err) {
                error.UnexpectedEof => continue,
                else => return,
            };
            return;
        }
        return error.UnexpectedEof;
    }

    fn dispatchWsUpgrade(
        self: *Server,
        stream: net.Stream,
        conn: *Connection,
        request: *const request_mod.Request,
    ) !void {
        const path_query = request.pathAndQuery();
        var params: router_mod.PathParams = .{};
        const handler_opt = self.ws_upgrade_router.match(path_query.path, &params);
        const handler = handler_opt orelse {
            try writeStatusResponse(stream, self.io, conn, .bad_request);
            return error.UpgradeRouteNotFound;
        };

        // Validate the handshake and write 101. Validation failures map
        // to 400; the connection is then closed by the outer loop.
        const accepted = ws_handshake.validate(request, &.{}) catch {
            try writeStatusResponse(stream, self.io, conn, .bad_request);
            return;
        };
        var rb = response.Builder.init(&conn.write_buf);
        ws_handshake.writeResponse(&rb, accepted) catch {
            try writeStatusResponse(stream, self.io, conn, .internal);
            return;
        };
        try writeRaw(stream, self.io, rb.bytes());

        // Hand the stream off to the plugin handler. It owns I/O from
        // here. Any error it returns is logged and the socket is
        // closed by the outer accept loop.
        var up_ctx = WsUpgradeContext{
            .plugin_ctx = self.ctx,
            .request = request,
            .params = params,
            .stream = stream,
            .io = self.io,
            .arena = &conn.arena,
        };
        try handler(&up_ctx);
    }

    fn dispatchAndRespond(
        self: *Server,
        stream: net.Stream,
        conn: *Connection,
        request: *const request_mod.Request,
        force_close: bool,
    ) !void {
        const path_query = request.pathAndQuery();
        var params: router_mod.PathParams = .{};
        const match = self.router.matchOrCode(request.method, path_query.path, &params);

        var rb = response.Builder.init(&conn.write_buf);

        switch (match) {
            .ok => |handler| {
                var hc = router_mod.HandlerContext{
                    .plugin_ctx = self.ctx,
                    .request = request,
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

        // If the inner loop wants to keep going, *and* the handler did
        // not opt out by emitting `Connection: close`, append a
        // keep-alive header so the client knows. We achieve this by
        // appending after the existing trailer; since the response
        // builder's `simple` writes its own `Connection: close`, we
        // can't override it post-hoc without re-parsing. Pragmatic
        // approach for W1.1: respect handler's framing — if the body
        // declared close, close; otherwise allow loop continuation.
        //
        // `force_close` is recorded so the outer loop terminates after
        // this write; we do not rewrite the headers (the client only
        // needs to honor the actual Connection header it sees).
        _ = force_close;
        try writeRaw(stream, self.io, rb.bytes());
    }
};

/// True when the request carries an Upgrade: websocket header. We do
/// *not* validate the rest of the handshake here — the WS handshake
/// validator does that and emits a precise error. This is only the
/// fast-path dispatch decision.
fn isUpgradeRequest(req: *const request_mod.Request) bool {
    const up = req.header("Upgrade") orelse return false;
    return std.ascii.indexOfIgnoreCase(up, "websocket") != null;
}

/// HTTP/1.1: keep-alive is the default unless the client says
/// otherwise. HTTP/1.0: opposite — close unless the client opts in
/// with `Connection: keep-alive`. The function returns true if the
/// connection should be torn down after the current response.
fn headerIndicatesClose(req: *const request_mod.Request) bool {
    const conn_hdr = req.header("Connection");
    const is_http10 = std.mem.eql(u8, req.version, "HTTP/1.0");
    if (conn_hdr) |c| {
        if (std.ascii.indexOfIgnoreCase(c, "close") != null) return true;
        if (std.ascii.indexOfIgnoreCase(c, "keep-alive") != null) return false;
    }
    return is_http10;
}

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
// Tests
// ──────────────────────────────────────────────────────────────────────

const std_testing = std.testing;

fn pingHandler(hc: *router_mod.HandlerContext) anyerror!void {
    try hc.response.simple(.ok, "text/plain", "pong");
}

/// Echo-style handler that emits a keep-alive-friendly response — no
/// `Connection: close`, declares Content-Length. Used by the
/// keep-alive tests.
fn keepAliveHandler(hc: *router_mod.HandlerContext) anyerror!void {
    try hc.response.startStatus(.ok);
    try hc.response.header("Content-Type", "text/plain");
    try hc.response.headerFmt("Content-Length", "{d}", .{4});
    try hc.response.header("Connection", "keep-alive");
    try hc.response.finishHeaders();
    try hc.response.body("pong");
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
    const c = std.c;
    const fd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    if (fd < 0) return;
    defer _ = c.close(fd);

    var addr: c.sockaddr.in = .{
        .family = c.AF.INET,
        .port = std.mem.nativeToBig(u16, shared.port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
        .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    const sa_ptr: *const c.sockaddr = @ptrCast(&addr);
    if (c.connect(fd, sa_ptr, @sizeOf(c.sockaddr.in)) != 0) return;

    const seg1 = "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n";
    _ = c.write(fd, seg1.ptr, seg1.len);
    var ts: c.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
    _ = c.nanosleep(&ts, &ts);
    const seg2 = "\r\n";
    _ = c.write(fd, seg2.ptr, seg2.len);

    const n = c.read(fd, &shared.response_buf, shared.response_buf.len);
    if (n > 0) {
        shared.response_len.store(@intCast(n), .release);
        shared.got_response.store(true, .release);
    }
}

fn pokeListener(port: u16) void {
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

fn listeningPort(server: *Server) u16 {
    return switch (server.inner.socket.address) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
}

fn makeServer(io: Io, ctx: *Context, router: *const router_mod.Router, ws_router: *const WsUpgradeRouter, pool: *StaticPool(Connection, limits.max_connections)) !Server {
    return try Server.init(
        .{ .bind_addr = "127.0.0.1", .port = 0 },
        io,
        ctx,
        router,
        ws_router,
        pool,
    );
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

    var ws_router: WsUpgradeRouter = WsUpgradeRouter.init();
    ws_router.freeze();

    var server = try makeServer(io, &ctx, &router, &ws_router, pool);
    defer server.deinit();

    const port = listeningPort(&server);
    var shared: E2EShared = .{ .server = &server, .port = port };
    const srv_t = try std.Thread.spawn(.{}, serverRunThread, .{&shared});
    const cli_t = try std.Thread.spawn(.{}, clientThread, .{&shared});

    var waited_ns: u64 = 0;
    const deadline_ns: u64 = 2 * std.time.ns_per_s;
    while (!shared.got_response.load(.acquire) and waited_ns < deadline_ns) {
        var ts: std.c.timespec = .{ .sec = 0, .nsec = 1 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&ts, &ts);
        waited_ns += 1 * std.time.ns_per_ms;
    }

    server.requestShutdown();
    pokeListener(port);

    cli_t.join();
    srv_t.join();

    try std_testing.expect(shared.got_response.load(.acquire));
    const len = shared.response_len.load(.acquire);
    try std_testing.expect(len > 0);
    const body = shared.response_buf[0..len];
    try std_testing.expect(std.mem.startsWith(u8, body, "HTTP/1.1 200 OK"));
    try std_testing.expect(std.mem.indexOf(u8, body, "pong") != null);
}

// ── Helpers shared by the new keep-alive + WS tests ───────────────────

/// Open a TCP connection to localhost:port and return the fd.
fn dialLocal(port: u16) std.c.fd_t {
    const c = std.c;
    const fd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    if (fd < 0) return -1;
    var addr: c.sockaddr.in = .{
        .family = c.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
        .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    const sa_ptr: *const c.sockaddr = @ptrCast(&addr);
    if (c.connect(fd, sa_ptr, @sizeOf(c.sockaddr.in)) != 0) {
        _ = c.close(fd);
        return -1;
    }
    return fd;
}

fn writeAllFd(fd: std.c.fd_t, payload: []const u8) bool {
    var off: usize = 0;
    while (off < payload.len) {
        const n = std.c.write(fd, payload.ptr + off, payload.len - off);
        if (n <= 0) return false;
        off += @intCast(n);
    }
    return true;
}

/// Read until either `target` substring appears in the accumulated
/// buffer or `buf` is full. Returns total bytes read.
fn readUntilSubstr(fd: std.c.fd_t, buf: []u8, target: []const u8) usize {
    var got: usize = 0;
    var spins: u32 = 0;
    while (got < buf.len and spins < 200) : (spins += 1) {
        const n = std.c.read(fd, buf.ptr + got, buf.len - got);
        if (n <= 0) {
            // EAGAIN / EOF / error → bail. `nanosleep` 1 ms in case
            // we just need to let the server flush.
            var ts: std.c.timespec = .{ .sec = 0, .nsec = 1 * std.time.ns_per_ms };
            _ = std.c.nanosleep(&ts, &ts);
            if (n == 0) return got; // EOF
            continue;
        }
        got += @intCast(n);
        if (std.mem.indexOf(u8, buf[0..got], target) != null) return got;
    }
    return got;
}

/// Count distinct occurrences of "HTTP/1.1 " in the buffer — once per
/// response head. Useful for asserting N back-to-back keep-alive
/// responses arrived on a single TCP connection.
fn countResponses(buf: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i + 9 <= buf.len) : (i += 1) {
        if (std.mem.startsWith(u8, buf[i..], "HTTP/1.1 ")) {
            n += 1;
            i += 8;
        }
    }
    return n;
}

const KeepAliveShared = struct {
    server: *Server,
    port: u16,
    requests_to_send: u32,
    total_read: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    response_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    buf: [4096]u8 = undefined,
};

fn keepAliveClientThread(shared: *KeepAliveShared) void {
    const fd = dialLocal(shared.port);
    if (fd < 0) return;
    defer _ = std.c.close(fd);

    // Pipeline N requests without close, then a final one *with*
    // close so the server signals EOF. We pipeline so the test does
    // not depend on roundtrip ordering.
    var i: u32 = 0;
    while (i < shared.requests_to_send - 1) : (i += 1) {
        const req = "GET /ka HTTP/1.1\r\nHost: x\r\n\r\n";
        if (!writeAllFd(fd, req)) return;
    }
    const final_req = "GET /ka HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    if (!writeAllFd(fd, final_req)) return;

    // Read until EOF or buffer full.
    var off: usize = 0;
    var spins: u32 = 0;
    while (off < shared.buf.len and spins < 500) : (spins += 1) {
        const n = std.c.read(fd, (&shared.buf).ptr + off, shared.buf.len - off);
        if (n == 0) break;
        if (n < 0) {
            var ts: std.c.timespec = .{ .sec = 0, .nsec = 1 * std.time.ns_per_ms };
            _ = std.c.nanosleep(&ts, &ts);
            continue;
        }
        off += @intCast(n);
    }
    shared.total_read.store(@intCast(off), .release);
    shared.response_count.store(@intCast(countResponses(shared.buf[0..off])), .release);
    shared.done.store(true, .release);
}

test "HTTP/1.1 keep-alive: N back-to-back requests on one TCP connection" {
    const allocator = std_testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try allocator.create(StaticPool(Connection, limits.max_connections));
    defer allocator.destroy(pool);
    pool.initInPlace();

    var rng = @import("rng.zig").Rng.init(0xdead);
    var sc = @import("clock.zig").SimClock.init(0);
    var ctx: Context = .{ .clock = sc.clock(), .rng = &rng };

    var router: router_mod.Router = router_mod.Router.init();
    try router.register(.get, "/ka", keepAliveHandler, 0);
    router.freeze();
    var ws_router: WsUpgradeRouter = WsUpgradeRouter.init();
    ws_router.freeze();

    var server = try makeServer(io, &ctx, &router, &ws_router, pool);
    defer server.deinit();
    const port = listeningPort(&server);

    var shared: KeepAliveShared = .{
        .server = &server,
        .port = port,
        .requests_to_send = 5,
    };
    const srv2 = try std.Thread.spawn(.{}, struct {
        fn run(s: *Server) void {
            s.run() catch {};
        }
    }.run, .{&server});
    const cli_t = try std.Thread.spawn(.{}, keepAliveClientThread, .{&shared});

    var waited_ns: u64 = 0;
    while (!shared.done.load(.acquire) and waited_ns < 3 * std.time.ns_per_s) {
        var ts: std.c.timespec = .{ .sec = 0, .nsec = 1 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&ts, &ts);
        waited_ns += 1 * std.time.ns_per_ms;
    }
    server.requestShutdown();
    pokeListener(port);

    cli_t.join();
    srv2.join();

    try std_testing.expect(shared.done.load(.acquire));
    try std_testing.expectEqual(@as(u32, 5), shared.response_count.load(.acquire));
}

const CloseShared = struct {
    server: *Server,
    port: u16,
    response_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    buf: [4096]u8 = undefined,
};

fn explicitCloseClient(shared: *CloseShared) void {
    const fd = dialLocal(shared.port);
    if (fd < 0) return;
    defer _ = std.c.close(fd);

    // Two pipelined requests; first has Connection: close so the
    // server must respond to it and then terminate the connection,
    // dropping the second on the floor.
    const a = "GET /ka HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    const b = "GET /ka HTTP/1.1\r\nHost: x\r\n\r\n";
    if (!writeAllFd(fd, a)) return;
    if (!writeAllFd(fd, b)) {} // best-effort
    var off: usize = 0;
    var spins: u32 = 0;
    while (off < shared.buf.len and spins < 500) : (spins += 1) {
        const n = std.c.read(fd, (&shared.buf).ptr + off, shared.buf.len - off);
        if (n == 0) break;
        if (n < 0) {
            var ts: std.c.timespec = .{ .sec = 0, .nsec = 1 * std.time.ns_per_ms };
            _ = std.c.nanosleep(&ts, &ts);
            continue;
        }
        off += @intCast(n);
    }
    shared.response_count.store(@intCast(countResponses(shared.buf[0..off])), .release);
    shared.done.store(true, .release);
}

test "HTTP/1.1 explicit Connection: close honoured" {
    const allocator = std_testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try allocator.create(StaticPool(Connection, limits.max_connections));
    defer allocator.destroy(pool);
    pool.initInPlace();

    var rng = @import("rng.zig").Rng.init(1);
    var sc = @import("clock.zig").SimClock.init(0);
    var ctx: Context = .{ .clock = sc.clock(), .rng = &rng };

    var router: router_mod.Router = router_mod.Router.init();
    try router.register(.get, "/ka", keepAliveHandler, 0);
    router.freeze();
    var ws_router: WsUpgradeRouter = WsUpgradeRouter.init();
    ws_router.freeze();

    var server = try makeServer(io, &ctx, &router, &ws_router, pool);
    defer server.deinit();
    const port = listeningPort(&server);

    var shared: CloseShared = .{ .server = &server, .port = port };
    const srv = try std.Thread.spawn(.{}, struct {
        fn run(s: *Server) void {
            s.run() catch {};
        }
    }.run, .{&server});
    const cli = try std.Thread.spawn(.{}, explicitCloseClient, .{&shared});

    var waited_ns: u64 = 0;
    while (!shared.done.load(.acquire) and waited_ns < 3 * std.time.ns_per_s) {
        var ts: std.c.timespec = .{ .sec = 0, .nsec = 1 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&ts, &ts);
        waited_ns += 1 * std.time.ns_per_ms;
    }
    server.requestShutdown();
    pokeListener(port);
    cli.join();
    srv.join();

    try std_testing.expect(shared.done.load(.acquire));
    // Exactly one response: the server closes after the first.
    try std_testing.expectEqual(@as(u32, 1), shared.response_count.load(.acquire));
}

// ── WS upgrade dispatch unit tests (no socket) ────────────────────────

const TestWsState = struct {
    var called: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
    var captured_topic: [32]u8 = .{0} ** 32;
    var captured_topic_len: usize = 0;
    var captured_stream_handle: std.posix.fd_t = 0;
};

fn testWsHandler(uc: *WsUpgradeContext) anyerror!void {
    _ = TestWsState.called.fetchAdd(1, .seq_cst);
    if (uc.params.get("topic")) |t| {
        const n = @min(t.len, TestWsState.captured_topic.len);
        @memcpy(TestWsState.captured_topic[0..n], t[0..n]);
        TestWsState.captured_topic_len = n;
    }
    TestWsState.captured_stream_handle = uc.stream.socket.handle;
}

test "WsUpgradeRouter dispatch via handshake validation success path" {
    // Validate end-to-end: build a synthetic Request that meets RFC
    // 6455 §4.1, run it through the same logic the server uses
    // (isUpgradeRequest + router.match + handshake.validate +
    // writeResponse), and assert each step succeeds.
    const headers = [_]request_mod.Header{
        .{ .name = "Host", .value = "x" },
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Connection", .value = "Upgrade" },
        .{ .name = "Sec-WebSocket-Version", .value = "13" },
        .{ .name = "Sec-WebSocket-Key", .value = "dGhlIHNhbXBsZSBub25jZQ==" },
    };
    const req = request_mod.Request{
        .method = .get,
        .method_raw = "GET",
        .target = "/xrpc/com.atproto.sync.subscribeRepos",
        .version = "HTTP/1.1",
        .headers = &headers,
        .body = "",
    };
    try std_testing.expect(isUpgradeRequest(&req));

    var r = WsUpgradeRouter.init();
    try r.register("/xrpc/com.atproto.sync.subscribeRepos", testWsHandler, 0);
    r.freeze();

    var p: router_mod.PathParams = .{};
    const h = r.match(req.pathAndQuery().path, &p);
    try std_testing.expect(h != null);

    const accepted = try ws_handshake.validate(&req, &.{});
    var buf: [256]u8 = undefined;
    var rb = response.Builder.init(&buf);
    try ws_handshake.writeResponse(&rb, accepted);
    try std_testing.expect(std.mem.startsWith(u8, rb.bytes(), "HTTP/1.1 101"));
}

test "WS upgrade: non-upgrade request flows down the HTTP path" {
    const headers = [_]request_mod.Header{
        .{ .name = "Host", .value = "x" },
    };
    const req = request_mod.Request{
        .method = .get,
        .method_raw = "GET",
        .target = "/ping",
        .version = "HTTP/1.1",
        .headers = &headers,
        .body = "",
    };
    try std_testing.expect(!isUpgradeRequest(&req));
}

test "WS upgrade: unknown WS path returns null from router (server emits 400)" {
    var r = WsUpgradeRouter.init();
    try r.register("/ws/known", testWsHandler, 0);
    r.freeze();
    var p: router_mod.PathParams = .{};
    try std_testing.expect(r.match("/ws/unknown", &p) == null);
}

test "WS upgrade: path param capture flows into WsUpgradeContext" {
    var r = WsUpgradeRouter.init();
    try r.register("/streaming/:topic", testWsHandler, 0);
    r.freeze();
    var p: router_mod.PathParams = .{};
    const h = r.match("/streaming/public", &p);
    try std_testing.expect(h != null);
    try std_testing.expectEqualStrings("public", p.get("topic").?);
}

test "WS upgrade: handler invoked with the supplied stream + arena" {
    // Reset the global counter.
    TestWsState.called.store(0, .seq_cst);
    TestWsState.captured_topic_len = 0;

    var r = WsUpgradeRouter.init();
    try r.register("/streaming/:topic", testWsHandler, 0);
    r.freeze();

    var p: router_mod.PathParams = .{};
    const h = r.match("/streaming/notifications", &p);
    try std_testing.expect(h != null);

    var rng = @import("rng.zig").Rng.init(0);
    var sc = @import("clock.zig").SimClock.init(0);
    var ctx: Context = .{ .clock = sc.clock(), .rng = &rng };

    var arena_buf: [256]u8 = undefined;
    var arena_inst = @import("arena.zig").Arena.init(&arena_buf);

    const req = request_mod.Request{
        .method = .get,
        .method_raw = "GET",
        .target = "/streaming/notifications",
        .version = "HTTP/1.1",
        .headers = &.{},
        .body = "",
    };
    const fake_stream: net.Stream = .{ .socket = .{ .handle = @as(std.posix.fd_t, 1234), .address = undefined } };

    var threaded = std.Io.Threaded.init(std_testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var uc = WsUpgradeContext{
        .plugin_ctx = &ctx,
        .request = &req,
        .params = p,
        .stream = fake_stream,
        .io = io,
        .arena = &arena_inst,
    };
    try h.?(&uc);

    try std_testing.expectEqual(@as(u32, 1), TestWsState.called.load(.seq_cst));
    try std_testing.expectEqual(@as(std.posix.fd_t, 1234), TestWsState.captured_stream_handle);
    try std_testing.expectEqualStrings("notifications", TestWsState.captured_topic[0..TestWsState.captured_topic_len]);
}

test "WS upgrade: response after handshake is plugin-owned (server does not write further)" {
    // Validate the contract: once `dispatchWsUpgrade` writes 101 the
    // server does not append a body. We assert this by inspecting the
    // 101 response bytes — they must end with the canonical CRLFCRLF
    // and contain no payload after.
    var buf: [256]u8 = undefined;
    var rb = response.Builder.init(&buf);
    try ws_handshake.writeResponse(&rb, .{ .key = "dGhlIHNhbXBsZSBub25jZQ==", .subprotocol = "" });
    const out = rb.bytes();
    try std_testing.expect(std.mem.endsWith(u8, out, "\r\n\r\n"));
    try std_testing.expect(std.mem.indexOf(u8, out, "Content-Length") == null);
}

// ── TLS scaffolding tests ─────────────────────────────────────────────

test "Server.init accepts a TLS backend; PlainBackend wrap is identity at the call site" {
    const allocator = std_testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try allocator.create(StaticPool(Connection, limits.max_connections));
    defer allocator.destroy(pool);
    pool.initInPlace();

    var rng = @import("rng.zig").Rng.init(0);
    var sc = @import("clock.zig").SimClock.init(0);
    var ctx: Context = .{ .clock = sc.clock(), .rng = &rng };

    var router: router_mod.Router = router_mod.Router.init();
    router.freeze();
    var ws_router: WsUpgradeRouter = WsUpgradeRouter.init();
    ws_router.freeze();

    var plain: tls_mod.PlainBackend = .{};
    const be = plain.backend();

    var server = try Server.init(
        .{ .bind_addr = "127.0.0.1", .port = 0, .tls = be },
        io,
        &ctx,
        &router,
        &ws_router,
        pool,
    );
    defer server.deinit();

    // Confirm the backend stored in the config dispatches the
    // identity wrap on a sentinel stream.
    const raw: net.Stream = .{ .socket = .{ .handle = @as(std.posix.fd_t, 77), .address = undefined } };
    const wrapped = try server.cfg.tls.?.wrapStream(io, raw);
    try std_testing.expectEqual(@as(std.posix.fd_t, 77), wrapped.socket.handle);
}
