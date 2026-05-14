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
        var read_scratch: [4096]u8 = undefined;
        var reader = net.Stream.Reader.init(stream, self.io, &read_scratch);
        var hdrs_scratch: parser.HeaderArray = undefined;
        while (true) {
            if (conn.read_len >= conn.read_buf.len) return error.HeaderTooLarge;
            const dest = conn.read_buf[conn.read_len..];
            const n = reader.interface.readSliceShort(dest) catch return error.UnexpectedEof;
            if (n == 0) return error.UnexpectedEof;
            conn.read_len += n;
            _ = parser.parse(conn.read_buf[0..conn.read_len], &hdrs_scratch) catch |err| switch (err) {
                error.UnexpectedEof => continue,
                else => return err,
            };
            return;
        }
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
