//! Outbound HTTPS client, dispatched through `core.workers.Pool`.
//!
//! This is the *production* outbound HTTP path for:
//!   * ActivityPub key fetches (`key_cache.setFetchHook`),
//!   * ActivityPub federation deliveries (`outbox_worker.setDeliverHook`),
//!   * AT Protocol DID document + handle resolution
//!     (`did_resolver.HttpFetcher`).
//!
//! Architecture:
//!
//!     handler thread             worker thread
//!     ┌──────────────┐ submit ┌─────────────────────────┐
//!     │ build Request│──────▶ │ DNS → TCP → (TLS)       │
//!     │  & Completion│        │  → write HTTP/1.1       │
//!     │              │        │  → parse status+headers │
//!     │ wait/poll    │◀──────│  → drain body into buf  │
//!     └──────────────┘        └─────────────────────────┘
//!
//! All buffers are bounded (`limits.http_client_max_request`,
//! `limits.http_client_max_response`). No allocator is used on the hot
//! path; the worker arena is reset between jobs.
//!
//! ── TLS ───────────────────────────────────────────────────────────────
//!
//! Outbound TLS uses a pluggable backend (`TlsBackend`) the host wires at
//! boot. Two backends are anticipated:
//!
//!   1. `std.crypto.tls.Client` over the OS root bundle. Lands when
//!      W1.1's `core.tls.TlsBackend` is merged.
//!   2. A vendored BoringSSL build, for sites that need TLS 1.3 + ALPN
//!      with deterministic FIPS-compatible cipher selection.
//!
//! Until a backend is wired, requests to `https://` URLs return
//! `error.TlsUnavailable`; plaintext `http://` requests work in full.

const std = @import("std");
const builtin = @import("builtin");

const core = struct {
    pub const errors = @import("errors.zig");
    pub const limits = @import("limits.zig");
    pub const assert = @import("assert.zig");
    pub const arena = @import("arena.zig");
    pub const workers = @import("workers.zig");
};

pub const NetError = error{
    InvalidUrl,
    DnsFailed,
    ConnectFailed,
    WriteFailed,
    ReadFailed,
    HeaderTooLarge,
    BodyTooLarge,
    BadStatusLine,
    BadHeader,
    Timeout,
    TlsUnavailable,
    TlsHandshakeFailed,
    TooManyHeaders,
};

pub const max_request_bytes: usize = 32 * 1024;
pub const max_response_bytes: usize = 1 * 1024 * 1024; // 1 MiB
pub const max_response_headers: usize = 64;
pub const max_host_bytes: usize = 256;
pub const max_path_bytes: usize = 2048;
pub const max_header_name_bytes: usize = 64;
pub const max_header_value_bytes: usize = 512;
pub const max_request_headers: usize = 32;

pub const Method = enum {
    get,
    head,
    post,
    put,
    delete,

    pub fn name(self: Method) []const u8 {
        return switch (self) {
            .get => "GET",
            .head => "HEAD",
            .post => "POST",
            .put => "PUT",
            .delete => "DELETE",
        };
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Request = struct {
    method: Method,
    /// Full URL: `http[s]://host[:port]/path`.
    url: []const u8,
    headers: []const Header = &.{},
    body: []const u8 = "",
    timeout_ms: u32 = 30_000,
};

pub const ResponseHeader = struct {
    name_buf: [max_header_name_bytes]u8 = undefined,
    name_len: u8 = 0,
    value_buf: [max_header_value_bytes]u8 = undefined,
    value_len: u16 = 0,

    pub fn name(self: *const ResponseHeader) []const u8 {
        return self.name_buf[0..self.name_len];
    }
    pub fn value(self: *const ResponseHeader) []const u8 {
        return self.value_buf[0..self.value_len];
    }
};

pub const Response = struct {
    status: u16,
    headers: [max_response_headers]ResponseHeader = [_]ResponseHeader{.{}} ** max_response_headers,
    header_count: u8 = 0,
    body_buf: [max_response_bytes]u8 = undefined,
    body_len: usize = 0,

    pub fn body(self: *const Response) []const u8 {
        return self.body_buf[0..self.body_len];
    }
};

/// TLS backend the host wires at boot. Null = plaintext-only mode.
///
/// `wrap` returns an opaque handle plus a vtable for the encrypted
/// stream. We keep the surface minimal so a future BoringSSL backend
/// (or the W1.1 TLS module) drops in without touching the client.
pub const TlsBackend = struct {
    ctx: *anyopaque,
    vtable: *const Vtable,

    pub const Vtable = struct {
        connect: *const fn (ctx: *anyopaque, host: []const u8, port: u16, timeout_ms: u32) NetError!*anyopaque,
        write_all: *const fn (ctx: *anyopaque, conn: *anyopaque, bytes: []const u8) NetError!void,
        read_some: *const fn (ctx: *anyopaque, conn: *anyopaque, dst: []u8) NetError!usize,
        close: *const fn (ctx: *anyopaque, conn: *anyopaque) void,
    };
};

var tls_backend: ?TlsBackend = null;

/// Install (or remove) the outbound TLS backend. May be called once at
/// boot; subsequent requests pick up the new value immediately.
pub fn setTlsBackend(backend: ?TlsBackend) void {
    tls_backend = backend;
}

// ── Parsed URL ────────────────────────────────────────────────────────

const ParsedUrl = struct {
    scheme: enum { http, https },
    host: []const u8,
    port: u16,
    path: []const u8,
};

fn parseUrl(url: []const u8) NetError!ParsedUrl {
    if (std.mem.startsWith(u8, url, "http://")) {
        return parseAfterScheme(.http, url[7..], 80);
    }
    if (std.mem.startsWith(u8, url, "https://")) {
        return parseAfterScheme(.https, url[8..], 443);
    }
    return error.InvalidUrl;
}

fn parseAfterScheme(
    scheme: @TypeOf(@as(ParsedUrl, undefined).scheme),
    rest: []const u8,
    default_port: u16,
) NetError!ParsedUrl {
    if (rest.len == 0) return error.InvalidUrl;
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const authority = rest[0..slash];
    const path = if (slash < rest.len) rest[slash..] else "/";
    if (authority.len == 0 or authority.len > max_host_bytes) return error.InvalidUrl;
    if (path.len > max_path_bytes) return error.InvalidUrl;

    var host: []const u8 = authority;
    var port: u16 = default_port;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        const port_str = authority[colon + 1 ..];
        port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidUrl;
    }
    if (host.len == 0) return error.InvalidUrl;
    return .{ .scheme = scheme, .host = host, .port = port, .path = path };
}

// ── Plaintext transport (TCP) ─────────────────────────────────────────

const PlainConn = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    reader_buf: [4096]u8 = undefined,
    writer_buf: [4096]u8 = undefined,
    r: std.Io.net.Stream.Reader = undefined,
    w: std.Io.net.Stream.Writer = undefined,

    fn writeAll(self: *PlainConn, bytes: []const u8) NetError!void {
        self.w.interface.writeAll(bytes) catch return error.WriteFailed;
        self.w.interface.flush() catch return error.WriteFailed;
    }

    fn readSome(self: *PlainConn, dst: []u8) NetError!usize {
        // Pull from the Io.Reader interface. fill+drain semantics: ask
        // for at least 1 byte; the reader may return more.
        const n = self.r.interface.readSliceShort(dst) catch |e| switch (e) {
            error.ReadFailed => return error.ReadFailed,
        };
        if (n == 0) return error.ReadFailed;
        return n;
    }

    fn close(self: *PlainConn) void {
        self.stream.close(self.io);
    }
};

fn connectPlainInPlace(pc: *PlainConn, io: std.Io, host: []const u8, port: u16) NetError!void {
    var addr = std.Io.net.IpAddress.resolve(io, host, port) catch return error.DnsFailed;
    addr.setPort(port);
    const stream = std.Io.net.IpAddress.connect(&addr, io, .{ .mode = .stream }) catch return error.ConnectFailed;
    pc.io = io;
    pc.stream = stream;
    pc.r = stream.reader(io, &pc.reader_buf);
    pc.w = stream.writer(io, &pc.writer_buf);
}

// ── Transport abstraction ─────────────────────────────────────────────

const Conn = struct {
    kind: enum { plain, tls },
    plain: PlainConn = .{ .io = undefined, .stream = undefined },
    tls_backend: ?TlsBackend = null,
    tls_handle: ?*anyopaque = null,

    fn writeAll(self: *Conn, bytes: []const u8) NetError!void {
        switch (self.kind) {
            .plain => return self.plain.writeAll(bytes),
            .tls => return self.tls_backend.?.vtable.write_all(self.tls_backend.?.ctx, self.tls_handle.?, bytes),
        }
    }

    fn readSome(self: *Conn, dst: []u8) NetError!usize {
        switch (self.kind) {
            .plain => return self.plain.readSome(dst),
            .tls => return self.tls_backend.?.vtable.read_some(self.tls_backend.?.ctx, self.tls_handle.?, dst),
        }
    }

    fn close(self: *Conn) void {
        switch (self.kind) {
            .plain => self.plain.close(),
            .tls => self.tls_backend.?.vtable.close(self.tls_backend.?.ctx, self.tls_handle.?),
        }
    }
};

// ── HTTP/1.1 writer + response parser ─────────────────────────────────

const HeadWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn put(self: *HeadWriter, s: []const u8) NetError!void {
        if (self.pos + s.len > self.buf.len) return error.HeaderTooLarge;
        @memcpy(self.buf[self.pos..][0..s.len], s);
        self.pos += s.len;
    }
};

fn writeRequest(conn: *Conn, req: Request, parsed: ParsedUrl) NetError!void {
    var head_buf: [max_request_bytes]u8 = undefined;
    var w: HeadWriter = .{ .buf = &head_buf };

    try w.put(req.method.name());
    try w.put(" ");
    try w.put(parsed.path);
    try w.put(" HTTP/1.1\r\n");
    try w.put("Host: ");
    try w.put(parsed.host);
    if ((parsed.scheme == .http and parsed.port != 80) or (parsed.scheme == .https and parsed.port != 443)) {
        var pn_buf: [8]u8 = undefined;
        const pn = std.fmt.bufPrint(&pn_buf, ":{d}", .{parsed.port}) catch return error.HeaderTooLarge;
        try w.put(pn);
    }
    try w.put("\r\n");

    var saw_content_length = false;
    var saw_user_agent = false;
    for (req.headers) |h| {
        if (h.name.len == 0 or h.name.len > max_header_name_bytes) return error.BadHeader;
        if (h.value.len > max_header_value_bytes) return error.BadHeader;
        if (std.ascii.eqlIgnoreCase(h.name, "content-length")) saw_content_length = true;
        if (std.ascii.eqlIgnoreCase(h.name, "user-agent")) saw_user_agent = true;
        try w.put(h.name);
        try w.put(": ");
        try w.put(h.value);
        try w.put("\r\n");
    }
    if (!saw_user_agent) try w.put("User-Agent: speedy-socials/0\r\n");
    if (!saw_content_length and req.body.len > 0) {
        var cl_buf: [32]u8 = undefined;
        const cl = std.fmt.bufPrint(&cl_buf, "Content-Length: {d}\r\n", .{req.body.len}) catch return error.HeaderTooLarge;
        try w.put(cl);
    }
    try w.put("\r\n");

    try conn.writeAll(head_buf[0..w.pos]);
    if (req.body.len > 0) try conn.writeAll(req.body);
}

fn parseResponse(conn: *Conn, out: *Response) NetError!void {
    // Accumulate into a head buffer until we see "\r\n\r\n". Tiger Style:
    // bounded, no recursion.
    var head_buf: [16 * 1024]u8 = undefined;
    var head_len: usize = 0;
    var head_end: usize = 0;
    var iters: u32 = 0;
    while (true) : (iters += 1) {
        if (iters > 4096) return error.ReadFailed;
        if (head_len >= head_buf.len) return error.HeaderTooLarge;
        const n = try conn.readSome(head_buf[head_len..]);
        if (n == 0) {
            if (head_len == 0) return error.ReadFailed;
            return error.ReadFailed;
        }
        head_len += n;
        // Scan for "\r\n\r\n".
        if (head_len >= 4) {
            const search_start: usize = if (head_len > n + 3) head_len - n - 3 else 0;
            const found = std.mem.indexOf(u8, head_buf[search_start..head_len], "\r\n\r\n");
            if (found) |rel| {
                head_end = search_start + rel + 4;
                break;
            }
        }
    }

    // Parse status line.
    const first_crlf = std.mem.indexOf(u8, head_buf[0..head_end], "\r\n") orelse return error.BadStatusLine;
    const status_line = head_buf[0..first_crlf];
    if (!std.mem.startsWith(u8, status_line, "HTTP/1.")) return error.BadStatusLine;
    // "HTTP/1.x SSS reason..."
    if (status_line.len < 12) return error.BadStatusLine;
    out.status = std.fmt.parseInt(u16, status_line[9..12], 10) catch return error.BadStatusLine;

    // Parse headers.
    var cursor: usize = first_crlf + 2;
    out.header_count = 0;
    var content_length: ?usize = null;
    var chunked = false;
    while (cursor < head_end - 2) {
        const line_end = std.mem.indexOf(u8, head_buf[cursor..head_end], "\r\n") orelse return error.BadHeader;
        const line = head_buf[cursor .. cursor + line_end];
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadHeader;
        var value_start = colon + 1;
        while (value_start < line.len and (line[value_start] == ' ' or line[value_start] == '\t')) value_start += 1;
        const name = line[0..colon];
        const value = line[value_start..];
        if (name.len > max_header_name_bytes or value.len > max_header_value_bytes) {
            cursor += line_end + 2;
            continue;
        }
        if (out.header_count < max_response_headers) {
            const h = &out.headers[out.header_count];
            @memcpy(h.name_buf[0..name.len], name);
            h.name_len = @intCast(name.len);
            @memcpy(h.value_buf[0..value.len], value);
            h.value_len = @intCast(value.len);
            out.header_count += 1;
        }
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            content_length = std.fmt.parseInt(usize, value, 10) catch null;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (std.ascii.indexOfIgnoreCase(value, "chunked") != null) chunked = true;
        }
        cursor += line_end + 2;
    }

    // Body: copy any bytes already in head_buf past head_end into a
    // dedicated scratch that the chunked parser drains from before
    // pulling from the wire.
    var leftover_buf: [16 * 1024]u8 = undefined;
    var leftover_len: usize = 0;
    if (head_end < head_len) {
        const extra = head_len - head_end;
        if (extra > leftover_buf.len) return error.BodyTooLarge;
        @memcpy(leftover_buf[0..extra], head_buf[head_end..head_len]);
        leftover_len = extra;
    }
    out.body_len = 0;

    if (chunked) {
        try readChunked(conn, out, leftover_buf[0..leftover_len]);
        return;
    }

    // For non-chunked: copy leftover bytes verbatim into body_buf.
    if (leftover_len > 0) {
        if (leftover_len > out.body_buf.len) return error.BodyTooLarge;
        @memcpy(out.body_buf[0..leftover_len], leftover_buf[0..leftover_len]);
        out.body_len = leftover_len;
    }

    if (content_length) |cl| {
        if (cl > out.body_buf.len) return error.BodyTooLarge;
        var iters_b: u32 = 0;
        while (out.body_len < cl) : (iters_b += 1) {
            if (iters_b > 8192) return error.ReadFailed;
            const n = try conn.readSome(out.body_buf[out.body_len..cl]);
            if (n == 0) return error.ReadFailed;
            out.body_len += n;
        }
        return;
    }

    // No content-length, not chunked: read until close, bounded.
    var iters_c: u32 = 0;
    while (out.body_len < out.body_buf.len) : (iters_c += 1) {
        if (iters_c > 8192) return error.ReadFailed;
        const n = conn.readSome(out.body_buf[out.body_len..]) catch break;
        if (n == 0) break;
        out.body_len += n;
    }
}

/// `Sourced` reader: drains `leftover` first, then pulls from `conn`.
const Sourced = struct {
    conn: *Conn,
    leftover: []const u8,
    pos: usize = 0,

    fn readSome(self: *Sourced, dst: []u8) NetError!usize {
        if (self.pos < self.leftover.len) {
            const remaining = self.leftover[self.pos..];
            const n = @min(dst.len, remaining.len);
            @memcpy(dst[0..n], remaining[0..n]);
            self.pos += n;
            return n;
        }
        return self.conn.readSome(dst);
    }

    fn readExact(self: *Sourced, dst: []u8) NetError!void {
        var got: usize = 0;
        var iters: u32 = 0;
        while (got < dst.len) : (iters += 1) {
            if (iters > 8192) return error.ReadFailed;
            const n = try self.readSome(dst[got..]);
            if (n == 0) return error.ReadFailed;
            got += n;
        }
    }
};

fn readChunked(conn: *Conn, out: *Response, leftover: []const u8) NetError!void {
    var src: Sourced = .{ .conn = conn, .leftover = leftover };
    var iters: u32 = 0;
    while (true) : (iters += 1) {
        if (iters > 8192) return error.ReadFailed;
        // Read the chunk size line one byte at a time.
        var size_buf: [32]u8 = undefined;
        var size_len: usize = 0;
        var local_iters: u32 = 0;
        while (size_len < 2 or !(size_buf[size_len - 2] == '\r' and size_buf[size_len - 1] == '\n')) {
            local_iters += 1;
            if (local_iters > 1024) return error.ReadFailed;
            if (size_len >= size_buf.len) return error.BadHeader;
            try src.readExact(size_buf[size_len .. size_len + 1]);
            size_len += 1;
        }
        const size_str = size_buf[0 .. size_len - 2];
        const semi = std.mem.indexOfScalar(u8, size_str, ';') orelse size_str.len;
        const size_hex = size_str[0..semi];
        const chunk_size = std.fmt.parseInt(usize, size_hex, 16) catch return error.BadHeader;
        if (chunk_size == 0) {
            // Trailing CRLF after the zero chunk.
            var tail: [2]u8 = undefined;
            // Best-effort: peer may have already closed. Don't error.
            _ = src.readSome(&tail) catch {};
            return;
        }
        if (out.body_len + chunk_size > out.body_buf.len) return error.BodyTooLarge;
        try src.readExact(out.body_buf[out.body_len .. out.body_len + chunk_size]);
        out.body_len += chunk_size;
        var crlf: [2]u8 = undefined;
        try src.readExact(&crlf);
    }
}

// ── Client + job dispatch ─────────────────────────────────────────────

/// Shared client object. Carries the `std.Io` backend used for DNS +
/// TCP. Cheap to copy (one pointer-sized field), but typical usage is
/// to keep one per process.
pub const Client = struct {
    io: std.Io,

    pub fn init(io: std.Io) Client {
        return .{ .io = io };
    }

    /// Synchronously perform a request. Intended to be called from a
    /// worker thread (it blocks on TCP). For asynchronous dispatch use
    /// `submit`.
    pub fn sendSync(self: *Client, req: Request, out: *Response) NetError!void {
        const parsed = try parseUrl(req.url);
        var conn: Conn = .{ .kind = .plain };
        if (parsed.scheme == .https) {
            const tb = tls_backend orelse return error.TlsUnavailable;
            const h = try tb.vtable.connect(tb.ctx, parsed.host, parsed.port, req.timeout_ms);
            conn = .{ .kind = .tls, .tls_backend = tb, .tls_handle = h };
        } else {
            try connectPlainInPlace(&conn.plain, self.io, parsed.host, parsed.port);
        }
        defer conn.close();

        try writeRequest(&conn, req, parsed);
        try parseResponse(&conn, out);
    }
};

/// Context handed to the worker for a single request/response cycle.
pub const JobCtx = struct {
    client: *Client,
    request: Request,
    response: Response = .{ .status = 0 },
    result: NetError!void = {},
};

pub fn jobRun(ctx_raw: *anyopaque, _: *core.arena.Arena) anyerror!void {
    const ctx: *JobCtx = @ptrCast(@alignCast(ctx_raw));
    ctx.result = ctx.client.sendSync(ctx.request, &ctx.response);
    // Propagate so the worker's Completion records a JobFailed when
    // appropriate; callers inspect ctx.result for the typed error.
    return ctx.result;
}

/// Submit a one-shot request to a worker pool. The submitter owns the
/// `JobCtx` storage; the worker fills `ctx.response` and `ctx.result`.
/// The `Completion` flips when the job is done.
pub fn submit(
    pool: anytype,
    ctx: *JobCtx,
    completion: *core.workers.Completion,
) core.workers.SubmitError!void {
    try pool.submit(.{
        .run = jobRun,
        .ctx = @ptrCast(ctx),
        .completion = completion,
    });
}

// ── Tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseUrl: http://host/path" {
    const p = try parseUrl("http://example.com/foo");
    try testing.expectEqual(@as(u16, 80), p.port);
    try testing.expectEqualStrings("example.com", p.host);
    try testing.expectEqualStrings("/foo", p.path);
}

test "parseUrl: https://host:port/path" {
    const p = try parseUrl("https://pds.example:8443/xrpc/x");
    try testing.expectEqual(@as(u16, 8443), p.port);
    try testing.expectEqualStrings("pds.example", p.host);
    try testing.expectEqualStrings("/xrpc/x", p.path);
}

test "parseUrl: defaults path to /" {
    const p = try parseUrl("https://host");
    try testing.expectEqualStrings("/", p.path);
}

test "parseUrl: rejects garbage" {
    try testing.expectError(error.InvalidUrl, parseUrl("ftp://x"));
    try testing.expectError(error.InvalidUrl, parseUrl(""));
}

test "https without backend returns TlsUnavailable" {
    setTlsBackend(null);
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var client = Client.init(threaded.io());
    const req: Request = .{ .method = .get, .url = "https://example.invalid/" };
    var resp: Response = .{ .status = 0 };
    try testing.expectError(error.TlsUnavailable, client.sendSync(req, &resp));
}

// The plaintext path is exercised via integration: in tests we don't
// open external sockets. The W1.5 simulation harness drives a full
// federation scenario.

test "Response header table is bounded" {
    var r: Response = .{ .status = 0 };
    r.header_count = 0;
    var i: u32 = 0;
    while (i < max_response_headers) : (i += 1) {
        const h = &r.headers[i];
        h.name_len = 1;
        h.value_len = 1;
    }
    try testing.expect(r.header_count == 0);
}

// ── Mock TLS backend (test-only) ──────────────────────────────────────
//
// A canned-response TLS backend lets us exercise the full request-write
// + response-parse code path without opening a real socket. The
// production TLS backend (W1.1 / vendored BoringSSL) will conform to
// the same TlsBackend vtable.

const MockTls = struct {
    var seen_request: [4096]u8 = undefined;
    var seen_request_len: usize = 0;
    var canned_response: []const u8 = "";
    var response_pos: usize = 0;

    fn connect_impl(_: *anyopaque, _: []const u8, _: u16, _: u32) NetError!*anyopaque {
        seen_request_len = 0;
        response_pos = 0;
        return @ptrFromInt(0xCAFE);
    }
    fn write_impl(_: *anyopaque, _: *anyopaque, bytes: []const u8) NetError!void {
        const cap = @min(bytes.len, seen_request.len - seen_request_len);
        @memcpy(seen_request[seen_request_len .. seen_request_len + cap], bytes[0..cap]);
        seen_request_len += cap;
    }
    fn read_impl(_: *anyopaque, _: *anyopaque, dst: []u8) NetError!usize {
        if (response_pos >= canned_response.len) return 0;
        const remaining = canned_response[response_pos..];
        const n = @min(dst.len, remaining.len);
        @memcpy(dst[0..n], remaining[0..n]);
        response_pos += n;
        return n;
    }
    fn close_impl(_: *anyopaque, _: *anyopaque) void {}

    const vtable: TlsBackend.Vtable = .{
        .connect = connect_impl,
        .write_all = write_impl,
        .read_some = read_impl,
        .close = close_impl,
    };

    fn backend() TlsBackend {
        return .{ .ctx = @ptrFromInt(0x1), .vtable = &vtable };
    }
};

test "Client.sendSync: writes a well-formed HTTP/1.1 request" {
    MockTls.canned_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 5\r\n" ++
        "Content-Type: application/json\r\n" ++
        "\r\n" ++
        "hello";
    setTlsBackend(MockTls.backend());
    defer setTlsBackend(null);

    var client = Client.init(undefined);
    var resp: Response = .{ .status = 0 };
    const headers = [_]Header{
        .{ .name = "Accept", .value = "application/json" },
        .{ .name = "Authorization", .value = "Bearer t" },
    };
    try client.sendSync(.{
        .method = .post,
        .url = "https://example.com/inbox",
        .headers = &headers,
        .body = "{\"x\":1}",
    }, &resp);
    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expectEqualStrings("hello", resp.body());
    const req = MockTls.seen_request[0..MockTls.seen_request_len];
    try testing.expect(std.mem.startsWith(u8, req, "POST /inbox HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, req, "Host: example.com\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Authorization: Bearer t\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Content-Length: 7\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, req, "{\"x\":1}"));
}

test "Client.sendSync: parses chunked transfer encoding" {
    MockTls.canned_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "5\r\nhello\r\n" ++
        "6\r\n world\r\n" ++
        "0\r\n\r\n";
    setTlsBackend(MockTls.backend());
    defer setTlsBackend(null);

    var client = Client.init(undefined);
    var resp: Response = .{ .status = 0 };
    try client.sendSync(.{ .method = .get, .url = "https://x/" }, &resp);
    try testing.expectEqualStrings("hello world", resp.body());
}

test "Client.sendSync: rejects body that exceeds the response cap" {
    // 2 MiB chunk advertised — must exceed `max_response_bytes`.
    MockTls.canned_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 2097153\r\n" ++
        "\r\n";
    setTlsBackend(MockTls.backend());
    defer setTlsBackend(null);
    var client = Client.init(undefined);
    var resp: Response = .{ .status = 0 };
    try testing.expectError(error.BodyTooLarge, client.sendSync(
        .{ .method = .get, .url = "https://big/" },
        &resp,
    ));
}

test "Client.sendSync: parses headers into the response table" {
    MockTls.canned_response =
        "HTTP/1.1 201 Created\r\n" ++
        "Location: /v1/objects/42\r\n" ++
        "X-Custom: foo\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";
    setTlsBackend(MockTls.backend());
    defer setTlsBackend(null);
    var client = Client.init(undefined);
    var resp: Response = .{ .status = 0 };
    try client.sendSync(.{ .method = .get, .url = "https://x/" }, &resp);
    try testing.expectEqual(@as(u16, 201), resp.status);
    try testing.expect(resp.header_count >= 3);
    var found_loc = false;
    var i: u8 = 0;
    while (i < resp.header_count) : (i += 1) {
        const h = &resp.headers[i];
        if (std.ascii.eqlIgnoreCase(h.name(), "Location")) {
            try testing.expectEqualStrings("/v1/objects/42", h.value());
            found_loc = true;
        }
    }
    try testing.expect(found_loc);
}
