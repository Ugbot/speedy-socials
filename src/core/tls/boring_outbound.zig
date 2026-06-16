//! C5: Outbound TLS client backed by the system OpenSSL link, with
//! certificate **pinning**.
//!
//! The default outbound backend (`native_outbound`, `std.crypto.tls.Client`)
//! does not expose the peer's certificate chain after the handshake, so it
//! cannot enforce a pin. OpenSSL does: after `SSL_connect` succeeds we pull
//! the leaf with `SSL_get1_peer_certificate`, DER-encode it with `i2d_X509`,
//! and feed it to the `cert_admin` pin hook. A hook that returns false fails
//! the connection. This backend also speaks TLS 1.2 (the `ianic`/std client
//! path is 1.3-centric), useful for older federation peers.
//!
//! Selected at boot with `TLS_OUTBOUND=openssl`; otherwise `native_outbound`
//! stays the default.
//!
//! Conforms to the `core.http_client.TlsBackend` vtable (host/port/timeout —
//! DNS + TCP + handshake happen inside `connect`).
//!
//! Tiger Style:
//!   * One `SSL_CTX` built at `init`; the CA trust store is loaded once.
//!   * Per-connection state lives in a fixed-size slot pool (no hot-path
//!     allocation). The conn handle handed back through the vtable is the
//!     `*Slot` itself.
//!   * The TCP socket is created blocking (plain `socket()`/`connect()`),
//!     so `SSL_connect`/`SSL_read`/`SSL_write` block on the worker thread —
//!     matching the synchronous `http_client` send model.

const std = @import("std");
const openssl = @import("../crypto/openssl.zig");
const c = openssl.c;
const cert_admin = @import("cert_admin.zig");
const limits = @import("../limits.zig");
const http_client = @import("../http_client.zig");

const NetError = http_client.NetError;
const HttpTlsBackend = http_client.TlsBackend;

pub const max_slots: usize = limits.max_inflight_deliveries + 32;

pub const Slot = struct {
    in_use: bool = false,
    fd: c_int = -1,
    ssl: ?*c.SSL = null,
};

pub const BoringOutboundBackend = struct {
    ctx: *c.SSL_CTX,
    /// When true, OpenSSL verifies the peer chain against the system trust
    /// store *in addition to* any pin hook. Disabled in tests that drive a
    /// self-signed fixture; enabled for production federation.
    verify_peer: bool,
    slots: [max_slots]Slot = [_]Slot{.{}} ** max_slots,
    lock: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn init(verify_peer: bool) openssl.Error!BoringOutboundBackend {
        openssl.ensureLibraryInit();
        const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.CtxCreateFailed;
        errdefer c.SSL_CTX_free(ctx);
        if (verify_peer) {
            // Load the OS trust store and require a valid chain.
            if (c.SSL_CTX_set_default_verify_paths(ctx) != 1) return error.CtxCreateFailed;
            c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
        } else {
            c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
        }
        return .{ .ctx = ctx, .verify_peer = verify_peer };
    }

    pub fn deinit(self: *BoringOutboundBackend) void {
        for (&self.slots) |*s| {
            if (s.ssl) |ssl| {
                _ = c.SSL_shutdown(ssl);
                c.SSL_free(ssl);
            }
            if (s.fd >= 0) _ = std.c.close(s.fd);
            s.* = .{};
        }
        c.SSL_CTX_free(self.ctx);
    }

    pub fn backend(self: *BoringOutboundBackend) HttpTlsBackend {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub const vtable: HttpTlsBackend.Vtable = .{
        .connect = connectImpl,
        .write_all = writeAllImpl,
        .read_some = readSomeImpl,
        .close = closeImpl,
    };

    // ── Vtable impls ──────────────────────────────────────────────────

    fn connectImpl(ptr: *anyopaque, host: []const u8, port: u16, timeout_ms: u32) NetError!*anyopaque {
        const self: *BoringOutboundBackend = @ptrCast(@alignCast(ptr));
        const slot = self.allocSlot() orelse return error.ConnectFailed;
        // On any error after this point the slot may already hold an open
        // fd / SSL — tear them down fully (incl. close_notify) so the peer
        // doesn't block on a half-open session, then free the slot.
        errdefer self.teardownSlot(slot);

        const fd = dialBlocking(host, port, timeout_ms) catch |e| return e;
        slot.fd = fd;

        const ssl = c.SSL_new(self.ctx) orelse return error.TlsUnavailable;
        slot.ssl = ssl;
        if (c.SSL_set_fd(ssl, fd) != 1) return error.TlsHandshakeFailed;

        // SNI: tell the server which host we want (and let OpenSSL match
        // the cert against it during verification). host must be NUL-term.
        var host_z: [http_client.max_host_bytes + 1]u8 = undefined;
        if (host.len <= http_client.max_host_bytes) {
            @memcpy(host_z[0..host.len], host);
            host_z[host.len] = 0;
            _ = c.SSL_ctrl(
                ssl,
                c.SSL_CTRL_SET_TLSEXT_HOSTNAME,
                c.TLSEXT_NAMETYPE_host_name,
                @ptrCast(&host_z),
            );
            if (self.verify_peer) {
                // Also bind hostname verification (rejects valid-chain /
                // wrong-host certs).
                _ = c.SSL_set1_host(ssl, &host_z);
            }
        }

        if (c.SSL_connect(ssl) != 1) return error.TlsHandshakeFailed;

        // C5: certificate pinning. If a pin hook is registered, hand it the
        // DER-encoded leaf; a false return aborts the connection.
        if (cert_admin.currentPinHook()) |hook| {
            if (!checkPin(ssl, host, hook)) return error.TlsHandshakeFailed;
        }

        return @ptrCast(slot);
    }

    fn writeAllImpl(_: *anyopaque, conn: *anyopaque, bytes: []const u8) NetError!void {
        const slot: *Slot = @ptrCast(@alignCast(conn));
        const ssl = slot.ssl orelse return error.WriteFailed;
        var off: usize = 0;
        while (off < bytes.len) {
            const n = c.SSL_write(ssl, bytes.ptr + off, @intCast(bytes.len - off));
            if (n > 0) {
                off += @intCast(n);
                continue;
            }
            return error.WriteFailed;
        }
    }

    fn readSomeImpl(_: *anyopaque, conn: *anyopaque, dst: []u8) NetError!usize {
        const slot: *Slot = @ptrCast(@alignCast(conn));
        const ssl = slot.ssl orelse return error.ReadFailed;
        const n = c.SSL_read(ssl, dst.ptr, @intCast(dst.len));
        if (n > 0) return @intCast(n);
        if (n == 0) return 0;
        const err = c.SSL_get_error(ssl, n);
        if (err == c.SSL_ERROR_ZERO_RETURN) return 0;
        return error.ReadFailed;
    }

    fn closeImpl(ptr: *anyopaque, conn: *anyopaque) void {
        const self: *BoringOutboundBackend = @ptrCast(@alignCast(ptr));
        const slot: *Slot = @ptrCast(@alignCast(conn));
        self.teardownSlot(slot);
    }

    /// Close the SSL session (sending close_notify) and the fd, then free
    /// the slot. Safe to call on a partially-initialised slot.
    fn teardownSlot(self: *BoringOutboundBackend, slot: *Slot) void {
        if (slot.ssl) |ssl| {
            _ = c.SSL_shutdown(ssl);
            c.SSL_free(ssl);
            slot.ssl = null;
        }
        if (slot.fd >= 0) {
            _ = std.c.close(slot.fd);
            slot.fd = -1;
        }
        self.releaseSlot(slot);
    }

    // ── Internals ─────────────────────────────────────────────────────

    fn lockAcquire(self: *BoringOutboundBackend) void {
        while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
    }
    fn lockRelease(self: *BoringOutboundBackend) void {
        self.lock.store(false, .release);
    }

    fn allocSlot(self: *BoringOutboundBackend) ?*Slot {
        self.lockAcquire();
        defer self.lockRelease();
        for (&self.slots) |*s| {
            if (!s.in_use) {
                s.* = .{ .in_use = true };
                return s;
            }
        }
        return null;
    }

    fn releaseSlot(self: *BoringOutboundBackend, slot: *Slot) void {
        self.lockAcquire();
        defer self.lockRelease();
        slot.* = .{};
    }
};

/// DER-encode the peer leaf cert and run the pin hook. Factored out so the
/// pin decision is unit-testable. Returns true (allow) when there is a cert
/// and the hook accepts it; false otherwise.
fn checkPin(ssl: *c.SSL, host: []const u8, hook: cert_admin.PinHook) bool {
    const x509 = c.SSL_get1_peer_certificate(ssl) orelse return false;
    defer c.X509_free(x509);
    // DER-encode into a caller-owned buffer to avoid OpenSSL's allocating
    // form (whose free path is `OPENSSL_free`, an untranslatable macro).
    // Probe the length first, then encode in place: `i2d_X509(x, &p)` with
    // a non-null `*p` writes to `p` and advances it. A leaf cert is a few
    // hundred bytes to ~2 KiB; 16 KiB is generous headroom.
    var der_buf: [16 * 1024]u8 = undefined;
    const need = c.i2d_X509(x509, null);
    if (need <= 0 or @as(usize, @intCast(need)) > der_buf.len) return false;
    var p: [*c]u8 = &der_buf;
    const der_len = c.i2d_X509(x509, &p);
    if (der_len <= 0) return false;
    const der = der_buf[0..@intCast(der_len)];
    return hook(host, der);
}

/// Resolve host:port and open a *blocking* TCP socket via getaddrinfo +
/// socket + connect, trying each returned address until one connects.
/// Applies SO_RCVTIMEO/SNDTIMEO from `timeout_ms` so the handshake and
/// subsequent reads can't hang forever.
fn dialBlocking(host: []const u8, port: u16, timeout_ms: u32) NetError!c_int {
    var host_z: [http_client.max_host_bytes + 1]u8 = undefined;
    if (host.len > http_client.max_host_bytes) return error.InvalidUrl;
    @memcpy(host_z[0..host.len], host);
    host_z[host.len] = 0;

    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch return error.InvalidUrl;
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

fn applyTimeouts(fd: c_int, timeout_ms: u32) void {
    if (timeout_ms == 0) return;
    const tv = std.posix.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    const bytes = std.mem.asBytes(&tv);
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, bytes) catch {};
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, bytes) catch {};
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "boring_outbound: vtable conforms to http_client.TlsBackend.Vtable" {
    try testing.expectEqual(HttpTlsBackend.Vtable, @TypeOf(BoringOutboundBackend.vtable));
}

test "boring_outbound: init builds a CTX and backend() wires the vtable" {
    var be = try BoringOutboundBackend.init(false);
    defer be.deinit();
    const tb = be.backend();
    try testing.expectEqual(@as(*anyopaque, @ptrCast(&be)), tb.ctx);
    try testing.expect(tb.vtable == &BoringOutboundBackend.vtable);
}

test "boring_outbound: slot pool bounded; acquire/release round-trips" {
    var be = try BoringOutboundBackend.init(false);
    defer be.deinit();
    try testing.expectEqual(max_slots, be.slots.len);
    const s = be.allocSlot() orelse return error.TestUnexpectedResult;
    try testing.expect(s.in_use);
    be.releaseSlot(s);
    try testing.expect(!s.in_use);
}

const fixture_cert_path = "tests/fixtures/test.crt";
const fixture_key_path = "tests/fixtures/test.key";

fn readFixture(path: []const u8, alloc: std.mem.Allocator) ![]u8 {
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    return std.Io.Dir.cwd().readFileAlloc(threaded.io(), path, alloc, .limited(64 * 1024));
}

/// Spin a one-shot OpenSSL TLS server on 127.0.0.1:<ephemeral> and return
/// the bound port + listening fd. Used to exercise `connect` end-to-end.
const TestServer = struct {
    listen_fd: c_int,
    port: u16,
    server_ctx: *c.SSL_CTX,

    fn start(cert_pem: []const u8, key_pem: []const u8) !TestServer {
        openssl.ensureLibraryInit();
        var sctx = try openssl.SslCtx.initServer(cert_pem, key_pem);
        errdefer sctx.deinit();
        const lfd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
        if (lfd < 0) return error.SkipZigTest;
        var one: c_int = 1;
        _ = std.c.setsockopt(lfd, std.c.SOL.SOCKET, std.c.SO.REUSEADDR, &one, @sizeOf(c_int));
        var addr: std.c.sockaddr.in = std.mem.zeroes(std.c.sockaddr.in);
        addr.family = std.c.AF.INET;
        addr.port = std.mem.nativeToBig(u16, 0); // ephemeral
        addr.addr = std.mem.nativeToBig(u32, 0x7f000001); // 127.0.0.1
        if (std.c.bind(lfd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) != 0) {
            _ = std.c.close(lfd);
            return error.SkipZigTest;
        }
        if (std.c.listen(lfd, 1) != 0) {
            _ = std.c.close(lfd);
            return error.SkipZigTest;
        }
        var bound: std.c.sockaddr.in = std.mem.zeroes(std.c.sockaddr.in);
        var blen: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        if (std.c.getsockname(lfd, @ptrCast(&bound), &blen) != 0) {
            _ = std.c.close(lfd);
            return error.SkipZigTest;
        }
        const port = std.mem.bigToNative(u16, bound.port);
        return .{ .listen_fd = lfd, .port = port, .server_ctx = sctx.raw };
    }

    /// Accept one connection and complete the TLS handshake. Runs on a
    /// worker thread.
    fn acceptOnce(self: *TestServer) void {
        const cfd = std.c.accept(self.listen_fd, null, null);
        if (cfd < 0) return;
        defer _ = std.c.close(cfd);
        // CI backstop: never let a stuck handshake/read hang the join.
        applyTimeouts(cfd, 3000);
        const ssl = c.SSL_new(self.server_ctx) orelse return;
        defer c.SSL_free(ssl);
        _ = c.SSL_set_fd(ssl, cfd);
        _ = c.SSL_accept(ssl);
        // Hold the session open briefly so the client can finish its pin
        // check; a tiny read drains until the client closes.
        var buf: [16]u8 = undefined;
        _ = c.SSL_read(ssl, &buf, buf.len);
        _ = c.SSL_shutdown(ssl);
    }

    fn stop(self: *TestServer) void {
        _ = std.c.close(self.listen_fd);
        c.SSL_CTX_free(self.server_ctx);
    }
};

// Module-global capture for the pin-hook tests (the hook is a plain fn
// pointer, so it communicates via a global — guarded by running these
// tests serially within one binary).
var g_pin_seen_der_len: usize = 0;
var g_pin_decision: bool = true;

fn recordingPinHook(host: []const u8, der: []const u8) bool {
    _ = host;
    g_pin_seen_der_len = der.len;
    return g_pin_decision;
}

test "boring_outbound: end-to-end connect runs the pin hook with the real leaf DER" {
    const cert = readFixture(fixture_cert_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(cert);
    const key = readFixture(fixture_key_path, testing.allocator) catch return error.SkipZigTest;
    defer testing.allocator.free(key);

    var srv = TestServer.start(cert, key) catch |e| switch (e) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return e,
    };
    defer srv.stop();
    const th = try std.Thread.spawn(.{}, TestServer.acceptOnce, .{&srv});

    // verify_peer = false: the fixture is self-signed; we test the *pin*,
    // not the CA chain.
    var be = try BoringOutboundBackend.init(false);
    defer be.deinit();

    // Accepting pin → connect succeeds and the hook saw a non-empty DER.
    g_pin_seen_der_len = 0;
    g_pin_decision = true;
    cert_admin.setPinHook(recordingPinHook);
    defer cert_admin.clearPinHook();

    const conn = BoringOutboundBackend.vtable.connect(&be, "127.0.0.1", srv.port, 2000) catch |e| {
        th.join();
        return e;
    };
    BoringOutboundBackend.vtable.close(&be, conn);
    th.join();
    try testing.expect(g_pin_seen_der_len > 0);
}

test "boring_outbound: a rejecting pin hook fails the connection" {
    const cert = readFixture(fixture_cert_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(cert);
    const key = readFixture(fixture_key_path, testing.allocator) catch return error.SkipZigTest;
    defer testing.allocator.free(key);

    var srv = TestServer.start(cert, key) catch |e| switch (e) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return e,
    };
    defer srv.stop();
    const th = try std.Thread.spawn(.{}, TestServer.acceptOnce, .{&srv});

    var be = try BoringOutboundBackend.init(false);
    defer be.deinit();

    g_pin_decision = false; // reject
    cert_admin.setPinHook(recordingPinHook);
    defer cert_admin.clearPinHook();

    const r = BoringOutboundBackend.vtable.connect(&be, "127.0.0.1", srv.port, 2000);
    th.join();
    try testing.expectError(error.TlsHandshakeFailed, r);
}
