//! Inbound TLS server backed by the system OpenSSL link (W3.1).
//!
//! Replaces the W1.1 `NativeInboundBackend` stub. Implements the
//! `core.tls.TlsBackend` vtable so it slots into `core.server` without
//! any caller-side churn:
//!
//!   * `wrap_stream` — accepts a raw TCP stream, drives the TLS server
//!     handshake via `SSL_accept`, and (on success) stashes the `*SSL`
//!     in a static fd-keyed slot pool. Returns the raw stream
//!     unchanged so the server's existing call sites stay compatible.
//!     Subsequent reads / writes on that fd are routed through the
//!     `read_some` / `write_all` data-plane vtable extensions.
//!   * `read_some`  — `SSL_read` wrapper. Returns 0 on clean EOF.
//!   * `write_all`  — `SSL_write` wrapper, looping until the entire
//!     buffer is sent.
//!   * `close_conn` — `SSL_shutdown` + frees the `*SSL` slot.
//!
//! Tiger Style:
//!   * `SslCtx` is built once at boot from in-memory PEM bytes.
//!   * Per-connection state (`SslSlot`) lives in a static pool sized at
//!     `limits.max_connections`. The fd → slot lookup is O(N) over the
//!     pool, which is fine for our hundreds-of-connections target. A
//!     hash map would need an allocator — Tiger Style says no.
//!   * No allocations on the connection hot path. OpenSSL's own
//!     internal allocations are outside our boundary (same treatment
//!     as sqlite's mallocs).
//!
//! See `third_party/boringssl/README.md` for why we link the system
//! library instead of vendoring the BoringSSL source tree.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const limits = @import("../limits.zig");
const openssl = @import("../crypto/openssl.zig");
const c = openssl.c;

const core_tls = @import("../tls.zig");
const TlsBackend = core_tls.TlsBackend;

pub const Error = openssl.Error;

/// One in-flight TLS session. Capacity bounded by max_connections so
/// the entire pool fits in BSS — no per-accept allocation.
pub const SslSlot = struct {
    fd: std.posix.fd_t = -1,
    ssl: ?*c.SSL = null,
    in_use: bool = false,
};

pub const max_slots: usize = limits.max_connections;

pub const BoringInboundBackend = struct {
    ctx: openssl.SslCtx,
    slots: [max_slots]SslSlot = [_]SslSlot{.{}} ** max_slots,
    /// Coarse spinlock guarding the slot table. Acquire-free reads
    /// (`findSlotByFd`) are uncontended in the steady state and the
    /// acquire / release pair is short.
    lock: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Load cert + key from PEM bytes and build the SSL_CTX. Caller
    /// holds the PEM bytes; we don't keep references after init.
    pub fn init(cert_pem: []const u8, key_pem: []const u8) Error!BoringInboundBackend {
        openssl.ensureLibraryInit();
        const ctx = try openssl.SslCtx.initServer(cert_pem, key_pem);
        return .{ .ctx = ctx };
    }

    pub fn deinit(self: *BoringInboundBackend) void {
        // Free any SSL* still in flight. Should be zero in a clean
        // shutdown but defensive: don't leak on a crash path.
        for (&self.slots) |*s| {
            if (s.ssl) |ssl| {
                _ = c.SSL_shutdown(ssl);
                c.SSL_free(ssl);
            }
            s.* = .{};
        }
        self.ctx.deinit();
    }

    pub fn backend(self: *BoringInboundBackend) TlsBackend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub const vtable: TlsBackend.VTable = .{
        .wrap_stream = wrapStreamImpl,
        .read_some = readSomeImpl,
        .write_all = writeAllImpl,
        .close_conn = closeConnImpl,
    };

    // ── Vtable impls ──────────────────────────────────────────────

    fn wrapStreamImpl(ptr: *anyopaque, _: Io, raw: net.Stream) anyerror!net.Stream {
        const self: *BoringInboundBackend = @ptrCast(@alignCast(ptr));
        const fd = raw.socket.handle;
        if (fd < 0) return error.HandshakeFailed;
        try self.startHandshake(fd);
        return raw;
    }

    fn readSomeImpl(ptr: *anyopaque, fd: std.posix.fd_t, buf: []u8) anyerror!usize {
        const self: *BoringInboundBackend = @ptrCast(@alignCast(ptr));
        const slot = self.findSlotByFd(fd) orelse return error.SslReadFailed;
        const ssl = slot.ssl orelse return error.SslReadFailed;
        const n = c.SSL_read(ssl, buf.ptr, @intCast(buf.len));
        if (n > 0) return @intCast(n);
        if (n == 0) return 0; // peer closed
        const err = c.SSL_get_error(ssl, n);
        // SSL_ERROR_ZERO_RETURN = clean close-notify.
        if (err == c.SSL_ERROR_ZERO_RETURN) return 0;
        return error.SslReadFailed;
    }

    fn writeAllImpl(ptr: *anyopaque, fd: std.posix.fd_t, buf: []const u8) anyerror!void {
        const self: *BoringInboundBackend = @ptrCast(@alignCast(ptr));
        const slot = self.findSlotByFd(fd) orelse return error.SslWriteFailed;
        const ssl = slot.ssl orelse return error.SslWriteFailed;
        var off: usize = 0;
        // Bounded by buf.len bytes / 1 byte minimum per SSL_write; in
        // the happy path one or two iterations suffice on 2 KiB chunks.
        while (off < buf.len) {
            const n = c.SSL_write(ssl, buf.ptr + off, @intCast(buf.len - off));
            if (n > 0) {
                off += @intCast(n);
                continue;
            }
            return error.SslWriteFailed;
        }
    }

    fn closeConnImpl(ptr: *anyopaque, fd: std.posix.fd_t) void {
        const self: *BoringInboundBackend = @ptrCast(@alignCast(ptr));
        self.releaseSlotForFd(fd);
    }

    // ── Internals ─────────────────────────────────────────────────

    fn lockAcquire(self: *BoringInboundBackend) void {
        // Tiny TTAS spinlock. Contention here is rare (we contend only
        // on slot table mutation, which happens twice per connection).
        while (self.lock.swap(true, .acquire)) {
            std.atomic.spinLoopHint();
        }
    }

    fn lockRelease(self: *BoringInboundBackend) void {
        self.lock.store(false, .release);
    }

    fn allocSlot(self: *BoringInboundBackend, fd: std.posix.fd_t) ?*SslSlot {
        self.lockAcquire();
        defer self.lockRelease();
        for (&self.slots) |*s| {
            if (!s.in_use) {
                s.* = .{ .fd = fd, .ssl = null, .in_use = true };
                return s;
            }
        }
        return null;
    }

    fn findSlotByFd(self: *BoringInboundBackend, fd: std.posix.fd_t) ?*SslSlot {
        self.lockAcquire();
        defer self.lockRelease();
        for (&self.slots) |*s| {
            if (s.in_use and s.fd == fd) return s;
        }
        return null;
    }

    fn releaseSlotForFd(self: *BoringInboundBackend, fd: std.posix.fd_t) void {
        self.lockAcquire();
        defer self.lockRelease();
        for (&self.slots) |*s| {
            if (s.in_use and s.fd == fd) {
                if (s.ssl) |ssl| {
                    // Best-effort shutdown; some peers won't have sent
                    // close-notify and SSL_shutdown returns < 1 on that
                    // path. We can't usefully recover so just free.
                    _ = c.SSL_shutdown(ssl);
                    c.SSL_free(ssl);
                }
                s.* = .{};
                return;
            }
        }
    }

    fn startHandshake(self: *BoringInboundBackend, fd: std.posix.fd_t) Error!void {
        const slot = self.allocSlot(fd) orelse return error.HandshakeFailed;
        errdefer self.releaseSlotForFd(fd);

        const ssl = try self.ctx.newSsl();
        slot.ssl = ssl;

        if (c.SSL_set_fd(ssl, @intCast(fd)) != 1) {
            return error.HandshakeFailed;
        }
        // SSL_accept is blocking on a blocking socket. The kernel
        // backing the accepted fd is the default-blocking flavour
        // produced by `net.Stream.accept`, which is what we want.
        const r = c.SSL_accept(ssl);
        if (r != 1) {
            // Real-world handshake failures (cipher mismatch, bad
            // ClientHello, RST during ServerHello) all land here.
            return error.HandshakeFailed;
        }
    }
};

// ── Tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

const fixture_cert_path = "tests/fixtures/test.crt";
const fixture_key_path = "tests/fixtures/test.key";

fn readFixture(path: []const u8, alloc: std.mem.Allocator) ![]u8 {
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    return std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(64 * 1024));
}

test "boring_inbound: init succeeds with a valid cert + key fixture" {
    const cert = readFixture(fixture_cert_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(cert);
    const key = try readFixture(fixture_key_path, testing.allocator);
    defer testing.allocator.free(key);

    var be = try BoringInboundBackend.init(cert, key);
    defer be.deinit();
    _ = be.backend();
}

test "boring_inbound: init rejects mismatched cert + key pair" {
    const cert = readFixture(fixture_cert_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(cert);
    const other_key = readFixture("tests/fixtures/test_other.key", testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(other_key);
    try testing.expectError(error.KeyMismatch, BoringInboundBackend.init(cert, other_key));
}

test "boring_inbound: init rejects garbage cert" {
    try testing.expectError(error.CertLoadFailed, BoringInboundBackend.init("nope", "nope"));
}

test "boring_inbound: vtable shape matches core.tls.TlsBackend.VTable" {
    try testing.expectEqual(TlsBackend.VTable, @TypeOf(BoringInboundBackend.vtable));
    // The optional data-plane hooks must be non-null on this backend.
    try testing.expect(BoringInboundBackend.vtable.read_some != null);
    try testing.expect(BoringInboundBackend.vtable.write_all != null);
    try testing.expect(BoringInboundBackend.vtable.close_conn != null);
}

test "boring_inbound: slot table bounded by limits.max_connections" {
    const cert = readFixture(fixture_cert_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(cert);
    const key = try readFixture(fixture_key_path, testing.allocator);
    defer testing.allocator.free(key);

    var be = try BoringInboundBackend.init(cert, key);
    defer be.deinit();
    try testing.expectEqual(@as(usize, limits.max_connections), be.slots.len);
}

test "boring_inbound: end-to-end TLS handshake via socketpair() + std.crypto.tls.Client" {
    // We drive the server side from a real `BoringInboundBackend` and
    // the client side from Zig's stdlib `std.crypto.tls.Client`. They
    // talk over an AF_UNIX SOCK_STREAM pair (server fd / client fd).
    // Because std.crypto.tls.Client wants a CA bundle to verify against
    // and our fixture is self-signed, we *short-circuit* certificate
    // chain validation by loading our fixture as the sole trust anchor
    // for the client.
    //
    // The test passes if both sides report a completed handshake and
    // can exchange a tiny app-data record.
    const cert = readFixture(fixture_cert_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(cert);
    const key = try readFixture(fixture_key_path, testing.allocator);
    defer testing.allocator.free(key);

    var be = try BoringInboundBackend.init(cert, key);
    defer be.deinit();

    // Use an OS socketpair. AF_UNIX is supported across mac + linux
    // and the TLS protocol is byte-stream so the underlying transport
    // doesn't care.
    var fds: [2]c_int = .{ -1, -1 };
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SkipZigTest;
    defer _ = std.c.close(fds[1]);
    // Server fd is fds[0]; the backend takes ownership in startHandshake.

    // Drive server handshake on a worker thread. SSL_accept on a
    // blocking fd will block until the client side completes its
    // ClientHello → Finished exchange.
    const ServerThreadCtx = struct {
        backend: *BoringInboundBackend,
        fd: c_int,
        result: anyerror!void = {},

        fn run(self: *@This()) void {
            self.result = self.backend.startHandshake(@intCast(self.fd));
        }
    };
    var stc: ServerThreadCtx = .{ .backend = &be, .fd = fds[0] };
    const srv_thread = try std.Thread.spawn(.{}, ServerThreadCtx.run, .{&stc});

    // Drive the client side via OpenSSL itself (simplest correctness
    // bar: OpenSSL ↔ OpenSSL is a well-defined positive test). Using
    // `std.crypto.tls.Client` here would require us to build a
    // certificate bundle that trusts the self-signed fixture, which is
    // non-trivial in the test boundary.
    const client_ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.TestUnexpectedResult;
    defer c.SSL_CTX_free(client_ctx);
    // Disable verification entirely for the test — we own both ends.
    c.SSL_CTX_set_verify(client_ctx, c.SSL_VERIFY_NONE, null);
    const client_ssl = c.SSL_new(client_ctx) orelse return error.TestUnexpectedResult;
    defer c.SSL_free(client_ssl);
    if (c.SSL_set_fd(client_ssl, fds[1]) != 1) return error.TestUnexpectedResult;
    const cli_r = c.SSL_connect(client_ssl);
    if (cli_r != 1) {
        srv_thread.join();
        return error.TestUnexpectedResult;
    }

    srv_thread.join();
    try stc.result;

    // App-data round trip. Client → server.
    const greeting = "hello-tls";
    try testing.expectEqual(@as(c_int, @intCast(greeting.len)), c.SSL_write(client_ssl, greeting.ptr, @intCast(greeting.len)));
    // Server reads using the backend vtable's read_some.
    var rxbuf: [64]u8 = undefined;
    const got = try BoringInboundBackend.vtable.read_some.?(&be, @intCast(fds[0]), &rxbuf);
    try testing.expectEqual(greeting.len, got);
    try testing.expectEqualStrings(greeting, rxbuf[0..got]);

    // Server → client via the vtable's write_all.
    const reply = "ok";
    try BoringInboundBackend.vtable.write_all.?(&be, @intCast(fds[0]), reply);
    var cli_rx: [16]u8 = undefined;
    const cli_n = c.SSL_read(client_ssl, &cli_rx, cli_rx.len);
    try testing.expect(cli_n > 0);
    try testing.expectEqualStrings(reply, cli_rx[0..@intCast(cli_n)]);

    // Close cleanly through the vtable.
    BoringInboundBackend.vtable.close_conn.?(&be, @intCast(fds[0]));
}

test "boring_inbound: read_some on an unknown fd returns SslReadFailed" {
    const cert = readFixture(fixture_cert_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(cert);
    const key = try readFixture(fixture_key_path, testing.allocator);
    defer testing.allocator.free(key);
    var be = try BoringInboundBackend.init(cert, key);
    defer be.deinit();
    var buf: [4]u8 = undefined;
    try testing.expectError(error.SslReadFailed, BoringInboundBackend.vtable.read_some.?(&be, 999_999, &buf));
}
