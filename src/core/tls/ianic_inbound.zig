//! Inbound TLS server backed by the pure-Zig `ianic/tls.zig` library.
//!
//! Replaces `boring_inbound` as the default inbound TLS backend. Pure
//! Zig — no system OpenSSL dependency for the server path. The OpenSSL
//! link stays in place narrowly to provide RSA-PKCS1v15-SHA256 signing
//! for ActivityPub federation, which ianic does not expose as a
//! standalone primitive.
//!
//! Tiger Style:
//!   * `CertKeyPair` is built once at boot from the in-memory PEM bytes
//!     loaded by `app/main.zig`.
//!   * Per-connection state (`Slot`) is heap-allocated once at boot in
//!     a fixed-size pool (`limits.tls_inbound_max_connections`). The
//!     pool capacity is intentionally smaller than `max_connections`
//!     because each slot carries ~33 KiB of TLS input/output buffers
//!     plus the Zig 0.16 `net.Stream.Reader/Writer` storage — sizing
//!     the pool to the plain-HTTP connection limit would burn tens of
//!     MiB of BSS that's never touched. Operators who need more
//!     concurrent HTTPS connections terminate TLS at an LB.
//!   * `findSlotByFd` is O(N) over the pool. With N ≤ 1024 the linear
//!     scan beats any allocator-backed map at our connection rate.
//!
//! Trade-offs vs the (now-removed-from-the-boot-path) OpenSSL backend:
//!   * TLS 1.3 only on server side (ianic's server is 1.3-only). 1.2
//!     clients fail handshake. Mastodon and Bluesky both support 1.3.
//!   * No multi-SNI cert table yet — a single `CertKeyPair` per backend
//!     instance. Same shape as boring_inbound today.
//!   * No ALPN advertisement in this initial wiring; can be enabled
//!     later via `Options.alpn_protocols`.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;
const tls = @import("tls");

const limits = @import("../limits.zig");
const core_tls = @import("../tls.zig");
const sni_mod = @import("sni.zig");
const TlsBackend = core_tls.TlsBackend;

/// Maximum number of per-SNI certificates a single backend can host. The
/// default cert (used when SNI is absent / unmatched) is separate, so
/// this bounds only the named virtual hosts.
pub const max_sni_certs: usize = 16;

/// One SNI-keyed certificate. The host string is stored inline so the
/// table needs no allocator on the lookup path.
pub const SniCert = struct {
    host_buf: [128]u8 = undefined,
    host_len: u8 = 0,
    auth: tls.config.CertKeyPair = undefined,

    pub fn host(self: *const SniCert) []const u8 {
        return self.host_buf[0..self.host_len];
    }
};

pub const Error = error{
    InitFailed,
    HandshakeFailed,
    KeyMismatch,
    CertLoadFailed,
    KeyLoadFailed,
    SlotsExhausted,
    SlotMissing,
    TlsReadFailed,
    TlsWriteFailed,
};

/// One in-flight TLS session. Carries the buffers + stream wrappers +
/// the ianic `Connection` value. The slot must live at a stable
/// address for the lifetime of the connection because `tls.Connection`
/// holds interior pointers into the `r`/`w` fields here.
pub const Slot = struct {
    fd: std.posix.fd_t = -1,
    in_use: bool = false,
    io: Io = undefined,
    raw_stream: net.Stream = undefined,
    /// ianic's input record-decryption buffer. Sized exactly to
    /// `tls.input_buffer_len` so any single TLS record fits.
    reader_buf: [tls.input_buffer_len]u8 = undefined,
    writer_buf: [tls.output_buffer_len]u8 = undefined,
    r: net.Stream.Reader = undefined,
    w: net.Stream.Writer = undefined,
    conn: tls.Connection = undefined,
};

pub const max_slots: usize = limits.tls_inbound_max_connections;

pub const IanicInboundBackend = struct {
    /// Cert + key, owned for the lifetime of the backend.
    auth: tls.config.CertKeyPair,
    /// Allocator that backed `auth` so we can free its `Bundle` on
    /// shutdown. The backend itself uses no allocator on the hot path.
    auth_allocator: std.mem.Allocator,
    /// PRNG source for handshake nonces. ianic asks for a `std.Random`;
    /// we hand it one backed by the host `Io` so deterministic-replay
    /// builds can swap it for a TimeSim-style PRNG later.
    rng_source: std.Random.IoSource,
    /// Cached `Io` used to read `Io.Clock.real.now()` during handshakes.
    /// Captured at backend `init` time.
    io: Io,

    /// Pool of per-connection slots. Heap-allocated at boot via the
    /// composition root's allocator. Holding by pointer so slot
    /// addresses are stable across moves of the backend struct itself.
    slots: []Slot,

    /// C2: per-SNI certificate table. Populated at boot from
    /// `TLS_SNI_CERTS`; empty by default (single-cert behaviour). Lookup
    /// is a bounded linear scan keyed on the ClientHello `server_name`.
    sni_certs: [max_sni_certs]SniCert = undefined,
    sni_count: u8 = 0,

    /// Coarse spinlock guarding the slot table. Contention here is
    /// rare (twice per connection: alloc + release). The TLS read /
    /// write hot path does its own per-slot work without taking this.
    lock: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Load a cert + key from PEM bytes and build the server `CertKeyPair`.
    /// Allocates only during boot; the returned backend owns its
    /// `Bundle` until `deinit`.
    pub fn init(
        allocator: std.mem.Allocator,
        io: Io,
        cert_pem: []const u8,
        key_pem: []const u8,
    ) !IanicInboundBackend {
        const auth = tls.config.CertKeyPair.fromSlice(allocator, io, cert_pem, key_pem) catch |err| switch (err) {
            error.OutOfMemory => return error.InitFailed,
            else => {
                // The most common failure here is "the supplied key
                // doesn't match the cert" or "the cert PEM is unparseable."
                // Both are operator misconfiguration; surface a single
                // catch-all that exercises the same code path as the
                // OpenSSL backend.
                std.log.warn("IanicInboundBackend.init: CertKeyPair.fromSlice failed with {s}", .{@errorName(err)});
                return error.CertLoadFailed;
            },
        };
        const slots = try allocator.alloc(Slot, max_slots);
        for (slots) |*s| s.* = .{};
        return .{
            .auth = auth,
            .auth_allocator = allocator,
            .rng_source = .{ .io = io },
            .io = io,
            .slots = slots,
        };
    }

    /// C4: hot-reload the cert + key without disrupting in-flight
    /// connections. We build a NEW `CertKeyPair`, then swap it onto
    /// the backend under the lock. In-flight TLS sessions keep using
    /// the previous cipher (the cert is only used at handshake time);
    /// new accepts pick up the fresh one.
    pub fn reloadCertKey(
        self: *IanicInboundBackend,
        cert_pem: []const u8,
        key_pem: []const u8,
    ) !void {
        const new_auth = tls.config.CertKeyPair.fromSlice(self.auth_allocator, self.io, cert_pem, key_pem) catch |err| switch (err) {
            error.OutOfMemory => return error.InitFailed,
            else => return error.CertLoadFailed,
        };
        self.lockAcquire();
        defer self.lockRelease();
        var old = self.auth;
        self.auth = new_auth;
        old.deinit(self.auth_allocator);
    }

    /// C2: register a certificate for a specific SNI host. Built once at
    /// boot from `TLS_SNI_CERTS`. Returns `error.Full` past the table
    /// cap. The host string is truncated to `SniCert.host_buf.len`.
    pub fn addSniCert(
        self: *IanicInboundBackend,
        host: []const u8,
        cert_pem: []const u8,
        key_pem: []const u8,
    ) !void {
        if (self.sni_count >= max_sni_certs) return error.Full;
        const auth = tls.config.CertKeyPair.fromSlice(self.auth_allocator, self.io, cert_pem, key_pem) catch |err| switch (err) {
            error.OutOfMemory => return error.InitFailed,
            else => return error.CertLoadFailed,
        };
        var slot: SniCert = .{ .auth = auth };
        const n = @min(host.len, slot.host_buf.len);
        @memcpy(slot.host_buf[0..n], host[0..n]);
        slot.host_len = @intCast(n);
        self.sni_certs[self.sni_count] = slot;
        self.sni_count += 1;
    }

    /// Pick the certificate for a handshake. When the ClientHello carried
    /// a `server_name` that matches a registered SNI cert, use it;
    /// otherwise fall back to the default cert. Case-insensitive match
    /// (DNS names are case-insensitive).
    fn selectAuth(self: *IanicInboundBackend, server_name: ?[]const u8) *tls.config.CertKeyPair {
        if (server_name) |sn| {
            var i: u8 = 0;
            while (i < self.sni_count) : (i += 1) {
                if (std.ascii.eqlIgnoreCase(self.sni_certs[i].host(), sn)) {
                    return &self.sni_certs[i].auth;
                }
            }
        }
        return &self.auth;
    }

    pub fn deinit(self: *IanicInboundBackend) void {
        // Tear down any in-flight TLS sessions. In a clean shutdown
        // this should be a no-op — the server stops accepting before
        // we get here and existing connections complete via the
        // close-conn vtable. Defensive on the crash path.
        for (self.slots) |*s| {
            if (s.in_use) {
                // Best-effort close; ignore TLS-shutdown errors.
                _ = s.conn.close() catch {};
                s.* = .{};
            }
        }
        self.auth_allocator.free(self.slots);
        self.auth.deinit(self.auth_allocator);
        var i: u8 = 0;
        while (i < self.sni_count) : (i += 1) {
            self.sni_certs[i].auth.deinit(self.auth_allocator);
        }
    }

    pub fn backend(self: *IanicInboundBackend) TlsBackend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub const vtable: TlsBackend.VTable = .{
        .wrap_stream = wrapStreamImpl,
        .read_some = readSomeImpl,
        .write_all = writeAllImpl,
        .close_conn = closeConnImpl,
    };

    // ── Vtable impls ──────────────────────────────────────────────

    fn wrapStreamImpl(ptr: *anyopaque, io: Io, raw: net.Stream) anyerror!net.Stream {
        const self: *IanicInboundBackend = @ptrCast(@alignCast(ptr));
        const fd = raw.socket.handle;
        if (fd < 0) return error.HandshakeFailed;
        const slot = self.allocSlot(fd) orelse return error.SlotsExhausted;
        errdefer self.releaseSlotForFd(fd);

        slot.io = io;
        slot.raw_stream = raw;

        // C2: when SNI certs are configured, peek the (plaintext)
        // ClientHello to pick the matching cert before the handshake.
        // The peeked bytes stay in the socket buffer for `tls.server` to
        // re-read. Skip the syscall entirely in the common single-cert
        // case so we don't pay for a peek nobody uses.
        var auth = &self.auth;
        if (self.sni_count > 0) {
            var peek_buf: [sni_mod.max_peek]u8 = undefined;
            const server_name = sni_mod.peekServerName(fd, &peek_buf);
            auth = self.selectAuth(server_name);
        }

        slot.r = raw.reader(io, &slot.reader_buf);
        slot.w = raw.writer(io, &slot.writer_buf);

        const now = Io.Clock.real.now(io);
        slot.conn = tls.server(&slot.r.interface, &slot.w.interface, .{
            .auth = auth,
            .now = now,
            .rng = self.rng_source.interface(),
        }) catch return error.HandshakeFailed;

        // Return the raw stream unchanged. Subsequent reads / writes
        // come back through the data-plane vtable below, which routes
        // through `slot.conn`.
        return raw;
    }

    fn readSomeImpl(ptr: *anyopaque, fd: std.posix.fd_t, buf: []u8) anyerror!usize {
        const self: *IanicInboundBackend = @ptrCast(@alignCast(ptr));
        const slot = self.findSlotByFd(fd) orelse return error.SlotMissing;
        // `Connection.read` returns 0 on clean close-notify; matches
        // the `read_some` contract.
        const n = slot.conn.read(buf) catch |err| switch (err) {
            error.EndOfStream => return 0,
            else => return error.TlsReadFailed,
        };
        return n;
    }

    fn writeAllImpl(ptr: *anyopaque, fd: std.posix.fd_t, buf: []const u8) anyerror!void {
        const self: *IanicInboundBackend = @ptrCast(@alignCast(ptr));
        const slot = self.findSlotByFd(fd) orelse return error.SlotMissing;
        slot.conn.writeAll(buf) catch return error.TlsWriteFailed;
    }

    fn closeConnImpl(ptr: *anyopaque, fd: std.posix.fd_t) void {
        const self: *IanicInboundBackend = @ptrCast(@alignCast(ptr));
        self.releaseSlotForFd(fd);
    }

    // ── Internals ─────────────────────────────────────────────────

    fn lockAcquire(self: *IanicInboundBackend) void {
        while (self.lock.swap(true, .acquire)) {
            std.atomic.spinLoopHint();
        }
    }

    fn lockRelease(self: *IanicInboundBackend) void {
        self.lock.store(false, .release);
    }

    fn allocSlot(self: *IanicInboundBackend, fd: std.posix.fd_t) ?*Slot {
        self.lockAcquire();
        defer self.lockRelease();
        for (self.slots) |*s| {
            if (!s.in_use) {
                s.* = .{ .fd = fd, .in_use = true };
                return s;
            }
        }
        return null;
    }

    fn findSlotByFd(self: *IanicInboundBackend, fd: std.posix.fd_t) ?*Slot {
        self.lockAcquire();
        defer self.lockRelease();
        for (self.slots) |*s| {
            if (s.in_use and s.fd == fd) return s;
        }
        return null;
    }

    fn releaseSlotForFd(self: *IanicInboundBackend, fd: std.posix.fd_t) void {
        self.lockAcquire();
        defer self.lockRelease();
        for (self.slots) |*s| {
            if (s.in_use and s.fd == fd) {
                // Best-effort close-notify. If the peer is already
                // gone (RST), `close` errors; we can't usefully
                // recover, so swallow the error.
                _ = s.conn.close() catch {};
                s.* = .{};
                return;
            }
        }
    }
};

// ── Tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

const fixture_cert_path = "tests/fixtures/test.crt";
const fixture_key_path = "tests/fixtures/test.key";
const fixture_other_key_path = "tests/fixtures/test_other.key";

fn readFixture(path: []const u8, alloc: std.mem.Allocator) ![]u8 {
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    return std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(64 * 1024));
}

test "ianic_inbound: init succeeds with a valid cert + key fixture" {
    const cert = readFixture(fixture_cert_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(cert);
    const key = try readFixture(fixture_key_path, testing.allocator);
    defer testing.allocator.free(key);

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var be = try IanicInboundBackend.init(testing.allocator, threaded.io(), cert, key);
    defer be.deinit();
    _ = be.backend();
    try testing.expectEqual(@as(usize, max_slots), be.slots.len);
}

test "ianic_inbound: init accepts mismatched cert + key (validation deferred to handshake)" {
    // Unlike the OpenSSL backend, ianic does not cross-check the cert
    // and key at load time — it parses each PEM independently and the
    // mismatch only surfaces during the TLS handshake when the server
    // attempts to sign with the wrong key. This test pins that
    // behaviour so a future change that *does* validate at init also
    // updates this expectation explicitly.
    const cert = readFixture(fixture_cert_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(cert);
    const other_key = readFixture(fixture_other_key_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(other_key);

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var be = try IanicInboundBackend.init(testing.allocator, threaded.io(), cert, other_key);
    defer be.deinit();
}

test "ianic_inbound: init rejects garbage cert + key" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    try testing.expectError(error.CertLoadFailed, IanicInboundBackend.init(testing.allocator, threaded.io(), "nope", "nope"));
}

test "ianic_inbound: vtable shape matches core.tls.TlsBackend.VTable" {
    try testing.expectEqual(TlsBackend.VTable, @TypeOf(IanicInboundBackend.vtable));
    try testing.expect(IanicInboundBackend.vtable.read_some != null);
    try testing.expect(IanicInboundBackend.vtable.write_all != null);
    try testing.expect(IanicInboundBackend.vtable.close_conn != null);
}

test "ianic_inbound: SNI selection picks the named cert, falls back to default" {
    const cert = readFixture(fixture_cert_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(cert);
    const key = try readFixture(fixture_key_path, testing.allocator);
    defer testing.allocator.free(key);

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var be = try IanicInboundBackend.init(testing.allocator, threaded.io(), cert, key);
    defer be.deinit();

    // No SNI certs yet: everything resolves to the default.
    try testing.expect(be.selectAuth("anything") == &be.auth);
    try testing.expect(be.selectAuth(null) == &be.auth);

    try be.addSniCert("host-b.example.com", cert, key);
    try be.addSniCert("host-c.example.com", cert, key);
    try testing.expectEqual(@as(u8, 2), be.sni_count);

    // Exact + case-insensitive match returns the SNI slot, not default.
    try testing.expect(be.selectAuth("host-b.example.com") == &be.sni_certs[0].auth);
    try testing.expect(be.selectAuth("HOST-B.EXAMPLE.COM") == &be.sni_certs[0].auth);
    try testing.expect(be.selectAuth("host-c.example.com") == &be.sni_certs[1].auth);
    // Unknown host / no SNI → default.
    try testing.expect(be.selectAuth("unknown.example.com") == &be.auth);
    try testing.expect(be.selectAuth(null) == &be.auth);
}

test "ianic_inbound: SNI table enforces its capacity bound" {
    const cert = readFixture(fixture_cert_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(cert);
    const key = try readFixture(fixture_key_path, testing.allocator);
    defer testing.allocator.free(key);

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var be = try IanicInboundBackend.init(testing.allocator, threaded.io(), cert, key);
    defer be.deinit();

    var host_buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < max_sni_certs) : (i += 1) {
        const h = std.fmt.bufPrint(&host_buf, "h{d}.example.com", .{i}) catch unreachable;
        try be.addSniCert(h, cert, key);
    }
    try testing.expectError(error.Full, be.addSniCert("overflow.example.com", cert, key));
}

test "ianic_inbound: read/write on an unknown fd surface SlotMissing" {
    const cert = readFixture(fixture_cert_path, testing.allocator) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer testing.allocator.free(cert);
    const key = try readFixture(fixture_key_path, testing.allocator);
    defer testing.allocator.free(key);

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var be = try IanicInboundBackend.init(testing.allocator, threaded.io(), cert, key);
    defer be.deinit();
    var rxbuf: [4]u8 = undefined;
    try testing.expectError(error.SlotMissing, IanicInboundBackend.vtable.read_some.?(&be, 999_999, &rxbuf));
    try testing.expectError(error.SlotMissing, IanicInboundBackend.vtable.write_all.?(&be, 999_999, "x"));
}
