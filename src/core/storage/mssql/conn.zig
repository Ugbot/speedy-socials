//! D2: TDS connection — the socket-bearing wire layer that frames TDS
//! packets over a blocking TCP socket and drives the login handshake plus
//! request/response exchanges. The byte-level packet construction and
//! token-stream parsing live in `tds.zig` (pure, unit-tested); this module
//! is the thin I/O wrapper that those pure functions feed.
//!
//! TLS: when the connection config requests `tls=require`, Pre-Login
//! advertises ENCRYPT_ON and the TDS-wrapped TLS handshake runs (see
//! `tls_transport.zig`) before LOGIN7; thereafter LOGIN7 and every request/
//! response travels inside the TLS session. `tls=off` keeps the plaintext
//! path (advertise ENCRYPT_NOT_SUP). The wire layer (`writeAll`/`readExact`)
//! is identical either way — it transparently routes through the TLS client
//! when `tls_active`.
//!
//! ⚠️ LIVE VALIDATION PENDING A RUNNABLE SQL SERVER. SQL Server cannot run
//! on this arm64 host (segfaults under qemu), so the network round-trip in
//! this file is NOT exercised against a real server here. The packet codec
//! and the TDS-wrapped-TLS framing it depends on ARE unit-tested
//! (`tds_test.zig`, `tls_transport.zig`'s socketpair tests). When a reachable
//! SQL Server is available, set `MSSQL_TEST_URL` (optionally with
//! `?tls=require`) and the gated live test in `mssql_backend.zig` will
//! exercise this path end-to-end.
//!
//! Networking uses `std.c` sockets + getaddrinfo (this repo's Zig 0.16 std
//! lacks `std.net`); mirrors `tls/boring_outbound.zig`'s dial idiom.
//!
//! Tiger Style: one fixed send buffer + one fixed receive buffer per
//! connection (no hot-path allocation); responses are reassembled into the
//! receive buffer across multi-packet streams up to its capacity.

const std = @import("std");
const tds = @import("tds.zig");
const tls_transport = @import("tls_transport.zig");
const Certificate = std.crypto.Certificate;

pub const Error = error{
    DnsFailed,
    ConnectFailed,
    SocketError,
    WriteFailed,
    ReadFailed,
    Closed,
    BufferTooSmall,
    LoginFailed,
    ProtocolError,
    ResponseTooLarge,
    ServerError,
    TlsHandshakeFailed,
    TlsRequiredButRefused,
    /// `tls=require` demanded a verified channel but the system CA trust
    /// store could not be loaded — fail closed rather than fall back to an
    /// unverified connection.
    TlsTrustStoreUnavailable,
} || tds.Error;

/// TLS negotiation policy, selected via the `mssql://...?tls=...` URL flag.
///   * `off`              — plaintext (advertise ENCRYPT_NOT_SUP); never TLS.
///   * `require`          — advertise ENCRYPT_ON; perform the TDS-wrapped TLS
///                          handshake and run LOGIN7 + all later traffic over
///                          TLS, VERIFYING the server certificate chain
///                          against the system trust store AND the requested
///                          hostname. This is the secure default: a network
///                          MITM cannot intercept the cleartext credentials.
///   * `require_noverify` — TLS as above but with certificate + hostname
///                          verification DISABLED (encrypt only). Opt-in
///                          escape hatch for self-signed/dev SQL Servers, via
///                          `?tls=require-noverify`.
pub const TlsMode = enum { off, require, require_noverify };

/// Per-connection send buffer. One request must fit (single-packet path).
pub const send_buf_len: usize = 64 * 1024;
/// Per-connection receive buffer. Reassembled response stream cap.
pub const recv_buf_len: usize = 256 * 1024;

pub const max_host_bytes: usize = 255;

pub const Config = struct {
    host: []const u8,
    port: u16 = 1433,
    username: []const u8,
    password: []const u8,
    database: []const u8 = "",
    timeout_ms: u32 = 5000,
    tls: TlsMode = .off,
};

pub const Conn = struct {
    fd: c_int = -1,
    packet_id: u8 = 0,
    /// Last server ERROR token captured during the most recent exchange.
    last_error_number: i32 = 0,
    /// Number of rows the last DONE token reported (when DONE_COUNT set).
    last_row_count: u64 = 0,
    /// True once the TDS-wrapped TLS handshake has completed; all wire I/O
    /// then flows through `tls_client` rather than the raw fd.
    tls_active: bool = false,
    send_buf: [send_buf_len]u8 = undefined,
    recv_buf: [recv_buf_len]u8 = undefined,

    // ── TLS state (only populated when `tls_active`) ───────────────────────
    // `tls_xport` bridges the std TLS client to the TDS-wrapped socket during
    // the handshake and to the raw socket afterward (see tls_transport.zig).
    // `tls_threaded`/`tls_io` provide the `Io` the std TLS client requires;
    // they own no sockets (the fd is owned here).
    tls_xport: tls_transport.TdsTlsTransport = undefined,
    tls_client: std.crypto.tls.Client = undefined,
    tls_threaded: std.Io.Threaded = undefined,
    /// System CA trust store, loaded only for the verifying `.require` mode.
    /// `tls_bundle_loaded` gates its `deinit` in `close`.
    tls_bundle: Certificate.Bundle = Certificate.Bundle.empty,
    tls_bundle_lock: std.Io.RwLock = std.Io.RwLock.init,
    tls_bundle_loaded: bool = false,

    /// Open a TCP connection, perform Pre-Login, optionally negotiate TLS,
    /// then LOGIN7 with SQL auth.
    pub fn connect(self: *Conn, cfg: Config) Error!void {
        self.fd = try dialBlocking(cfg.host, cfg.port, cfg.timeout_ms);
        errdefer {
            _ = std.c.close(self.fd);
            self.fd = -1;
        }
        self.tls_active = false;

        // Pre-Login. Advertise ENCRYPT_ON when TLS is requested, otherwise
        // ENCRYPT_NOT_SUP for the plaintext fallback path.
        const enc_advert: u8 = switch (cfg.tls) {
            .off => tds.ENCRYPT_NOT_SUP,
            .require, .require_noverify => tds.ENCRYPT_ON,
        };
        const pre_len = try tds.buildPreLogin(&self.send_buf, enc_advert);
        try self.writeAll(self.send_buf[0..pre_len]);
        const pre_resp = try self.readResponse();

        if (cfg.tls != .off) {
            const srv_enc = tds.parsePreLoginEncryption(pre_resp) catch return error.ProtocolError;
            // The server must accept (ENCRYPT_ON) or mandate (ENCRYPT_REQ)
            // encryption; ENCRYPT_NOT_SUP means it refuses TLS entirely.
            if (srv_enc == tds.ENCRYPT_NOT_SUP) return error.TlsRequiredButRefused;
            try self.startTls(cfg.host, cfg.tls == .require);
        }

        // LOGIN7 — over TLS if the handshake activated it, else plaintext.
        const login_len = try tds.buildLogin7(&self.send_buf, .{
            .username = cfg.username,
            .password = cfg.password,
            .database = cfg.database,
        });
        try self.writeAll(self.send_buf[0..login_len]);
        const login_resp = try self.readResponse();
        try self.checkLoginAck(login_resp);
    }

    /// Drive the TDS-wrapped TLS handshake: the std TLS client performs the
    /// full handshake against `tls_xport`, whose Reader/Writer wrap the TLS
    /// records in TDS 0x12 packets until completion. On return TLS records
    /// flow directly over the socket and `tls_active` is set.
    /// `verify` true (the `.require` default): load the system CA trust store
    /// and verify the server certificate chain AND that it was issued for
    /// `host` — a network MITM cannot intercept the channel that carries
    /// LOGIN7's credentials. `verify` false (`.require_noverify`): encrypt
    /// only, no peer authentication (opt-in, for self-signed/dev servers).
    fn startTls(self: *Conn, host: []const u8, verify: bool) Error!void {
        self.tls_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
        const io = self.tls_threaded.io();
        errdefer self.tls_threaded.deinit();

        self.tls_xport.init(self.fd, tds.default_packet_size);

        var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
        io.vtable.randomSecure(io.userdata, &entropy) catch return error.TlsHandshakeFailed;
        const now = std.Io.Timestamp.now(io, std.Io.Clock.real);

        const HostOpt = @FieldType(std.crypto.tls.Client.Options, "host");
        const CaOpt = @FieldType(std.crypto.tls.Client.Options, "ca");
        var host_opt: HostOpt = .no_verification;
        var ca_opt: CaOpt = .no_verification;
        if (verify) {
            // Fail closed if the OS trust store can't be loaded: a `require`
            // connection must never silently downgrade to unverified.
            self.tls_bundle = Certificate.Bundle.empty;
            self.tls_bundle.rescan(std.heap.page_allocator, io, now) catch
                return error.TlsTrustStoreUnavailable;
            self.tls_bundle_loaded = true;
            errdefer {
                self.tls_bundle.deinit(std.heap.page_allocator);
                self.tls_bundle_loaded = false;
            }
            host_opt = .{ .explicit = host };
            ca_opt = .{ .bundle = .{
                .gpa = std.heap.page_allocator,
                .io = io,
                .lock = &self.tls_bundle_lock,
                .bundle = &self.tls_bundle,
            } };
        }

        const opts: std.crypto.tls.Client.Options = .{
            .host = host_opt,
            .ca = ca_opt,
            .write_buffer = &self.tls_xport.writer_buf_app,
            .read_buffer = &self.tls_xport.read_buf_app,
            .entropy = &entropy,
            .realtime_now = now,
        };
        self.tls_client = std.crypto.tls.Client.init(&self.tls_xport.reader, &self.tls_xport.writer, opts) catch
            return error.TlsHandshakeFailed;
        // Handshake complete: drop TDS wrapping for subsequent records.
        self.tls_xport.finishHandshake();
        self.tls_active = true;
    }

    pub fn close(self: *Conn) void {
        if (self.tls_active) {
            self.tls_client.end() catch {};
            self.tls_threaded.deinit();
            self.tls_active = false;
        }
        if (self.tls_bundle_loaded) {
            self.tls_bundle.deinit(std.heap.page_allocator);
            self.tls_bundle_loaded = false;
        }
        if (self.fd >= 0) {
            _ = std.c.close(self.fd);
            self.fd = -1;
        }
    }

    /// Send a SQL_BATCH and return the reassembled token-stream payload
    /// (slice into `recv_buf`). `txn` is the active transaction descriptor.
    pub fn sqlBatch(self: *Conn, sql: []const u8, txn: u64) Error![]const u8 {
        const n = try tds.buildSqlBatchWithHeaders(&self.send_buf, sql, txn);
        try self.writeAll(self.send_buf[0..n]);
        return self.readResponse();
    }

    /// Send an RPC sp_executesql with bound params and return the token
    /// stream (slice into `recv_buf`).
    pub fn rpcExecuteSql(self: *Conn, sql: []const u8, params: []const tds.RpcParam) Error![]const u8 {
        const n = try tds.buildRpcExecuteSql(&self.send_buf, sql, params);
        try self.writeAll(self.send_buf[0..n]);
        return self.readResponse();
    }

    // ── Wire I/O ─────────────────────────────────────────────────────────

    fn writeAll(self: *Conn, buf: []const u8) Error!void {
        if (self.tls_active) {
            self.tls_client.writer.writeAll(buf) catch return error.WriteFailed;
            self.tls_client.writer.flush() catch return error.WriteFailed;
            return;
        }
        var off: usize = 0;
        while (off < buf.len) {
            const n = std.c.write(self.fd, buf.ptr + off, buf.len - off);
            if (n <= 0) return error.WriteFailed;
            off += @intCast(n);
        }
    }

    /// Read one full TDS response message — possibly several packets, joined
    /// until a header with the EOM status bit is seen — into `recv_buf`, and
    /// return the concatenated PAYLOAD (headers stripped).
    fn readResponse(self: *Conn) Error![]const u8 {
        var payload_len: usize = 0;
        while (true) {
            var hdr: [tds.header_len]u8 = undefined;
            try self.readExact(&hdr);
            // Bound the declared packet length against our receive buffer so a
            // malicious server cannot announce an oversized packet and drive
            // an over-read into `recv_buf`.
            const h = try tds.parseHeaderBounded(&hdr, self.recv_buf.len);
            const body_len = h.payloadLen();
            if (payload_len + body_len > self.recv_buf.len) return error.ResponseTooLarge;
            try self.readExact(self.recv_buf[payload_len .. payload_len + body_len]);
            payload_len += body_len;
            if (h.isEom()) break;
        }
        return self.recv_buf[0..payload_len];
    }

    fn readExact(self: *Conn, dst: []u8) Error!void {
        if (self.tls_active) {
            // Decrypted TDS bytes come from the TLS client's reader.
            self.tls_client.reader.readSliceAll(dst) catch return error.ReadFailed;
            return;
        }
        var off: usize = 0;
        while (off < dst.len) {
            const n = std.c.read(self.fd, dst.ptr + off, dst.len - off);
            if (n == 0) return error.Closed;
            if (n < 0) return error.ReadFailed;
            off += @intCast(n);
        }
    }

    // ── Token-stream helpers ───────────────────────────────────────────────

    /// Scan a login response for LOGINACK; raise LoginFailed (with the
    /// server error captured) if an ERROR token appears instead.
    fn checkLoginAck(self: *Conn, payload: []const u8) Error!void {
        var r = tds.Reader.init(payload);
        var saw_ack = false;
        while (!r.atEnd()) {
            const tok = try r.u8_();
            switch (tok) {
                @intFromEnum(tds.Token.loginack) => {
                    _ = try tds.parseLoginAck(&r);
                    saw_ack = true;
                },
                @intFromEnum(tds.Token.error_) => {
                    const m = try tds.parseServerMessage(&r);
                    self.last_error_number = m.number;
                    return error.LoginFailed;
                },
                @intFromEnum(tds.Token.info) => {
                    _ = try tds.parseServerMessage(&r);
                },
                @intFromEnum(tds.Token.envchange) => try tds.skipEnvChange(&r),
                @intFromEnum(tds.Token.done), @intFromEnum(tds.Token.doneproc), @intFromEnum(tds.Token.doneinproc) => {
                    _ = try tds.parseDone(&r);
                },
                else => return error.ProtocolError,
            }
        }
        if (!saw_ack) return error.LoginFailed;
    }
};

// ── Blocking dial (std.c + getaddrinfo; mirrors boring_outbound.zig) ──────

fn dialBlocking(host: []const u8, port: u16, timeout_ms: u32) Error!c_int {
    if (host.len > max_host_bytes) return error.ConnectFailed;
    var host_z: [max_host_bytes + 1]u8 = undefined;
    @memcpy(host_z[0..host.len], host);
    host_z[host.len] = 0;

    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch return error.ConnectFailed;
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

test {
    // Pull the codec + TLS-transport tests in when compiled standalone.
    _ = tds;
    _ = tls_transport;
}
