//! D2: TDS connection — the socket-bearing wire layer that frames TDS
//! packets over a blocking TCP socket and drives the login handshake plus
//! request/response exchanges. The byte-level packet construction and
//! token-stream parsing live in `tds.zig` (pure, unit-tested); this module
//! is the thin I/O wrapper that those pure functions feed.
//!
//! ⚠️ LIVE VALIDATION PENDING A RUNNABLE SQL SERVER. SQL Server cannot run
//! on this arm64 host (segfaults under qemu), so the network round-trip in
//! this file is NOT exercised against a real server here. The packet codec
//! it depends on IS exhaustively unit-tested in `tds_test.zig`. When a
//! reachable SQL Server is available, set `MSSQL_TEST_URL` and the gated
//! live test in `mssql_backend.zig` will exercise this path end-to-end.
//!
//! Networking uses `std.c` sockets + getaddrinfo (this repo's Zig 0.16 std
//! lacks `std.net`); mirrors `tls/boring_outbound.zig`'s dial idiom.
//!
//! Tiger Style: one fixed send buffer + one fixed receive buffer per
//! connection (no hot-path allocation); responses are reassembled into the
//! receive buffer across multi-packet streams up to its capacity.

const std = @import("std");
const tds = @import("tds.zig");

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
} || tds.Error;

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
};

pub const Conn = struct {
    fd: c_int = -1,
    packet_id: u8 = 0,
    /// Last server ERROR token captured during the most recent exchange.
    last_error_number: i32 = 0,
    /// Number of rows the last DONE token reported (when DONE_COUNT set).
    last_row_count: u64 = 0,
    send_buf: [send_buf_len]u8 = undefined,
    recv_buf: [recv_buf_len]u8 = undefined,

    /// Open a TCP connection, perform Pre-Login, then LOGIN7 with SQL auth.
    pub fn connect(self: *Conn, cfg: Config) Error!void {
        self.fd = try dialBlocking(cfg.host, cfg.port, cfg.timeout_ms);
        errdefer {
            _ = std.c.close(self.fd);
            self.fd = -1;
        }

        // Pre-Login. We advertise ENCRYPT_NOT_SUP (plaintext) — TLS for TDS
        // is a follow-on; the wire layer is identical once a TLS stream is
        // substituted for the raw fd.
        const pre_len = try tds.buildPreLogin(&self.send_buf, tds.ENCRYPT_NOT_SUP);
        try self.writeAll(self.send_buf[0..pre_len]);
        const pre_resp = try self.readResponse();
        _ = pre_resp; // server's encryption response; we ignore for plaintext.

        // LOGIN7.
        const login_len = try tds.buildLogin7(&self.send_buf, .{
            .username = cfg.username,
            .password = cfg.password,
            .database = cfg.database,
        });
        try self.writeAll(self.send_buf[0..login_len]);
        const login_resp = try self.readResponse();
        try self.checkLoginAck(login_resp);
    }

    pub fn close(self: *Conn) void {
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
            const h = try tds.parseHeader(&hdr);
            const body_len = h.payloadLen();
            if (payload_len + body_len > self.recv_buf.len) return error.ResponseTooLarge;
            try self.readExact(self.recv_buf[payload_len .. payload_len + body_len]);
            payload_len += body_len;
            if (h.isEom()) break;
        }
        return self.recv_buf[0..payload_len];
    }

    fn readExact(self: *Conn, dst: []u8) Error!void {
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
    // Pull the codec tests in when this module is compiled standalone.
    _ = tds;
}
