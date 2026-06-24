//! D2: TDS (Tabular Data Stream) protocol codec — a pure-function subset
//! sufficient to authenticate (SQL auth) and run parameterized statements
//! against Microsoft SQL Server, mirroring the pure-Zig Postgres path.
//!
//! Scope (MS-TDS, protocol version 7.4 / TDS 0x74000004):
//!   * Packet framing: the 8-byte TDS packet header (Type/Status/Length/
//!     SPID/PacketID/Window). All multi-byte header fields are BIG-endian.
//!   * Pre-Login request: option-token table (VERSION + ENCRYPTION +
//!     INSTOPT + THREADID + MARS) followed by the option payloads.
//!   * LOGIN7 request: the fixed 36-byte field, the variable offset/length
//!     table, then the UCS-2/UTF-16LE payload. The password is obfuscated
//!     per spec (nibble-swap then XOR 0xA5).
//!   * SQL_BATCH request (UTF-16LE SQL text) and the RPC sp_executesql
//!     request used to bind `@pN` parameters (the parameterized path).
//!   * Token-stream response parsing: LOGINACK (0xAD), COLMETADATA (0x81),
//!     ROW (0xD1), DONE/DONEPROC/DONEINPROC (0xFD/0xFE/0xFF), ERROR (0xAA),
//!     INFO (0xAB), ENVCHANGE (0xE3), ORDER (0xA9), RETURNSTATUS (0x79).
//!
//! Everything here is a PURE function over byte buffers — no sockets, no
//! allocation beyond caller-supplied fixed buffers — so it is exhaustively
//! unit-testable without a live server (which this arm64 host cannot run).
//!
//! Tiger Style: bounded buffers, explicit lengths, no hidden allocation,
//! integer widths chosen to match the wire.

const std = @import("std");

// ── Packet types (TDS message type, first header byte) ───────────────────
pub const PacketType = enum(u8) {
    sql_batch = 0x01,
    rpc = 0x03,
    tabular_result = 0x04, // server → client response
    attention = 0x06,
    bulk_load = 0x07,
    transaction_mgr = 0x0E,
    login7 = 0x10,
    sspi = 0x11,
    pre_login = 0x12,
};

// ── Packet status flags (second header byte) ─────────────────────────────
pub const status_normal: u8 = 0x00;
pub const status_eom: u8 = 0x01; // End Of Message — last packet of a request
pub const status_ignore: u8 = 0x02;

/// The fixed TDS packet header is 8 bytes.
pub const header_len: usize = 8;
/// Conventional negotiated packet size. Requests here fit in one packet;
/// responses are reassembled across packets by the backend's reader.
pub const default_packet_size: u32 = 4096;

/// Hard ceiling on a single TDS packet length. The length field is a u16,
/// so 0xFFFF is the absolute protocol maximum; a server claiming more is
/// impossible by construction, but callers additionally bound against their
/// own receive buffer via `parseHeaderBounded`.
pub const max_packet_len: usize = std.math.maxInt(u16);

pub const Error = error{
    BufferTooSmall,
    Truncated,
    Malformed,
    UnsupportedToken,
    TooManyColumns,
    /// A server-supplied packet length exceeds the receive buffer it must
    /// fit into — a malicious/buggy server trying to drive an over-read.
    PacketTooLarge,
};

pub const max_columns: usize = 64;

// ─────────────────────────────────────────────────────────────────────────
// Packet header
// ─────────────────────────────────────────────────────────────────────────

/// Write the 8-byte TDS packet header into `buf`. `total_len` is the FULL
/// packet length (header + payload); it is encoded BIG-endian per spec.
/// PacketID is a per-message counter (low byte); SPID/Window are 0 from the
/// client. Returns the number of bytes written (always `header_len`).
pub fn writeHeader(buf: []u8, ptype: PacketType, status: u8, total_len: u16, packet_id: u8) Error!usize {
    if (buf.len < header_len) return error.BufferTooSmall;
    buf[0] = @intFromEnum(ptype);
    buf[1] = status;
    // Length is big-endian.
    buf[2] = @intCast((total_len >> 8) & 0xFF);
    buf[3] = @intCast(total_len & 0xFF);
    // SPID (2) — 0 from client.
    buf[4] = 0;
    buf[5] = 0;
    // PacketID (1), Window (1).
    buf[6] = packet_id;
    buf[7] = 0;
    return header_len;
}

pub const Header = struct {
    ptype: u8,
    status: u8,
    length: u16, // full packet length incl header
    spid: u16,
    packet_id: u8,
    window: u8,

    pub fn isEom(self: Header) bool {
        return (self.status & status_eom) != 0;
    }
    pub fn payloadLen(self: Header) usize {
        return @as(usize, self.length) - header_len;
    }
};

pub fn parseHeader(buf: []const u8) Error!Header {
    return parseHeaderBounded(buf, max_packet_len);
}

/// Parse a TDS packet header, rejecting any packet whose declared total
/// length exceeds `max_len`. The wire layer passes its receive-buffer size
/// here so a malicious server cannot announce an oversized packet and drive
/// an over-read/overflow when the body is read into a fixed buffer.
pub fn parseHeaderBounded(buf: []const u8, max_len: usize) Error!Header {
    if (buf.len < header_len) return error.Truncated;
    const length = (@as(u16, buf[2]) << 8) | @as(u16, buf[3]);
    if (length < header_len) return error.Malformed;
    if (length > max_len) return error.PacketTooLarge;
    return .{
        .ptype = buf[0],
        .status = buf[1],
        .length = length,
        .spid = (@as(u16, buf[4]) << 8) | @as(u16, buf[5]),
        .packet_id = buf[6],
        .window = buf[7],
    };
}

// ─────────────────────────────────────────────────────────────────────────
// Little-endian write helpers (TDS payload bodies are little-endian)
// ─────────────────────────────────────────────────────────────────────────

fn putU16le(buf: []u8, off: usize, v: u16) void {
    buf[off] = @intCast(v & 0xFF);
    buf[off + 1] = @intCast((v >> 8) & 0xFF);
}
fn putU32le(buf: []u8, off: usize, v: u32) void {
    buf[off] = @intCast(v & 0xFF);
    buf[off + 1] = @intCast((v >> 8) & 0xFF);
    buf[off + 2] = @intCast((v >> 16) & 0xFF);
    buf[off + 3] = @intCast((v >> 24) & 0xFF);
}

fn readU16le(buf: []const u8, off: usize) u16 {
    return @as(u16, buf[off]) | (@as(u16, buf[off + 1]) << 8);
}
fn readU32le(buf: []const u8, off: usize) u32 {
    return @as(u32, buf[off]) | (@as(u32, buf[off + 1]) << 8) |
        (@as(u32, buf[off + 2]) << 16) | (@as(u32, buf[off + 3]) << 24);
}
fn readU64le(buf: []const u8, off: usize) u64 {
    var v: u64 = 0;
    var i: usize = 0;
    while (i < 8) : (i += 1) v |= @as(u64, buf[off + i]) << @intCast(i * 8);
    return v;
}

/// Encode an ASCII slice as UCS-2/UTF-16LE into `out`, returning bytes
/// written (= 2 * input length). Characters above U+00FF are not expected
/// in identifiers/credentials here; each byte becomes a low-byte unit.
pub fn ucs2Encode(out: []u8, s: []const u8) Error!usize {
    if (out.len < s.len * 2) return error.BufferTooSmall;
    var i: usize = 0;
    for (s) |ch| {
        out[i] = ch;
        out[i + 1] = 0;
        i += 2;
    }
    return i;
}

// ─────────────────────────────────────────────────────────────────────────
// Password obfuscation (MS-TDS §2.2.6.4 — LOGIN7)
// ─────────────────────────────────────────────────────────────────────────

/// In-place obfuscate a UCS-2/UTF-16LE password buffer. For each byte:
/// swap the nibbles, then XOR with 0xA5. This is reversible and is NOT
/// encryption — it is the on-wire scrambling SQL Server expects.
pub fn obfuscatePassword(pw_ucs2: []u8) void {
    for (pw_ucs2) |*b| {
        const swapped: u8 = (b.* << 4) | (b.* >> 4);
        b.* = swapped ^ 0xA5;
    }
}

/// Reverse of `obfuscatePassword` (XOR 0xA5 then swap nibbles). Provided so
/// the unit tests can assert round-trip equality of the scrambling.
pub fn deobfuscatePassword(pw_ucs2: []u8) void {
    for (pw_ucs2) |*b| {
        const x: u8 = b.* ^ 0xA5;
        b.* = (x << 4) | (x >> 4);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Pre-Login request
// ─────────────────────────────────────────────────────────────────────────

pub const PRELOGIN_VERSION: u8 = 0x00;
pub const PRELOGIN_ENCRYPTION: u8 = 0x01;
pub const PRELOGIN_INSTOPT: u8 = 0x02;
pub const PRELOGIN_THREADID: u8 = 0x03;
pub const PRELOGIN_MARS: u8 = 0x04;
pub const PRELOGIN_TERMINATOR: u8 = 0xFF;

/// Encryption negotiation byte values (ENCRYPTION option payload).
pub const ENCRYPT_OFF: u8 = 0x00; // encryption available, off after login
pub const ENCRYPT_ON: u8 = 0x01;
pub const ENCRYPT_NOT_SUP: u8 = 0x02; // client does not support encryption
pub const ENCRYPT_REQ: u8 = 0x03;

/// Build a complete Pre-Login PACKET (header + payload) into `buf`.
/// Options advertised: VERSION (6 bytes: 4 version + 2 subbuild),
/// ENCRYPTION (1 byte), INSTOPT (1 byte "\0"), THREADID (4 bytes), MARS
/// (1 byte). The option table entries are {token(1), offset(2 BE),
/// length(2 BE)} relative to the START of the option data region (i.e. the
/// byte after the terminator). Returns the total packet length.
pub fn buildPreLogin(buf: []u8, encryption: u8) Error!usize {
    // Option table: 5 options * 5 bytes + 1 terminator = 26 bytes.
    const n_opts = 5;
    const table_len = n_opts * 5 + 1;

    // Payload sizes per option.
    const ver_len: u16 = 6;
    const enc_len: u16 = 1;
    const inst_len: u16 = 1;
    const thread_len: u16 = 4;
    const mars_len: u16 = 1;

    const payload_len: usize = table_len + ver_len + enc_len + inst_len + thread_len + mars_len;
    const total: usize = header_len + payload_len;
    if (buf.len < total) return error.BufferTooSmall;

    _ = try writeHeader(buf, .pre_login, status_eom, @intCast(total), 0);
    const p = buf[header_len..];

    // Offsets are relative to the start of the option DATA (after the table).
    var data_off: u16 = @intCast(table_len);
    var t: usize = 0; // table write cursor

    const writeEntry = struct {
        fn f(pp: []u8, cursor: usize, token: u8, off: u16, len: u16) void {
            pp[cursor] = token;
            pp[cursor + 1] = @intCast((off >> 8) & 0xFF); // BE
            pp[cursor + 2] = @intCast(off & 0xFF);
            pp[cursor + 3] = @intCast((len >> 8) & 0xFF); // BE
            pp[cursor + 4] = @intCast(len & 0xFF);
        }
    }.f;

    writeEntry(p, t, PRELOGIN_VERSION, data_off, ver_len);
    t += 5;
    data_off += ver_len;
    writeEntry(p, t, PRELOGIN_ENCRYPTION, data_off, enc_len);
    t += 5;
    data_off += enc_len;
    writeEntry(p, t, PRELOGIN_INSTOPT, data_off, inst_len);
    t += 5;
    data_off += inst_len;
    writeEntry(p, t, PRELOGIN_THREADID, data_off, thread_len);
    t += 5;
    data_off += thread_len;
    writeEntry(p, t, PRELOGIN_MARS, data_off, mars_len);
    t += 5;
    data_off += mars_len;
    p[t] = PRELOGIN_TERMINATOR;
    t += 1;

    // Option data region.
    var d: usize = table_len;
    // VERSION: 4-byte version (major.minor.build-hi.build-lo) + 2-byte subbuild.
    // Advertise a plausible client version (9.0.0.0).
    p[d] = 9;
    p[d + 1] = 0;
    p[d + 2] = 0;
    p[d + 3] = 0;
    putU16le(p, d + 4, 0);
    d += ver_len;
    // ENCRYPTION
    p[d] = encryption;
    d += enc_len;
    // INSTOPT — empty instance name, single NUL terminator byte.
    p[d] = 0;
    d += inst_len;
    // THREADID — client thread id (0 is fine).
    putU32le(p, d, 0);
    d += thread_len;
    // MARS — disabled.
    p[d] = 0;
    d += mars_len;

    std.debug.assert(d == payload_len);
    return total;
}

/// Parse the server's Pre-Login RESPONSE payload (token table identical in
/// shape to the request) and return the ENCRYPTION option byte the server
/// chose. The response carries the same {token(1), offset(2 BE), length(2
/// BE)} table terminated by 0xFF. Per MS-TDS §2.2.6.5 each option's offset
/// is measured from the START of the PRELOGIN message data (i.e. the option
/// table itself is at offset 0), so an option's payload lives at
/// `payload[offset]` directly — matching how `buildPreLogin` emits them.
/// Returns `error.Malformed` if the ENCRYPTION option is absent or its
/// payload is empty / out of range.
///
/// The server replies with ENCRYPT_OFF (0x00), ENCRYPT_ON (0x01),
/// ENCRYPT_NOT_SUP (0x02), or ENCRYPT_REQ (0x03). The caller (conn.zig)
/// decides whether to start the TLS handshake based on this byte combined
/// with the client's policy (`tls=require|off`).
pub fn parsePreLoginEncryption(payload: []const u8) Error!u8 {
    var j: usize = 0;
    while (true) {
        if (j >= payload.len) return error.Truncated;
        if (payload[j] == PRELOGIN_TERMINATOR) break;
        if (j + 5 > payload.len) return error.Truncated;
        const token = payload[j];
        const off = (@as(usize, payload[j + 1]) << 8) | @as(usize, payload[j + 2]);
        const len = (@as(usize, payload[j + 3]) << 8) | @as(usize, payload[j + 4]);
        if (token == PRELOGIN_ENCRYPTION) {
            if (len == 0) return error.Malformed;
            if (off >= payload.len) return error.Malformed;
            return payload[off];
        }
        j += 5;
    }
    return error.Malformed;
}

// ─────────────────────────────────────────────────────────────────────────
// TDS-wrapped TLS handshake framing (MS-TDS §2.2.6.5 / "TLS over TDS")
// ─────────────────────────────────────────────────────────────────────────
//
// During the TDS Pre-Login phase the TLS handshake records are not sent
// raw: each batch of TLS handshake bytes the client emits is wrapped in one
// or more TDS packets of type PRELOGIN (0x12) with the standard 8-byte TDS
// header, the final packet of a batch carrying the EOM status bit. The
// server replies the same way. Once the TLS handshake completes the wrapping
// is dropped and TLS records flow directly over the socket (LOGIN7 and every
// subsequent TDS message then travels *inside* the TLS session).
//
// These are PURE functions over byte buffers — the chunking (TLS handshake
// bytes → TDS 0x12 packets) and dechunking (TDS 0x12 payloads → contiguous
// handshake bytes) are exhaustively unit-testable without a socket, which is
// the whole point on a host that cannot run SQL Server.

/// The max TLS-handshake payload that fits in one TDS packet given a target
/// total packet size: `packet_size - header_len`. SQL Server's pre-login TLS
/// packets conventionally use the default 4096-byte packet size.
pub fn tlsChunkPayloadCap(packet_size: u32) usize {
    std.debug.assert(packet_size > header_len);
    return @as(usize, packet_size) - header_len;
}

/// Frame `handshake` (raw TLS handshake bytes the TLS client produced) into
/// `out` as a sequence of TDS PRELOGIN (0x12) packets, each at most
/// `packet_size` bytes total. Every packet but the last has `status_normal`;
/// the last has `status_eom`. `packet_id` seeds the per-packet counter (it
/// wraps at 256, matching the 1-byte PacketID field). A zero-length
/// `handshake` still emits one empty EOM packet (a valid, if unusual, TDS
/// message). Returns the number of bytes written to `out`.
pub fn frameTlsHandshake(out: []u8, handshake: []const u8, packet_size: u32, packet_id: u8) Error!usize {
    const cap = tlsChunkPayloadCap(packet_size);
    var written: usize = 0;
    var src: usize = 0;
    var pid: u8 = packet_id;
    // Emit at least one packet (handles the empty-handshake case).
    while (true) {
        const remaining = handshake.len - src;
        const chunk = @min(remaining, cap);
        const is_last = (src + chunk) >= handshake.len;
        const total = header_len + chunk;
        if (written + total > out.len) return error.BufferTooSmall;
        const status: u8 = if (is_last) status_eom else status_normal;
        _ = try writeHeader(out[written .. written + header_len], .pre_login, status, @intCast(total), pid);
        if (chunk > 0) @memcpy(out[written + header_len .. written + total], handshake[src .. src + chunk]);
        written += total;
        src += chunk;
        pid +%= 1;
        if (is_last) break;
    }
    return written;
}

/// The result of dechunking a TDS-wrapped handshake stream: the contiguous
/// handshake bytes recovered, plus how many bytes of `framed` were consumed
/// (so a caller draining a socket buffer knows where the next message starts)
/// and whether an EOM-terminated message was fully assembled.
pub const Dechunked = struct {
    /// Bytes written into the caller's destination buffer.
    payload_len: usize,
    /// Bytes consumed from the `framed` input.
    consumed: usize,
    /// True once a packet carrying the EOM bit was seen (message complete).
    complete: bool,
};

/// Strip TDS packet headers from `framed` (a buffer holding one or more
/// type-0x12 TDS packets) and copy the concatenated PAYLOAD bytes into `out`,
/// stopping after the packet whose header sets the EOM bit. If `framed` ends
/// mid-message (no EOM yet, or a partial header/body) the function returns
/// what it could assemble with `complete=false` and `consumed` set to the
/// last whole-packet boundary — the caller then reads more socket bytes and
/// calls again with the unconsumed tail prepended.
pub fn dechunkTlsHandshake(out: []u8, framed: []const u8) Error!Dechunked {
    var payload_len: usize = 0;
    var consumed: usize = 0;
    while (true) {
        if (consumed + header_len > framed.len) {
            // Not even a full header buffered yet.
            return .{ .payload_len = payload_len, .consumed = consumed, .complete = false };
        }
        const h = try parseHeader(framed[consumed .. consumed + header_len]);
        const body_len = h.payloadLen();
        if (consumed + h.length > framed.len) {
            // Header present but body not fully buffered.
            return .{ .payload_len = payload_len, .consumed = consumed, .complete = false };
        }
        if (payload_len + body_len > out.len) return error.BufferTooSmall;
        const body_start = consumed + header_len;
        if (body_len > 0) {
            @memcpy(out[payload_len .. payload_len + body_len], framed[body_start .. body_start + body_len]);
        }
        payload_len += body_len;
        consumed += h.length;
        if (h.isEom()) {
            return .{ .payload_len = payload_len, .consumed = consumed, .complete = true };
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// LOGIN7 request
// ─────────────────────────────────────────────────────────────────────────

/// Inputs for a SQL-authentication LOGIN7 message.
pub const Login7 = struct {
    hostname: []const u8 = "speedy",
    username: []const u8,
    password: []const u8,
    app_name: []const u8 = "speedy-socials",
    server_name: []const u8 = "",
    database: []const u8 = "",
    /// TDS version. 7.4 = 0x74000004.
    tds_version: u32 = 0x74000004,
    packet_size: u32 = default_packet_size,
};

/// The LOGIN7 fixed portion preceding the variable offset/length table is
/// 36 bytes: Length(4) + TDSVersion(4) + PacketSize(4) + ClientProgVer(4) +
/// ClientPID(4) + ConnectionID(4) + OptionFlags1/2/3 + TypeFlags (4 total) +
/// ClientTimeZone(4) + ClientLCID(4). The offset/length table that follows
/// has 9 {offset,length} pairs plus ClientID(6) plus SSPI/AtchDBFile/
/// ChangePassword fields; we emit the standard layout.
const login7_fixed_len: usize = 36;
/// The offset/length variable table is a fixed 58-byte block in TDS 7.x:
///   HostName, UserName, Password, AppName, ServerName, (unused ext 4),
///   CltIntName, Language, Database  → 9 * 4 = 36 bytes
///   ClientID                        → 6 bytes
///   SSPI off/len                    → 4 bytes
///   AtchDBFile off/len              → 4 bytes
///   ChangePassword off/len          → 4 bytes
///   SSPILong                        → 4 bytes
const login7_var_table_len: usize = 36 + 6 + 4 + 4 + 4 + 4; // 58

/// Build a complete LOGIN7 packet (header + payload) into `buf`. The
/// password is obfuscated in place in the payload. Returns total length.
pub fn buildLogin7(buf: []u8, login: Login7) Error!usize {
    const var_region_start: usize = login7_fixed_len + login7_var_table_len;

    // Compute UCS-2 byte lengths.
    const host_b = login.hostname.len * 2;
    const user_b = login.username.len * 2;
    const pass_b = login.password.len * 2;
    const app_b = login.app_name.len * 2;
    const srv_b = login.server_name.len * 2;
    const clt_name = "speedy-tds";
    const clt_b = clt_name.len * 2;
    const db_b = login.database.len * 2;

    const data_len = host_b + user_b + pass_b + app_b + srv_b + clt_b + db_b;
    const payload_len = var_region_start + data_len;
    const total = header_len + payload_len;
    if (buf.len < total) return error.BufferTooSmall;
    if (payload_len > 0xFFFF) return error.BufferTooSmall;

    @memset(buf[0..total], 0);
    _ = try writeHeader(buf, .login7, status_eom, @intCast(total), 0);
    const p = buf[header_len..total];

    // ── Fixed 36-byte header ──
    putU32le(p, 0, @intCast(payload_len)); // Length (of LOGIN7 payload)
    putU32le(p, 4, login.tds_version); // TDSVersion (LE on wire here)
    putU32le(p, 8, login.packet_size); // PacketSize
    putU32le(p, 12, 0x00000007); // ClientProgVer
    putU32le(p, 16, 0); // ClientPID
    putU32le(p, 20, 0); // ConnectionID
    // OptionFlags1: USE_DB_ON(0x20)|INIT_DB_FATAL(0x40)|SET_LANG_ON... keep
    // a safe default of 0. OptionFlags2: ODBC(0x02). TypeFlags: 0.
    p[24] = 0x00; // OptionFlags1
    p[25] = 0x00; // OptionFlags2
    p[26] = 0x00; // TypeFlags
    p[27] = 0x00; // OptionFlags3
    putU32le(p, 28, 0); // ClientTimeZone
    putU32le(p, 32, 0); // ClientLCID

    // ── Variable offset/length table (starts at byte 36) ──
    // Offsets are relative to the START of the LOGIN7 payload (p[0]).
    var cur: u16 = @intCast(var_region_start);
    var tcur: usize = login7_fixed_len;

    const setpair = struct {
        fn f(pp: []u8, at: usize, off: u16, char_len: usize) void {
            putU16le(pp, at, off);
            putU16le(pp, at + 2, @intCast(char_len)); // length in CHARACTERS
        }
    }.f;

    // HostName
    setpair(p, tcur, cur, login.hostname.len);
    tcur += 4;
    cur += @intCast(host_b);
    // UserName
    setpair(p, tcur, cur, login.username.len);
    tcur += 4;
    cur += @intCast(user_b);
    // Password
    setpair(p, tcur, cur, login.password.len);
    tcur += 4;
    cur += @intCast(pass_b);
    // AppName
    setpair(p, tcur, cur, login.app_name.len);
    tcur += 4;
    cur += @intCast(app_b);
    // ServerName
    setpair(p, tcur, cur, login.server_name.len);
    tcur += 4;
    cur += @intCast(srv_b);
    // Extension / unused (off=0,len=0)
    setpair(p, tcur, 0, 0);
    tcur += 4;
    // CltIntName (client interface library name)
    setpair(p, tcur, cur, clt_name.len);
    tcur += 4;
    cur += @intCast(clt_b);
    // Language (empty)
    setpair(p, tcur, cur, 0);
    tcur += 4;
    // Database
    setpair(p, tcur, cur, login.database.len);
    tcur += 4;
    cur += @intCast(db_b);

    // ClientID (6 bytes MAC) — zeros.
    tcur += 6;
    // SSPI off/len
    setpair(p, tcur, 0, 0);
    tcur += 4;
    // AtchDBFile off/len
    setpair(p, tcur, 0, 0);
    tcur += 4;
    // ChangePassword off/len
    setpair(p, tcur, 0, 0);
    tcur += 4;
    // SSPILong (4) — zero.
    tcur += 4;
    std.debug.assert(tcur == var_region_start);

    // ── Variable data region (UCS-2) ──
    var d: usize = var_region_start;
    d += try ucs2Encode(p[d..], login.hostname);
    d += try ucs2Encode(p[d..], login.username);
    const pass_start = d;
    d += try ucs2Encode(p[d..], login.password);
    obfuscatePassword(p[pass_start .. pass_start + pass_b]);
    d += try ucs2Encode(p[d..], login.app_name);
    d += try ucs2Encode(p[d..], login.server_name);
    d += try ucs2Encode(p[d..], clt_name);
    d += try ucs2Encode(p[d..], login.database);
    std.debug.assert(d == payload_len);

    return total;
}

// ─────────────────────────────────────────────────────────────────────────
// SQL_BATCH request
// ─────────────────────────────────────────────────────────────────────────

/// Build a SQL_BATCH packet carrying `sql` as UTF-16LE. No ALL_HEADERS
/// stream is prefixed (optional for TDS 7.2+ without a transaction
/// descriptor requirement in single-statement use); for correctness with
/// servers that demand it, see `buildSqlBatchWithHeaders`. Returns total len.
pub fn buildSqlBatch(buf: []u8, sql: []const u8) Error!usize {
    return buildSqlBatchWithHeaders(buf, sql, 0);
}

/// SQL_BATCH with an ALL_HEADERS stream carrying a Transaction Descriptor
/// header (required by modern SQL Server for batches). `txn_descriptor` is
/// the 8-byte transaction descriptor (0 outside an explicit transaction).
pub fn buildSqlBatchWithHeaders(buf: []u8, sql: []const u8, txn_descriptor: u64) Error!usize {
    // ALL_HEADERS: TotalLength(4) + [ HeaderLength(4) + HeaderType(2) +
    // Data ]. Transaction Descriptor header data = txn(8) + outstanding(4).
    const txhdr_data_len = 8 + 4;
    const txhdr_len = 4 + 2 + txhdr_data_len; // 18
    const all_headers_len = 4 + txhdr_len; // 22

    const sql_b = sql.len * 2;
    const payload_len = all_headers_len + sql_b;
    const total = header_len + payload_len;
    if (buf.len < total) return error.BufferTooSmall;

    _ = try writeHeader(buf, .sql_batch, status_eom, @intCast(total), 0);
    const p = buf[header_len..total];

    putU32le(p, 0, @intCast(all_headers_len)); // ALL_HEADERS TotalLength
    putU32le(p, 4, @intCast(txhdr_len)); // HeaderLength
    putU16le(p, 8, 0x0002); // HeaderType = Transaction Descriptor
    // Transaction descriptor (8) + OutstandingRequestCount (4 = 1).
    var i: usize = 0;
    while (i < 8) : (i += 1) p[10 + i] = @intCast((txn_descriptor >> @intCast(i * 8)) & 0xFF);
    putU32le(p, 18, 1);

    _ = try ucs2Encode(p[all_headers_len..], sql);
    return total;
}

// ─────────────────────────────────────────────────────────────────────────
// RPC sp_executesql request (parameterized — the `@pN` path)
// ─────────────────────────────────────────────────────────────────────────

/// A single bound RPC parameter. Mirrors the storage `BindValue` shapes the
/// backend will translate. The codec emits the matching TDS type token.
pub const RpcParam = union(enum) {
    null_,
    int: i64,
    real: f64,
    /// NVARCHAR text (UTF-16LE on the wire).
    text: []const u8,
    /// VARBINARY bytes.
    blob: []const u8,
};

// Procedure id shortcut for sp_executesql.
const SP_EXECUTESQL: u16 = 10;

// Type tokens used for parameters.
const TYPE_INTN: u8 = 0x26; // variable-length int (1/2/4/8)
const TYPE_FLTN: u8 = 0x6D; // variable-length float (4/8)
const TYPE_NVARCHAR: u8 = 0xE7; // NVARCHAR / NCHAR (with collation)
const TYPE_BIGVARBINARY: u8 = 0xA5; // VARBINARY
const TYPE_NULL: u8 = 0x1F;

/// Compute the bytes a `@declN type` clause occupies in UTF-16. Used to
/// build the `@params` string that sp_executesql requires.
fn declFor(param: RpcParam) []const u8 {
    return switch (param) {
        .null_ => "nvarchar(1)",
        .int => "bigint",
        .real => "float",
        .text => "nvarchar(max)",
        .blob => "varbinary(max)",
    };
}

/// Build the parameter declaration string `@p1 t1,@p2 t2,...` into `out`
/// (ASCII), returning its length. Parameter names are **1-based** to match
/// the `@pN` placeholders zorm's mssql dialect emits in the SQL text (see
/// `zorm/src/contract.zig` `Dialect.placeholder`). Used internally and
/// exposed for tests.
pub fn buildParamDecls(out: []u8, params: []const RpcParam) Error!usize {
    var n: usize = 0;
    for (params, 0..) |param, idx| {
        if (idx != 0) {
            if (n >= out.len) return error.BufferTooSmall;
            out[n] = ',';
            n += 1;
        }
        const decl = declFor(param);
        const piece = std.fmt.bufPrint(out[n..], "@p{d} {s}", .{ idx + 1, decl }) catch return error.BufferTooSmall;
        n += piece.len;
    }
    return n;
}

/// Emit one NVARCHAR RPC value (used for both the SQL text and @params).
/// Format: USHORTLEN type header = type(1) + maxlen(2) + collation(5) for
/// NVARCHAR; then a 2-byte actual length followed by the UTF-16 bytes.
fn writeNVarcharParamName(p: []u8, off: usize, name: []const u8) Error!usize {
    // Parameter name: B_VARCHAR (len byte = char count) of UCS-2.
    if (off + 1 > p.len) return error.BufferTooSmall;
    p[off] = @intCast(name.len);
    var d = off + 1;
    d += try ucs2Encode(p[d..], name);
    return d - off;
}

/// Build a complete RPC sp_executesql request packet for `sql` with the
/// given bound `params`. `@pN` placeholders in `sql` map positionally to
/// `params[N]`. Returns the total packet length. The caller passes the SQL
/// already written with `@pN` placeholders (zorm's mssql dialect emits them).
pub fn buildRpcExecuteSql(buf: []u8, sql: []const u8, params: []const RpcParam) Error!usize {
    if (buf.len < header_len + 32) return error.BufferTooSmall;
    const p = buf[header_len..];
    var d: usize = 0;

    // ALL_HEADERS (Transaction Descriptor) — required for RPC too.
    const txhdr_data_len = 8 + 4;
    const txhdr_len = 4 + 2 + txhdr_data_len;
    const all_headers_len = 4 + txhdr_len;
    if (d + all_headers_len > p.len) return error.BufferTooSmall;
    putU32le(p, 0, @intCast(all_headers_len));
    putU32le(p, 4, @intCast(txhdr_len));
    putU16le(p, 8, 0x0002);
    var z: usize = 0;
    while (z < 12) : (z += 1) p[10 + z] = 0;
    putU32le(p, 18, 1);
    d = all_headers_len;

    // ── RPC request: ProcID path (0xFFFF then PROCID) ──
    if (d + 4 > p.len) return error.BufferTooSmall;
    putU16le(p, d, 0xFFFF); // name length 0xFFFF → ProcID follows
    putU16le(p, d + 2, SP_EXECUTESQL); // ProcID = 10
    d += 4;
    // OptionFlags (2 bytes) = 0.
    if (d + 2 > p.len) return error.BufferTooSmall;
    putU16le(p, d, 0);
    d += 2;

    // ── Parameter 1: @stmt NVARCHAR = sql ──
    // Unnamed (length 0), status 0, then NVARCHAR type info + value.
    d += try writeRpcUnnamedHeader(p, d);
    d += try writeNVarcharValue(p, d, sql);

    // ── Parameter 2: @params NVARCHAR = "@p0 t0,@p1 t1,..." ──
    var decl_buf: [1024]u8 = undefined;
    const decl_len = try buildParamDecls(&decl_buf, params);
    d += try writeRpcUnnamedHeader(p, d);
    d += try writeNVarcharValue(p, d, decl_buf[0..decl_len]);

    // ── Parameters 3..N: the actual @p1..@pN values, named (1-based) ──
    var name_buf: [16]u8 = undefined;
    for (params, 0..) |param, idx| {
        const name = std.fmt.bufPrint(&name_buf, "@p{d}", .{idx + 1}) catch return error.BufferTooSmall;
        d += try writeNVarcharParamName(p, d, name);
        // status flag byte
        if (d + 1 > p.len) return error.BufferTooSmall;
        p[d] = 0;
        d += 1;
        d += try writeParamValue(p, d, param);
    }

    const total = header_len + d;
    if (total > 0xFFFF) return error.BufferTooSmall;
    _ = try writeHeader(buf, .rpc, status_eom, @intCast(total), 0);
    return total;
}

/// Write an unnamed parameter header: name length byte (0) + status (0).
fn writeRpcUnnamedHeader(p: []u8, off: usize) Error!usize {
    if (off + 2 > p.len) return error.BufferTooSmall;
    p[off] = 0; // B_VARCHAR name length = 0
    p[off + 1] = 0; // status flags
    return 2;
}

/// Write NVARCHAR type info + value for a UTF-16 string. Layout:
/// type(1=0xE7) + maxLen(2) + collation(5) + actualLen(2) + UTF-16 bytes.
/// For NVARCHAR(MAX) the wire uses a PLP encoding; to keep the codec simple
/// and bounded we cap at the non-MAX 0xFFFF maxlen form (8000 bytes), which
/// covers statement text and parameter decls in practice. Longer text is
/// chunked by the backend via temp tables if ever needed.
fn writeNVarcharValue(p: []u8, off: usize, s: []const u8) Error!usize {
    const byte_len = s.len * 2;
    const needed = 1 + 2 + 5 + 2 + byte_len;
    if (off + needed > p.len) return error.BufferTooSmall;
    if (byte_len > 0xFFFF) return error.BufferTooSmall;
    var d = off;
    p[d] = TYPE_NVARCHAR;
    d += 1;
    putU16le(p, d, 0x1F40); // maxLen = 8000 (NVARCHAR(4000) octet cap)
    d += 2;
    // Collation (5 bytes): LCID 0x0409 + flags + version + sortid.
    p[d] = 0x09;
    p[d + 1] = 0x04;
    p[d + 2] = 0x00;
    p[d + 3] = 0x00;
    p[d + 4] = 0x00;
    d += 5;
    putU16le(p, d, @intCast(byte_len)); // actual length in BYTES
    d += 2;
    d += try ucs2Encode(p[d..], s);
    return d - off;
}

/// Write a single bound parameter's type info + value.
fn writeParamValue(p: []u8, off: usize, param: RpcParam) Error!usize {
    switch (param) {
        .null_ => {
            // NVARCHAR(1) with NULL value: type + maxlen + collation + len=0xFFFF.
            const needed = 1 + 2 + 5 + 2;
            if (off + needed > p.len) return error.BufferTooSmall;
            var d = off;
            p[d] = TYPE_NVARCHAR;
            d += 1;
            putU16le(p, d, 2); // maxLen
            d += 2;
            @memset(p[d .. d + 5], 0);
            d += 5;
            putU16le(p, d, 0xFFFF); // NULL marker for NVARCHAR
            d += 2;
            return d - off;
        },
        .int => |v| {
            // INTN: type(1) + maxLen(1=8) + actualLen(1=8) + 8 LE bytes.
            const needed = 3 + 8;
            if (off + needed > p.len) return error.BufferTooSmall;
            var d = off;
            p[d] = TYPE_INTN;
            p[d + 1] = 8; // declared max length
            p[d + 2] = 8; // actual length (BIGINT)
            d += 3;
            const uv: u64 = @bitCast(v);
            var i: usize = 0;
            while (i < 8) : (i += 1) p[d + i] = @intCast((uv >> @intCast(i * 8)) & 0xFF);
            d += 8;
            return d - off;
        },
        .real => |v| {
            const needed = 3 + 8;
            if (off + needed > p.len) return error.BufferTooSmall;
            var d = off;
            p[d] = TYPE_FLTN;
            p[d + 1] = 8;
            p[d + 2] = 8;
            d += 3;
            const uv: u64 = @bitCast(v);
            var i: usize = 0;
            while (i < 8) : (i += 1) p[d + i] = @intCast((uv >> @intCast(i * 8)) & 0xFF);
            d += 8;
            return d - off;
        },
        .text => |s| return writeNVarcharValue(p, off, s),
        .blob => |s| {
            // BIGVARBINARY: type(1) + maxLen(2) + actualLen(2) + bytes.
            if (s.len > 0xFFFF) return error.BufferTooSmall;
            const needed = 1 + 2 + 2 + s.len;
            if (off + needed > p.len) return error.BufferTooSmall;
            var d = off;
            p[d] = TYPE_BIGVARBINARY;
            d += 1;
            putU16le(p, d, 0x1F40); // maxLen
            d += 2;
            putU16le(p, d, @intCast(s.len));
            d += 2;
            if (s.len > 0) @memcpy(p[d .. d + s.len], s);
            d += s.len;
            return d - off;
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Token-stream response parsing
// ─────────────────────────────────────────────────────────────────────────

pub const Token = enum(u8) {
    returnstatus = 0x79,
    colmetadata = 0x81,
    order = 0xA9,
    error_ = 0xAA,
    info = 0xAB,
    loginack = 0xAD,
    row = 0xD1,
    nbcrow = 0xD2,
    envchange = 0xE3,
    done = 0xFD,
    doneproc = 0xFE,
    doneinproc = 0xFF,
};

/// A parsed ERROR/INFO token (MS-TDS §2.2.7.10 / .13).
pub const ServerMessage = struct {
    number: i32,
    state: u8,
    class: u8, // severity
    message: []const u8, // UTF-16LE on wire; this slice points into the buffer
};

/// LOGINACK fields.
pub const LoginAck = struct {
    interface: u8,
    tds_version: u32,
    prog_name: []const u8, // UTF-16LE
    server_version: u32,
};

/// Column metadata for one result column (subset of fields we care about).
pub const ColumnMeta = struct {
    user_type: u32 = 0,
    flags: u16 = 0,
    type_token: u8 = 0,
    /// Effective max byte length for var-length types (0 for fixed).
    max_len: u32 = 0,
    name_utf16: []const u8 = &.{},
};

pub const ColMetadata = struct {
    columns: [max_columns]ColumnMeta = undefined,
    count: usize = 0,
};

/// One decoded cell value from a ROW token.
pub const CellKind = enum { null_, int, real, text, blob };
pub const Cell = struct {
    kind: CellKind = .null_,
    int_val: i64 = 0,
    real_val: f64 = 0,
    bytes: []const u8 = &.{}, // points into the source buffer
};

/// A cursor over a token stream payload. The parser is fully streaming and
/// bounds-checked; it never reads past `data`.
pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }
    pub fn remaining(self: *const Reader) usize {
        return self.data.len - self.pos;
    }
    pub fn atEnd(self: *const Reader) bool {
        return self.pos >= self.data.len;
    }
    fn need(self: *const Reader, n: usize) Error!void {
        if (self.pos + n > self.data.len) return error.Truncated;
    }
    pub fn u8_(self: *Reader) Error!u8 {
        try self.need(1);
        const v = self.data[self.pos];
        self.pos += 1;
        return v;
    }
    pub fn u16le(self: *Reader) Error!u16 {
        try self.need(2);
        const v = readU16le(self.data, self.pos);
        self.pos += 2;
        return v;
    }
    pub fn u32le(self: *Reader) Error!u32 {
        try self.need(4);
        const v = readU32le(self.data, self.pos);
        self.pos += 4;
        return v;
    }
    pub fn u64le(self: *Reader) Error!u64 {
        try self.need(8);
        const v = readU64le(self.data, self.pos);
        self.pos += 8;
        return v;
    }
    pub fn i32le(self: *Reader) Error!i32 {
        return @bitCast(try self.u32le());
    }
    pub fn bytes(self: *Reader, n: usize) Error![]const u8 {
        try self.need(n);
        const s = self.data[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }
    pub fn peekToken(self: *const Reader) Error!u8 {
        try self.need(1);
        return self.data[self.pos];
    }
};

/// Parse an ERROR (0xAA) or INFO (0xAB) token body. The token byte must be
/// consumed by the caller already; `r` points at the token's length field.
pub fn parseServerMessage(r: *Reader) Error!ServerMessage {
    const total_len = try r.u16le(); // token length in bytes
    const start = r.pos;
    const number = try r.i32le();
    const state = try r.u8_();
    const class = try r.u8_();
    const msg_char_len = try r.u16le(); // length in UTF-16 characters
    const msg = try r.bytes(@as(usize, msg_char_len) * 2);
    // ServerName (B_VARCHAR), ProcName (B_VARCHAR), LineNumber: skip the
    // remainder using the declared total length to stay robust.
    const consumed = r.pos - start;
    if (consumed < total_len) {
        _ = try r.bytes(total_len - consumed);
    }
    return .{ .number = number, .state = state, .class = class, .message = msg };
}

/// Parse a LOGINACK (0xAD) token body.
pub fn parseLoginAck(r: *Reader) Error!LoginAck {
    const total_len = try r.u16le();
    const start = r.pos;
    const iface = try r.u8_();
    const tds_ver = try r.u32le();
    const name_char_len = try r.u8_(); // B_VARCHAR
    const name = try r.bytes(@as(usize, name_char_len) * 2);
    // ProgVersion: 4 bytes (major,minor,buildhi,buildlo).
    const sv = try r.u32le();
    const consumed = r.pos - start;
    if (consumed < total_len) _ = try r.bytes(total_len - consumed);
    return .{ .interface = iface, .tds_version = tds_ver, .prog_name = name, .server_version = sv };
}

/// Map a TDS type token to a coarse cell kind for value decoding.
fn kindForType(type_token: u8) CellKind {
    return switch (type_token) {
        // Fixed + variable integers.
        0x30, 0x26, 0x38, 0x6C, 0x68 => .int, // INT1, INTN, INT4, MONEY*, BIT family
        0x34, 0x3A, 0x7F, 0x22 => .int,
        // Floats.
        0x3B, 0x6D, 0x6E => .real, // FLT4, FLTN, FLT8
        // Binary.
        0x2D, 0xA5, 0x25, 0x6F, 0xAD => .blob, // BIGVARBINARY/IMAGE/etc.
        // Text-ish: NVARCHAR/VARCHAR/CHAR/NCHAR/NTEXT/TEXT, decimals, dates.
        else => .text,
    };
}

/// Returns true if the type token is a fixed-length type (no length prefix
/// in COLMETADATA or ROW). MS-TDS encodes fixed types with no TYPE_INFO len.
fn isFixedLen(type_token: u8) ?u32 {
    return switch (type_token) {
        0x1F => 0, // NULL
        0x30 => 1, // INT1 (tinyint)
        0x32 => 1, // BIT
        0x34 => 2, // INT2 (smallint)
        0x38 => 4, // INT4 (int)
        0x3A => 4, // DATETIM4 (smalldatetime)
        0x3B => 4, // FLT4 (real)
        0x3C => 8, // MONEY
        0x3D => 8, // DATETIME
        0x3E => 8, // FLT8 (float)
        0x7A => 4, // MONEY4 (smallmoney)
        0x7F => 8, // INT8 (bigint)
        else => null,
    };
}

/// True for var-length types whose length prefix is 1 byte (BYTELEN).
fn isByteLen(type_token: u8) bool {
    return switch (type_token) {
        0x26, // INTN
        0x68, // BITN
        0x6D, // FLTN
        0x6E, // MONEYN
        0x6F, // DATETIMN
        0x24, // GUID
        0x2F, // CHAR
        0x27, // VARCHAR (legacy)
        0x2D, // BINARY (legacy)
        0x25, // VARBINARY (legacy)
        0x6A, // DECIMAL
        0x6C, // NUMERIC
        => true,
        else => false,
    };
}

/// True for var-length types whose length prefix is 2 bytes (USHORTLEN):
/// the BIG* family (BIGVARCHAR, BIGCHAR, BIGVARBINARY, BIGBINARY, NVARCHAR,
/// NCHAR). Length 0xFFFF means NULL.
fn isUShortLen(type_token: u8) bool {
    return switch (type_token) {
        0xA5, // BIGVARBINARY
        0xAD, // BIGBINARY
        0xA7, // BIGVARCHAR
        0xAF, // BIGCHAR
        0xE7, // NVARCHAR
        0xEF, // NCHAR
        => true,
        else => false,
    };
}

/// True for var-length types whose length prefix is 4 bytes (LONGLEN):
/// TEXT, NTEXT, IMAGE. Length 0xFFFFFFFF means NULL.
fn isLongLen(type_token: u8) bool {
    return switch (type_token) {
        0x23, // TEXT
        0x63, // NTEXT
        0x22, // IMAGE
        => true,
        else => false,
    };
}

/// Parse the TYPE_INFO portion that follows the type token in COLMETADATA,
/// advancing `r` past it and returning the column's effective max_len. For
/// types carrying a collation (CHAR/VARCHAR/NVARCHAR families) the 5-byte
/// collation is consumed. For DECIMAL/NUMERIC the precision+scale (2 bytes)
/// is consumed.
fn parseTypeInfo(r: *Reader, type_token: u8, out: *ColumnMeta) Error!void {
    out.type_token = type_token;
    if (isFixedLen(type_token)) |fl| {
        out.max_len = fl;
        return;
    }
    if (isByteLen(type_token)) {
        out.max_len = try r.u8_();
        if (type_token == 0x6A or type_token == 0x6C) {
            _ = try r.u8_(); // precision
            _ = try r.u8_(); // scale
        }
        if (type_token == 0x2F or type_token == 0x27) {
            // legacy CHAR/VARCHAR carry collation (5 bytes)
            _ = try r.bytes(5);
        }
        return;
    }
    if (isUShortLen(type_token)) {
        out.max_len = try r.u16le();
        // BIGCHAR/BIGVARCHAR/NCHAR/NVARCHAR carry a 5-byte collation.
        switch (type_token) {
            0xA7, 0xAF, 0xE7, 0xEF => _ = try r.bytes(5),
            else => {},
        }
        return;
    }
    if (isLongLen(type_token)) {
        out.max_len = try r.u32le();
        switch (type_token) {
            0x23, 0x63 => { // TEXT/NTEXT collation
                _ = try r.bytes(5);
            },
            else => {},
        }
        // TableName: a USHORT count of parts each a US_VARCHAR.
        const parts = try r.u16le();
        var i: usize = 0;
        while (i < parts) : (i += 1) {
            const cl = try r.u16le();
            _ = try r.bytes(@as(usize, cl) * 2);
        }
        return;
    }
    return error.UnsupportedToken;
}

/// Parse a COLMETADATA (0x81) token body. The token byte is already
/// consumed; `r` points at the 2-byte column count.
pub fn parseColMetadata(r: *Reader) Error!ColMetadata {
    var meta: ColMetadata = .{};
    const count = try r.u16le();
    if (count == 0xFFFF) {
        // No metadata (e.g. a batch with no result set).
        meta.count = 0;
        return meta;
    }
    if (count > max_columns) return error.TooManyColumns;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        var col: ColumnMeta = .{};
        col.user_type = try r.u32le(); // USERTYPE (4 bytes in TDS 7.2+)
        col.flags = try r.u16le();
        const type_token = try r.u8_();
        try parseTypeInfo(r, type_token, &col);
        // ColName: B_VARCHAR (1-byte char count) of UTF-16.
        const name_char_len = try r.u8_();
        col.name_utf16 = try r.bytes(@as(usize, name_char_len) * 2);
        meta.columns[i] = col;
    }
    meta.count = count;
    return meta;
}

/// Decode the on-wire value for one column in a ROW token into a `Cell`,
/// advancing `r`. `kindForType` decides interpretation; integer/float bytes
/// are little-endian; text/blob `bytes` point into the source buffer.
fn parseCell(r: *Reader, col: ColumnMeta) Error!Cell {
    const tt = col.type_token;
    var cell: Cell = .{};
    const kind = kindForType(tt);

    if (isFixedLen(tt)) |fl| {
        if (fl == 0) {
            cell.kind = .null_;
            return cell;
        }
        const raw = try r.bytes(fl);
        applyScalar(&cell, kind, raw);
        return cell;
    }

    // Variable-length: read length prefix, 0xFF.. all-ones means NULL.
    var data_len: usize = 0;
    var is_null = false;
    if (isByteLen(tt)) {
        const l = try r.u8_();
        if (l == 0xFF) is_null = true else data_len = l;
    } else if (isUShortLen(tt)) {
        const l = try r.u16le();
        if (l == 0xFFFF) is_null = true else data_len = l;
    } else if (isLongLen(tt)) {
        // LONGLEN values are preceded by a text pointer unless NULL.
        const tptr_len = try r.u8_();
        if (tptr_len == 0) {
            is_null = true;
        } else {
            _ = try r.bytes(tptr_len); // text pointer
            _ = try r.bytes(8); // timestamp
            const l = try r.u32le();
            if (l == 0xFFFFFFFF) is_null = true else data_len = l;
        }
    } else {
        return error.UnsupportedToken;
    }

    if (is_null) {
        cell.kind = .null_;
        return cell;
    }
    const raw = try r.bytes(data_len);
    applyScalar(&cell, kind, raw);
    return cell;
}

fn applyScalar(cell: *Cell, kind: CellKind, raw: []const u8) void {
    switch (kind) {
        .int => {
            var v: i64 = 0;
            // Sign-extend from the value's natural width.
            if (raw.len == 8) {
                v = @bitCast(readU64le(raw, 0));
            } else {
                var u: u64 = 0;
                var i: usize = 0;
                while (i < raw.len and i < 8) : (i += 1) u |= @as(u64, raw[i]) << @intCast(i * 8);
                // sign-extend
                if (raw.len < 8 and raw.len > 0 and (raw[raw.len - 1] & 0x80) != 0) {
                    const fill_from: u6 = @intCast(raw.len * 8);
                    var b: u6 = fill_from;
                    while (b < 64) : (b += 1) u |= @as(u64, 1) << b;
                }
                v = @bitCast(u);
            }
            cell.kind = .int;
            cell.int_val = v;
        },
        .real => {
            if (raw.len == 8) {
                cell.real_val = @bitCast(readU64le(raw, 0));
            } else if (raw.len == 4) {
                const bits: u32 = readU32le(raw, 0);
                cell.real_val = @floatCast(@as(f32, @bitCast(bits)));
            }
            cell.kind = .real;
        },
        .blob => {
            cell.kind = .blob;
            cell.bytes = raw;
        },
        .text, .null_ => {
            cell.kind = .text;
            cell.bytes = raw;
        },
    }
}

/// Parse a ROW (0xD1) token body into up to `meta.count` cells. The token
/// byte is already consumed. Cell text/blob bytes point into `r.data`.
pub fn parseRow(r: *Reader, meta: *const ColMetadata, out: []Cell) Error!usize {
    if (out.len < meta.count) return error.BufferTooSmall;
    var i: usize = 0;
    while (i < meta.count) : (i += 1) {
        out[i] = try parseCell(r, meta.columns[i]);
    }
    return meta.count;
}

/// DONE/DONEPROC/DONEINPROC token body. The token byte is consumed already.
pub const Done = struct {
    status: u16,
    cur_cmd: u16,
    row_count: u64,

    pub fn more(self: Done) bool {
        return (self.status & 0x0001) != 0; // DONE_MORE
    }
    pub fn countValid(self: Done) bool {
        return (self.status & 0x0010) != 0; // DONE_COUNT
    }
};

pub fn parseDone(r: *Reader) Error!Done {
    const status = try r.u16le();
    const cur_cmd = try r.u16le();
    // RowCount is 8 bytes in TDS 7.2+.
    const row_count = try r.u64le();
    return .{ .status = status, .cur_cmd = cur_cmd, .row_count = row_count };
}

/// Skip an ENVCHANGE (0xE3) token (length-prefixed) — we don't act on env
/// changes but must consume them to stay aligned.
pub fn skipEnvChange(r: *Reader) Error!void {
    const len = try r.u16le();
    _ = try r.bytes(len);
}

/// Skip an ORDER (0xA9) token (length-prefixed list of column indices).
pub fn skipOrder(r: *Reader) Error!void {
    const len = try r.u16le();
    _ = try r.bytes(len);
}

/// Skip a RETURNSTATUS (0x79) token — a single 4-byte i32.
pub fn skipReturnStatus(r: *Reader) Error!void {
    _ = try r.u32le();
}

test {
    _ = @import("tds_test.zig");
}
