//! Pure-Zig MySQL/MariaDB client/server wire-protocol codec (protocol 41).
//!
//! This module is the *pure* half of the driver: every function here is a
//! total function over byte slices with no I/O, no allocation beyond
//! caller-supplied buffers, and no global state. That makes the entire
//! protocol layer unit-testable WITHOUT a live server — the tests at the
//! bottom round-trip every packet shape against hand-encoded fixtures.
//!
//! Scope (subset sufficient to run the SQL zorm's `.mysql` dialect emits):
//!   - Packet framing: 3-byte little-endian length + 1-byte sequence id.
//!   - Length-encoded integers and length-encoded strings (LEN-ENC).
//!   - Initial handshake (HandshakeV10) parse → server capabilities +
//!     20-byte auth scramble (plugin-data parts 1 & 2 concatenated).
//!   - `mysql_native_password` scramble:
//!       SHA1(pwd) XOR SHA1( scramble || SHA1(SHA1(pwd)) ).
//!   - HandshakeResponse41 encode (CLIENT_PROTOCOL_41 + secure-conn caps).
//!   - Generic packet classification: OK (0x00), EOF (0xfe, <9 bytes),
//!     ERR (0xff) with SQLSTATE; plus OK's affected_rows / last_insert_id.
//!   - COM_QUERY (0x03) encode; result-set column-count + ColumnDefinition41
//!     parse; text-protocol row parse (each field a LEN-ENC string or NULL).
//!   - Prepared statements: COM_STMT_PREPARE (0x16) request + PREPARE_OK
//!     response parse; COM_STMT_EXECUTE (0x17) encode with the binary
//!     parameter NULL-bitmap + typed values; COM_STMT_CLOSE (0x19); binary
//!     result-row parse (NULL-bitmap + per-type binary decode).
//!
//! Tiger Style: bounded everything. Encoders write into a caller `Writer`
//! backed by a fixed array; parsers advance a `Reader` cursor and return
//! typed errors on truncation rather than reading out of bounds.

const std = @import("std");
const Sha1 = std.crypto.hash.Sha1;

pub const Error = error{
    /// Buffer ran out before the field could be read/written.
    Truncated,
    /// A length-encoded value used a marker this subset doesn't support.
    Unsupported,
    /// The packet's first byte didn't match the expected kind.
    UnexpectedPacket,
};

// ── Capability flags (subset we set / inspect) ───────────────────────────
pub const CLIENT_LONG_PASSWORD: u32 = 0x00000001;
pub const CLIENT_FOUND_ROWS: u32 = 0x00000002;
pub const CLIENT_LONG_FLAG: u32 = 0x00000004;
pub const CLIENT_CONNECT_WITH_DB: u32 = 0x00000008;
pub const CLIENT_PROTOCOL_41: u32 = 0x00000200;
pub const CLIENT_TRANSACTIONS: u32 = 0x00002000;
pub const CLIENT_SECURE_CONNECTION: u32 = 0x00008000;
pub const CLIENT_PLUGIN_AUTH: u32 = 0x00080000;
pub const CLIENT_DEPRECATE_EOF: u32 = 0x01000000;

// ── MySQL column type codes (subset we bind / decode) ─────────────────────
pub const MYSQL_TYPE_TINY: u8 = 0x01;
pub const MYSQL_TYPE_SHORT: u8 = 0x02;
pub const MYSQL_TYPE_LONG: u8 = 0x03;
pub const MYSQL_TYPE_FLOAT: u8 = 0x04;
pub const MYSQL_TYPE_DOUBLE: u8 = 0x05;
pub const MYSQL_TYPE_NULL: u8 = 0x06;
pub const MYSQL_TYPE_LONGLONG: u8 = 0x08;
pub const MYSQL_TYPE_VARCHAR: u8 = 0x0f;
pub const MYSQL_TYPE_NEWDECIMAL: u8 = 0xf6;
pub const MYSQL_TYPE_BLOB: u8 = 0xfc;
pub const MYSQL_TYPE_VAR_STRING: u8 = 0xfd;
pub const MYSQL_TYPE_STRING: u8 = 0xfe;

// ── Command bytes ────────────────────────────────────────────────────────
pub const COM_QUERY: u8 = 0x03;
pub const COM_STMT_PREPARE: u8 = 0x16;
pub const COM_STMT_EXECUTE: u8 = 0x17;
pub const COM_STMT_CLOSE: u8 = 0x19;

// ── Length-encoded integer markers ───────────────────────────────────────
const LENENC_U16: u8 = 0xfc;
const LENENC_U24: u8 = 0xfd;
const LENENC_U64: u8 = 0xfe;
const NULL_BYTE: u8 = 0xfb; // length-encoded NULL marker (in a string column)

// ──────────────────────────────────────────────────────────────────────
// Reader — a bounds-checked forward cursor over a byte slice.
// ──────────────────────────────────────────────────────────────────────

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn remaining(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }

    pub fn atEnd(self: *const Reader) bool {
        return self.pos >= self.buf.len;
    }

    pub fn readByte(self: *Reader) Error!u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        const v = self.buf[self.pos];
        self.pos += 1;
        return v;
    }

    pub fn peek(self: *const Reader) Error!u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        return self.buf[self.pos];
    }

    /// Read `n` little-endian bytes as an unsigned integer (n ∈ 1..8).
    pub fn uint(self: *Reader, n: usize) Error!u64 {
        if (self.pos + n > self.buf.len) return error.Truncated;
        var v: u64 = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            v |= @as(u64, self.buf[self.pos + i]) << @intCast(i * 8);
        }
        self.pos += n;
        return v;
    }

    pub fn bytes(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.Truncated;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }

    pub fn skip(self: *Reader, n: usize) Error!void {
        if (self.pos + n > self.buf.len) return error.Truncated;
        self.pos += n;
    }

    /// A NUL-terminated string; cursor advances past the NUL.
    pub fn cstr(self: *Reader) Error![]const u8 {
        const start = self.pos;
        while (self.pos < self.buf.len) : (self.pos += 1) {
            if (self.buf[self.pos] == 0) {
                const s = self.buf[start..self.pos];
                self.pos += 1; // consume NUL
                return s;
            }
        }
        return error.Truncated;
    }

    /// Length-encoded integer. 0xfb (NULL) is rejected here — callers that
    /// allow NULL must peek first (see `lenEncStr`).
    pub fn lenEncInt(self: *Reader) Error!u64 {
        const first = try self.readByte();
        return switch (first) {
            0...0xfa => first,
            LENENC_U16 => self.uint(2),
            LENENC_U24 => self.uint(3),
            LENENC_U64 => self.uint(8),
            else => error.Unsupported, // 0xfb NULL handled by caller
        };
    }

    /// Length-encoded string, or `null` when the field is the LEN-ENC NULL
    /// marker (0xfb). The returned slice aliases the underlying buffer.
    pub fn lenEncStr(self: *Reader) Error!?[]const u8 {
        const first = try self.peek();
        if (first == NULL_BYTE) {
            self.pos += 1;
            return null;
        }
        const n = try self.lenEncInt();
        return try self.bytes(@intCast(n));
    }
};

// ──────────────────────────────────────────────────────────────────────
// Writer — a bounds-checked forward cursor into a caller-owned buffer.
// ──────────────────────────────────────────────────────────────────────

pub const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    pub fn slice(self: *const Writer) []const u8 {
        return self.buf[0..self.pos];
    }

    pub fn writeByte(self: *Writer, v: u8) Error!void {
        if (self.pos >= self.buf.len) return error.Truncated;
        self.buf[self.pos] = v;
        self.pos += 1;
    }

    /// Write `v` as `n` little-endian bytes.
    pub fn uint(self: *Writer, v: u64, n: usize) Error!void {
        if (self.pos + n > self.buf.len) return error.Truncated;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            self.buf[self.pos + i] = @truncate(v >> @intCast(i * 8));
        }
        self.pos += n;
    }

    pub fn bytes(self: *Writer, s: []const u8) Error!void {
        if (self.pos + s.len > self.buf.len) return error.Truncated;
        @memcpy(self.buf[self.pos .. self.pos + s.len], s);
        self.pos += s.len;
    }

    pub fn cstr(self: *Writer, s: []const u8) Error!void {
        try self.bytes(s);
        try self.writeByte(0);
    }

    pub fn lenEncInt(self: *Writer, v: u64) Error!void {
        if (v < 0xfb) {
            try self.writeByte(@intCast(v));
        } else if (v <= 0xffff) {
            try self.writeByte(LENENC_U16);
            try self.uint(v, 2);
        } else if (v <= 0xff_ffff) {
            try self.writeByte(LENENC_U24);
            try self.uint(v, 3);
        } else {
            try self.writeByte(LENENC_U64);
            try self.uint(v, 8);
        }
    }

    pub fn lenEncStr(self: *Writer, s: []const u8) Error!void {
        try self.lenEncInt(s.len);
        try self.bytes(s);
    }
};

// ──────────────────────────────────────────────────────────────────────
// Packet framing.
// ──────────────────────────────────────────────────────────────────────

pub const header_len: usize = 4;

/// Write a 4-byte packet header (3-byte LE length + sequence id) in front
/// of an already-written payload of `payload_len` bytes. Returns the header
/// bytes; callers send `header ++ payload`.
pub fn encodeHeader(out: *[header_len]u8, payload_len: usize, seq: u8) void {
    out[0] = @truncate(payload_len);
    out[1] = @truncate(payload_len >> 8);
    out[2] = @truncate(payload_len >> 16);
    out[3] = seq;
}

pub const PacketHeader = struct {
    length: u32,
    seq: u8,
};

pub fn decodeHeader(buf: []const u8) Error!PacketHeader {
    if (buf.len < header_len) return error.Truncated;
    const len: u32 = @as(u32, buf[0]) | (@as(u32, buf[1]) << 8) | (@as(u32, buf[2]) << 16);
    return .{ .length = len, .seq = buf[3] };
}

// ──────────────────────────────────────────────────────────────────────
// Initial handshake (HandshakeV10).
// ──────────────────────────────────────────────────────────────────────

pub const max_scramble = 20;

pub const Handshake = struct {
    protocol_version: u8,
    capabilities: u32,
    auth_plugin_name_buf: [64]u8 = undefined,
    auth_plugin_name_len: u8 = 0,
    scramble_buf: [max_scramble]u8 = undefined,
    scramble_len: u8 = 0,

    pub fn authPluginName(self: *const Handshake) []const u8 {
        return self.auth_plugin_name_buf[0..self.auth_plugin_name_len];
    }
    pub fn scramble(self: *const Handshake) []const u8 {
        return self.scramble_buf[0..self.scramble_len];
    }
};

/// Parse a HandshakeV10 packet *payload* (header already stripped).
pub fn parseHandshake(payload: []const u8) Error!Handshake {
    var r = Reader.init(payload);
    var h: Handshake = .{ .protocol_version = 0, .capabilities = 0 };
    h.protocol_version = try r.readByte();
    if (h.protocol_version != 10) return error.UnexpectedPacket;
    _ = try r.cstr(); // server version string
    _ = try r.uint(4); // connection id
    const auth1 = try r.bytes(8); // auth-plugin-data-part-1 (8 bytes)
    _ = try r.readByte(); // filler (0x00)
    const cap_low: u32 = @intCast(try r.uint(2));
    if (r.atEnd()) {
        // Minimal handshake (rare): only the low capability word present.
        h.capabilities = cap_low;
        copyScramble(&h, auth1, &.{});
        return h;
    }
    _ = try r.readByte(); // character set
    _ = try r.uint(2); // status flags
    const cap_high: u32 = @intCast(try r.uint(2));
    h.capabilities = cap_low | (cap_high << 16);
    const auth_data_len = try r.readByte(); // length of combined auth-plugin-data
    try r.skip(10); // reserved (all zero)

    // auth-plugin-data-part-2: at least 13 bytes when SECURE_CONNECTION,
    // but only the first (auth_data_len - 8) are real scramble; the spec
    // guarantees at least 13 with a trailing NUL we drop.
    var auth2: []const u8 = &.{};
    if (h.capabilities & CLIENT_SECURE_CONNECTION != 0) {
        const part2_len: usize = @max(13, @as(usize, auth_data_len) -| 8);
        const part2 = try r.bytes(part2_len);
        // Real scramble part-2 length is auth_data_len-8 (drop trailing NUL).
        const real = @min(part2.len, @as(usize, auth_data_len) -| 8);
        auth2 = part2[0..real];
    }
    copyScramble(&h, auth1, auth2);

    if (h.capabilities & CLIENT_PLUGIN_AUTH != 0) {
        const name = try r.cstr();
        const n = @min(name.len, h.auth_plugin_name_buf.len);
        @memcpy(h.auth_plugin_name_buf[0..n], name[0..n]);
        h.auth_plugin_name_len = @intCast(n);
    }
    return h;
}

fn copyScramble(h: *Handshake, part1: []const u8, part2: []const u8) void {
    var n: usize = 0;
    const c1 = @min(part1.len, max_scramble);
    @memcpy(h.scramble_buf[0..c1], part1[0..c1]);
    n += c1;
    const c2 = @min(part2.len, max_scramble - n);
    if (c2 > 0) @memcpy(h.scramble_buf[n .. n + c2], part2[0..c2]);
    n += c2;
    h.scramble_len = @intCast(n);
}

// ──────────────────────────────────────────────────────────────────────
// mysql_native_password scramble.
//
//   token = SHA1(password) XOR SHA1( scramble || SHA1(SHA1(password)) )
//
// An empty password yields an empty token (server treats it as no auth
// data). The result is always 20 bytes for a non-empty password.
// ──────────────────────────────────────────────────────────────────────

pub fn nativePasswordScramble(password: []const u8, scramble: []const u8, out: *[20]u8) usize {
    if (password.len == 0) return 0;

    var sha1_pwd: [20]u8 = undefined;
    Sha1.hash(password, &sha1_pwd, .{});

    var sha1_sha1_pwd: [20]u8 = undefined;
    Sha1.hash(&sha1_pwd, &sha1_sha1_pwd, .{});

    var h = Sha1.init(.{});
    h.update(scramble);
    h.update(&sha1_sha1_pwd);
    var inner: [20]u8 = undefined;
    h.final(&inner);

    var i: usize = 0;
    while (i < 20) : (i += 1) out[i] = sha1_pwd[i] ^ inner[i];
    return 20;
}

// ──────────────────────────────────────────────────────────────────────
// HandshakeResponse41.
// ──────────────────────────────────────────────────────────────────────

/// The fixed client capability set we advertise. PROTOCOL_41 + secure
/// connection + plugin auth + transactions; CONNECT_WITH_DB only when a
/// database name is supplied (added by the encoder).
pub fn clientCapabilities(with_db: bool) u32 {
    var caps: u32 = CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG | CLIENT_PROTOCOL_41 |
        CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
    if (with_db) caps |= CLIENT_CONNECT_WITH_DB;
    return caps;
}

pub const HandshakeResponse = struct {
    username: []const u8,
    auth_response: []const u8, // 20-byte token (or empty)
    database: []const u8 = "", // empty → CONNECT_WITH_DB not set
    max_packet: u32 = 16 * 1024 * 1024,
    charset: u8 = 0x21, // utf8_general_ci
};

/// Encode a HandshakeResponse41 *payload* (header added by the caller).
pub fn encodeHandshakeResponse(w: *Writer, resp: HandshakeResponse) Error!void {
    const with_db = resp.database.len > 0;
    const caps = clientCapabilities(with_db);
    try w.uint(caps, 4);
    try w.uint(resp.max_packet, 4);
    try w.writeByte(resp.charset);
    var i: usize = 0;
    while (i < 23) : (i += 1) try w.writeByte(0); // filler
    try w.cstr(resp.username);
    // SECURE_CONNECTION: length-prefixed (1 byte) auth response.
    try w.writeByte(@intCast(resp.auth_response.len));
    try w.bytes(resp.auth_response);
    if (with_db) try w.cstr(resp.database);
    // PLUGIN_AUTH: the auth plugin name.
    try w.cstr("mysql_native_password");
}

// ──────────────────────────────────────────────────────────────────────
// Generic response packets: OK / ERR / EOF.
// ──────────────────────────────────────────────────────────────────────

pub const PacketKind = enum { ok, err, eof, other };

/// Classify a response packet payload by its first byte + length.
/// EOF (0xfe) is only EOF when shorter than 9 bytes; otherwise a 0xfe lead
/// byte is a length-encoded-integer in a result row.
pub fn classify(payload: []const u8) PacketKind {
    if (payload.len == 0) return .other;
    return switch (payload[0]) {
        0x00 => .ok,
        0xff => .err,
        0xfe => if (payload.len < 9) .eof else .other,
        else => .other,
    };
}

pub const OkPacket = struct {
    affected_rows: u64,
    last_insert_id: u64,
};

pub fn parseOk(payload: []const u8) Error!OkPacket {
    var r = Reader.init(payload);
    if ((try r.readByte()) != 0x00) return error.UnexpectedPacket;
    const affected = try r.lenEncInt();
    const last_id = try r.lenEncInt();
    return .{ .affected_rows = affected, .last_insert_id = last_id };
}

pub const ErrPacket = struct {
    code: u16,
    sqlstate_buf: [5]u8 = .{ 0, 0, 0, 0, 0 },
    has_sqlstate: bool = false,
    message_buf: [256]u8 = undefined,
    message_len: u16 = 0,

    pub fn sqlstate(self: *const ErrPacket) ?[]const u8 {
        return if (self.has_sqlstate) self.sqlstate_buf[0..] else null;
    }
    pub fn message(self: *const ErrPacket) []const u8 {
        return self.message_buf[0..self.message_len];
    }
};

pub fn parseErr(payload: []const u8) Error!ErrPacket {
    var r = Reader.init(payload);
    if ((try r.readByte()) != 0xff) return error.UnexpectedPacket;
    var e: ErrPacket = .{ .code = @intCast(try r.uint(2)) };
    // Protocol 41: a '#' marker then a 5-char SQLSTATE.
    if ((try r.peek()) == '#') {
        _ = try r.readByte();
        const ss = try r.bytes(5);
        @memcpy(&e.sqlstate_buf, ss);
        e.has_sqlstate = true;
    }
    const rest = r.buf[r.pos..];
    const n = @min(rest.len, e.message_buf.len);
    @memcpy(e.message_buf[0..n], rest[0..n]);
    e.message_len = @intCast(n);
    return e;
}

// ──────────────────────────────────────────────────────────────────────
// COM_QUERY (text protocol).
// ──────────────────────────────────────────────────────────────────────

pub fn encodeQuery(w: *Writer, sql: []const u8) Error!void {
    try w.writeByte(COM_QUERY);
    try w.bytes(sql);
}

/// First result-set packet after COM_QUERY: a length-encoded column count.
pub fn parseColumnCount(payload: []const u8) Error!u64 {
    var r = Reader.init(payload);
    return r.lenEncInt();
}

pub const ColumnDef = struct {
    type_code: u8,
    name_buf: [64]u8 = undefined,
    name_len: u8 = 0,

    pub fn name(self: *const ColumnDef) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// Parse a ColumnDefinition41 packet payload. We only need the type code
/// (for binary-row decoding) and the column name; the rest is skipped.
pub fn parseColumnDef(payload: []const u8) Error!ColumnDef {
    var r = Reader.init(payload);
    _ = try r.lenEncStr(); // catalog ("def")
    _ = try r.lenEncStr(); // schema
    _ = try r.lenEncStr(); // table
    _ = try r.lenEncStr(); // org_table
    const name_s = (try r.lenEncStr()) orelse &[_]u8{};
    _ = try r.lenEncStr(); // org_name
    _ = try r.lenEncInt(); // length of fixed-length fields (0x0c)
    _ = try r.uint(2); // character set
    _ = try r.uint(4); // column length
    const type_code = try r.readByte();
    var cd: ColumnDef = .{ .type_code = type_code };
    const n = @min(name_s.len, cd.name_buf.len);
    @memcpy(cd.name_buf[0..n], name_s[0..n]);
    cd.name_len = @intCast(n);
    return cd;
}

/// One text-protocol field: a length-encoded string, or NULL (0xfb).
/// `r` advances past the field. Returns null for SQL NULL.
pub fn parseTextField(r: *Reader) Error!?[]const u8 {
    return r.lenEncStr();
}

// ──────────────────────────────────────────────────────────────────────
// Prepared statements (binary protocol).
// ──────────────────────────────────────────────────────────────────────

pub fn encodePrepare(w: *Writer, sql: []const u8) Error!void {
    try w.writeByte(COM_STMT_PREPARE);
    try w.bytes(sql);
}

pub const PrepareOk = struct {
    statement_id: u32,
    num_columns: u16,
    num_params: u16,
};

/// COM_STMT_PREPARE_OK: status(0x00) + stmt id + columns + params + ...
pub fn parsePrepareOk(payload: []const u8) Error!PrepareOk {
    var r = Reader.init(payload);
    if ((try r.readByte()) != 0x00) return error.UnexpectedPacket;
    const id: u32 = @intCast(try r.uint(4));
    const cols: u16 = @intCast(try r.uint(2));
    const params: u16 = @intCast(try r.uint(2));
    return .{ .statement_id = id, .num_columns = cols, .num_params = params };
}

pub fn encodeStmtClose(w: *Writer, statement_id: u32) Error!void {
    try w.writeByte(COM_STMT_CLOSE);
    try w.uint(statement_id, 4);
}

/// One bound parameter for COM_STMT_EXECUTE. `text`/`blob` are sent as the
/// `MYSQL_TYPE_VAR_STRING`/`BLOB` length-encoded string; the dialect's `?`
/// placeholders accept these via implicit conversion.
pub const Param = union(enum) {
    null_,
    int: i64,
    real: f64,
    text: []const u8,
    blob: []const u8,

    fn typeCode(self: Param) u8 {
        return switch (self) {
            .null_ => MYSQL_TYPE_NULL,
            .int => MYSQL_TYPE_LONGLONG,
            .real => MYSQL_TYPE_DOUBLE,
            .text => MYSQL_TYPE_VAR_STRING,
            .blob => MYSQL_TYPE_BLOB,
        };
    }
};

/// Encode COM_STMT_EXECUTE for `statement_id` binding `params`.
/// Layout: cmd, stmt_id(4), flags(1=CURSOR_TYPE_NO_CURSOR=0),
/// iteration(4=1), then if params: NULL-bitmap, new_params_bound_flag(1),
/// per-param type(2), then per-param values (non-NULL only).
pub fn encodeStmtExecute(w: *Writer, statement_id: u32, params: []const Param) Error!void {
    try w.writeByte(COM_STMT_EXECUTE);
    try w.uint(statement_id, 4);
    try w.writeByte(0x00); // flags: CURSOR_TYPE_NO_CURSOR
    try w.uint(1, 4); // iteration count (always 1)
    if (params.len == 0) return;

    // NULL-bitmap: ceil(n/8) bytes, bit i set when param i is NULL.
    const bitmap_len = (params.len + 7) / 8;
    var bm: [32]u8 = [_]u8{0} ** 32; // bounded: ≤256 params
    if (bitmap_len > bm.len) return error.Unsupported;
    for (params, 0..) |p, i| {
        if (p == .null_) bm[i / 8] |= @as(u8, 1) << @intCast(i % 8);
    }
    try w.bytes(bm[0..bitmap_len]);

    try w.writeByte(0x01); // new_params_bound_flag (types follow)
    // Per-parameter type (2 bytes: type code + unsigned flag=0).
    for (params) |p| {
        try w.writeByte(p.typeCode());
        try w.writeByte(0x00);
    }
    // Per-parameter value (skip NULLs — they're in the bitmap).
    for (params) |p| {
        switch (p) {
            .null_ => {},
            .int => |v| try w.uint(@bitCast(v), 8),
            .real => |v| try w.uint(@bitCast(v), 8),
            .text => |s| try w.lenEncStr(s),
            .blob => |s| try w.lenEncStr(s),
        }
    }
}

/// One decoded binary-protocol column value.
pub const BinaryValue = union(enum) {
    null_,
    int: i64,
    real: f64,
    str: []const u8, // aliases the row buffer
};

/// Parse a binary-protocol result row. The row payload starts with a
/// 0x00 header byte, then a NULL-bitmap of ceil((n+2)/8) bytes (offset by
/// 2 per spec), then non-NULL values in column order. `out` is filled with
/// up to `out.len` decoded values; `cols` supplies each column's type.
pub fn parseBinaryRow(payload: []const u8, cols: []const ColumnDef, out: []BinaryValue) Error!void {
    std.debug.assert(out.len >= cols.len);
    var r = Reader.init(payload);
    if ((try r.readByte()) != 0x00) return error.UnexpectedPacket;

    const bitmap_len = (cols.len + 7 + 2) / 8;
    const bitmap = try r.bytes(bitmap_len);

    for (cols, 0..) |col, i| {
        const bit = i + 2; // binary-row bitmap is offset by 2
        const is_null = (bitmap[bit / 8] >> @intCast(bit % 8)) & 1 != 0;
        if (is_null) {
            out[i] = .null_;
            continue;
        }
        out[i] = try decodeBinaryValue(&r, col.type_code);
    }
}

fn decodeBinaryValue(r: *Reader, type_code: u8) Error!BinaryValue {
    return switch (type_code) {
        MYSQL_TYPE_TINY => .{ .int = @as(i8, @bitCast(try r.readByte())) },
        MYSQL_TYPE_SHORT => .{ .int = @as(i16, @bitCast(@as(u16, @intCast(try r.uint(2))))) },
        MYSQL_TYPE_LONG => .{ .int = @as(i32, @bitCast(@as(u32, @intCast(try r.uint(4))))) },
        MYSQL_TYPE_LONGLONG => .{ .int = @as(i64, @bitCast(try r.uint(8))) },
        MYSQL_TYPE_FLOAT => blk: {
            const bits: u32 = @intCast(try r.uint(4));
            const f: f32 = @bitCast(bits);
            break :blk .{ .real = f };
        },
        MYSQL_TYPE_DOUBLE => blk: {
            const bits: u64 = try r.uint(8);
            break :blk .{ .real = @bitCast(bits) };
        },
        // Everything string-ish (VARCHAR/STRING/BLOB/DECIMAL/...) is a
        // length-encoded string in the binary protocol.
        else => blk: {
            const s = (try r.lenEncStr()) orelse &[_]u8{};
            break :blk .{ .str = s };
        },
    };
}

// ──────────────────────────────────────────────────────────────────────
// Tests — pure codec round-trips, no server required.
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "lenEncInt: round-trip across all width thresholds" {
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();
    const samples = [_]u64{ 0, 1, 0xfa, 0xfb, 0xff, 0x100, 0xffff, 0x10000, 0xff_ffff, 0x100_0000, 0xdead_beef_cafe };
    for (samples) |v| {
        var buf: [16]u8 = undefined;
        var w = Writer.init(&buf);
        try w.lenEncInt(v);
        var r = Reader.init(w.slice());
        try testing.expectEqual(v, try r.lenEncInt());
        try testing.expect(r.atEnd());
    }
    // Plus a batch of random values.
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        const v = rand.int(u64) >> @intCast(rand.intRangeAtMost(u6, 0, 63));
        var buf: [16]u8 = undefined;
        var w = Writer.init(&buf);
        try w.lenEncInt(v);
        var r = Reader.init(w.slice());
        try testing.expectEqual(v, try r.lenEncInt());
    }
}

test "lenEncStr: round-trip + NULL marker" {
    var buf: [64]u8 = undefined;
    var w = Writer.init(&buf);
    try w.lenEncStr("hello mysql");
    var r = Reader.init(w.slice());
    const s = (try r.lenEncStr()) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("hello mysql", s);

    // A bare 0xfb byte parses as NULL.
    var r2 = Reader.init(&[_]u8{NULL_BYTE});
    try testing.expect((try r2.lenEncStr()) == null);
}

test "packet header encode/decode round-trip" {
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const len = rand.intRangeAtMost(u32, 0, 0xff_ffff);
        const seq = rand.int(u8);
        var hdr: [header_len]u8 = undefined;
        encodeHeader(&hdr, len, seq);
        const h = try decodeHeader(&hdr);
        try testing.expectEqual(len, h.length);
        try testing.expectEqual(seq, h.seq);
    }
}

test "parseHandshake: protocol 41 with secure-connection scramble" {
    // Hand-build a HandshakeV10 with a 20-byte scramble split 8 + 12(+NUL).
    var buf: [128]u8 = undefined;
    var w = Writer.init(&buf);
    try w.writeByte(10); // protocol version
    try w.cstr("5.7.40-mysql"); // server version
    try w.uint(0x0102_0304, 4); // connection id
    const scram = "ABCDEFGH" ++ "IJKLMNOPQRST"; // 8 + 12 = 20 bytes
    try w.bytes(scram[0..8]);
    try w.writeByte(0); // filler
    const caps = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
    try w.uint(caps & 0xffff, 2); // cap low
    try w.writeByte(0x21); // charset
    try w.uint(0, 2); // status
    try w.uint((caps >> 16) & 0xffff, 2); // cap high
    try w.writeByte(21); // auth-data length (8 + 13)
    var j: usize = 0;
    while (j < 10) : (j += 1) try w.writeByte(0); // reserved
    try w.bytes(scram[8..20]); // part2 real (12)
    try w.writeByte(0); // trailing NUL of part2
    try w.cstr("mysql_native_password");

    const h = try parseHandshake(w.slice());
    try testing.expectEqual(@as(u8, 10), h.protocol_version);
    try testing.expectEqual(caps, h.capabilities);
    try testing.expectEqualStrings("mysql_native_password", h.authPluginName());
    try testing.expectEqual(@as(u8, 20), h.scramble_len);
    try testing.expectEqualSlices(u8, scram, h.scramble());
}

test "nativePasswordScramble: empty password yields empty token; known vector is 20 bytes + deterministic" {
    var out: [20]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), nativePasswordScramble("", "anyscramble", &out));

    // Determinism + XOR self-inverse property: applying SHA1(pwd) recovers
    // SHA1(scramble || SHA1(SHA1(pwd))), which equals the same recompute.
    const pwd = "s3cr3t-passw0rd";
    const scr = "12345678901234567890"; // 20-byte scramble
    const n = nativePasswordScramble(pwd, scr, &out);
    try testing.expectEqual(@as(usize, 20), n);

    // Recompute SHA1(pwd) and verify token XOR SHA1(pwd) == inner hash,
    // proving the construction matches the documented formula.
    var sha1_pwd: [20]u8 = undefined;
    Sha1.hash(pwd, &sha1_pwd, .{});
    var sha1_sha1: [20]u8 = undefined;
    Sha1.hash(&sha1_pwd, &sha1_sha1, .{});
    var hh = Sha1.init(.{});
    hh.update(scr);
    hh.update(&sha1_sha1);
    var inner: [20]u8 = undefined;
    hh.final(&inner);
    var recovered: [20]u8 = undefined;
    for (0..20) |i| recovered[i] = out[i] ^ sha1_pwd[i];
    try testing.expectEqualSlices(u8, &inner, &recovered);

    // A second call with identical inputs is byte-identical (no state).
    var out2: [20]u8 = undefined;
    _ = nativePasswordScramble(pwd, scr, &out2);
    try testing.expectEqualSlices(u8, &out, &out2);
}

test "encodeHandshakeResponse: parses back caps + username + auth + db + plugin" {
    var token: [20]u8 = undefined;
    _ = nativePasswordScramble("pw", "12345678901234567890", &token);
    var buf: [256]u8 = undefined;
    var w = Writer.init(&buf);
    try encodeHandshakeResponse(&w, .{
        .username = "appuser",
        .auth_response = &token,
        .database = "speedy",
    });

    var r = Reader.init(w.slice());
    const caps: u32 = @intCast(try r.uint(4));
    try testing.expect(caps & CLIENT_PROTOCOL_41 != 0);
    try testing.expect(caps & CLIENT_CONNECT_WITH_DB != 0);
    try testing.expect(caps & CLIENT_SECURE_CONNECTION != 0);
    _ = try r.uint(4); // max packet
    _ = try r.readByte(); // charset
    try r.skip(23); // filler
    try testing.expectEqualStrings("appuser", try r.cstr());
    const auth_len = try r.readByte();
    try testing.expectEqual(@as(u8, 20), auth_len);
    try testing.expectEqualSlices(u8, &token, try r.bytes(20));
    try testing.expectEqualStrings("speedy", try r.cstr());
    try testing.expectEqualStrings("mysql_native_password", try r.cstr());
}

test "encodeHandshakeResponse: no database omits CONNECT_WITH_DB + db field" {
    var buf: [256]u8 = undefined;
    var w = Writer.init(&buf);
    try encodeHandshakeResponse(&w, .{ .username = "u", .auth_response = "" });
    var r = Reader.init(w.slice());
    const caps: u32 = @intCast(try r.uint(4));
    try testing.expect(caps & CLIENT_CONNECT_WITH_DB == 0);
    _ = try r.uint(4);
    _ = try r.readByte();
    try r.skip(23);
    try testing.expectEqualStrings("u", try r.cstr());
    try testing.expectEqual(@as(u8, 0), try r.readByte()); // empty auth len
    try testing.expectEqualStrings("mysql_native_password", try r.cstr());
}

test "classify + parseOk/parseErr/eof" {
    // OK: 0x00, affected=5, last_id=42, then status/warnings.
    var okbuf: [16]u8 = undefined;
    var okw = Writer.init(&okbuf);
    try okw.writeByte(0x00);
    try okw.lenEncInt(5);
    try okw.lenEncInt(42);
    try okw.uint(0x0002, 2); // status flags
    try okw.uint(0, 2); // warnings
    try testing.expectEqual(PacketKind.ok, classify(okw.slice()));
    const ok = try parseOk(okw.slice());
    try testing.expectEqual(@as(u64, 5), ok.affected_rows);
    try testing.expectEqual(@as(u64, 42), ok.last_insert_id);

    // ERR: 0xff, code 1062, '#', SQLSTATE 23000, message.
    var errbuf: [64]u8 = undefined;
    var errw = Writer.init(&errbuf);
    try errw.writeByte(0xff);
    try errw.uint(1062, 2);
    try errw.writeByte('#');
    try errw.bytes("23000");
    try errw.bytes("Duplicate entry");
    try testing.expectEqual(PacketKind.err, classify(errw.slice()));
    const e = try parseErr(errw.slice());
    try testing.expectEqual(@as(u16, 1062), e.code);
    try testing.expectEqualStrings("23000", e.sqlstate().?);
    try testing.expectEqualStrings("Duplicate entry", e.message());

    // EOF: 0xfe with < 9 bytes.
    try testing.expectEqual(PacketKind.eof, classify(&[_]u8{ 0xfe, 0, 0, 0, 0 }));
    // 0xfe with ≥ 9 bytes is NOT eof (it's a lenenc-int row lead).
    try testing.expectEqual(PacketKind.other, classify(&[_]u8{0xfe} ** 9));
}

test "encodeQuery + parseColumnCount + parseColumnDef + text row" {
    var qbuf: [64]u8 = undefined;
    var qw = Writer.init(&qbuf);
    try encodeQuery(&qw, "SELECT 1");
    try testing.expectEqual(COM_QUERY, qw.slice()[0]);
    try testing.expectEqualStrings("SELECT 1", qw.slice()[1..]);

    // Column count packet.
    var ccbuf: [4]u8 = undefined;
    var ccw = Writer.init(&ccbuf);
    try ccw.lenEncInt(2);
    try testing.expectEqual(@as(u64, 2), try parseColumnCount(ccw.slice()));

    // ColumnDefinition41 for an INT named "a".
    var cdbuf: [128]u8 = undefined;
    var cdw = Writer.init(&cdbuf);
    try cdw.lenEncStr("def");
    try cdw.lenEncStr("speedy");
    try cdw.lenEncStr("t");
    try cdw.lenEncStr("t");
    try cdw.lenEncStr("a");
    try cdw.lenEncStr("a");
    try cdw.lenEncInt(0x0c);
    try cdw.uint(0x3f, 2); // charset (binary)
    try cdw.uint(11, 4); // column length
    try cdw.writeByte(MYSQL_TYPE_LONG);
    const cd = try parseColumnDef(cdw.slice());
    try testing.expectEqual(MYSQL_TYPE_LONG, cd.type_code);
    try testing.expectEqualStrings("a", cd.name());

    // Text-protocol row: a lenenc string then a NULL.
    var rowbuf: [32]u8 = undefined;
    var roww = Writer.init(&rowbuf);
    try roww.lenEncStr("123");
    try roww.writeByte(NULL_BYTE);
    var rr = Reader.init(roww.slice());
    const f0 = (try parseTextField(&rr)) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("123", f0);
    try testing.expect((try parseTextField(&rr)) == null);
}

test "parsePrepareOk + encodePrepare + encodeStmtClose" {
    var pbuf: [32]u8 = undefined;
    var pw = Writer.init(&pbuf);
    try encodePrepare(&pw, "INSERT INTO t VALUES (?)");
    try testing.expectEqual(COM_STMT_PREPARE, pw.slice()[0]);

    var okbuf: [16]u8 = undefined;
    var okw = Writer.init(&okbuf);
    try okw.writeByte(0x00);
    try okw.uint(7, 4); // stmt id
    try okw.uint(3, 2); // columns
    try okw.uint(1, 2); // params
    const ok = try parsePrepareOk(okw.slice());
    try testing.expectEqual(@as(u32, 7), ok.statement_id);
    try testing.expectEqual(@as(u16, 3), ok.num_columns);
    try testing.expectEqual(@as(u16, 1), ok.num_params);

    var cbuf: [8]u8 = undefined;
    var cw = Writer.init(&cbuf);
    try encodeStmtClose(&cw, 7);
    try testing.expectEqual(COM_STMT_CLOSE, cw.slice()[0]);
    var cr = Reader.init(cw.slice()[1..]);
    try testing.expectEqual(@as(u64, 7), try cr.uint(4));
}

test "encodeStmtExecute: NULL-bitmap + types + values for mixed params" {
    const params = [_]Param{
        .{ .int = -7 },
        .null_,
        .{ .text = "hi" },
        .{ .real = 1.5 },
    };
    var buf: [128]u8 = undefined;
    var w = Writer.init(&buf);
    try encodeStmtExecute(&w, 9, &params);

    var r = Reader.init(w.slice());
    try testing.expectEqual(COM_STMT_EXECUTE, try r.readByte());
    try testing.expectEqual(@as(u64, 9), try r.uint(4));
    try testing.expectEqual(@as(u8, 0), try r.readByte()); // flags
    try testing.expectEqual(@as(u64, 1), try r.uint(4)); // iteration

    // NULL-bitmap: 1 byte for 4 params, only bit 1 set (the .null_).
    const bm = try r.readByte();
    try testing.expectEqual(@as(u8, 0b0000_0010), bm);
    try testing.expectEqual(@as(u8, 0x01), try r.readByte()); // new_params_bound

    // Types (2 bytes each, in order).
    try testing.expectEqual(MYSQL_TYPE_LONGLONG, try r.readByte());
    _ = try r.readByte();
    try testing.expectEqual(MYSQL_TYPE_NULL, try r.readByte());
    _ = try r.readByte();
    try testing.expectEqual(MYSQL_TYPE_VAR_STRING, try r.readByte());
    _ = try r.readByte();
    try testing.expectEqual(MYSQL_TYPE_DOUBLE, try r.readByte());
    _ = try r.readByte();

    // Values (NULL skipped): int(-7), str "hi", double 1.5.
    try testing.expectEqual(@as(i64, -7), @as(i64, @bitCast(try r.uint(8))));
    const s = (try r.lenEncStr()) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("hi", s);
    try testing.expectEqual(@as(f64, 1.5), @as(f64, @bitCast(try r.uint(8))));
    try testing.expect(r.atEnd());
}

test "parseBinaryRow: NULL-bitmap offset-by-2 + per-type decode" {
    // Columns: LONGLONG, VAR_STRING, DOUBLE — middle one NULL.
    const cols = [_]ColumnDef{
        .{ .type_code = MYSQL_TYPE_LONGLONG },
        .{ .type_code = MYSQL_TYPE_VAR_STRING },
        .{ .type_code = MYSQL_TYPE_DOUBLE },
    };
    var buf: [64]u8 = undefined;
    var w = Writer.init(&buf);
    try w.writeByte(0x00); // row header
    // bitmap: ceil((3+2)/8)=1 byte. Column index 1 NULL → bit (1+2)=3.
    try w.writeByte(@as(u8, 1) << 3);
    try w.uint(@bitCast(@as(i64, 123456789)), 8); // col0
    // col1 NULL → no bytes
    try w.uint(@bitCast(@as(f64, 2.71828)), 8); // col2

    var out: [3]BinaryValue = undefined;
    try parseBinaryRow(w.slice(), &cols, &out);
    try testing.expectEqual(@as(i64, 123456789), out[0].int);
    try testing.expect(out[1] == .null_);
    try testing.expectApproxEqAbs(@as(f64, 2.71828), out[2].real, 1e-9);
}

test "Reader: truncation is a typed error, never OOB" {
    var r = Reader.init(&[_]u8{ 0x01, 0x02 });
    try testing.expectError(error.Truncated, r.uint(4));
    var r2 = Reader.init(&[_]u8{});
    try testing.expectError(error.Truncated, r2.readByte());
    var r3 = Reader.init(&[_]u8{ 'a', 'b' }); // no NUL terminator
    try testing.expectError(error.Truncated, r3.cstr());
}
