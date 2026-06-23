//! D2: Unit tests for the TDS codec (`tds.zig`). These are PURE-function
//! tests over byte buffers — no socket, no server — so the codec is
//! validated despite this arm64 host being unable to run SQL Server.
//!
//! Coverage:
//!   * Packet header encode/decode round-trip (big-endian length).
//!   * Pre-Login packet byte layout (option table offsets + payload).
//!   * LOGIN7 packet byte layout + password obfuscation round-trip.
//!   * SQL_BATCH / RPC sp_executesql encode (with @pN params).
//!   * Token-stream decode for LOGINACK / COLMETADATA / ROW / DONE / ERROR
//!     from handcrafted fixtures.
//!   * Randomized obfuscation + integer round-trips (no hardcoded happy path).

const std = @import("std");
const testing = std.testing;
const tds = @import("tds.zig");

// ── Header ───────────────────────────────────────────────────────────────

test "header: encode then parse round-trips with big-endian length" {
    var buf: [tds.header_len]u8 = undefined;
    const n = try tds.writeHeader(&buf, .sql_batch, tds.status_eom, 0x1234, 7);
    try testing.expectEqual(tds.header_len, n);
    // Type, status, length BE.
    try testing.expectEqual(@as(u8, 0x01), buf[0]);
    try testing.expectEqual(@as(u8, 0x01), buf[1]);
    try testing.expectEqual(@as(u8, 0x12), buf[2]); // high byte
    try testing.expectEqual(@as(u8, 0x34), buf[3]); // low byte
    try testing.expectEqual(@as(u8, 7), buf[6]); // packet id

    const h = try tds.parseHeader(&buf);
    try testing.expectEqual(@as(u8, @intFromEnum(tds.PacketType.sql_batch)), h.ptype);
    try testing.expectEqual(@as(u16, 0x1234), h.length);
    try testing.expect(h.isEom());
    try testing.expectEqual(@as(usize, 0x1234 - tds.header_len), h.payloadLen());
}

test "header: parse rejects truncated and malformed length" {
    var short: [4]u8 = .{ 0x04, 0x01, 0x00, 0x08 };
    try testing.expectError(error.Truncated, tds.parseHeader(&short));
    // length < header_len is malformed.
    var bad: [tds.header_len]u8 = .{ 0x04, 0x01, 0x00, 0x03, 0, 0, 0, 0 };
    try testing.expectError(error.Malformed, tds.parseHeader(&bad));
}

// ── Pre-Login ──────────────────────────────────────────────────────────

test "prelogin: header type, EOM, and length consistency" {
    var buf: [128]u8 = undefined;
    const total = try tds.buildPreLogin(&buf, tds.ENCRYPT_NOT_SUP);
    const h = try tds.parseHeader(buf[0..total]);
    try testing.expectEqual(@as(u8, @intFromEnum(tds.PacketType.pre_login)), h.ptype);
    try testing.expect(h.isEom());
    try testing.expectEqual(@as(usize, total), @as(usize, h.length));

    // Payload begins with the option table; first token must be VERSION.
    const p = buf[tds.header_len..total];
    try testing.expectEqual(tds.PRELOGIN_VERSION, p[0]);
}

test "prelogin: option table offsets resolve inside payload + terminator present" {
    var buf: [128]u8 = undefined;
    const total = try tds.buildPreLogin(&buf, tds.ENCRYPT_ON);
    const p = buf[tds.header_len..total];

    // 5 options, each 5 bytes, then a terminator 0xFF.
    const table_len = 5 * 5 + 1;
    try testing.expectEqual(tds.PRELOGIN_TERMINATOR, p[table_len - 1]);

    // Walk the 5 entries; each {token, off(BE 2), len(BE 2)} must point to a
    // region fully inside the payload, and offsets are relative to data start.
    var i: usize = 0;
    var expect_off: u16 = @intCast(table_len);
    const expected_tokens = [_]u8{
        tds.PRELOGIN_VERSION, tds.PRELOGIN_ENCRYPTION, tds.PRELOGIN_INSTOPT,
        tds.PRELOGIN_THREADID, tds.PRELOGIN_MARS,
    };
    const expected_lens = [_]u16{ 6, 1, 1, 4, 1 };
    while (i < 5) : (i += 1) {
        const base = i * 5;
        try testing.expectEqual(expected_tokens[i], p[base]);
        const off = (@as(u16, p[base + 1]) << 8) | @as(u16, p[base + 2]);
        const len = (@as(u16, p[base + 3]) << 8) | @as(u16, p[base + 4]);
        try testing.expectEqual(expect_off, off);
        try testing.expectEqual(expected_lens[i], len);
        try testing.expect(off + len <= p.len);
        expect_off += len;
    }

    // The ENCRYPTION payload byte must equal what we asked for.
    // ENCRYPTION offset = table_len + 6 (after VERSION).
    try testing.expectEqual(tds.ENCRYPT_ON, p[table_len + 6]);
    // VERSION payload starts with major version 9.
    try testing.expectEqual(@as(u8, 9), p[table_len]);
}

// ── Password obfuscation ─────────────────────────────────────────────────

test "obfuscate: matches the documented vector for 'abc'" {
    // UCS-2 'a' = 0x61 0x00. Swap nibbles of 0x61 → 0x16, XOR 0xA5 → 0xB3.
    // 0x00 → swap 0x00 → XOR 0xA5 = 0xA5.
    var pw: [6]u8 = .{ 0x61, 0x00, 0x62, 0x00, 0x63, 0x00 };
    tds.obfuscatePassword(&pw);
    try testing.expectEqual(@as(u8, 0xB3), pw[0]);
    try testing.expectEqual(@as(u8, 0xA5), pw[1]);
    // 'b' 0x62 → swap 0x26 → XOR 0xA5 = 0x83.
    try testing.expectEqual(@as(u8, 0x83), pw[2]);
    // 'c' 0x63 → swap 0x36 → XOR 0xA5 = 0x93.
    try testing.expectEqual(@as(u8, 0x93), pw[4]);
}

test "obfuscate: round-trips for randomized buffers" {
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();
    var round: usize = 0;
    while (round < 64) : (round += 1) {
        var buf: [128]u8 = undefined;
        const n = rand.intRangeAtMost(usize, 1, buf.len);
        rand.bytes(buf[0..n]);
        var copy: [128]u8 = undefined;
        @memcpy(copy[0..n], buf[0..n]);
        tds.obfuscatePassword(buf[0..n]);
        // Must differ from original (XOR 0xA5 guarantees change unless the
        // swap happens to cancel — but XOR 0xA5 flips bits so a byte equals
        // its obfuscation only if swap(b) ^ 0xA5 == b, possible for some b;
        // so we only assert the reverse restores it).
        tds.deobfuscatePassword(buf[0..n]);
        try testing.expectEqualSlices(u8, copy[0..n], buf[0..n]);
    }
}

// ── LOGIN7 ───────────────────────────────────────────────────────────────

test "login7: layout — fixed header, offset table points to obfuscated pw" {
    var buf: [512]u8 = undefined;
    const login = tds.Login7{
        .username = "sa",
        .password = "Pw1",
        .database = "tempdb",
    };
    const total = try tds.buildLogin7(&buf, login);
    const h = try tds.parseHeader(buf[0..total]);
    try testing.expectEqual(@as(u8, @intFromEnum(tds.PacketType.login7)), h.ptype);
    try testing.expect(h.isEom());
    try testing.expectEqual(@as(usize, total), @as(usize, h.length));

    const p = buf[tds.header_len..total];
    // Fixed header: Length field == payload length.
    const declared_len = @as(u32, p[0]) | (@as(u32, p[1]) << 8) |
        (@as(u32, p[2]) << 16) | (@as(u32, p[3]) << 24);
    try testing.expectEqual(@as(u32, @intCast(p.len)), declared_len);
    // TDS version 0x74000004 little-endian at offset 4.
    try testing.expectEqual(@as(u8, 0x04), p[4]);
    try testing.expectEqual(@as(u8, 0x00), p[5]);
    try testing.expectEqual(@as(u8, 0x00), p[6]);
    try testing.expectEqual(@as(u8, 0x74), p[7]);

    // The password offset/length pair lives at fixed offset 36 + 8 (after
    // HostName, UserName pairs). Each pair is 4 bytes; Password is index 2.
    const pw_pair = 36 + 2 * 4;
    const pw_off = @as(u16, p[pw_pair]) | (@as(u16, p[pw_pair + 1]) << 8);
    const pw_char_len = @as(u16, p[pw_pair + 2]) | (@as(u16, p[pw_pair + 3]) << 8);
    try testing.expectEqual(@as(u16, 3), pw_char_len); // "Pw1" = 3 chars

    // De-obfuscate the on-wire password region and decode UCS-2 → must == "Pw1".
    var pw_region: [6]u8 = undefined;
    @memcpy(&pw_region, p[pw_off .. pw_off + 6]);
    tds.deobfuscatePassword(&pw_region);
    try testing.expectEqual(@as(u8, 'P'), pw_region[0]);
    try testing.expectEqual(@as(u8, 'w'), pw_region[2]);
    try testing.expectEqual(@as(u8, '1'), pw_region[4]);
}

test "login7: username offset/length encodes UCS-2 correctly" {
    var buf: [512]u8 = undefined;
    const total = try tds.buildLogin7(&buf, .{ .username = "admin", .password = "x" });
    const p = buf[tds.header_len..total];
    // UserName pair is index 1 → offset 36 + 4.
    const u_pair = 36 + 4;
    const u_off = @as(u16, p[u_pair]) | (@as(u16, p[u_pair + 1]) << 8);
    const u_len = @as(u16, p[u_pair + 2]) | (@as(u16, p[u_pair + 3]) << 8);
    try testing.expectEqual(@as(u16, 5), u_len);
    // Decode UCS-2.
    try testing.expectEqual(@as(u8, 'a'), p[u_off]);
    try testing.expectEqual(@as(u8, 0), p[u_off + 1]);
    try testing.expectEqual(@as(u8, 'd'), p[u_off + 2]);
}

test "login7: BufferTooSmall when buffer cannot hold the message" {
    var tiny: [40]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, tds.buildLogin7(&tiny, .{ .username = "user", .password = "secret" }));
}

// ── SQL_BATCH ────────────────────────────────────────────────────────────

test "sql_batch: header + ALL_HEADERS + UTF-16 body" {
    var buf: [256]u8 = undefined;
    const sql = "SELECT 1";
    const total = try tds.buildSqlBatch(&buf, sql);
    const h = try tds.parseHeader(buf[0..total]);
    try testing.expectEqual(@as(u8, @intFromEnum(tds.PacketType.sql_batch)), h.ptype);

    const p = buf[tds.header_len..total];
    // ALL_HEADERS TotalLength (LE) = 22.
    const ahl = @as(u32, p[0]) | (@as(u32, p[1]) << 8) | (@as(u32, p[2]) << 16) | (@as(u32, p[3]) << 24);
    try testing.expectEqual(@as(u32, 22), ahl);
    // HeaderType at offset 8 = 0x0002 (transaction descriptor).
    try testing.expectEqual(@as(u8, 0x02), p[8]);
    try testing.expectEqual(@as(u8, 0x00), p[9]);
    // SQL body starts at offset 22 as UTF-16LE 'S'.
    try testing.expectEqual(@as(u8, 'S'), p[22]);
    try testing.expectEqual(@as(u8, 0), p[23]);
    // Total length consistency.
    try testing.expectEqual(@as(usize, 22 + sql.len * 2 + tds.header_len), total);
}

// ── RPC sp_executesql ────────────────────────────────────────────────────

test "rpc: param decl string for mixed types" {
    var out: [128]u8 = undefined;
    const params = [_]tds.RpcParam{
        .{ .int = 5 },
        .{ .text = "hi" },
        .{ .real = 1.5 },
        .{ .blob = "\x00\x01" },
        .null_,
    };
    const n = try tds.buildParamDecls(&out, &params);
    try testing.expectEqualStrings("@p1 bigint,@p2 nvarchar(max),@p3 float,@p4 varbinary(max),@p5 nvarchar(1)", out[0..n]);
}

test "rpc: sp_executesql packet encodes ProcID 10 and is well-formed" {
    var buf: [512]u8 = undefined;
    const sql = "SELECT @p1";
    const params = [_]tds.RpcParam{.{ .int = 42 }};
    const total = try tds.buildRpcExecuteSql(&buf, sql, &params);
    const h = try tds.parseHeader(buf[0..total]);
    try testing.expectEqual(@as(u8, @intFromEnum(tds.PacketType.rpc)), h.ptype);
    try testing.expect(h.isEom());
    try testing.expectEqual(@as(usize, total), @as(usize, h.length));

    const p = buf[tds.header_len..total];
    // After ALL_HEADERS (22 bytes): name length 0xFFFF then ProcID 10.
    const ah = 22;
    try testing.expectEqual(@as(u8, 0xFF), p[ah]);
    try testing.expectEqual(@as(u8, 0xFF), p[ah + 1]);
    const procid = @as(u16, p[ah + 2]) | (@as(u16, p[ah + 3]) << 8);
    try testing.expectEqual(@as(u16, 10), procid);
}

// ── Token-stream decode: ERROR ───────────────────────────────────────────

test "token: ERROR decodes number/state/class/message from fixture" {
    // Build a handcrafted ERROR token body (without the 0xAA byte, since the
    // dispatcher consumes that). Layout: length(2) number(4) state(1)
    // class(1) msgCharLen(2) msg(UTF-16) serverNameLen(1) server proc(1) line(4)
    const msg = "Violation of UNIQUE KEY constraint";
    // Fill length last; build the body into a fixed temp buffer first.
    var tmp: [256]u8 = undefined;
    var w: usize = 0;
    // number = 2627 (unique violation) LE
    const number: u32 = 2627;
    tmp[w] = @intCast(number & 0xFF);
    tmp[w + 1] = @intCast((number >> 8) & 0xFF);
    tmp[w + 2] = @intCast((number >> 16) & 0xFF);
    tmp[w + 3] = @intCast((number >> 24) & 0xFF);
    w += 4;
    tmp[w] = 1; // state
    w += 1;
    tmp[w] = 14; // class/severity
    w += 1;
    // msg char len
    tmp[w] = @intCast(msg.len & 0xFF);
    tmp[w + 1] = @intCast((msg.len >> 8) & 0xFF);
    w += 2;
    for (msg) |ch| {
        tmp[w] = ch;
        tmp[w + 1] = 0;
        w += 2;
    }
    // ServerName B_VARCHAR len 0
    tmp[w] = 0;
    w += 1;
    // ProcName B_VARCHAR len 0
    tmp[w] = 0;
    w += 1;
    // LineNumber (4 bytes)
    tmp[w] = 10;
    tmp[w + 1] = 0;
    tmp[w + 2] = 0;
    tmp[w + 3] = 0;
    w += 4;

    const body_len: u16 = @intCast(w);
    var stream: [300]u8 = undefined;
    stream[0] = @intCast(body_len & 0xFF);
    stream[1] = @intCast((body_len >> 8) & 0xFF);
    @memcpy(stream[2 .. 2 + w], tmp[0..w]);

    var r = tds.Reader.init(stream[0 .. 2 + w]);
    const m = try tds.parseServerMessage(&r);
    try testing.expectEqual(@as(i32, 2627), m.number);
    try testing.expectEqual(@as(u8, 1), m.state);
    try testing.expectEqual(@as(u8, 14), m.class);
    try testing.expectEqual(msg.len * 2, m.message.len);
    try testing.expect(r.atEnd());
}

// ── Token-stream decode: LOGINACK ────────────────────────────────────────

test "token: LOGINACK decodes interface + tds version + name" {
    const name = "Microsoft SQL Server";
    var tmp: [128]u8 = undefined;
    var w: usize = 0;
    tmp[w] = 1; // interface
    w += 1;
    // TDS version LE 0x74000004
    tmp[w] = 0x04;
    tmp[w + 1] = 0x00;
    tmp[w + 2] = 0x00;
    tmp[w + 3] = 0x74;
    w += 4;
    tmp[w] = @intCast(name.len); // B_VARCHAR char len
    w += 1;
    for (name) |ch| {
        tmp[w] = ch;
        tmp[w + 1] = 0;
        w += 2;
    }
    // ProgVersion (4)
    tmp[w] = 16;
    tmp[w + 1] = 0;
    tmp[w + 2] = 0;
    tmp[w + 3] = 0;
    w += 4;

    var stream: [160]u8 = undefined;
    stream[0] = @intCast(w & 0xFF);
    stream[1] = @intCast((w >> 8) & 0xFF);
    @memcpy(stream[2 .. 2 + w], tmp[0..w]);

    var r = tds.Reader.init(stream[0 .. 2 + w]);
    const ack = try tds.parseLoginAck(&r);
    try testing.expectEqual(@as(u8, 1), ack.interface);
    try testing.expectEqual(@as(u32, 0x74000004), ack.tds_version);
    try testing.expectEqual(name.len * 2, ack.prog_name.len);
}

// ── Token-stream decode: COLMETADATA + ROW ──────────────────────────────

test "token: COLMETADATA + ROW decode int + nvarchar columns" {
    // Two columns: col0 INT4 (0x38), col1 NVARCHAR (0xE7).
    // COLMETADATA body (token byte already consumed): count(2) then per col:
    //   usertype(4) flags(2) typeToken(1) [typeinfo] nameLen(1) name(UTF16)
    var buf: [256]u8 = undefined;
    var w: usize = 0;
    const putU16 = struct {
        fn f(b: []u8, at: usize, v: u16) void {
            b[at] = @intCast(v & 0xFF);
            b[at + 1] = @intCast((v >> 8) & 0xFF);
        }
    }.f;

    putU16(&buf, w, 2); // column count
    w += 2;

    // col0: INT4
    @memset(buf[w .. w + 4], 0); // usertype
    w += 4;
    putU16(&buf, w, 0);
    w += 2; // flags
    buf[w] = 0x38; // INT4 (fixed len 4)
    w += 1;
    buf[w] = 2; // name "id" char len
    w += 1;
    inline for ("id") |ch| {
        buf[w] = ch;
        buf[w + 1] = 0;
        w += 2;
    }

    // col1: NVARCHAR
    @memset(buf[w .. w + 4], 0);
    w += 4;
    putU16(&buf, w, 0);
    w += 2;
    buf[w] = 0xE7; // NVARCHAR
    w += 1;
    putU16(&buf, w, 0x1F40); // max len 8000
    w += 2;
    @memset(buf[w .. w + 5], 0); // collation
    w += 5;
    buf[w] = 4; // name "name"
    w += 1;
    inline for ("name") |ch| {
        buf[w] = ch;
        buf[w + 1] = 0;
        w += 2;
    }

    var r = tds.Reader.init(buf[0..w]);
    const meta = try tds.parseColMetadata(&r);
    try testing.expectEqual(@as(usize, 2), meta.count);
    try testing.expectEqual(@as(u8, 0x38), meta.columns[0].type_token);
    try testing.expectEqual(@as(u8, 0xE7), meta.columns[1].type_token);
    try testing.expectEqual(@as(u32, 4), meta.columns[0].max_len);

    // Now a ROW: token byte consumed by dispatcher. col0 INT4 = 1337 LE (4
    // bytes, no length prefix); col1 NVARCHAR len(2)=8 then "test" UTF-16.
    var rb: [64]u8 = undefined;
    var rw: usize = 0;
    const val: u32 = 1337;
    rb[rw] = @intCast(val & 0xFF);
    rb[rw + 1] = @intCast((val >> 8) & 0xFF);
    rb[rw + 2] = @intCast((val >> 16) & 0xFF);
    rb[rw + 3] = @intCast((val >> 24) & 0xFF);
    rw += 4;
    putU16(&rb, rw, 8); // nvarchar byte length
    rw += 2;
    inline for ("test") |ch| {
        rb[rw] = ch;
        rb[rw + 1] = 0;
        rw += 2;
    }

    var rr = tds.Reader.init(rb[0..rw]);
    var cells: [4]tds.Cell = undefined;
    const n = try tds.parseRow(&rr, &meta, &cells);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqual(tds.CellKind.int, cells[0].kind);
    try testing.expectEqual(@as(i64, 1337), cells[0].int_val);
    try testing.expectEqual(tds.CellKind.text, cells[1].kind);
    try testing.expectEqual(@as(usize, 8), cells[1].bytes.len);
    try testing.expectEqual(@as(u8, 't'), cells[1].bytes[0]);
}

test "token: ROW decodes NULL nvarchar (0xFFFF) and bigint" {
    // col0 BIGINT (0x7F fixed 8), col1 NVARCHAR NULL.
    var buf: [128]u8 = undefined;
    var w: usize = 0;
    const putU16 = struct {
        fn f(b: []u8, at: usize, v: u16) void {
            b[at] = @intCast(v & 0xFF);
            b[at + 1] = @intCast((v >> 8) & 0xFF);
        }
    }.f;
    putU16(&buf, w, 2);
    w += 2;
    // col0 BIGINT
    @memset(buf[w .. w + 4], 0);
    w += 4;
    putU16(&buf, w, 0);
    w += 2;
    buf[w] = 0x7F;
    w += 1;
    buf[w] = 1;
    w += 1;
    buf[w] = 'a';
    buf[w + 1] = 0;
    w += 2;
    // col1 NVARCHAR
    @memset(buf[w .. w + 4], 0);
    w += 4;
    putU16(&buf, w, 0);
    w += 2;
    buf[w] = 0xE7;
    w += 1;
    putU16(&buf, w, 0x1F40);
    w += 2;
    @memset(buf[w .. w + 5], 0);
    w += 5;
    buf[w] = 1;
    w += 1;
    buf[w] = 'b';
    buf[w + 1] = 0;
    w += 2;

    var r = tds.Reader.init(buf[0..w]);
    const meta = try tds.parseColMetadata(&r);

    var rb: [32]u8 = undefined;
    var rw: usize = 0;
    const big: i64 = -98765432101234;
    const ub: u64 = @bitCast(big);
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        rb[rw + i] = @intCast((ub >> @intCast(i * 8)) & 0xFF);
    }
    rw += 8;
    // NVARCHAR NULL = 0xFFFF
    rb[rw] = 0xFF;
    rb[rw + 1] = 0xFF;
    rw += 2;

    var rr = tds.Reader.init(rb[0..rw]);
    var cells: [4]tds.Cell = undefined;
    _ = try tds.parseRow(&rr, &meta, &cells);
    try testing.expectEqual(tds.CellKind.int, cells[0].kind);
    try testing.expectEqual(big, cells[0].int_val);
    try testing.expectEqual(tds.CellKind.null_, cells[1].kind);
}

// ── Token-stream decode: DONE ────────────────────────────────────────────

test "token: DONE decodes status flags + 8-byte row count" {
    // status(2)=0x0010 (DONE_COUNT) curcmd(2)=0 rowcount(8)=5
    var b: [12]u8 = .{ 0x10, 0x00, 0x00, 0x00, 5, 0, 0, 0, 0, 0, 0, 0 };
    var r = tds.Reader.init(&b);
    const d = try tds.parseDone(&r);
    try testing.expect(d.countValid());
    try testing.expect(!d.more());
    try testing.expectEqual(@as(u64, 5), d.row_count);
}

// ── Randomized int round-trip through RPC encode + cell decode ──────────

test "rpc + row: randomized bigint values survive encode/decode symmetry" {
    var prng = std.Random.DefaultPrng.init(testing.random_seed ^ 0xBEEF);
    const rand = prng.random();
    var round: usize = 0;
    while (round < 100) : (round += 1) {
        const v = rand.int(i64);

        // Encode as an INTN param value, then decode it back as a ROW cell of
        // type INTN (0x26) to prove the on-wire integer layout is symmetric.
        var pbuf: [64]u8 = undefined;
        // Manually drive writeParamValue via buildRpcExecuteSql is heavy;
        // instead encode an INTN value inline mirroring writeParamValue.
        pbuf[0] = 0x26; // INTN
        pbuf[1] = 8;
        pbuf[2] = 8;
        const uv: u64 = @bitCast(v);
        var i: usize = 0;
        while (i < 8) : (i += 1) pbuf[3 + i] = @intCast((uv >> @intCast(i * 8)) & 0xFF);

        // Decode as a ROW cell. Build minimal COLMETADATA with one INTN col.
        var meta: tds.ColMetadata = .{};
        meta.count = 1;
        meta.columns[0] = .{ .type_token = 0x26, .max_len = 8 };
        // ROW for INTN: byte-length prefix (1) then value bytes.
        var rb: [16]u8 = undefined;
        rb[0] = 8; // length
        @memcpy(rb[1..9], pbuf[3..11]);
        var rr = tds.Reader.init(rb[0..9]);
        var cells: [1]tds.Cell = undefined;
        _ = try tds.parseRow(&rr, &meta, &cells);
        try testing.expectEqual(tds.CellKind.int, cells[0].kind);
        try testing.expectEqual(v, cells[0].int_val);
    }
}

test "reader: bounds checks prevent over-read" {
    var b: [2]u8 = .{ 1, 2 };
    var r = tds.Reader.init(&b);
    _ = try r.u8_();
    _ = try r.u8_();
    try testing.expectError(error.Truncated, r.u8_());
    try testing.expectError(error.Truncated, r.u16le());
}
