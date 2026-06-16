//! C2: Server Name Indication (SNI) extraction from a TLS ClientHello.
//!
//! The very first bytes a TLS client sends — the ClientHello record — are
//! plaintext (TLS 1.2 and 1.3 alike; the encryption only begins after the
//! handshake). The `server_name` extension (RFC 6066 §3, carried through
//! RFC 8446 §4.1.2) therefore lets a server pick the right certificate
//! *before* it starts the handshake.
//!
//! We `recv(…, MSG_PEEK)` the first record without consuming it, parse out
//! the `host_name`, then hand the still-buffered bytes to the real TLS
//! engine, which re-reads them from the socket as if we'd never looked.
//! No patch to the TLS library is required.
//!
//! The parser is total: every malformed / truncated / unexpected input
//! returns `null` rather than erroring or reading out of bounds. SNI is a
//! routing hint, never trusted data — a missing or bogus name simply
//! falls back to the default certificate.
//!
//! Record layout we walk (all integers big-endian):
//!
//!   TLSPlaintext           : type(1)=0x16  legacy_version(2)  length(2)
//!   Handshake              : msg_type(1)=0x01  length(3)
//!   ClientHello            : legacy_version(2)  random(32)
//!                            session_id          <opaque 8..  u8 len>
//!                            cipher_suites       <          u16 len>
//!                            compression_methods <opaque 1..  u8 len>
//!                            extensions          <          u16 len>
//!   Extension              : extension_type(2)  extension_data<u16 len>
//!   server_name (type 0)   : server_name_list<u16 len> of
//!                              { name_type(1)=0  HostName<u16 len> }

const std = @import("std");

const handshake_record: u8 = 0x16;
const client_hello: u8 = 0x01;
const ext_server_name: u16 = 0x0000;
const name_type_host: u8 = 0x00;

/// Largest ClientHello we will peek. Real ClientHellos are a few hundred
/// bytes; 4 KiB covers even ones padded with many extensions / large
/// session tickets without unbounded buffering.
pub const max_peek: usize = 4096;

/// A little-endian-safe sequential reader over a byte slice that never
/// reads past the end — every accessor returns `null` on underflow.
const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn readU8(self: *Cursor) ?u8 {
        if (self.pos + 1 > self.buf.len) return null;
        const v = self.buf[self.pos];
        self.pos += 1;
        return v;
    }

    fn readU16(self: *Cursor) ?u16 {
        if (self.pos + 2 > self.buf.len) return null;
        const v = std.mem.readInt(u16, self.buf[self.pos..][0..2], .big);
        self.pos += 2;
        return v;
    }

    fn readU24(self: *Cursor) ?u32 {
        if (self.pos + 3 > self.buf.len) return null;
        const b = self.buf[self.pos..][0..3];
        self.pos += 3;
        return (@as(u32, b[0]) << 16) | (@as(u32, b[1]) << 8) | @as(u32, b[2]);
    }

    /// Advance `n` bytes; returns false if that would overrun.
    fn skip(self: *Cursor, n: usize) bool {
        if (self.pos + n > self.buf.len) return false;
        self.pos += n;
        return true;
    }

    /// Borrow `n` bytes and advance; null on overrun.
    fn take(self: *Cursor, n: usize) ?[]const u8 {
        if (self.pos + n > self.buf.len) return null;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }
};

/// Parse a buffered ClientHello record and return the SNI `host_name`,
/// or null if absent/malformed. The returned slice aliases `record`.
pub fn parseServerName(record: []const u8) ?[]const u8 {
    var c = Cursor{ .buf = record };

    // ── TLS record header ──
    if ((c.readU8() orelse return null) != handshake_record) return null;
    _ = c.readU16() orelse return null; // legacy record version
    const rec_len = c.readU16() orelse return null;
    // The handshake body must fit within the declared record length and
    // within what we actually peeked. Clamp the cursor's view to the
    // smaller of the two so a lying length can't read neighbouring data.
    const body_end = @min(c.pos + rec_len, record.len);
    c.buf = record[0..body_end];

    // ── Handshake header ──
    if ((c.readU8() orelse return null) != client_hello) return null;
    _ = c.readU24() orelse return null; // handshake length

    // ── ClientHello ──
    _ = c.readU16() orelse return null; // legacy_version
    if (!c.skip(32)) return null; // random

    const sid_len = c.readU8() orelse return null;
    if (!c.skip(sid_len)) return null; // session_id

    const cs_len = c.readU16() orelse return null;
    if (!c.skip(cs_len)) return null; // cipher_suites

    const comp_len = c.readU8() orelse return null;
    if (!c.skip(comp_len)) return null; // compression_methods

    // Extensions block is optional in the wire format (absent => no SNI).
    const ext_total = c.readU16() orelse return null;
    const ext_end = @min(c.pos + ext_total, c.buf.len);

    while (c.pos < ext_end) {
        const ext_type = c.readU16() orelse return null;
        const ext_len = c.readU16() orelse return null;
        const ext_data = c.take(ext_len) orelse return null;
        if (ext_type == ext_server_name) {
            return parseServerNameExtension(ext_data);
        }
    }
    return null;
}

/// Parse the body of a `server_name` extension and return the first
/// `host_name` entry. Per RFC 6066 the list may carry multiple names but
/// in practice (and per RFC 8446) it carries exactly one HostName.
fn parseServerNameExtension(data: []const u8) ?[]const u8 {
    var c = Cursor{ .buf = data };
    const list_len = c.readU16() orelse return null;
    const list_end = @min(c.pos + list_len, data.len);
    while (c.pos < list_end) {
        const name_type = c.readU8() orelse return null;
        const name_len = c.readU16() orelse return null;
        const name = c.take(name_len) orelse return null;
        if (name_type == name_type_host and name.len > 0) return name;
    }
    return null;
}

/// Peek the first TLS record on `fd` without consuming it and extract the
/// SNI host. `scratch` is caller-owned (size it to `max_peek`). Returns
/// null on any read error or when no SNI is present — the caller falls
/// back to the default certificate. The bytes stay in the socket buffer
/// for the TLS engine to read normally.
pub fn peekServerName(fd: std.c.fd_t, scratch: []u8) ?[]const u8 {
    const want = @min(scratch.len, max_peek);
    const n = std.c.recv(fd, scratch.ptr, want, std.c.MSG.PEEK);
    if (n <= 0) return null;
    return parseServerName(scratch[0..@intCast(n)]);
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

/// Build a minimal but well-formed ClientHello record carrying a single
/// SNI host. Returns the number of bytes written into `out`.
fn buildClientHello(out: []u8, host: []const u8) usize {
    var w: usize = 0;
    const put8 = struct {
        fn f(b: []u8, p: *usize, v: u8) void {
            b[p.*] = v;
            p.* += 1;
        }
    }.f;
    const put16 = struct {
        fn f(b: []u8, p: *usize, v: u16) void {
            std.mem.writeInt(u16, b[p.*..][0..2], v, .big);
            p.* += 2;
        }
    }.f;

    // Build the SNI extension data first so we know its length.
    var sni_ext: [300]u8 = undefined;
    var sp: usize = 0;
    // server_name_list length
    put16(&sni_ext, &sp, @intCast(1 + 2 + host.len));
    put8(&sni_ext, &sp, name_type_host);
    put16(&sni_ext, &sp, @intCast(host.len));
    @memcpy(sni_ext[sp .. sp + host.len], host);
    sp += host.len;
    const sni_data = sni_ext[0..sp];

    // Extensions block: just the one server_name extension.
    var exts: [320]u8 = undefined;
    var ep: usize = 0;
    put16(&exts, &ep, ext_server_name);
    put16(&exts, &ep, @intCast(sni_data.len));
    @memcpy(exts[ep .. ep + sni_data.len], sni_data);
    ep += sni_data.len;
    const ext_block = exts[0..ep];

    // ClientHello body.
    var body: [512]u8 = undefined;
    var bp: usize = 0;
    put16(&body, &bp, 0x0303); // legacy_version TLS 1.2
    @memset(body[bp .. bp + 32], 0xAB); // random
    bp += 32;
    put8(&body, &bp, 0); // session_id length 0
    put16(&body, &bp, 2); // cipher_suites length
    put16(&body, &bp, 0x1301); // one suite
    put8(&body, &bp, 1); // compression_methods length
    put8(&body, &bp, 0); // null compression
    put16(&body, &bp, @intCast(ext_block.len)); // extensions length
    @memcpy(body[bp .. bp + ext_block.len], ext_block);
    bp += ext_block.len;
    const ch_body = body[0..bp];

    // Handshake header + record header.
    put8(out, &w, handshake_record);
    put16(out, &w, 0x0301); // record legacy version
    put16(out, &w, @intCast(4 + ch_body.len)); // record length
    put8(out, &w, client_hello);
    // handshake length (u24)
    out[w] = 0;
    std.mem.writeInt(u16, out[w + 1 ..][0..2], @intCast(ch_body.len), .big);
    w += 3;
    @memcpy(out[w .. w + ch_body.len], ch_body);
    w += ch_body.len;
    return w;
}

test "parseServerName: extracts host from a well-formed ClientHello" {
    var buf: [1024]u8 = undefined;
    const n = buildClientHello(&buf, "host-a.example.com");
    const got = parseServerName(buf[0..n]) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("host-a.example.com", got);
}

test "parseServerName: distinct hosts round-trip distinctly (randomized)" {
    var prng = std.Random.DefaultPrng.init(0x5_4E_1);
    const rand = prng.random();
    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-";
    var trial: usize = 0;
    while (trial < 200) : (trial += 1) {
        var host_buf: [64]u8 = undefined;
        const len = rand.intRangeAtMost(usize, 1, host_buf.len);
        for (host_buf[0..len]) |*ch| ch.* = alphabet[rand.intRangeLessThan(usize, 0, alphabet.len)];
        const host = host_buf[0..len];

        var rec: [1024]u8 = undefined;
        const n = buildClientHello(&rec, host);
        const got = parseServerName(rec[0..n]) orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(host, got);
    }
}

test "parseServerName: no SNI extension returns null" {
    // A ClientHello with an empty extensions block.
    var buf: [128]u8 = undefined;
    var w: usize = 0;
    buf[w] = handshake_record;
    w += 1;
    std.mem.writeInt(u16, buf[w..][0..2], 0x0301, .big);
    w += 2;
    // body: version(2)+random(32)+sid(1)+cs(2+2)+comp(1+1)+ext_len(2)=43
    const body_len: u16 = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2;
    std.mem.writeInt(u16, buf[w..][0..2], 4 + body_len, .big);
    w += 2;
    buf[w] = client_hello;
    w += 1;
    buf[w] = 0;
    std.mem.writeInt(u16, buf[w + 1 ..][0..2], body_len, .big);
    w += 3;
    std.mem.writeInt(u16, buf[w..][0..2], 0x0303, .big);
    w += 2;
    @memset(buf[w .. w + 32], 0);
    w += 32;
    buf[w] = 0; // session id len
    w += 1;
    std.mem.writeInt(u16, buf[w..][0..2], 2, .big); // cipher suites len
    w += 2;
    std.mem.writeInt(u16, buf[w..][0..2], 0x1301, .big);
    w += 2;
    buf[w] = 1; // compression len
    w += 1;
    buf[w] = 0;
    w += 1;
    std.mem.writeInt(u16, buf[w..][0..2], 0, .big); // extensions len 0
    w += 2;
    try testing.expect(parseServerName(buf[0..w]) == null);
}

test "parseServerName: truncated / malformed inputs never crash, return null" {
    var prng = std.Random.DefaultPrng.init(0xBAD_5_1);
    const rand = prng.random();
    // Build a valid hello, then feed every truncation of it.
    var full: [1024]u8 = undefined;
    const n = buildClientHello(&full, "example.org");
    var cut: usize = 0;
    while (cut < n) : (cut += 1) {
        _ = parseServerName(full[0..cut]); // must not crash
    }
    // Pure random noise of varying lengths.
    var trial: usize = 0;
    while (trial < 500) : (trial += 1) {
        var noise: [256]u8 = undefined;
        const len = rand.intRangeAtMost(usize, 0, noise.len);
        rand.bytes(noise[0..len]);
        _ = parseServerName(noise[0..len]); // must not crash
    }
    // A non-handshake record type is rejected.
    full[0] = 0x17; // application_data
    try testing.expect(parseServerName(full[0..n]) == null);
}

test "parseServerName: lying record length cannot read past the buffer" {
    var buf: [1024]u8 = undefined;
    const n = buildClientHello(&buf, "victim.example");
    // Inflate the record length field to claim far more than we have.
    std.mem.writeInt(u16, buf[3..][0..2], 0xFFFF, .big);
    // Still must parse safely (and, here, still find the host since the
    // bytes are present) or return null — never overrun.
    _ = parseServerName(buf[0..n]);
}
