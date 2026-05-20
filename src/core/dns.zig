//! Minimal DNS TXT record lookup via libc `res_query` / `res_search`.
//!
//! Used by AT-18b for handle resolution: an atproto handle MAY publish
//! its DID via a `_atproto.<handle>` TXT record, which we look up here
//! when the HTTPS `/.well-known/atproto-did` path 404s.
//!
//! Caller invokes `lookupTxt(name, out)`; we issue a synchronous DNS
//! query, parse the response, and return the first TXT record's
//! contents. Bounded — no allocator, output capped at `out.len`.

const std = @import("std");

pub const Error = error{
    ResolverInitFailed,
    QueryFailed,
    NoRecord,
    Truncated,
    Malformed,
};

// libc bindings — `<resolv.h>`.
extern "c" fn res_init() c_int;
extern "c" fn res_query(dname: [*:0]const u8, class: c_int, type_: c_int, answer: [*]u8, anslen: c_int) c_int;

pub const C_IN: c_int = 1;
pub const T_TXT: c_int = 16;

const HEADER_BYTES: usize = 12;

/// Look up the first TXT record for `name`. Returns the slice written
/// into `out` (without the libc length-byte framing).
pub fn lookupTxt(name: []const u8, out: []u8) Error![]const u8 {
    if (name.len == 0 or name.len > 253) return error.Malformed;
    var name_z_buf: [256]u8 = undefined;
    if (name.len + 1 > name_z_buf.len) return error.Malformed;
    @memcpy(name_z_buf[0..name.len], name);
    name_z_buf[name.len] = 0;
    const name_z: [*:0]const u8 = @ptrCast(&name_z_buf);

    if (res_init() != 0) return error.ResolverInitFailed;

    var resp: [4096]u8 = undefined;
    const n = res_query(name_z, C_IN, T_TXT, &resp, resp.len);
    if (n <= 0) return error.QueryFailed;
    const len: usize = @intCast(n);
    if (len < HEADER_BYTES) return error.Malformed;

    // Parse DNS response. Skip the question section, then walk
    // answer RRs until we find a TXT.
    const qdcount: u16 = (@as(u16, resp[4]) << 8) | resp[5];
    const ancount: u16 = (@as(u16, resp[6]) << 8) | resp[7];
    if (ancount == 0) return error.NoRecord;

    var pos: usize = HEADER_BYTES;
    var qi: u16 = 0;
    while (qi < qdcount) : (qi += 1) {
        pos = try skipName(resp[0..len], pos);
        pos += 4; // qtype(2) + qclass(2)
        if (pos > len) return error.Malformed;
    }

    var ai: u16 = 0;
    while (ai < ancount) : (ai += 1) {
        pos = try skipName(resp[0..len], pos);
        if (pos + 10 > len) return error.Malformed;
        const rtype: u16 = (@as(u16, resp[pos]) << 8) | resp[pos + 1];
        const rdlength: u16 = (@as(u16, resp[pos + 8]) << 8) | resp[pos + 9];
        pos += 10;
        if (pos + rdlength > len) return error.Malformed;

        if (rtype != T_TXT) {
            pos += rdlength;
            continue;
        }
        // RDATA for TXT is one or more <length-prefixed string>. Return
        // the first one.
        if (rdlength == 0) return error.Malformed;
        const txt_len: u8 = resp[pos];
        if (txt_len == 0) return error.Malformed;
        if (@as(usize, txt_len) + 1 > rdlength) return error.Malformed;
        if (txt_len > out.len) return error.Truncated;
        @memcpy(out[0..txt_len], resp[pos + 1 .. pos + 1 + txt_len]);
        return out[0..txt_len];
    }
    return error.NoRecord;
}

/// Walk a DNS label sequence; handles pointer compression. Returns the
/// position immediately after the name.
fn skipName(buf: []const u8, start: usize) Error!usize {
    var pos = start;
    var guard: u8 = 0;
    while (guard < 128) : (guard += 1) {
        if (pos >= buf.len) return error.Malformed;
        const b = buf[pos];
        if (b == 0) return pos + 1;
        if (b & 0xC0 == 0xC0) {
            // Compressed pointer — name ends after the 2 bytes.
            return pos + 2;
        }
        if (b & 0xC0 != 0) return error.Malformed;
        pos += 1 + @as(usize, b);
    }
    return error.Malformed;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "DNS: lookupTxt rejects empty name" {
    var buf: [256]u8 = undefined;
    try testing.expectError(error.Malformed, lookupTxt("", &buf));
}

test "DNS: skipName follows pointer compression" {
    // Build a tiny synthetic packet: name "x" at offset 12, then a
    // pointer back to it.
    var pkt: [40]u8 = .{0} ** 40;
    pkt[12] = 1;
    pkt[13] = 'x';
    pkt[14] = 0;
    pkt[15] = 0xC0;
    pkt[16] = 12;
    const after_direct = try skipName(&pkt, 12);
    try testing.expectEqual(@as(usize, 15), after_direct);
    const after_pointer = try skipName(&pkt, 15);
    try testing.expectEqual(@as(usize, 17), after_pointer);
}
