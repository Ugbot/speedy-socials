//! Op-D / F2: TLS cert-expiry probe for the `/readyz` deep-check.
//!
//! Reads the PEM at `TLS_CERT_PATH`, parses the leaf certificate,
//! and returns its `notAfter` in unix seconds. The /readyz hook
//! reports not-ready when the cert is within `expiry_warn_seconds`
//! of expiry (default 7 days).
//!
//! Tiger Style: fixed-buffer PEM reader, no allocator on the probe
//! path. The probe is rate-limited at the caller — calling it on
//! every /readyz hit is fine since we re-read the file each time
//! (a cron-style swap will still be picked up).

const std = @import("std");

pub const Error = error{
    OpenFailed,
    ReadFailed,
    BadPem,
    ParseFailed,
};

pub const default_warn_seconds: i64 = 7 * 24 * 60 * 60;

pub const ProbeResult = struct {
    not_after_unix: i64,
    seconds_until_expiry: i64,
    /// True when `seconds_until_expiry < warn_threshold`.
    expiring_soon: bool,
};

pub fn probe(cert_path: []const u8, now_unix: i64, warn_threshold: i64) Error!ProbeResult {
    var path_z_buf: [512]u8 = undefined;
    if (cert_path.len + 1 > path_z_buf.len) return error.OpenFailed;
    @memcpy(path_z_buf[0..cert_path.len], cert_path);
    path_z_buf[cert_path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_z_buf);

    const fd = std.c.open(path_z, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
    if (fd < 0) return error.OpenFailed;
    defer _ = std.c.close(fd);

    var pem: [16 * 1024]u8 = undefined;
    var total: usize = 0;
    while (total < pem.len) {
        const got = std.c.read(fd, (&pem).ptr + total, pem.len - total);
        if (got <= 0) break;
        total += @intCast(got);
    }
    if (total == 0) return error.ReadFailed;

    const der = try extractFirstPemBlock(pem[0..total]);
    const not_after = parseNotAfter(der) catch return error.ParseFailed;
    const remaining = not_after - now_unix;
    return .{
        .not_after_unix = not_after,
        .seconds_until_expiry = remaining,
        .expiring_soon = remaining < warn_threshold,
    };
}

fn extractFirstPemBlock(pem: []const u8) ![]const u8 {
    // PEM: `-----BEGIN CERTIFICATE-----\n<base64...>\n-----END CERTIFICATE-----`.
    const begin = "-----BEGIN CERTIFICATE-----";
    const endmarker = "-----END CERTIFICATE-----";
    const start = std.mem.indexOf(u8, pem, begin) orelse return error.BadPem;
    const end = std.mem.indexOfPos(u8, pem, start + begin.len, endmarker) orelse return error.BadPem;
    // For probing we don't need the decoded DER; just return the
    // base64-bracketed slice. parseNotAfter handles it.
    return pem[start + begin.len .. end];
}

fn parseNotAfter(b64_block: []const u8) !i64 {
    // Decode base64 → DER → parse ASN.1 to find the validity not-After.
    // We use stdlib's `std.crypto.Certificate.parse` which expects a
    // Certificate struct. For our needs we re-implement a *minimum*
    // ASN.1 walk that pulls the not-After UTCTime.
    var decoded: [8 * 1024]u8 = undefined;
    var dec_len: usize = 0;
    var i: usize = 0;
    // strip whitespace
    var clean: [16 * 1024]u8 = undefined;
    var cn: usize = 0;
    while (i < b64_block.len) : (i += 1) {
        const ch = b64_block[i];
        if (ch == ' ' or ch == '\n' or ch == '\r' or ch == '\t') continue;
        if (cn >= clean.len) return error.OutOfMemory;
        clean[cn] = ch;
        cn += 1;
    }
    const enc = std.base64.standard;
    const max_dec = enc.Decoder.calcSizeForSlice(clean[0..cn]) catch return error.BadPem;
    if (max_dec > decoded.len) return error.OutOfMemory;
    try enc.Decoder.decode(decoded[0..max_dec], clean[0..cn]);
    dec_len = max_dec;

    // ASN.1 walk: Certificate ::= SEQUENCE { tbsCertificate ::= SEQUENCE {
    //   version [0] EXPLICIT (optional),
    //   serialNumber INTEGER,
    //   signature AlgorithmIdentifier,
    //   issuer Name,
    //   validity ::= SEQUENCE { notBefore Time, notAfter Time },
    //   ...
    // } }
    var p: usize = 0;
    // outer SEQUENCE
    p = try consumeTag(decoded[0..dec_len], p, 0x30);
    const outer_len = try readLength(decoded[0..dec_len], &p);
    _ = outer_len;
    // tbsCertificate SEQUENCE
    p = try consumeTag(decoded[0..dec_len], p, 0x30);
    const tbs_len = try readLength(decoded[0..dec_len], &p);
    _ = tbs_len;
    // optional [0] version
    if (p < dec_len and decoded[p] == 0xA0) {
        p += 1;
        const vlen = try readLength(decoded[0..dec_len], &p);
        p += vlen;
    }
    // serialNumber INTEGER
    p = try consumeTag(decoded[0..dec_len], p, 0x02);
    const sn_len = try readLength(decoded[0..dec_len], &p);
    p += sn_len;
    // signature AlgorithmIdentifier SEQUENCE
    p = try consumeTag(decoded[0..dec_len], p, 0x30);
    const sig_len = try readLength(decoded[0..dec_len], &p);
    p += sig_len;
    // issuer Name SEQUENCE
    p = try consumeTag(decoded[0..dec_len], p, 0x30);
    const issuer_len = try readLength(decoded[0..dec_len], &p);
    p += issuer_len;
    // validity SEQUENCE
    p = try consumeTag(decoded[0..dec_len], p, 0x30);
    const val_len = try readLength(decoded[0..dec_len], &p);
    _ = val_len;
    // notBefore: UTCTime (0x17) or GeneralizedTime (0x18)
    const not_before_tag = decoded[p];
    p += 1;
    const nb_len = try readLength(decoded[0..dec_len], &p);
    _ = not_before_tag;
    p += nb_len;
    // notAfter: same
    const not_after_tag = decoded[p];
    p += 1;
    const na_len = try readLength(decoded[0..dec_len], &p);
    if (p + na_len > dec_len) return error.BadPem;
    const na_bytes = decoded[p .. p + na_len];
    return parseAsn1Time(not_after_tag, na_bytes);
}

fn consumeTag(buf: []const u8, p: usize, expected: u8) !usize {
    if (p >= buf.len) return error.BadPem;
    if (buf[p] != expected) return error.BadPem;
    return p + 1;
}

fn readLength(buf: []const u8, p: *usize) !usize {
    if (p.* >= buf.len) return error.BadPem;
    const b = buf[p.*];
    p.* += 1;
    if (b & 0x80 == 0) return @intCast(b);
    const n_bytes: usize = b & 0x7F;
    if (n_bytes == 0 or n_bytes > 4) return error.BadPem;
    if (p.* + n_bytes > buf.len) return error.BadPem;
    var len: usize = 0;
    var i: usize = 0;
    while (i < n_bytes) : (i += 1) {
        len = (len << 8) | @as(usize, buf[p.* + i]);
    }
    p.* += n_bytes;
    return len;
}

fn parseAsn1Time(tag: u8, bytes: []const u8) !i64 {
    // 0x17 = UTCTime "YYMMDDHHMMSSZ" (13 bytes).
    // 0x18 = GeneralizedTime "YYYYMMDDHHMMSSZ" (15 bytes).
    if (tag == 0x17 and bytes.len == 13) {
        const yy = try parse2(bytes[0..2]);
        const year: i64 = if (yy < 50) 2000 + yy else 1900 + yy;
        return makeUnix(year, try parse2(bytes[2..4]), try parse2(bytes[4..6]), try parse2(bytes[6..8]), try parse2(bytes[8..10]), try parse2(bytes[10..12]));
    }
    if (tag == 0x18 and bytes.len == 15) {
        const yyyy = try parse4(bytes[0..4]);
        return makeUnix(yyyy, try parse2(bytes[4..6]), try parse2(bytes[6..8]), try parse2(bytes[8..10]), try parse2(bytes[10..12]), try parse2(bytes[12..14]));
    }
    return error.BadPem;
}

fn parse2(b: []const u8) !i64 {
    if (b.len < 2) return error.BadPem;
    return @as(i64, b[0] - '0') * 10 + @as(i64, b[1] - '0');
}

fn parse4(b: []const u8) !i64 {
    if (b.len < 4) return error.BadPem;
    return @as(i64, b[0] - '0') * 1000 + @as(i64, b[1] - '0') * 100 + @as(i64, b[2] - '0') * 10 + @as(i64, b[3] - '0');
}

fn makeUnix(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) i64 {
    // Days from civil (Howard Hinnant). Year, month, day are calendar.
    const y = if (month <= 2) year - 1 else year;
    const era: i64 = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe: u32 = @intCast(y - era * 400);
    const doy: u32 = @intCast(@as(i64, @divFloor((153 * (if (month > 2) month - 3 else month + 9) + 2), 5)) + day - 1);
    const doe: i64 = @intCast(yoe * 365 + yoe / 4 - yoe / 100 + doy);
    const days_since_epoch = era * 146097 + doe - 719468;
    return days_since_epoch * 86400 + hour * 3600 + minute * 60 + second;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "F2: parse2 reads two-digit ASCII" {
    try testing.expectEqual(@as(i64, 12), try parse2("12"));
    try testing.expectEqual(@as(i64, 30), try parse2("30"));
}

test "F2: makeUnix computes a known date" {
    // 2026-05-20 00:00:00 UTC = 1763596800.
    try testing.expectEqual(@as(i64, 1747699200), makeUnix(2025, 5, 20, 0, 0, 0));
}

test "F2: probe rejects an unreadable path" {
    try testing.expectError(error.OpenFailed, probe("/nonexistent/cert.pem", 0, default_warn_seconds));
}
