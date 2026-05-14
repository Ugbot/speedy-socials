//! Minimal image header decoder.
//!
//! Sniffs PNG, JPEG, GIF and WebP magic bytes and returns the canonical
//! mime type plus width/height (when cheaply parseable from the
//! container header — no pixel decode).
//!
//! Tiger Style: bounded. The decoder walks at most a few hundred bytes
//! of header, never allocates, and refuses anything malformed up front.

const std = @import("std");

pub const Kind = enum { png, jpeg, gif, webp, unknown };

pub const Info = struct {
    kind: Kind,
    mime: []const u8, // canonical mime; "application/octet-stream" for unknown
    width: ?u32 = null,
    height: ?u32 = null,
};

pub fn sniff(bytes: []const u8) Info {
    if (isPng(bytes)) return decodePng(bytes);
    if (isJpeg(bytes)) return decodeJpeg(bytes);
    if (isGif(bytes)) return decodeGif(bytes);
    if (isWebp(bytes)) return decodeWebp(bytes);
    return .{ .kind = .unknown, .mime = "application/octet-stream" };
}

// ── PNG ────────────────────────────────────────────────────────────
// Magic: 89 50 4E 47 0D 0A 1A 0A
// IHDR @ offset 8: 4-byte length, "IHDR", width(BE u32), height(BE u32)

fn isPng(b: []const u8) bool {
    return b.len >= 8 and std.mem.eql(u8, b[0..8], &.{ 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A });
}

fn decodePng(b: []const u8) Info {
    var info: Info = .{ .kind = .png, .mime = "image/png" };
    if (b.len < 24) return info;
    // IHDR chunk: 8 (sig) + 4 (len) + 4 ("IHDR") + width(4) + height(4)
    if (!std.mem.eql(u8, b[12..16], "IHDR")) return info;
    const w = std.mem.readInt(u32, b[16..20], .big);
    const h = std.mem.readInt(u32, b[20..24], .big);
    info.width = w;
    info.height = h;
    return info;
}

// ── JPEG ───────────────────────────────────────────────────────────
// SOI: FF D8. Walk segments FF Cx to find SOF (FF C0..C3, C5..C7,
// C9..CB, CD..CF excluding C4/CC). SOF: FF Cx, len (2 BE), precision (1),
// height (2 BE), width (2 BE).

fn isJpeg(b: []const u8) bool {
    return b.len >= 3 and b[0] == 0xFF and b[1] == 0xD8 and b[2] == 0xFF;
}

fn decodeJpeg(b: []const u8) Info {
    var info: Info = .{ .kind = .jpeg, .mime = "image/jpeg" };
    var i: usize = 2; // skip SOI
    var guard: u32 = 0;
    while (i + 8 < b.len and guard < 1024) : (guard += 1) {
        if (b[i] != 0xFF) break;
        // Skip fill bytes.
        while (i < b.len and b[i] == 0xFF) : (i += 1) {}
        if (i >= b.len) break;
        const marker = b[i];
        i += 1;
        // Standalone markers (no payload).
        if (marker == 0xD8 or marker == 0xD9 or (marker >= 0xD0 and marker <= 0xD7)) continue;
        if (i + 2 > b.len) break;
        const seg_len = (@as(usize, b[i]) << 8) | @as(usize, b[i + 1]);
        if (seg_len < 2) break;
        // SOF markers (frame headers) per ITU-T T.81.
        const is_sof = switch (marker) {
            0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF => true,
            else => false,
        };
        if (is_sof) {
            if (i + 7 > b.len) break;
            // i+2: precision; i+3..i+4 height; i+5..i+6 width.
            const h = (@as(u32, b[i + 3]) << 8) | @as(u32, b[i + 4]);
            const w = (@as(u32, b[i + 5]) << 8) | @as(u32, b[i + 6]);
            info.width = w;
            info.height = h;
            return info;
        }
        i += seg_len;
    }
    return info;
}

// ── GIF ────────────────────────────────────────────────────────────
// "GIF87a" or "GIF89a" then LSD: width(2 LE), height(2 LE)

fn isGif(b: []const u8) bool {
    if (b.len < 6) return false;
    return std.mem.eql(u8, b[0..6], "GIF87a") or std.mem.eql(u8, b[0..6], "GIF89a");
}

fn decodeGif(b: []const u8) Info {
    var info: Info = .{ .kind = .gif, .mime = "image/gif" };
    if (b.len < 10) return info;
    info.width = (@as(u32, b[7]) << 8) | @as(u32, b[6]);
    info.height = (@as(u32, b[9]) << 8) | @as(u32, b[8]);
    return info;
}

// ── WebP ───────────────────────────────────────────────────────────
// "RIFF" .... "WEBP" + chunk. We support VP8 (lossy), VP8L (lossless),
// VP8X (extended).

fn isWebp(b: []const u8) bool {
    return b.len >= 12 and std.mem.eql(u8, b[0..4], "RIFF") and std.mem.eql(u8, b[8..12], "WEBP");
}

fn decodeWebp(b: []const u8) Info {
    var info: Info = .{ .kind = .webp, .mime = "image/webp" };
    if (b.len < 30) return info;
    const tag = b[12..16];
    if (std.mem.eql(u8, tag, "VP8 ")) {
        // Lossy: at offset 20 we should find 0x9D 0x01 0x2A; then 2-byte
        // (LE) width|height with top bit reserved.
        if (b.len < 30) return info;
        if (b[23] != 0x9D or b[24] != 0x01 or b[25] != 0x2A) return info;
        const w = ((@as(u32, b[27]) << 8) | @as(u32, b[26])) & 0x3FFF;
        const h = ((@as(u32, b[29]) << 8) | @as(u32, b[28])) & 0x3FFF;
        info.width = w;
        info.height = h;
    } else if (std.mem.eql(u8, tag, "VP8L")) {
        // Lossless: signature 0x2F at byte 20, then 14-bit width-1 and
        // 14-bit height-1 packed LE.
        if (b[20] != 0x2F) return info;
        const b21: u32 = b[21];
        const b22: u32 = b[22];
        const b23: u32 = b[23];
        const b24: u32 = b[24];
        const w = ((b22 & 0x3F) << 8 | b21) + 1;
        const h = (((b24 & 0x0F) << 10) | (b23 << 2) | (b22 >> 6)) + 1;
        info.width = w;
        info.height = h;
    } else if (std.mem.eql(u8, tag, "VP8X")) {
        // Extended: canvas width-1 (3 bytes LE) at offset 24, height-1 at offset 27.
        if (b.len < 30) return info;
        const w = ((@as(u32, b[26]) << 16) | (@as(u32, b[25]) << 8) | @as(u32, b[24])) + 1;
        const h = ((@as(u32, b[29]) << 16) | (@as(u32, b[28]) << 8) | @as(u32, b[27])) + 1;
        info.width = w;
        info.height = h;
    }
    return info;
}

// ── tests ──────────────────────────────────────────────────────────

test "sniff: PNG dimensions" {
    // 1x1 transparent PNG (minimal header is enough to read IHDR).
    var buf: [24]u8 = undefined;
    @memcpy(buf[0..8], &[_]u8{ 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A });
    // length=13, "IHDR"
    buf[8] = 0;
    buf[9] = 0;
    buf[10] = 0;
    buf[11] = 13;
    @memcpy(buf[12..16], "IHDR");
    // width = 320 = 0x140
    buf[16] = 0;
    buf[17] = 0;
    buf[18] = 0x01;
    buf[19] = 0x40;
    // height = 200 = 0xC8
    buf[20] = 0;
    buf[21] = 0;
    buf[22] = 0;
    buf[23] = 0xC8;
    const info = sniff(&buf);
    try std.testing.expectEqual(Kind.png, info.kind);
    try std.testing.expectEqualStrings("image/png", info.mime);
    try std.testing.expectEqual(@as(u32, 320), info.width.?);
    try std.testing.expectEqual(@as(u32, 200), info.height.?);
}

test "sniff: JPEG dimensions via SOF0" {
    // SOI, APP0 with payload, then SOF0 with 480×640.
    // FF D8 (SOI) FF E0 00 10 "JFIF\0" 01 01 00 00 01 00 01 00 00
    // FF C0 00 11 08 02 80 01 E0 03 01 22 00 02 11 01 03 11 01
    const data = [_]u8{
        0xFF, 0xD8,
        0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00,
        0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0xFF, 0xC0, 0x00, 0x11, 0x08,
        0x02, 0x80, // height = 640
        0x01, 0xE0, // width  = 480
        0x03,
        0x01, 0x22, 0x00,
        0x02, 0x11, 0x01,
        0x03, 0x11, 0x01,
    };
    const info = sniff(&data);
    try std.testing.expectEqual(Kind.jpeg, info.kind);
    try std.testing.expectEqual(@as(u32, 480), info.width.?);
    try std.testing.expectEqual(@as(u32, 640), info.height.?);
}

test "sniff: GIF dimensions" {
    // GIF89a, width=10 (LE), height=20 (LE)
    const data = [_]u8{ 'G', 'I', 'F', '8', '9', 'a', 0x0A, 0x00, 0x14, 0x00 };
    const info = sniff(&data);
    try std.testing.expectEqual(Kind.gif, info.kind);
    try std.testing.expectEqual(@as(u32, 10), info.width.?);
    try std.testing.expectEqual(@as(u32, 20), info.height.?);
}

test "sniff: WebP VP8L dimensions" {
    // RIFF .... WEBP VP8L .... 0x2F + 14-bit w-1, 14-bit h-1 (LE packed)
    // Encode width=100, height=50 → w-1=99, h-1=49.
    // Layout: byte21..24 = (h-1<<14) | (w-1)
    const wm1: u32 = 99;
    const hm1: u32 = 49;
    const packed_lo: u32 = wm1 | (hm1 << 14);
    var data: [30]u8 = undefined;
    @memset(&data, 0);
    @memcpy(data[0..4], "RIFF");
    @memcpy(data[8..12], "WEBP");
    @memcpy(data[12..16], "VP8L");
    data[20] = 0x2F;
    data[21] = @intCast(packed_lo & 0xFF);
    data[22] = @intCast((packed_lo >> 8) & 0xFF);
    data[23] = @intCast((packed_lo >> 16) & 0xFF);
    data[24] = @intCast((packed_lo >> 24) & 0xFF);
    const info = sniff(&data);
    try std.testing.expectEqual(Kind.webp, info.kind);
    try std.testing.expectEqual(@as(u32, 100), info.width.?);
    try std.testing.expectEqual(@as(u32, 50), info.height.?);
}

test "sniff: unknown bytes fall through" {
    const data = "not an image at all";
    const info = sniff(data);
    try std.testing.expectEqual(Kind.unknown, info.kind);
    try std.testing.expectEqualStrings("application/octet-stream", info.mime);
}
