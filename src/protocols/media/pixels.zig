//! Sample an image down to a small RGBA buffer suitable for the
//! BlurHash encoder.
//!
//! Decoder coverage (deliberately limited — full decoders are
//! multi-day work and out of scope for the media plugin):
//!
//!   * PNG, 8-bit, non-interlaced, colour-type 2 (truecolour RGB)
//!     or 6 (truecolour + alpha). All five filter types are
//!     implemented.
//!   * JPEG / GIF / WebP — not decoded. The caller receives the
//!     stub-fallback flag and should fall back to a placeholder
//!     blurhash (see `stub_blurhash` below) rather than emit a
//!     wrong-looking hash.
//!
//! Tiger Style: output dimensions are caller-supplied and bounded
//! (≤ `sample_dim` per side). No allocations are made by this module
//! — the caller supplies a scratch buffer big enough for the inflated
//! scanline pixels.
//!
//! The intent is "good enough for a thumbnail-grade blur preview" not
//! pixel-accuracy. Nearest-neighbour resampling is fine here.

const std = @import("std");
const flate = std.compress.flate;
const image = @import("image.zig");

/// Resampled square edge length. Keep small — 32 is plenty for an
/// xc=4 / yc=3 blurhash.
pub const sample_dim: u32 = 32;

/// Returned when decoding is not supported for this kind of image.
pub const stub_blurhash: []const u8 = "L00000fQfQfQfQfQ";

pub const Error = error{
    Unsupported,
    Malformed,
    BufferTooSmall,
    DecompressFailed,
};

pub const Sample = struct {
    /// `sample_dim × sample_dim × 4` RGBA bytes. Written into the
    /// caller-supplied buffer.
    rgba: []u8,
    /// Source-image dimensions (for the upload response, not the
    /// resample target).
    src_width: u32,
    src_height: u32,
};

/// Sample the image down. Returns `error.Unsupported` if the format
/// is recognised but we cannot decode it — callers should then
/// substitute the stub blurhash.
pub fn sample(
    bytes: []const u8,
    info: image.Info,
    /// Scratch: at least 4 * src_width * src_height bytes for the
    /// fully-decoded source image, plus working room for the row
    /// buffer. For PNG that's `4 * w * h + (w * 4 + 1) * h` worst case.
    scratch: []u8,
    /// Output RGBA buffer: must be ≥ sample_dim*sample_dim*4.
    out_rgba: []u8,
) Error!Sample {
    if (out_rgba.len < @as(usize, sample_dim) * sample_dim * 4) return error.BufferTooSmall;
    if (info.kind != .png) return error.Unsupported;
    return samplePng(bytes, info, scratch, out_rgba);
}

// ── PNG decoder (subset) ───────────────────────────────────────────

const png_sig = [_]u8{ 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };

fn samplePng(bytes: []const u8, info: image.Info, scratch: []u8, out_rgba: []u8) Error!Sample {
    if (bytes.len < 8 + 25) return error.Malformed;
    if (!std.mem.eql(u8, bytes[0..8], &png_sig)) return error.Malformed;

    const src_w = info.width orelse return error.Malformed;
    const src_h = info.height orelse return error.Malformed;
    if (src_w == 0 or src_h == 0) return error.Malformed;

    // Parse IHDR for colour type + bit depth + interlace.
    // IHDR chunk starts at offset 8: 4 (len=13) + 4 ("IHDR") + 13 bytes.
    const ihdr = bytes[16..29];
    const bit_depth = ihdr[8];
    const colour_type = ihdr[9];
    const interlace = ihdr[12];
    if (bit_depth != 8) return error.Unsupported;
    if (interlace != 0) return error.Unsupported;
    const bytes_per_pixel: u32 = switch (colour_type) {
        2 => 3, // RGB
        6 => 4, // RGBA
        else => return error.Unsupported,
    };

    // Concatenate all IDAT chunks into `scratch`. We reserve the back
    // half of `scratch` for the decompressed output, front half for the
    // compressed concat.
    const decomp_bytes_needed: usize = @as(usize, src_h) * (@as(usize, src_w) * bytes_per_pixel + 1);
    // Layout: [compressed-concat][decompressed][filter-prev-row-scratch]
    const prev_row_len: usize = @as(usize, src_w) * 4;
    if (scratch.len < decomp_bytes_needed + prev_row_len + 64) return error.BufferTooSmall;

    // Carve sub-slices.
    const decomp_area = scratch[0..decomp_bytes_needed];
    const compressed_area = scratch[decomp_bytes_needed .. scratch.len - prev_row_len];
    const prev_row_area = scratch[scratch.len - prev_row_len ..];

    // Walk chunks starting after the 8-byte signature.
    var p: usize = 8;
    var comp_pos: usize = 0;
    while (p + 12 <= bytes.len) {
        const chunk_len = std.mem.readInt(u32, bytes[p .. p + 4][0..4], .big);
        const chunk_type = bytes[p + 4 .. p + 8];
        const chunk_data_start = p + 8;
        const chunk_data_end = chunk_data_start + chunk_len;
        if (chunk_data_end + 4 > bytes.len) return error.Malformed;
        if (std.mem.eql(u8, chunk_type, "IDAT")) {
            if (comp_pos + chunk_len > compressed_area.len) return error.BufferTooSmall;
            @memcpy(compressed_area[comp_pos .. comp_pos + chunk_len], bytes[chunk_data_start..chunk_data_end]);
            comp_pos += chunk_len;
        } else if (std.mem.eql(u8, chunk_type, "IEND")) {
            break;
        }
        p = chunk_data_end + 4; // skip CRC
    }
    if (comp_pos == 0) return error.Malformed;

    // Inflate (zlib container).
    var in_reader: std.Io.Reader = .fixed(compressed_area[0..comp_pos]);
    var window: [flate.max_window_len]u8 = undefined;
    var decomp = flate.Decompress.init(&in_reader, .zlib, &window);
    var decomp_writer: std.Io.Writer = .fixed(decomp_area);
    _ = decomp.reader.streamRemaining(&decomp_writer) catch return error.DecompressFailed;
    const decomp_len = decomp_writer.end;
    if (decomp_len != decomp_bytes_needed) return error.Malformed;

    // De-filter row by row, writing each pixel into an RGBA grid as we
    // go (in place, reusing the back portion of decomp_area is risky —
    // instead we sample on the fly to the output buffer).
    // Initialise out_rgba accumulator: build per-(sample_dim × sample_dim)
    // averages on a single pass.
    var sums: [sample_dim * sample_dim][4]u32 = undefined;
    var counts: [sample_dim * sample_dim]u32 = undefined;
    var i: u32 = 0;
    while (i < sample_dim * sample_dim) : (i += 1) {
        sums[i] = .{ 0, 0, 0, 0 };
        counts[i] = 0;
    }

    @memset(prev_row_area, 0);
    var current_row: [4 * 16384]u8 = undefined; // bounded scanline scratch (≤16k px wide)
    if (src_w > 16384) return error.Unsupported;
    const row_bytes: usize = @as(usize, src_w) * bytes_per_pixel;

    var y: u32 = 0;
    while (y < src_h) : (y += 1) {
        const row_off = y * (row_bytes + 1);
        const filter = decomp_area[row_off];
        const raw = decomp_area[row_off + 1 .. row_off + 1 + row_bytes];
        // De-filter into `current_row[0..row_bytes]`.
        try defilterRow(filter, raw, prev_row_area[0..row_bytes], current_row[0..row_bytes], bytes_per_pixel);
        // Expand to 4-byte RGBA in prev_row_area (we reuse it; after we
        // sample we move it to the new "previous" row).
        var x: u32 = 0;
        while (x < src_w) : (x += 1) {
            const px_in = current_row[x * bytes_per_pixel ..][0..bytes_per_pixel];
            const px_out_idx = x * 4;
            prev_row_area[px_out_idx + 0] = px_in[0];
            prev_row_area[px_out_idx + 1] = px_in[1];
            prev_row_area[px_out_idx + 2] = px_in[2];
            prev_row_area[px_out_idx + 3] = if (bytes_per_pixel == 4) px_in[3] else 0xFF;

            // Sample into the resampled grid using nearest-neighbour.
            const tx = (x * sample_dim) / src_w;
            const ty = (y * sample_dim) / src_h;
            const sidx = ty * sample_dim + tx;
            sums[sidx][0] += prev_row_area[px_out_idx + 0];
            sums[sidx][1] += prev_row_area[px_out_idx + 1];
            sums[sidx][2] += prev_row_area[px_out_idx + 2];
            sums[sidx][3] += prev_row_area[px_out_idx + 3];
            counts[sidx] += 1;
        }
        // For the next row's filter, prev row needs the raw filtered
        // output (not the expanded RGBA). Copy `current_row` back over
        // the front of prev_row_area.
        @memcpy(prev_row_area[0..row_bytes], current_row[0..row_bytes]);
    }

    // Write averages into out_rgba.
    var k: u32 = 0;
    while (k < sample_dim * sample_dim) : (k += 1) {
        const c = if (counts[k] == 0) 1 else counts[k];
        out_rgba[k * 4 + 0] = @intCast(sums[k][0] / c);
        out_rgba[k * 4 + 1] = @intCast(sums[k][1] / c);
        out_rgba[k * 4 + 2] = @intCast(sums[k][2] / c);
        out_rgba[k * 4 + 3] = @intCast(sums[k][3] / c);
    }

    return .{
        .rgba = out_rgba[0 .. sample_dim * sample_dim * 4],
        .src_width = src_w,
        .src_height = src_h,
    };
}

fn defilterRow(filter: u8, raw: []const u8, prev: []const u8, out: []u8, bpp: u32) Error!void {
    std.debug.assert(raw.len == out.len);
    std.debug.assert(prev.len == out.len);
    switch (filter) {
        0 => @memcpy(out, raw),
        1 => { // Sub
            var i: usize = 0;
            while (i < out.len) : (i += 1) {
                const left: u8 = if (i >= bpp) out[i - bpp] else 0;
                out[i] = raw[i] +% left;
            }
        },
        2 => { // Up
            var i: usize = 0;
            while (i < out.len) : (i += 1) out[i] = raw[i] +% prev[i];
        },
        3 => { // Average
            var i: usize = 0;
            while (i < out.len) : (i += 1) {
                const left: u32 = if (i >= bpp) out[i - bpp] else 0;
                const up: u32 = prev[i];
                const avg: u8 = @intCast((left + up) / 2);
                out[i] = raw[i] +% avg;
            }
        },
        4 => { // Paeth
            var i: usize = 0;
            while (i < out.len) : (i += 1) {
                const a: i32 = if (i >= bpp) out[i - bpp] else 0;
                const b: i32 = prev[i];
                const c: i32 = if (i >= bpp) prev[i - bpp] else 0;
                out[i] = raw[i] +% paeth(a, b, c);
            }
        },
        else => return error.Malformed,
    }
}

fn paeth(a: i32, b: i32, c: i32) u8 {
    const p = a + b - c;
    const pa = @abs(p - a);
    const pb = @abs(p - b);
    const pc = @abs(p - c);
    if (pa <= pb and pa <= pc) return @intCast(a);
    if (pb <= pc) return @intCast(b);
    return @intCast(c);
}

// ── tests ──────────────────────────────────────────────────────────

test "sample: rejects unsupported kinds (jpeg)" {
    var scratch: [1024]u8 = undefined;
    var out: [sample_dim * sample_dim * 4]u8 = undefined;
    const info: image.Info = .{ .kind = .jpeg, .mime = "image/jpeg", .width = 10, .height = 10 };
    try std.testing.expectError(error.Unsupported, sample("", info, &scratch, &out));
}

test "sample: tiny 2x2 raw PNG decodes through filter type 0" {
    // Hand-crafted PNG: signature + IHDR + IDAT + IEND.
    // 2x2 RGBA, filter-none, pixels:
    //   (255,0,0,255) (0,255,0,255)
    //   (0,0,255,255) (255,255,255,255)
    // Raw scanlines (with filter byte per row):
    //   0  FF 00 00 FF  00 FF 00 FF
    //   0  00 00 FF FF  FF FF FF FF
    // Total raw = 2 + 4*4 = 18 bytes.
    const raw_scanlines = [_]u8{
        0,    0xFF, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
        0,    0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    // Hand-built zlib stream using a single stored DEFLATE block.
    //   2 bytes zlib header (0x78 0x01) +
    //   1 byte block header (BFINAL=1, BTYPE=00) +
    //   2 bytes LEN LE + 2 bytes NLEN LE +
    //   raw literal bytes +
    //   4 bytes ADLER32 BE
    var idat_buf: [128]u8 = undefined;
    var idat_len: usize = 0;
    idat_buf[idat_len] = 0x78;
    idat_len += 1;
    idat_buf[idat_len] = 0x01;
    idat_len += 1;
    idat_buf[idat_len] = 0x01; // BFINAL=1, BTYPE=00
    idat_len += 1;
    const rs_len: u16 = @intCast(raw_scanlines.len);
    idat_buf[idat_len] = @intCast(rs_len & 0xFF);
    idat_buf[idat_len + 1] = @intCast(rs_len >> 8);
    idat_buf[idat_len + 2] = @intCast(~rs_len & 0xFF);
    idat_buf[idat_len + 3] = @intCast((~rs_len >> 8) & 0xFF);
    idat_len += 4;
    @memcpy(idat_buf[idat_len .. idat_len + raw_scanlines.len], &raw_scanlines);
    idat_len += raw_scanlines.len;
    // ADLER32
    var s1: u32 = 1;
    var s2: u32 = 0;
    for (raw_scanlines) |b| {
        s1 = (s1 + b) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    const adler = (s2 << 16) | s1;
    std.mem.writeInt(u32, idat_buf[idat_len..][0..4], adler, .big);
    idat_len += 4;
    const idat_data = idat_buf[0..idat_len];

    var png_buf: [256]u8 = undefined;
    var pos: usize = 0;
    // signature
    @memcpy(png_buf[0..8], &png_sig);
    pos = 8;
    // IHDR: len=13, "IHDR", w=2, h=2, depth=8, colour=6, comp=0, filter=0, interlace=0
    std.mem.writeInt(u32, png_buf[pos..][0..4], 13, .big);
    pos += 4;
    @memcpy(png_buf[pos .. pos + 4], "IHDR");
    pos += 4;
    std.mem.writeInt(u32, png_buf[pos..][0..4], 2, .big);
    pos += 4;
    std.mem.writeInt(u32, png_buf[pos..][0..4], 2, .big);
    pos += 4;
    png_buf[pos + 0] = 8;
    png_buf[pos + 1] = 6;
    png_buf[pos + 2] = 0;
    png_buf[pos + 3] = 0;
    png_buf[pos + 4] = 0;
    pos += 5;
    // CRC placeholder (decoder doesn't validate)
    pos += 4;
    // IDAT: len, "IDAT", data, CRC.
    std.mem.writeInt(u32, png_buf[pos..][0..4], @intCast(idat_data.len), .big);
    pos += 4;
    @memcpy(png_buf[pos .. pos + 4], "IDAT");
    pos += 4;
    @memcpy(png_buf[pos .. pos + idat_data.len], idat_data);
    pos += idat_data.len;
    pos += 4; // CRC
    // IEND
    std.mem.writeInt(u32, png_buf[pos..][0..4], 0, .big);
    pos += 4;
    @memcpy(png_buf[pos .. pos + 4], "IEND");
    pos += 4 + 4;

    const png_bytes = png_buf[0..pos];
    const info = image.sniff(png_bytes);
    try std.testing.expectEqual(image.Kind.png, info.kind);

    var scratch_buf: [1 << 17]u8 = undefined;
    var out_rgba: [sample_dim * sample_dim * 4]u8 = undefined;
    const s = try sample(png_bytes, info, &scratch_buf, &out_rgba);
    try std.testing.expectEqual(@as(u32, 2), s.src_width);
    try std.testing.expectEqual(@as(u32, 2), s.src_height);
    // The top-left sample pixel should be red.
    try std.testing.expectEqual(@as(u8, 0xFF), out_rgba[0]);
    try std.testing.expectEqual(@as(u8, 0x00), out_rgba[1]);
    try std.testing.expectEqual(@as(u8, 0x00), out_rgba[2]);
}
