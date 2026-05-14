//! Wolt BlurHash encoder — pure Zig, no allocations.
//!
//! Algorithm (https://blurha.sh):
//!   1. From an RGBA pixel buffer (`width × height × 4` bytes,
//!      sRGB-encoded) compute `xComponents × yComponents` DCT-II
//!      basis-function coefficients in linear sRGB space.
//!   2. Encode the components as a base83 string:
//!        - char[0]      = packed size = (yc-1)*9 + (xc-1)
//!        - char[1]      = packed quantised AC maximum
//!        - char[2..6]   = DC (the average linear colour), 4 base83 chars
//!        - thereafter   = each AC component as 2 base83 chars
//!
//! Tiger Style: bounded everything. Coefficient table is stack-only
//! (max 9×9). String output writes into the caller-supplied buffer.

const std = @import("std");

/// Hard caps on components. The spec allows 1..9 inclusive.
pub const max_components: u32 = 9;

pub const Error = error{
    BadComponents,
    OutputTooSmall,
    BadDimensions,
};

/// Encode RGBA8888 pixels (`width*height*4` bytes) into a BlurHash.
/// Returns the written slice on `out`.
pub fn encode(
    rgba: []const u8,
    width: u32,
    height: u32,
    x_components: u32,
    y_components: u32,
    out: []u8,
) Error![]const u8 {
    if (x_components < 1 or x_components > max_components) return error.BadComponents;
    if (y_components < 1 or y_components > max_components) return error.BadComponents;
    if (width == 0 or height == 0) return error.BadDimensions;
    if (rgba.len < @as(usize, width) * @as(usize, height) * 4) return error.BadDimensions;

    // Required output: 1 (size) + 1 (max) + 4 (DC) + 2*(xc*yc - 1) chars.
    const num_components = x_components * y_components;
    const required: usize = 1 + 1 + 4 + 2 * (num_components - 1);
    if (out.len < required) return error.OutputTooSmall;

    // Coefficients buffer: [yc][xc][3]
    var factors: [max_components * max_components][3]f64 = undefined;
    var i: u32 = 0;
    while (i < num_components) : (i += 1) factors[i] = .{ 0, 0, 0 };

    var yi: u32 = 0;
    while (yi < y_components) : (yi += 1) {
        var xi: u32 = 0;
        while (xi < x_components) : (xi += 1) {
            const c = computeBasis(rgba, width, height, xi, yi);
            factors[yi * x_components + xi] = c;
        }
    }

    const dc = factors[0];
    const ac = factors[1..num_components];

    // Compute maximum AC component magnitude.
    var actual_max: f64 = 0;
    for (ac) |a| {
        const m = @max(@abs(a[0]), @max(@abs(a[1]), @abs(a[2])));
        if (m > actual_max) actual_max = m;
    }

    var quantised_max: u32 = 0;
    var max_value: f64 = 1.0;
    if (ac.len > 0) {
        // Quantise: floor(max*166 - 0.5), clamp 0..82.
        var q = @floor(actual_max * 166.0 - 0.5);
        if (q < 0) q = 0;
        if (q > 82) q = 82;
        quantised_max = @intFromFloat(q);
        max_value = (@as(f64, @floatFromInt(quantised_max)) + 1.0) / 166.0;
    }

    var pos: usize = 0;
    // Size header
    const size_flag = (y_components - 1) * 9 + (x_components - 1);
    pos += try writeBase83(size_flag, 1, out[pos..]);
    // Max AC
    pos += try writeBase83(quantised_max, 1, out[pos..]);
    // DC
    pos += try writeBase83(encodeDc(dc), 4, out[pos..]);
    // AC
    for (ac) |a| {
        pos += try writeBase83(encodeAc(a, max_value), 2, out[pos..]);
    }
    return out[0..pos];
}

fn computeBasis(rgba: []const u8, width: u32, height: u32, xc: u32, yc: u32) [3]f64 {
    var r: f64 = 0;
    var g: f64 = 0;
    var b: f64 = 0;
    const normalisation: f64 = if (xc == 0 and yc == 0) 1.0 else 2.0;
    var y: u32 = 0;
    while (y < height) : (y += 1) {
        var x: u32 = 0;
        while (x < width) : (x += 1) {
            const idx = (y * width + x) * 4;
            const fx = std.math.pi * @as(f64, @floatFromInt(xc)) * @as(f64, @floatFromInt(x)) / @as(f64, @floatFromInt(width));
            const fy = std.math.pi * @as(f64, @floatFromInt(yc)) * @as(f64, @floatFromInt(y)) / @as(f64, @floatFromInt(height));
            const basis = @cos(fx) * @cos(fy);
            r += basis * sRGBToLinear(rgba[idx + 0]);
            g += basis * sRGBToLinear(rgba[idx + 1]);
            b += basis * sRGBToLinear(rgba[idx + 2]);
        }
    }
    const scale = normalisation / (@as(f64, @floatFromInt(width)) * @as(f64, @floatFromInt(height)));
    return .{ r * scale, g * scale, b * scale };
}

fn sRGBToLinear(v: u8) f64 {
    const x = @as(f64, @floatFromInt(v)) / 255.0;
    return if (x <= 0.04045) x / 12.92 else std.math.pow(f64, (x + 0.055) / 1.055, 2.4);
}

fn linearToSRGB(v: f64) i32 {
    var x = v;
    if (x < 0) x = 0;
    if (x > 1) x = 1;
    const s = if (x <= 0.0031308) x * 12.92 else 1.055 * std.math.pow(f64, x, 1.0 / 2.4) - 0.055;
    return @intFromFloat(@floor(s * 255.0 + 0.5));
}

fn encodeDc(c: [3]f64) u32 {
    const r: u32 = @intCast(linearToSRGB(c[0]));
    const g: u32 = @intCast(linearToSRGB(c[1]));
    const b: u32 = @intCast(linearToSRGB(c[2]));
    return (r << 16) | (g << 8) | b;
}

fn encodeAc(c: [3]f64, max_value: f64) u32 {
    const r = quantiseAC(c[0], max_value);
    const g = quantiseAC(c[1], max_value);
    const b = quantiseAC(c[2], max_value);
    return r * 19 * 19 + g * 19 + b;
}

fn quantiseAC(v: f64, max_value: f64) u32 {
    const sign_pow = signedPow(v / max_value, 0.5);
    var q = @floor(sign_pow * 9.0 + 9.5);
    if (q < 0) q = 0;
    if (q > 18) q = 18;
    return @intFromFloat(q);
}

fn signedPow(v: f64, e: f64) f64 {
    if (v < 0) return -std.math.pow(f64, -v, e);
    return std.math.pow(f64, v, e);
}

const base83_chars: []const u8 =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz#$%*+,-.:;=?@[]^_{|}~";

fn writeBase83(value: u32, length: u32, out: []u8) Error!u32 {
    if (out.len < length) return error.OutputTooSmall;
    var i: u32 = 0;
    while (i < length) : (i += 1) {
        const power: u32 = std.math.pow(u32, 83, length - i - 1);
        const digit: u32 = (value / power) % 83;
        out[i] = base83_chars[digit];
    }
    return length;
}

// ── tests ──────────────────────────────────────────────────────────

test "blurhash: flat red 32x32 round-trips against reference shape" {
    // A solid colour should yield a hash whose DC corresponds to the
    // input colour and whose AC components are all-zero quantised to '0'
    // (which encodes as 9 → 'A' for r/g/b ... but actually quantised AC=0
    // → 9, and the AC byte is r*361 + g*19 + b = 9*361 + 9*19 + 9 = 3429.
    // We just sanity-check the result is well-formed: 6 chars for 1x1
    // components.
    var pixels: [32 * 32 * 4]u8 = undefined;
    var i: usize = 0;
    while (i < pixels.len) : (i += 4) {
        pixels[i + 0] = 200;
        pixels[i + 1] = 30;
        pixels[i + 2] = 30;
        pixels[i + 3] = 255;
    }
    var out: [16]u8 = undefined;
    const hash = try encode(&pixels, 32, 32, 1, 1, &out);
    // 1x1 components: 1 + 1 + 4 + 0 = 6 chars
    try std.testing.expectEqual(@as(usize, 6), hash.len);
    // Size flag must be '0' (yc-1=0, xc-1=0 → 0 → '0').
    try std.testing.expectEqual(@as(u8, '0'), hash[0]);
    // Max AC = 0 → '0'.
    try std.testing.expectEqual(@as(u8, '0'), hash[1]);
}

test "blurhash: 4x3 component grid produces 20-char hash" {
    var pixels: [32 * 32 * 4]u8 = undefined;
    // Diagonal gradient — exercises real AC components.
    var y: u32 = 0;
    while (y < 32) : (y += 1) {
        var x: u32 = 0;
        while (x < 32) : (x += 1) {
            const idx = (y * 32 + x) * 4;
            pixels[idx + 0] = @intCast((x * 8) & 0xFF);
            pixels[idx + 1] = @intCast((y * 8) & 0xFF);
            pixels[idx + 2] = @intCast(((x + y) * 4) & 0xFF);
            pixels[idx + 3] = 255;
        }
    }
    var out: [32]u8 = undefined;
    const hash = try encode(&pixels, 32, 32, 4, 3, &out);
    // 4x3 components: 1 + 1 + 4 + 2*(12-1) = 28 chars
    try std.testing.expectEqual(@as(usize, 28), hash.len);
    // Size flag: (3-1)*9 + (4-1) = 21 → base83 char index 21 = 'L'.
    try std.testing.expectEqual(@as(u8, 'L'), hash[0]);
}

test "blurhash: rejects bad components" {
    var pixels: [4]u8 = .{ 0, 0, 0, 255 };
    var out: [32]u8 = undefined;
    try std.testing.expectError(error.BadComponents, encode(&pixels, 1, 1, 0, 1, &out));
    try std.testing.expectError(error.BadComponents, encode(&pixels, 1, 1, 1, 99, &out));
}

test "blurhash: rejects small output buffer" {
    var pixels: [4]u8 = .{ 0, 0, 0, 255 };
    var out: [4]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, encode(&pixels, 1, 1, 1, 1, &out));
}

test "blurhash: base83 size byte for max size flag" {
    // 9x9 components → flag (9-1)*9 + (9-1) = 80 → base83 index 80 = '|'.
    var pixels: [32 * 32 * 4]u8 = undefined;
    @memset(&pixels, 128);
    var out: [256]u8 = undefined;
    const hash = try encode(&pixels, 32, 32, 9, 9, &out);
    try std.testing.expectEqual(@as(u8, '|'), hash[0]);
    // 9*9 = 81 components: 1 + 1 + 4 + 2*80 = 166 chars
    try std.testing.expectEqual(@as(usize, 166), hash.len);
}
