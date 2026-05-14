//! multibase codec
//!
//! encodes and decodes multibase-encoded strings (prefix + encoded data).
//! supports base58btc (z prefix) and base32lower (b prefix).
//!
//! see: https://github.com/multiformats/multibase

const std = @import("std");

/// multibase encoding types
pub const Encoding = enum {
    base58btc, // z prefix
    base32lower, // b prefix

    pub fn fromPrefix(prefix: u8) ?Encoding {
        return switch (prefix) {
            'z' => .base58btc,
            'b' => .base32lower,
            else => null,
        };
    }
};

/// decode a multibase string, returning the raw bytes
/// the first character is the encoding prefix
pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len == 0) return error.EmptyInput;

    const encoding = Encoding.fromPrefix(input[0]) orelse return error.UnsupportedEncoding;

    return switch (encoding) {
        .base58btc => try base58btc.decode(allocator, input[1..]),
        .base32lower => try base32lower.decode(allocator, input[1..]),
    };
}

/// encode raw bytes to a multibase string with the given encoding
pub fn encode(allocator: std.mem.Allocator, encoding: Encoding, data: []const u8) ![]u8 {
    return switch (encoding) {
        .base58btc => try base58btc.encode(allocator, data),
        .base32lower => try base32lower.encode(allocator, data),
    };
}

/// base58btc codec (bitcoin alphabet)
pub const base58btc = struct {
    /// bitcoin base58 alphabet
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /// reverse lookup table
    const decode_table: [256]i8 = blk: {
        var table: [256]i8 = .{-1} ** 256;
        for (alphabet, 0..) |c, i| {
            table[c] = @intCast(i);
        }
        break :blk table;
    };

    /// encode bytes to base58btc string with 'z' multibase prefix
    pub fn encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        // count leading zero bytes → leading '1's
        var leading_zeros: usize = 0;
        for (input) |b| {
            if (b != 0) break;
            leading_zeros += 1;
        }

        if (input.len == 0 or leading_zeros == input.len) {
            // all zeros (or empty)
            const result = try allocator.alloc(u8, 1 + leading_zeros);
            result[0] = 'z'; // multibase prefix
            @memset(result[1..], '1');
            return result;
        }

        // load bytes into big integer (big-endian)
        var acc = try std.math.big.int.Managed.init(allocator);
        defer acc.deinit();

        for (input) |b| {
            try acc.shiftLeft(&acc, 8);
            try acc.addScalar(&acc, b);
        }

        // repeatedly divide by 58 to extract base58 digits
        var digits: std.ArrayList(u8) = .{};
        defer digits.deinit(allocator);

        var divisor = try std.math.big.int.Managed.initSet(allocator, @as(u64, 58));
        defer divisor.deinit();

        var quotient = try std.math.big.int.Managed.init(allocator);
        defer quotient.deinit();

        var remainder = try std.math.big.int.Managed.init(allocator);
        defer remainder.deinit();

        while (!acc.toConst().eqlZero()) {
            try quotient.divFloor(&remainder, &acc, &divisor);
            const digit: usize = @intCast(remainder.toConst().toInt(u64) catch 0);
            try digits.append(allocator, alphabet[digit]);
            try acc.copy(quotient.toConst());
        }

        // result: 'z' prefix + leading '1's + reversed digits
        const total_len = 1 + leading_zeros + digits.items.len;
        const result = try allocator.alloc(u8, total_len);
        result[0] = 'z'; // multibase prefix
        @memset(result[1 .. 1 + leading_zeros], '1');

        // digits were accumulated LSB-first, reverse into result
        const digit_slice = result[1 + leading_zeros ..];
        for (digits.items, 0..) |d, i| {
            digit_slice[digits.items.len - 1 - i] = d;
        }

        return result;
    }

    /// decode base58btc string to bytes
    pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) return allocator.alloc(u8, 0);

        // count leading zeros (1s in base58)
        var leading_zeros: usize = 0;
        for (input) |c| {
            if (c != '1') break;
            leading_zeros += 1;
        }

        // decode using big integer arithmetic
        var acc = try std.math.big.int.Managed.init(allocator);
        defer acc.deinit();

        var multiplier = try std.math.big.int.Managed.initSet(allocator, @as(u64, 58));
        defer multiplier.deinit();

        var temp = try std.math.big.int.Managed.init(allocator);
        defer temp.deinit();

        for (input) |c| {
            const digit = decode_table[c];
            if (digit < 0) return error.InvalidCharacter;

            try temp.mul(&acc, &multiplier);
            try acc.copy(temp.toConst());
            try acc.addScalar(&acc, @as(u8, @intCast(digit)));
        }

        // convert big int to bytes (big-endian)
        const limbs = acc.toConst().limbs;
        const limb_count = acc.len();

        var byte_count: usize = 0;
        if (limb_count > 0 and !acc.toConst().eqlZero()) {
            byte_count = (acc.toConst().bitCountAbs() + 7) / 8;
        }

        const result = try allocator.alloc(u8, leading_zeros + byte_count);
        @memset(result[0..leading_zeros], 0);

        // convert limbs to big-endian bytes
        if (byte_count > 0) {
            const output_slice = result[leading_zeros..];
            var pos: usize = byte_count;
            for (limbs[0..limb_count]) |limb| {
                const limb_bytes = @sizeOf(@TypeOf(limb));
                var i: usize = 0;
                while (i < limb_bytes and pos > 0) : (i += 1) {
                    pos -= 1;
                    output_slice[pos] = @truncate(limb >> @intCast(i * 8));
                }
            }
        }

        return result;
    }
};

/// base32lower codec (RFC 4648, lowercase, no padding)
pub const base32lower = struct {
    const alphabet = "abcdefghijklmnopqrstuvwxyz234567";

    const decode_table: [256]i8 = blk: {
        var table: [256]i8 = .{-1} ** 256;
        for (alphabet, 0..) |c, i| {
            table[c] = @intCast(i);
        }
        break :blk table;
    };

    /// encode bytes to base32lower string with 'b' multibase prefix
    pub fn encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) {
            const result = try allocator.alloc(u8, 1);
            result[0] = 'b';
            return result;
        }

        // base32: 5 bytes → 8 chars
        const out_len = (input.len * 8 + 4) / 5; // ceil(bits / 5)
        const result = try allocator.alloc(u8, 1 + out_len);
        result[0] = 'b'; // multibase prefix

        var bit_buf: u32 = 0;
        var bits: u5 = 0;
        var pos: usize = 1;

        for (input) |byte| {
            bit_buf = (bit_buf << 8) | byte;
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                const idx: u5 = @truncate(bit_buf >> bits);
                result[pos] = alphabet[idx];
                pos += 1;
            }
        }

        // remaining bits (left-aligned)
        if (bits > 0) {
            const idx: u5 = @truncate(bit_buf << (@as(u5, 5) - bits));
            result[pos] = alphabet[idx];
            pos += 1;
        }

        return result[0..pos];
    }

    /// decode base32lower string (no multibase prefix) to bytes
    pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) return allocator.alloc(u8, 0);

        const out_len = input.len * 5 / 8;
        const result = try allocator.alloc(u8, out_len);
        errdefer allocator.free(result);

        var bit_buf: u32 = 0;
        var bits: u4 = 0;
        var pos: usize = 0;

        for (input) |c| {
            if (c == '=') break; // stop at padding
            const digit = decode_table[c];
            if (digit < 0) return error.InvalidCharacter;

            bit_buf = (bit_buf << 5) | @as(u32, @intCast(digit));
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                result[pos] = @truncate(bit_buf >> bits);
                pos += 1;
            }
        }

        return allocator.realloc(result, pos);
    }
};

// === tests ===

test "base58btc decode" {
    const alloc = std.testing.allocator;

    // "abc" in base58btc
    // "abc" = 0x616263 = 6382179
    // expected base58btc: "ZiCa" (verify with external tool)
    {
        const decoded = try base58btc.decode(alloc, "ZiCa");
        defer alloc.free(decoded);
        try std.testing.expectEqualSlices(u8, "abc", decoded);
    }
}

test "base58btc decode with leading zeros" {
    const alloc = std.testing.allocator;

    // leading 1s map to leading zero bytes
    {
        const decoded = try base58btc.decode(alloc, "111");
        defer alloc.free(decoded);
        try std.testing.expectEqual(@as(usize, 3), decoded.len);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0 }, decoded);
    }
}

test "multibase decode base58btc" {
    const alloc = std.testing.allocator;

    // z prefix = base58btc
    {
        const decoded = try decode(alloc, "zZiCa");
        defer alloc.free(decoded);
        try std.testing.expectEqualSlices(u8, "abc", decoded);
    }
}

test "base58btc decode real multibase key - secp256k1" {
    const alloc = std.testing.allocator;
    const multicodec = @import("multicodec.zig");

    // from a real DID document: zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF
    // this is a compressed secp256k1 public key with multicodec prefix
    const key = "zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF";
    const decoded = try decode(alloc, key);
    defer alloc.free(decoded);

    // should decode to 35 bytes: 2-byte multicodec prefix (0xe7 0x01 varint) + 33-byte compressed key
    try std.testing.expectEqual(@as(usize, 35), decoded.len);

    // first two bytes should be secp256k1-pub multicodec prefix (0xe7 0x01 varint for 231)
    try std.testing.expectEqual(@as(u8, 0xe7), decoded[0]);
    try std.testing.expectEqual(@as(u8, 0x01), decoded[1]);

    // parse with multicodec
    const parsed = try multicodec.parsePublicKey(decoded);
    try std.testing.expectEqual(multicodec.KeyType.secp256k1, parsed.key_type);
    try std.testing.expectEqual(@as(usize, 33), parsed.raw.len);

    // compressed point prefix should be 0x02 or 0x03
    try std.testing.expect(parsed.raw[0] == 0x02 or parsed.raw[0] == 0x03);
}

test "base58btc encode-decode round-trip" {
    const alloc = std.testing.allocator;

    {
        const original = "abc";
        const encoded = try base58btc.encode(alloc, original);
        defer alloc.free(encoded);
        // should have 'z' prefix
        try std.testing.expectEqual(@as(u8, 'z'), encoded[0]);

        const decoded = try decode(alloc, encoded);
        defer alloc.free(decoded);
        try std.testing.expectEqualSlices(u8, original, decoded);
    }

    // round-trip with leading zeros
    {
        const original = &[_]u8{ 0, 0, 0x01 };
        const encoded = try base58btc.encode(alloc, original);
        defer alloc.free(encoded);
        const decoded = try decode(alloc, encoded);
        defer alloc.free(decoded);
        try std.testing.expectEqualSlices(u8, original, decoded);
    }
}

test "base32lower encode-decode round-trip" {
    const alloc = std.testing.allocator;

    {
        const original = "hello";
        const encoded = try base32lower.encode(alloc, original);
        defer alloc.free(encoded);
        try std.testing.expectEqual(@as(u8, 'b'), encoded[0]);

        const decoded = try decode(alloc, encoded);
        defer alloc.free(decoded);
        try std.testing.expectEqualSlices(u8, original, decoded);
    }

    // empty
    {
        const encoded = try base32lower.encode(alloc, "");
        defer alloc.free(encoded);
        try std.testing.expectEqualStrings("b", encoded);
    }
}

test "base32lower decode bafyrei prefix" {
    const alloc = std.testing.allocator;
    // CIDv1 dag-cbor sha2-256 always starts with "bafyrei" in base32lower
    // "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
    const input = "afyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
    const decoded = try base32lower.decode(alloc, input);
    defer alloc.free(decoded);
    // CIDv1: version=1(0x01), codec=dag-cbor(0x71), hash=sha2-256(0x12), len=32(0x20)
    try std.testing.expectEqual(@as(u8, 0x01), decoded[0]);
    try std.testing.expectEqual(@as(u8, 0x71), decoded[1]);
    try std.testing.expectEqual(@as(u8, 0x12), decoded[2]);
    try std.testing.expectEqual(@as(u8, 0x20), decoded[3]);
}
