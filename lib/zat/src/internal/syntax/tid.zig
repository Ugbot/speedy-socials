//! TID - Timestamp Identifier
//!
//! tids encode a timestamp and clock id in a base32-sortable format.
//! format: 13 characters using alphabet "234567abcdefghijklmnopqrstuvwxyz"
//! - first char must be 2-7 (high bit 0x40 must be 0)
//! - remaining chars encode 53-bit timestamp + 10-bit clock id
//!
//! the encoding is designed to be lexicographically sortable by time.
//! see: https://atproto.com/specs/record-key#record-key-type-tid

const std = @import("std");

pub const Tid = struct {
    raw: [13]u8,

    const alphabet = "234567abcdefghijklmnopqrstuvwxyz";

    /// parse a tid string. returns null if invalid.
    pub fn parse(s: []const u8) ?Tid {
        if (s.len != 13) return null;

        // first char high bit (0x40) must be 0, meaning only '2'-'7' allowed
        if (s[0] & 0x40 != 0) return null;

        var result: Tid = undefined;
        for (s, 0..) |c, i| {
            if (charToValue(c) == null) return null;
            result.raw[i] = c;
        }
        return result;
    }

    /// timestamp in microseconds since unix epoch
    pub fn timestamp(self: Tid) u64 {
        var ts: u64 = 0;
        for (self.raw[0..11]) |c| {
            const val = charToValue(c) orelse unreachable;
            ts = (ts << 5) | val;
        }
        return ts;
    }

    /// clock identifier (lower 10 bits)
    pub fn clockId(self: Tid) u10 {
        var id: u10 = 0;
        for (self.raw[11..13]) |c| {
            const val: u10 = @intCast(charToValue(c) orelse unreachable);
            id = (id << 5) | val;
        }
        return id;
    }

    /// generate tid from timestamp and clock id
    pub fn fromTimestamp(ts: u64, clock_id: u10) Tid {
        var result: Tid = undefined;

        // encode timestamp (53 bits -> 11 chars)
        var t = ts;
        var i: usize = 11;
        while (i > 0) {
            i -= 1;
            result.raw[i] = alphabet[@intCast(t & 0x1f)];
            t >>= 5;
        }

        // encode clock id (10 bits -> 2 chars)
        var c: u10 = clock_id;
        i = 13;
        while (i > 11) {
            i -= 1;
            result.raw[i] = alphabet[@intCast(c & 0x1f)];
            c >>= 5;
        }

        return result;
    }

    /// get the raw string representation
    pub fn str(self: *const Tid) []const u8 {
        return &self.raw;
    }

    fn charToValue(c: u8) ?u5 {
        return switch (c) {
            '2'...'7' => @intCast(c - '2'),
            'a'...'z' => @intCast(c - 'a' + 6),
            else => null,
        };
    }
};

test "parse valid tid" {
    // generate a valid tid and parse it back
    const generated = Tid.fromTimestamp(1704067200000000, 42);
    const tid = Tid.parse(generated.str()) orelse return error.InvalidTid;
    try std.testing.expectEqual(@as(u64, 1704067200000000), tid.timestamp());
    try std.testing.expectEqual(@as(u10, 42), tid.clockId());
}

test "reject invalid tid" {
    // wrong length
    try std.testing.expect(Tid.parse("abc") == null);
    try std.testing.expect(Tid.parse("") == null);

    // invalid chars
    try std.testing.expect(Tid.parse("0000000000000") == null);
    try std.testing.expect(Tid.parse("1111111111111") == null);

    // first char must be 2-7 (high bit 0x40 must be 0)
    try std.testing.expect(Tid.parse("a222222222222") == null);
    try std.testing.expect(Tid.parse("z222222222222") == null);
}

test "roundtrip" {
    const ts: u64 = 1704067200000000; // 2024-01-01 00:00:00 UTC in microseconds
    const clock: u10 = 42;

    const tid = Tid.fromTimestamp(ts, clock);
    try std.testing.expectEqual(ts, tid.timestamp());
    try std.testing.expectEqual(clock, tid.clockId());
}

test "valid first chars" {
    // first char must be 2-7 only
    try std.testing.expect(Tid.parse("2222222222222") != null);
    try std.testing.expect(Tid.parse("3222222222222") != null);
    try std.testing.expect(Tid.parse("4222222222222") != null);
    try std.testing.expect(Tid.parse("5222222222222") != null);
    try std.testing.expect(Tid.parse("6222222222222") != null);
    try std.testing.expect(Tid.parse("7222222222222") != null);
}

test "all valid chars in non-first position" {
    // chars 2-7 and a-z are valid after first position
    try std.testing.expect(Tid.parse("2aaaaaaaaaaaa") != null);
    try std.testing.expect(Tid.parse("2zzzzzzzzzzzz") != null);
    try std.testing.expect(Tid.parse("2234567234567") != null);
}

test "uppercase rejected" {
    try std.testing.expect(Tid.parse("2AAAAAAAAAAAA") == null);
    try std.testing.expect(Tid.parse("2AAAAAAAAaaaa") == null);
}
