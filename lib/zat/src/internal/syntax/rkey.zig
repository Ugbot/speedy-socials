//! Record Key (rkey)
//!
//! record keys identify individual records within a collection.
//!
//! validation rules:
//! - 1-512 characters
//! - allowed chars: A-Z, a-z, 0-9, period, hyphen, underscore, colon, tilde
//! - cannot be "." or ".."
//!
//! note: TIDs are a common rkey format but not the only valid one.
//! see tid.zig for TID-specific parsing.
//!
//! see: https://atproto.com/specs/record-key

const std = @import("std");

pub const Rkey = struct {
    /// the rkey string (borrowed, not owned)
    raw: []const u8,

    pub const min_length = 1;
    pub const max_length = 512;

    /// parse a record key string. returns null if invalid.
    pub fn parse(s: []const u8) ?Rkey {
        if (!isValid(s)) return null;
        return .{ .raw = s };
    }

    /// validate a record key string
    pub fn isValid(s: []const u8) bool {
        // length check
        if (s.len < min_length or s.len > max_length) return false;

        // cannot be "." or ".."
        if (std.mem.eql(u8, s, ".") or std.mem.eql(u8, s, "..")) return false;

        // check all characters are valid
        for (s) |c| {
            const valid = switch (c) {
                'A'...'Z', 'a'...'z', '0'...'9' => true,
                '.', '-', '_', ':', '~' => true,
                else => false,
            };
            if (!valid) return false;
        }

        return true;
    }

    /// get the rkey string
    pub fn str(self: Rkey) []const u8 {
        return self.raw;
    }
};

// === tests from atproto.com/specs/record-key ===

test "valid: simple rkey" {
    try std.testing.expect(Rkey.parse("abc123") != null);
    try std.testing.expect(Rkey.parse("self") != null);
}

test "valid: tid format" {
    try std.testing.expect(Rkey.parse("3jxtb5w2hkt2m") != null);
}

test "valid: with allowed special chars" {
    try std.testing.expect(Rkey.parse("abc.def") != null);
    try std.testing.expect(Rkey.parse("abc-def") != null);
    try std.testing.expect(Rkey.parse("abc_def") != null);
    try std.testing.expect(Rkey.parse("abc:def") != null);
    try std.testing.expect(Rkey.parse("abc~def") != null);
}

test "valid: mixed case" {
    try std.testing.expect(Rkey.parse("AbC123") != null);
    try std.testing.expect(Rkey.parse("ABC") != null);
}

test "valid: single character" {
    try std.testing.expect(Rkey.parse("a") != null);
    try std.testing.expect(Rkey.parse("1") != null);
}

test "valid: max length" {
    var buf: [512]u8 = undefined;
    @memset(&buf, 'a');
    try std.testing.expect(Rkey.parse(&buf) != null);
}

test "invalid: empty" {
    try std.testing.expect(Rkey.parse("") == null);
}

test "invalid: dot" {
    try std.testing.expect(Rkey.parse(".") == null);
}

test "invalid: double dot" {
    try std.testing.expect(Rkey.parse("..") == null);
}

test "invalid: too long" {
    var buf: [513]u8 = undefined;
    @memset(&buf, 'a');
    try std.testing.expect(Rkey.parse(&buf) == null);
}

test "invalid: forbidden characters" {
    try std.testing.expect(Rkey.parse("abc/def") == null);
    try std.testing.expect(Rkey.parse("abc?def") == null);
    try std.testing.expect(Rkey.parse("abc#def") == null);
    try std.testing.expect(Rkey.parse("abc@def") == null);
    try std.testing.expect(Rkey.parse("abc def") == null);
    try std.testing.expect(Rkey.parse("abc\ndef") == null);
}

test "invalid: non-ascii" {
    var buf = "abcdef".*;
    buf[2] = 200; // non-ascii byte
    try std.testing.expect(Rkey.parse(&buf) == null);
}
