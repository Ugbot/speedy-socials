//! Handle - AT Protocol Handle Identifier
//!
//! handles are domain-name based identifiers for accounts.
//! format: <segment>.<segment>...<tld>
//!
//! validation rules:
//! - max 253 characters
//! - ASCII only (a-z, 0-9, hyphen)
//! - 2+ segments separated by dots
//! - each segment: 1-63 chars, no leading/trailing hyphens
//! - final segment (TLD) cannot start with a digit
//! - case-insensitive, normalize to lowercase
//!
//! see: https://atproto.com/specs/handle

const std = @import("std");

pub const Handle = struct {
    /// the handle string (borrowed, not owned)
    raw: []const u8,

    pub const max_length = 253;

    /// parse a handle string. returns null if invalid.
    pub fn parse(s: []const u8) ?Handle {
        if (!isValid(s)) return null;
        return .{ .raw = s };
    }

    /// validate a handle string without allocating
    pub fn isValid(s: []const u8) bool {
        // length check
        if (s.len == 0 or s.len > max_length) return false;

        // must be ascii
        for (s) |c| {
            if (c > 127) return false;
        }

        var segment_count: usize = 0;
        var segment_start: usize = 0;
        var last_segment_start: usize = 0;

        for (s, 0..) |c, i| {
            if (c == '.') {
                const segment = s[segment_start..i];
                if (!isValidSegment(segment)) return false;
                segment_count += 1;
                last_segment_start = i + 1;
                segment_start = i + 1;
            }
        }

        // validate final segment (TLD)
        const tld = s[last_segment_start..];
        if (!isValidSegment(tld)) return false;
        if (!isValidTld(tld)) return false;
        segment_count += 1;

        // must have at least 2 segments
        return segment_count >= 2;
    }

    /// get the handle string
    pub fn str(self: Handle) []const u8 {
        return self.raw;
    }

    fn isValidSegment(seg: []const u8) bool {
        // 1-63 characters
        if (seg.len == 0 or seg.len > 63) return false;

        // cannot start or end with hyphen
        if (seg[0] == '-' or seg[seg.len - 1] == '-') return false;

        // only alphanumeric and hyphen
        for (seg) |c| {
            const valid = (c >= 'a' and c <= 'z') or
                (c >= 'A' and c <= 'Z') or
                (c >= '0' and c <= '9') or
                c == '-';
            if (!valid) return false;
        }

        return true;
    }

    fn isValidTld(tld: []const u8) bool {
        if (tld.len == 0) return false;
        // TLD cannot start with a digit
        const first = tld[0];
        return (first >= 'a' and first <= 'z') or (first >= 'A' and first <= 'Z');
    }
};

// === tests from atproto.com/specs/handle ===

test "valid: simple handle" {
    try std.testing.expect(Handle.parse("jay.bsky.social") != null);
    try std.testing.expect(Handle.parse("alice.example.com") != null);
}

test "valid: two segments" {
    try std.testing.expect(Handle.parse("example.com") != null);
    try std.testing.expect(Handle.parse("test.org") != null);
}

test "valid: many segments" {
    try std.testing.expect(Handle.parse("a.b.c.d.e.f") != null);
}

test "valid: with hyphens" {
    try std.testing.expect(Handle.parse("my-name.example.com") != null);
    try std.testing.expect(Handle.parse("test.my-domain.org") != null);
}

test "valid: with numbers" {
    try std.testing.expect(Handle.parse("user123.example.com") != null);
    try std.testing.expect(Handle.parse("123user.example.com") != null);
}

test "valid: uppercase (allowed, normalize to lowercase)" {
    try std.testing.expect(Handle.parse("LOUD.example.com") != null);
    try std.testing.expect(Handle.parse("Jay.Bsky.Social") != null);
}

test "invalid: single segment" {
    try std.testing.expect(Handle.parse("example") == null);
    try std.testing.expect(Handle.parse("localhost") == null);
}

test "invalid: TLD starts with digit" {
    try std.testing.expect(Handle.parse("john.0") == null);
    try std.testing.expect(Handle.parse("test.123") == null);
}

test "invalid: segment starts with hyphen" {
    try std.testing.expect(Handle.parse("-test.example.com") == null);
    try std.testing.expect(Handle.parse("test.-example.com") == null);
}

test "invalid: segment ends with hyphen" {
    try std.testing.expect(Handle.parse("test-.example.com") == null);
    try std.testing.expect(Handle.parse("test.example-.com") == null);
}

test "invalid: empty segment" {
    try std.testing.expect(Handle.parse(".example.com") == null);
    try std.testing.expect(Handle.parse("test..com") == null);
    try std.testing.expect(Handle.parse("test.example.") == null);
}

test "invalid: trailing dot" {
    try std.testing.expect(Handle.parse("example.com.") == null);
}

test "invalid: invalid characters" {
    try std.testing.expect(Handle.parse("test_name.example.com") == null);
    try std.testing.expect(Handle.parse("test@name.example.com") == null);
    try std.testing.expect(Handle.parse("test name.example.com") == null);
}

test "invalid: non-ascii" {
    try std.testing.expect(Handle.parse("tëst.example.com") == null);
}

test "invalid: too long" {
    // create a handle longer than 253 chars
    var buf: [300]u8 = undefined;
    @memset(&buf, 'a');
    buf[100] = '.';
    buf[200] = '.';
    @memcpy(buf[201..204], "com");
    try std.testing.expect(Handle.parse(buf[0..254]) == null);
}

test "invalid: segment too long" {
    // segment > 63 chars
    var buf: [100]u8 = undefined;
    @memset(&buf, 'a');
    buf[64] = '.';
    @memcpy(buf[65..68], "com");
    try std.testing.expect(Handle.parse(buf[0..68]) == null);
}
