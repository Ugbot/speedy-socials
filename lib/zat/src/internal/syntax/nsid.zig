//! NSID - Namespaced Identifier
//!
//! nsids identify lexicon schemas and record types.
//! format: <reversed-domain>.<name>
//!
//! validation rules:
//! - max 317 characters
//! - 3+ segments separated by dots
//! - domain authority: reversed domain (lowercase + digits + hyphens)
//! - name segment: letters and digits only, cannot start with digit
//! - each segment: 1-63 characters
//!
//! examples:
//! - app.bsky.feed.post
//! - com.atproto.repo.createRecord
//!
//! see: https://atproto.com/specs/nsid

const std = @import("std");

pub const Nsid = struct {
    /// the nsid string (borrowed, not owned)
    raw: []const u8,

    /// offset where the name segment starts
    name_start: usize,

    pub const max_length = 317;
    pub const max_segment_length = 63;

    /// parse an nsid string. returns null if invalid.
    pub fn parse(s: []const u8) ?Nsid {
        // length check
        if (s.len == 0 or s.len > max_length) return null;

        var segment_count: usize = 0;
        var segment_start: usize = 0;
        var last_dot: usize = 0;

        for (s, 0..) |c, i| {
            if (c == '.') {
                const segment = s[segment_start..i];
                // all segments except last must be valid domain segments
                if (!isValidDomainSegment(segment, segment_count == 0)) return null;
                segment_count += 1;
                last_dot = i;
                segment_start = i + 1;
            }
        }

        // validate final segment (name)
        const name_seg = s[segment_start..];
        if (!isValidNameSegment(name_seg)) return null;
        segment_count += 1;

        // must have at least 3 segments
        if (segment_count < 3) return null;

        return .{
            .raw = s,
            .name_start = last_dot + 1,
        };
    }

    /// the full nsid string
    pub fn str(self: Nsid) []const u8 {
        return self.raw;
    }

    /// the domain authority portion (reversed domain)
    pub fn authority(self: Nsid) []const u8 {
        return self.raw[0 .. self.name_start - 1];
    }

    /// the name segment
    pub fn name(self: Nsid) []const u8 {
        return self.raw[self.name_start..];
    }

    fn isValidDomainSegment(seg: []const u8, is_first: bool) bool {
        // 1-63 characters
        if (seg.len == 0 or seg.len > max_segment_length) return false;

        // cannot start or end with hyphen
        if (seg[0] == '-' or seg[seg.len - 1] == '-') return false;

        // first segment (TLD) must start with a letter
        if (is_first and !(seg[0] >= 'a' and seg[0] <= 'z')) return false;

        // lowercase letters, digits, and hyphens only
        for (seg) |c| {
            const valid = (c >= 'a' and c <= 'z') or
                (c >= '0' and c <= '9') or
                c == '-';
            if (!valid) return false;
        }

        return true;
    }

    fn isValidNameSegment(seg: []const u8) bool {
        // 1-63 characters
        if (seg.len == 0 or seg.len > max_segment_length) return false;

        // cannot start with digit
        const first = seg[0];
        if (first >= '0' and first <= '9') return false;

        // letters and digits only (no hyphens in name)
        for (seg) |c| {
            const valid = (c >= 'a' and c <= 'z') or
                (c >= 'A' and c <= 'Z') or
                (c >= '0' and c <= '9');
            if (!valid) return false;
        }

        return true;
    }
};

// === tests from atproto.com/specs/nsid ===

test "valid: common nsids" {
    const nsid1 = Nsid.parse("app.bsky.feed.post") orelse return error.InvalidNsid;
    try std.testing.expectEqualStrings("app.bsky.feed", nsid1.authority());
    try std.testing.expectEqualStrings("post", nsid1.name());

    const nsid2 = Nsid.parse("com.atproto.repo.createRecord") orelse return error.InvalidNsid;
    try std.testing.expectEqualStrings("com.atproto.repo", nsid2.authority());
    try std.testing.expectEqualStrings("createRecord", nsid2.name());
}

test "valid: minimum 3 segments" {
    try std.testing.expect(Nsid.parse("a.b.c") != null);
    try std.testing.expect(Nsid.parse("com.example.thing") != null);
}

test "valid: many segments" {
    try std.testing.expect(Nsid.parse("net.users.bob.ping") != null);
    try std.testing.expect(Nsid.parse("a.b.c.d.e.f") != null);
}

test "valid: name with numbers" {
    try std.testing.expect(Nsid.parse("com.example.thing2") != null);
    try std.testing.expect(Nsid.parse("app.bsky.feed.getPost1") != null);
}

test "valid: mixed case in name" {
    try std.testing.expect(Nsid.parse("com.example.fooBar") != null);
    try std.testing.expect(Nsid.parse("com.example.FooBar") != null);
}

test "invalid: only 2 segments" {
    try std.testing.expect(Nsid.parse("com.example") == null);
    try std.testing.expect(Nsid.parse("a.b") == null);
}

test "invalid: name starts with digit" {
    try std.testing.expect(Nsid.parse("com.example.3") == null);
    try std.testing.expect(Nsid.parse("com.example.3thing") == null);
}

test "invalid: name contains hyphen" {
    try std.testing.expect(Nsid.parse("com.example.foo-bar") == null);
}

test "invalid: domain segment uppercase" {
    try std.testing.expect(Nsid.parse("COM.example.thing") == null);
    try std.testing.expect(Nsid.parse("com.EXAMPLE.thing") == null);
}

test "invalid: empty segment" {
    try std.testing.expect(Nsid.parse(".example.thing") == null);
    try std.testing.expect(Nsid.parse("com..thing") == null);
    try std.testing.expect(Nsid.parse("com.example.") == null);
}

test "invalid: segment starts with hyphen" {
    try std.testing.expect(Nsid.parse("-com.example.thing") == null);
    try std.testing.expect(Nsid.parse("com.-example.thing") == null);
}

test "invalid: segment ends with hyphen" {
    try std.testing.expect(Nsid.parse("com-.example.thing") == null);
    try std.testing.expect(Nsid.parse("com.example-.thing") == null);
}

test "invalid: non-ascii" {
    // this would be "com.exa💩ple.thing" but we just use a byte > 127
    var buf = "com.example.thing".*;
    buf[5] = 200; // non-ascii byte
    try std.testing.expect(Nsid.parse(&buf) == null);
}

test "invalid: special characters" {
    try std.testing.expect(Nsid.parse("com.example.thing!") == null);
    try std.testing.expect(Nsid.parse("com.example.thing@") == null);
    try std.testing.expect(Nsid.parse("com.example.thing*") == null);
}
