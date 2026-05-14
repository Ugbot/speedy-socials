//! DID - Decentralized Identifier
//!
//! dids are persistent, long-term account identifiers based on W3C standard.
//! format: did:<method>:<identifier>
//!
//! validation rules:
//! - max 2048 characters
//! - method must be lowercase letters only
//! - identifier allows: a-zA-Z0-9._:%-
//! - cannot end with : or %
//! - cannot contain: / ? # [ ] @
//!
//! see: https://atproto.com/specs/did

const std = @import("std");

pub const Did = struct {
    /// the full did string (borrowed, not owned)
    raw: []const u8,

    /// offset where method starts (after "did:")
    method_start: usize,

    /// offset where method ends / identifier starts
    id_start: usize,

    pub const max_length = 2048;

    pub const Method = enum {
        plc,
        web,
        other,
    };

    /// parse a did string. returns null if invalid.
    pub fn parse(s: []const u8) ?Did {
        // length check
        if (s.len == 0 or s.len > max_length) return null;

        // must start with "did:"
        if (!std.mem.startsWith(u8, s, "did:")) return null;

        // find method end (next colon)
        const after_did = s[4..];
        const method_end = std.mem.indexOfScalar(u8, after_did, ':') orelse return null;
        if (method_end == 0) return null; // empty method

        // method must be lowercase letters only
        const method_str = after_did[0..method_end];
        for (method_str) |c| {
            if (c < 'a' or c > 'z') return null;
        }

        // identifier must not be empty
        const id_offset = 4 + method_end + 1;
        if (id_offset >= s.len) return null;

        const id_part = s[id_offset..];

        // cannot end with : or %
        const last = id_part[id_part.len - 1];
        if (last == ':' or last == '%') return null;

        // validate identifier characters
        if (!isValidIdentifier(id_part)) return null;

        return .{
            .raw = s,
            .method_start = 4,
            .id_start = id_offset,
        };
    }

    /// the method portion (e.g., "plc", "web")
    pub fn methodStr(self: Did) []const u8 {
        return self.raw[self.method_start .. self.id_start - 1];
    }

    /// the method as an enum (plc, web, or other)
    pub fn method(self: Did) Method {
        const m = self.methodStr();
        if (std.mem.eql(u8, m, "plc")) return .plc;
        if (std.mem.eql(u8, m, "web")) return .web;
        return .other;
    }

    /// the method-specific identifier
    pub fn identifier(self: Did) []const u8 {
        return self.raw[self.id_start..];
    }

    /// check if this is a plc did
    pub fn isPlc(self: Did) bool {
        return self.method() == .plc;
    }

    /// check if this is a web did
    pub fn isWeb(self: Did) bool {
        return self.method() == .web;
    }

    /// get the full did string
    pub fn str(self: Did) []const u8 {
        return self.raw;
    }

    fn isValidIdentifier(id: []const u8) bool {
        for (id) |c| {
            const valid = switch (c) {
                'a'...'z', 'A'...'Z', '0'...'9' => true,
                '.', '_', ':', '-', '%' => true,
                // explicitly reject invalid chars
                '/', '?', '#', '[', ']', '@' => false,
                else => false,
            };
            if (!valid) return false;
        }
        return true;
    }
};

// === tests from atproto.com/specs/did ===

test "valid: did:plc example" {
    const did = Did.parse("did:plc:z72i7hdynmk6r22z27h6tvur") orelse return error.InvalidDid;
    try std.testing.expect(did.isPlc());
    try std.testing.expectEqualStrings("plc", did.methodStr());
    try std.testing.expectEqualStrings("z72i7hdynmk6r22z27h6tvur", did.identifier());
}

test "valid: did:web example" {
    const did = Did.parse("did:web:blueskyweb.xyz") orelse return error.InvalidDid;
    try std.testing.expect(did.isWeb());
    try std.testing.expectEqualStrings("web", did.methodStr());
    try std.testing.expectEqualStrings("blueskyweb.xyz", did.identifier());
}

test "valid: did:web with port" {
    const did = Did.parse("did:web:localhost%3A8080") orelse return error.InvalidDid;
    try std.testing.expect(did.isWeb());
    try std.testing.expectEqualStrings("localhost%3A8080", did.identifier());
}

test "valid: other method" {
    const did = Did.parse("did:example:123456") orelse return error.InvalidDid;
    try std.testing.expect(did.method() == .other);
    try std.testing.expectEqualStrings("example", did.methodStr());
}

test "valid: identifier with allowed special chars" {
    try std.testing.expect(Did.parse("did:plc:abc.def") != null);
    try std.testing.expect(Did.parse("did:plc:abc_def") != null);
    try std.testing.expect(Did.parse("did:plc:abc:def") != null);
    try std.testing.expect(Did.parse("did:plc:abc-def") != null);
    try std.testing.expect(Did.parse("did:plc:abc%20def") != null);
}

test "invalid: missing prefix" {
    try std.testing.expect(Did.parse("plc:xyz") == null);
    try std.testing.expect(Did.parse("xyz") == null);
}

test "invalid: uppercase method" {
    try std.testing.expect(Did.parse("did:PLC:xyz") == null);
    try std.testing.expect(Did.parse("did:METHOD:val") == null);
}

test "invalid: empty method" {
    try std.testing.expect(Did.parse("did::xyz") == null);
}

test "invalid: empty identifier" {
    try std.testing.expect(Did.parse("did:plc:") == null);
    try std.testing.expect(Did.parse("did:web:") == null);
}

test "invalid: ends with colon or percent" {
    try std.testing.expect(Did.parse("did:plc:abc:") == null);
    try std.testing.expect(Did.parse("did:plc:abc%") == null);
}

test "invalid: contains forbidden chars" {
    try std.testing.expect(Did.parse("did:plc:abc/def") == null);
    try std.testing.expect(Did.parse("did:plc:abc?def") == null);
    try std.testing.expect(Did.parse("did:plc:abc#def") == null);
    try std.testing.expect(Did.parse("did:plc:abc[def") == null);
    try std.testing.expect(Did.parse("did:plc:abc]def") == null);
    try std.testing.expect(Did.parse("did:plc:abc@def") == null);
}

test "invalid: too long" {
    // create a did longer than 2048 chars
    var buf: [2100]u8 = undefined;
    @memset(&buf, 'a');
    @memcpy(buf[0..8], "did:plc:");
    try std.testing.expect(Did.parse(&buf) == null);
}
