//! DID — Decentralized Identifier parsing and validation.
//!
//! Tiger Style: pure, allocator-free. The `Did` struct is a borrowed
//! view over the input string. Resolution (over the network) is *not*
//! done here — it lands in a later phase via the worker pool. The
//! `resolve*` helpers are explicit stubs returning `error.NotImplemented`.
//!
//! Spec: https://atproto.com/specs/did

const std = @import("std");
const core = @import("core");
const assertLe = core.assert.assertLe;
const AtpError = core.errors.AtpError;

pub const max_did_bytes: usize = 2048;

pub const Method = enum { plc, web, other };

pub const Did = struct {
    raw: []const u8,
    method_start: usize, // offset just after "did:"
    id_start: usize, // offset just after second ":"

    pub fn methodStr(self: Did) []const u8 {
        return self.raw[self.method_start .. self.id_start - 1];
    }

    pub fn method(self: Did) Method {
        const m = self.methodStr();
        if (std.mem.eql(u8, m, "plc")) return .plc;
        if (std.mem.eql(u8, m, "web")) return .web;
        return .other;
    }

    pub fn identifier(self: Did) []const u8 {
        return self.raw[self.id_start..];
    }

    pub fn isPlc(self: Did) bool {
        return self.method() == .plc;
    }

    pub fn isWeb(self: Did) bool {
        return self.method() == .web;
    }
};

pub fn parse(s: []const u8) AtpError!Did {
    if (s.len == 0 or s.len > max_did_bytes) return error.BadDid;
    if (!std.mem.startsWith(u8, s, "did:")) return error.BadDid;

    const after = s[4..];
    const method_end = std.mem.indexOfScalar(u8, after, ':') orelse return error.BadDid;
    if (method_end == 0) return error.BadDid;

    // method = lowercase letters only
    var i: usize = 0;
    while (i < method_end) : (i += 1) {
        assertLe(i, after.len);
        const c = after[i];
        if (c < 'a' or c > 'z') return error.BadDid;
    }

    const id_offset = 4 + method_end + 1;
    if (id_offset >= s.len) return error.BadDid;
    const id_part = s[id_offset..];

    const last = id_part[id_part.len - 1];
    if (last == ':' or last == '%') return error.BadDid;

    var j: usize = 0;
    while (j < id_part.len) : (j += 1) {
        assertLe(j, id_part.len);
        const c = id_part[j];
        const ok = switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9' => true,
            '.', '_', ':', '-', '%' => true,
            else => false,
        };
        if (!ok) return error.BadDid;
    }

    return .{ .raw = s, .method_start = 4, .id_start = id_offset };
}

/// Network resolution stub. Will be implemented in a later phase using
/// the worker pool. Calling this today is a programmer error.
pub fn resolvePlcDocument(_: Did, _: []u8) AtpError!usize {
    return error.NotImplemented;
}

/// Network resolution stub for did:web.
pub fn resolveWebDocument(_: Did, _: []u8) AtpError!usize {
    return error.NotImplemented;
}

// ── Tests ──────────────────────────────────────────────────────────

test "did:plc valid" {
    const d = try parse("did:plc:z72i7hdynmk6r22z27h6tvur");
    try std.testing.expect(d.isPlc());
    try std.testing.expectEqualStrings("plc", d.methodStr());
    try std.testing.expectEqualStrings("z72i7hdynmk6r22z27h6tvur", d.identifier());
}

test "did:web valid + percent-port" {
    const a = try parse("did:web:example.com");
    try std.testing.expect(a.isWeb());
    const b = try parse("did:web:localhost%3A8080");
    try std.testing.expectEqualStrings("localhost%3A8080", b.identifier());
}

test "did: rejects missing prefix / uppercase method / empty parts / forbidden chars" {
    try std.testing.expectError(error.BadDid, parse("plc:xyz"));
    try std.testing.expectError(error.BadDid, parse("did:PLC:xyz"));
    try std.testing.expectError(error.BadDid, parse("did::xyz"));
    try std.testing.expectError(error.BadDid, parse("did:plc:"));
    try std.testing.expectError(error.BadDid, parse("did:plc:abc/def"));
    try std.testing.expectError(error.BadDid, parse("did:plc:abc:"));
    try std.testing.expectError(error.BadDid, parse("did:plc:abc%"));
}

test "did: resolve stubs return NotImplemented" {
    const d = try parse("did:web:example.com");
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.NotImplemented, resolveWebDocument(d, &buf));
    try std.testing.expectError(error.NotImplemented, resolvePlcDocument(d, &buf));
}
