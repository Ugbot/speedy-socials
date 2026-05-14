//! AT Protocol syntax validators: handle, NSID, rkey, AT-URI.
//!
//! Pure, allocator-free validators. Each parser returns either a tiny
//! borrowed-view struct on success or a typed error from `errors.AtpError`.
//!
//! Specs:
//!   * handle:  https://atproto.com/specs/handle
//!   * NSID:    https://atproto.com/specs/nsid
//!   * rkey:    https://atproto.com/specs/record-key
//!   * AT-URI:  https://atproto.com/specs/at-uri-scheme
//!
//! Tiger Style notes:
//!   - No recursion, no allocator. Every loop walks the slice once with
//!     `assertLe(i, s.len)` per iteration.
//!   - Validators rejected by returning typed errors (not `null`), so
//!     callers can pattern-match.

const std = @import("std");
const core = @import("core");
const assert_mod = core.assert;
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;
const AtpError = core.errors.AtpError;

const did_mod = @import("did.zig");

pub const max_handle_bytes: usize = 253;
pub const max_nsid_bytes: usize = 317;
pub const max_nsid_segment_bytes: usize = 63;
pub const min_rkey_bytes: usize = 1;
pub const max_rkey_bytes: usize = 512;
pub const max_at_uri_bytes: usize = 8 * 1024;

// ── Handle ─────────────────────────────────────────────────────────

pub const Handle = struct {
    raw: []const u8,

    pub fn parse(s: []const u8) AtpError!Handle {
        try validateHandle(s);
        return .{ .raw = s };
    }
};

fn validateHandle(s: []const u8) AtpError!void {
    if (s.len == 0 or s.len > max_handle_bytes) return error.BadHandle;

    // ASCII-only.
    var ascii_i: usize = 0;
    while (ascii_i < s.len) : (ascii_i += 1) {
        assertLe(ascii_i, s.len);
        if (s[ascii_i] > 127) return error.BadHandle;
    }

    // Walk segments; track last segment for TLD rule.
    var seg_start: usize = 0;
    var segments: u32 = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        assertLe(i, s.len);
        if (s[i] == '.') {
            try validateHandleSegment(s[seg_start..i]);
            segments += 1;
            seg_start = i + 1;
        }
    }

    const tld = s[seg_start..];
    try validateHandleSegment(tld);
    if (tld.len == 0) return error.BadHandle;
    const t0 = tld[0];
    const tld_starts_alpha = (t0 >= 'a' and t0 <= 'z') or (t0 >= 'A' and t0 <= 'Z');
    if (!tld_starts_alpha) return error.BadHandle;
    segments += 1;

    if (segments < 2) return error.BadHandle;
}

fn validateHandleSegment(seg: []const u8) AtpError!void {
    if (seg.len == 0 or seg.len > 63) return error.BadHandle;
    if (seg[0] == '-' or seg[seg.len - 1] == '-') return error.BadHandle;
    var i: usize = 0;
    while (i < seg.len) : (i += 1) {
        assertLe(i, seg.len);
        const c = seg[i];
        const ok = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '-';
        if (!ok) return error.BadHandle;
    }
}

// ── NSID ───────────────────────────────────────────────────────────

pub const Nsid = struct {
    raw: []const u8,
    name_start: usize,

    pub fn parse(s: []const u8) AtpError!Nsid {
        return validateNsid(s);
    }

    pub fn authority(self: Nsid) []const u8 {
        return self.raw[0 .. self.name_start - 1];
    }

    pub fn name(self: Nsid) []const u8 {
        return self.raw[self.name_start..];
    }
};

fn validateNsid(s: []const u8) AtpError!Nsid {
    if (s.len == 0 or s.len > max_nsid_bytes) return error.BadNsid;

    var seg_start: usize = 0;
    var segments: u32 = 0;
    var last_dot: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        assertLe(i, s.len);
        if (s[i] == '.') {
            try validateNsidDomainSegment(s[seg_start..i], segments == 0);
            segments += 1;
            last_dot = i;
            seg_start = i + 1;
        }
    }

    try validateNsidNameSegment(s[seg_start..]);
    segments += 1;

    if (segments < 3) return error.BadNsid;
    return .{ .raw = s, .name_start = last_dot + 1 };
}

fn validateNsidDomainSegment(seg: []const u8, is_first: bool) AtpError!void {
    if (seg.len == 0 or seg.len > max_nsid_segment_bytes) return error.BadNsid;
    if (seg[0] == '-' or seg[seg.len - 1] == '-') return error.BadNsid;
    if (is_first and !(seg[0] >= 'a' and seg[0] <= 'z')) return error.BadNsid;

    var i: usize = 0;
    while (i < seg.len) : (i += 1) {
        assertLe(i, seg.len);
        const c = seg[i];
        const ok = (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '-';
        if (!ok) return error.BadNsid;
    }
}

fn validateNsidNameSegment(seg: []const u8) AtpError!void {
    if (seg.len == 0 or seg.len > max_nsid_segment_bytes) return error.BadNsid;
    if (seg[0] >= '0' and seg[0] <= '9') return error.BadNsid;
    var i: usize = 0;
    while (i < seg.len) : (i += 1) {
        assertLe(i, seg.len);
        const c = seg[i];
        const ok = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9');
        if (!ok) return error.BadNsid;
    }
}

// ── Rkey ───────────────────────────────────────────────────────────

pub const Rkey = struct {
    raw: []const u8,

    pub fn parse(s: []const u8) AtpError!Rkey {
        try validateRkey(s);
        return .{ .raw = s };
    }
};

fn validateRkey(s: []const u8) AtpError!void {
    if (s.len < min_rkey_bytes or s.len > max_rkey_bytes) return error.BadRkey;
    if (std.mem.eql(u8, s, ".") or std.mem.eql(u8, s, "..")) return error.BadRkey;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        assertLe(i, s.len);
        const c = s[i];
        const ok = switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9' => true,
            '.', '-', '_', ':', '~' => true,
            else => false,
        };
        if (!ok) return error.BadRkey;
    }
}

// ── AT-URI ─────────────────────────────────────────────────────────

pub const AtUri = struct {
    raw: []const u8,
    authority_end: usize,
    /// 0 means "no collection", otherwise the byte offset of the slash
    /// terminating the collection (or s.len if collection is the last segment).
    collection_end: usize,

    const prefix = "at://";

    pub fn parse(s: []const u8) AtpError!AtUri {
        if (s.len < prefix.len or s.len > max_at_uri_bytes) return error.BadAtUri;
        if (!std.mem.startsWith(u8, s, prefix)) return error.BadAtUri;

        var i: usize = 0;
        while (i < s.len) : (i += 1) {
            assertLe(i, s.len);
            const c = s[i];
            if (c == ' ' or c == '#' or c == '?') return error.BadAtUri;
        }

        if (s[s.len - 1] == '/') return error.BadAtUri;

        const after_prefix = s[prefix.len..];
        if (after_prefix.len == 0) return error.BadAtUri;

        const authority_end_rel = std.mem.indexOfScalar(u8, after_prefix, '/');
        const auth_str = after_prefix[0 .. authority_end_rel orelse after_prefix.len];
        if (auth_str.len == 0) return error.BadAtUri;

        // Authority must be a DID or a handle.
        const did_ok = blk: {
            _ = did_mod.parse(auth_str) catch break :blk false;
            break :blk true;
        };
        const handle_ok = blk: {
            _ = Handle.parse(auth_str) catch break :blk false;
            break :blk true;
        };
        if (!did_ok and !handle_ok) return error.BadAtUri;

        if (authority_end_rel) |ae| {
            const after_auth = after_prefix[ae + 1 ..];
            if (after_auth.len == 0) return error.BadAtUri;

            const collection_end_rel = std.mem.indexOfScalar(u8, after_auth, '/');
            const coll_str = after_auth[0 .. collection_end_rel orelse after_auth.len];
            if (coll_str.len == 0) return error.BadAtUri;
            _ = try Nsid.parse(coll_str);

            if (collection_end_rel) |ce| {
                const rkey_str = after_auth[ce + 1 ..];
                if (rkey_str.len == 0) return error.BadAtUri;
                _ = try Rkey.parse(rkey_str);
                return .{
                    .raw = s,
                    .authority_end = prefix.len + ae,
                    .collection_end = prefix.len + ae + 1 + ce,
                };
            }

            return .{
                .raw = s,
                .authority_end = prefix.len + ae,
                .collection_end = s.len,
            };
        }

        return .{
            .raw = s,
            .authority_end = s.len,
            .collection_end = 0,
        };
    }

    pub fn authority(self: AtUri) []const u8 {
        return self.raw[prefix.len..self.authority_end];
    }

    pub fn collection(self: AtUri) ?[]const u8 {
        if (self.collection_end == 0) return null;
        return self.raw[self.authority_end + 1 .. self.collection_end];
    }

    pub fn rkey(self: AtUri) ?[]const u8 {
        if (self.collection_end == 0) return null;
        if (self.collection_end >= self.raw.len) return null;
        const r = self.raw[self.collection_end + 1 ..];
        if (r.len == 0) return null;
        return r;
    }

    /// Write `at://authority[/collection[/rkey]]` into `out`.
    /// Returns slice of `out` written, or error if it doesn't fit.
    pub fn format(
        out: []u8,
        authority_str: []const u8,
        collection_str: ?[]const u8,
        rkey_str: ?[]const u8,
    ) AtpError![]const u8 {
        var total: usize = prefix.len + authority_str.len;
        if (collection_str) |c| {
            total += 1 + c.len;
            if (rkey_str) |r| total += 1 + r.len;
        }
        if (out.len < total) return error.BadAtUri;

        var pos: usize = 0;
        @memcpy(out[pos..][0..prefix.len], prefix);
        pos += prefix.len;
        @memcpy(out[pos..][0..authority_str.len], authority_str);
        pos += authority_str.len;

        if (collection_str) |c| {
            out[pos] = '/';
            pos += 1;
            @memcpy(out[pos..][0..c.len], c);
            pos += c.len;
            if (rkey_str) |r| {
                out[pos] = '/';
                pos += 1;
                @memcpy(out[pos..][0..r.len], r);
                pos += r.len;
            }
        }
        assertLe(pos, out.len);
        return out[0..pos];
    }
};

// ── Tests ──────────────────────────────────────────────────────────

test "handle: valid two-segment" {
    _ = try Handle.parse("alice.example.com");
    _ = try Handle.parse("jay.bsky.social");
    _ = try Handle.parse("a.b");
}

test "handle: rejects single segment / digit-tld / hyphens / non-ascii" {
    try std.testing.expectError(error.BadHandle, Handle.parse("example"));
    try std.testing.expectError(error.BadHandle, Handle.parse("john.0"));
    try std.testing.expectError(error.BadHandle, Handle.parse("-bad.example.com"));
    try std.testing.expectError(error.BadHandle, Handle.parse("bad-.example.com"));
    try std.testing.expectError(error.BadHandle, Handle.parse(".example.com"));
    try std.testing.expectError(error.BadHandle, Handle.parse("test..com"));
    var nonascii = "abc.example.com".*;
    nonascii[0] = 0xC3;
    try std.testing.expectError(error.BadHandle, Handle.parse(&nonascii));
}

test "nsid: valid + authority/name split" {
    const n = try Nsid.parse("app.bsky.feed.post");
    try std.testing.expectEqualStrings("app.bsky.feed", n.authority());
    try std.testing.expectEqualStrings("post", n.name());
}

test "nsid: rejects 2-segment / digit-start name / hyphen in name / uppercase domain" {
    try std.testing.expectError(error.BadNsid, Nsid.parse("a.b"));
    try std.testing.expectError(error.BadNsid, Nsid.parse("com.example.3thing"));
    try std.testing.expectError(error.BadNsid, Nsid.parse("com.example.foo-bar"));
    try std.testing.expectError(error.BadNsid, Nsid.parse("COM.example.thing"));
    try std.testing.expectError(error.BadNsid, Nsid.parse("com..thing"));
}

test "rkey: valid forms" {
    _ = try Rkey.parse("abc123");
    _ = try Rkey.parse("self");
    _ = try Rkey.parse("3jxtb5w2hkt2m");
    _ = try Rkey.parse("a:b-c.d_e~f");
}

test "rkey: rejects empty / dot / slash" {
    try std.testing.expectError(error.BadRkey, Rkey.parse(""));
    try std.testing.expectError(error.BadRkey, Rkey.parse("."));
    try std.testing.expectError(error.BadRkey, Rkey.parse(".."));
    try std.testing.expectError(error.BadRkey, Rkey.parse("a/b"));
    try std.testing.expectError(error.BadRkey, Rkey.parse("a b"));
}

test "at-uri: full record uri" {
    const u = try AtUri.parse("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3jxtb5w2hkt2m");
    try std.testing.expectEqualStrings("did:plc:z72i7hdynmk6r22z27h6tvur", u.authority());
    try std.testing.expectEqualStrings("app.bsky.feed.post", u.collection().?);
    try std.testing.expectEqualStrings("3jxtb5w2hkt2m", u.rkey().?);
}

test "at-uri: handle authority + format roundtrip" {
    const u = try AtUri.parse("at://alice.bsky.social/app.bsky.feed.post/abc123");
    try std.testing.expectEqualStrings("alice.bsky.social", u.authority());

    var buf: [256]u8 = undefined;
    const out = try AtUri.format(&buf, "alice.bsky.social", "app.bsky.feed.post", "abc123");
    try std.testing.expectEqualStrings("at://alice.bsky.social/app.bsky.feed.post/abc123", out);
}

test "at-uri: rejects bad shapes" {
    try std.testing.expectError(error.BadAtUri, AtUri.parse("http://x"));
    try std.testing.expectError(error.BadAtUri, AtUri.parse("at://"));
    try std.testing.expectError(error.BadAtUri, AtUri.parse("at://did:plc:xyz/"));
    try std.testing.expectError(error.BadAtUri, AtUri.parse("at://did:plc:xyz/coll/"));
}
