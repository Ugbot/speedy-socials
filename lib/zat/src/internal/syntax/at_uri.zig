//! AT-URI Parser
//!
//! at-uris identify repositories and records in the atproto network.
//! format: at://<authority>[/<collection>[/<rkey>]]
//!
//! validation rules:
//! - max 8KB length
//! - no trailing slashes
//! - authority is either a DID or handle
//! - collection (if present) must be a valid NSID
//! - rkey (if present) must be a valid record key
//!
//! see: https://atproto.com/specs/at-uri-scheme

const std = @import("std");
const Did = @import("did.zig").Did;
const Handle = @import("handle.zig").Handle;
const Nsid = @import("nsid.zig").Nsid;
const Rkey = @import("rkey.zig").Rkey;

pub const AtUri = struct {
    /// the full uri string (borrowed, not owned)
    raw: []const u8,

    /// offset where authority ends (after "at://")
    authority_end: usize,

    /// offset where collection ends (0 if no collection)
    collection_end: usize,

    pub const max_length = 8 * 1024;
    const prefix = "at://";

    /// parse an at-uri. returns null if invalid.
    pub fn parse(s: []const u8) ?AtUri {
        // length check
        if (s.len < prefix.len or s.len > max_length) return null;

        // must start with "at://"
        if (!std.mem.startsWith(u8, s, prefix)) return null;

        // reject forbidden characters anywhere after prefix
        for (s) |c| {
            if (c == ' ' or c == '#' or c == '?') return null;
        }

        // no trailing slash
        if (s[s.len - 1] == '/') return null;

        const after_prefix = s[prefix.len..];
        if (after_prefix.len == 0) return null; // empty authority

        // find first slash (end of authority)
        const authority_end_rel = std.mem.indexOfScalar(u8, after_prefix, '/');

        const auth_str = after_prefix[0 .. authority_end_rel orelse after_prefix.len];
        if (auth_str.len == 0) return null;

        // authority must be a valid DID or handle
        if (Did.parse(auth_str) == null and Handle.parse(auth_str) == null) return null;

        if (authority_end_rel) |ae| {
            const after_authority = after_prefix[ae + 1 ..];
            if (after_authority.len == 0) return null; // trailing slash after authority

            // find second slash (end of collection)
            const collection_end_rel = std.mem.indexOfScalar(u8, after_authority, '/');

            const coll_str = after_authority[0 .. collection_end_rel orelse after_authority.len];
            if (coll_str.len == 0) return null; // empty collection

            // collection must be a valid NSID
            if (Nsid.parse(coll_str) == null) return null;

            if (collection_end_rel) |ce| {
                const rkey_str = after_authority[ce + 1 ..];
                if (rkey_str.len == 0) return null; // trailing slash after collection

                // rkey must be a valid record key
                if (Rkey.parse(rkey_str) == null) return null;

                return .{
                    .raw = s,
                    .authority_end = prefix.len + ae,
                    .collection_end = prefix.len + ae + 1 + ce,
                };
            } else {
                // uri with authority + collection only
                return .{
                    .raw = s,
                    .authority_end = prefix.len + ae,
                    .collection_end = s.len,
                };
            }
        } else {
            // authority only
            return .{
                .raw = s,
                .authority_end = s.len,
                .collection_end = 0,
            };
        }
    }

    /// the authority portion (DID or handle)
    pub fn authority(self: AtUri) []const u8 {
        return self.raw[prefix.len..self.authority_end];
    }

    /// the collection portion, or null if not present
    pub fn collection(self: AtUri) ?[]const u8 {
        if (self.collection_end == 0) return null;
        return self.raw[self.authority_end + 1 .. self.collection_end];
    }

    /// the rkey portion, or null if not present
    pub fn rkey(self: AtUri) ?[]const u8 {
        if (self.collection_end == 0) return null;
        if (self.collection_end >= self.raw.len) return null;
        const r = self.raw[self.collection_end + 1 ..];
        if (r.len == 0) return null;
        return r;
    }

    /// check if this uri has a collection component
    pub fn hasCollection(self: AtUri) bool {
        return self.collection_end != 0;
    }

    /// check if this uri has an rkey component
    pub fn hasRkey(self: AtUri) bool {
        return self.rkey() != null;
    }

    /// format a new at-uri into the provided buffer.
    /// returns the slice of the buffer used, or null if buffer too small.
    pub fn format(
        buf: []u8,
        authority_str: []const u8,
        collection_str: ?[]const u8,
        rkey_str: ?[]const u8,
    ) ?[]const u8 {
        var total_len = prefix.len + authority_str.len;
        if (collection_str) |c| {
            total_len += 1 + c.len;
            if (rkey_str) |r| {
                total_len += 1 + r.len;
            }
        }

        if (buf.len < total_len) return null;

        var pos: usize = 0;

        @memcpy(buf[pos..][0..prefix.len], prefix);
        pos += prefix.len;

        @memcpy(buf[pos..][0..authority_str.len], authority_str);
        pos += authority_str.len;

        if (collection_str) |c| {
            buf[pos] = '/';
            pos += 1;
            @memcpy(buf[pos..][0..c.len], c);
            pos += c.len;

            if (rkey_str) |r| {
                buf[pos] = '/';
                pos += 1;
                @memcpy(buf[pos..][0..r.len], r);
                pos += r.len;
            }
        }

        return buf[0..pos];
    }
};

// === tests from atproto.com/specs/at-uri-scheme ===

test "valid: full uri with did:plc" {
    const uri = AtUri.parse("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3jxtb5w2hkt2m") orelse return error.InvalidUri;
    try std.testing.expectEqualStrings("did:plc:z72i7hdynmk6r22z27h6tvur", uri.authority());
    try std.testing.expectEqualStrings("app.bsky.feed.post", uri.collection().?);
    try std.testing.expectEqualStrings("3jxtb5w2hkt2m", uri.rkey().?);
}

test "valid: full uri with did:web" {
    const uri = AtUri.parse("at://did:web:example.com/app.bsky.actor.profile/self") orelse return error.InvalidUri;
    try std.testing.expectEqualStrings("did:web:example.com", uri.authority());
    try std.testing.expectEqualStrings("app.bsky.actor.profile", uri.collection().?);
    try std.testing.expectEqualStrings("self", uri.rkey().?);
}

test "valid: full uri with handle" {
    const uri = AtUri.parse("at://alice.bsky.social/app.bsky.feed.post/abc123") orelse return error.InvalidUri;
    try std.testing.expectEqualStrings("alice.bsky.social", uri.authority());
    try std.testing.expectEqualStrings("app.bsky.feed.post", uri.collection().?);
    try std.testing.expectEqualStrings("abc123", uri.rkey().?);
}

test "valid: authority only" {
    const uri = AtUri.parse("at://did:plc:z72i7hdynmk6r22z27h6tvur") orelse return error.InvalidUri;
    try std.testing.expectEqualStrings("did:plc:z72i7hdynmk6r22z27h6tvur", uri.authority());
    try std.testing.expect(uri.collection() == null);
    try std.testing.expect(uri.rkey() == null);
    try std.testing.expect(!uri.hasCollection());
    try std.testing.expect(!uri.hasRkey());
}

test "valid: authority and collection only" {
    const uri = AtUri.parse("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post") orelse return error.InvalidUri;
    try std.testing.expectEqualStrings("did:plc:z72i7hdynmk6r22z27h6tvur", uri.authority());
    try std.testing.expectEqualStrings("app.bsky.feed.post", uri.collection().?);
    try std.testing.expect(uri.rkey() == null);
    try std.testing.expect(uri.hasCollection());
    try std.testing.expect(!uri.hasRkey());
}

test "invalid: missing prefix" {
    try std.testing.expect(AtUri.parse("did:plc:xyz/app.bsky.feed.post/abc") == null);
    try std.testing.expect(AtUri.parse("http://did:plc:xyz/collection/rkey") == null);
}

test "invalid: empty authority" {
    try std.testing.expect(AtUri.parse("at://") == null);
    try std.testing.expect(AtUri.parse("at:///collection/rkey") == null);
}

test "invalid: trailing slash" {
    try std.testing.expect(AtUri.parse("at://did:plc:xyz/") == null);
    try std.testing.expect(AtUri.parse("at://did:plc:xyz/collection/") == null);
    try std.testing.expect(AtUri.parse("at://did:plc:xyz/collection/rkey/") == null);
}

test "invalid: empty collection" {
    try std.testing.expect(AtUri.parse("at://did:plc:xyz//rkey") == null);
}

test "invalid: empty rkey" {
    try std.testing.expect(AtUri.parse("at://did:plc:xyz/collection/") == null);
}

test "format: full uri" {
    var buf: [256]u8 = undefined;
    const result = AtUri.format(&buf, "did:plc:xyz", "app.bsky.feed.post", "abc123") orelse return error.BufferTooSmall;
    try std.testing.expectEqualStrings("at://did:plc:xyz/app.bsky.feed.post/abc123", result);
}

test "format: authority only" {
    var buf: [256]u8 = undefined;
    const result = AtUri.format(&buf, "did:plc:xyz", null, null) orelse return error.BufferTooSmall;
    try std.testing.expectEqualStrings("at://did:plc:xyz", result);
}

test "format: authority and collection" {
    var buf: [256]u8 = undefined;
    const result = AtUri.format(&buf, "did:plc:xyz", "app.bsky.feed.post", null) orelse return error.BufferTooSmall;
    try std.testing.expectEqualStrings("at://did:plc:xyz/app.bsky.feed.post", result);
}
